"""Packet-controller integration without a network, VM or real credentials."""
import base64
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from vm.config import RouteConfig
from vm.route_contract import GUEST_IP


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("packet_controller_test", ROOT / "gateway/controller.py")
gateway = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gateway)


class PacketControllerTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="lemon-packet-controller-")
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name)
        data = json.loads((ROOT / "route.example.json").read_text())
        for node in data["network"].values():
            if isinstance(node, dict):
                node["password"] = "fixture-only-hysteria-password"
        data["wireguard"] = {
            "client_private_key": base64.b64encode(bytes(range(32))).decode(),
            "server_public_key": base64.b64encode(bytes(range(32, 64))).decode(),
        }
        self.user_config = RouteConfig.from_dict(data)
        self.profile = self.user_config.mihomo_profile()
        self.profile_path = self.state / "proxy.json"
        self.wireguard_path = self.state / "wireguard.json"
        self.user_config.render_proxy(self.profile_path)
        self.user_config.render_wireguard(self.wireguard_path)
        self.environment = self.user_config.gateway_env() | {
            "LEMON_PROXY_CONFIG": str(self.profile_path),
            "LEMON_WIREGUARD_CONFIG": str(self.wireguard_path),
        }
        self.config = gateway.Config(self.environment)
        self.config.uplink = "tap0"
        state_patch = mock.patch.object(gateway, "STATE", self.state)
        state_patch.start()
        self.addCleanup(state_patch.stop)
        registry = mock.patch.object(gateway, "registered_guests", return_value=[{"tap":"vm0","guest_cidr":"10.77.0.2/30","gateway_cidr":"10.77.0.1/30"}])
        registry.start(); self.addCleanup(registry.stop)
        uplink = mock.patch.object(gateway, "discover_uplink")
        uplink.start(); self.addCleanup(uplink.stop)

    def live_ready(self):
        (self.state / "ready.json").write_text(json.dumps({"mihomo_pid": 1001, "wireguard_pid": 1002,
                                                        'stream_pid': 1003}))
        return {"guest_ready": [{"elem": {"val": GUEST_IP, "expires": 20}}],
                "transport_ready": [{"elem": {"val": self.config.first_ip, "expires": 20}}]}

    def test_local_health_requires_all_three_live_transport_processes_and_leases(self):
        leases = self.live_ready()
        with mock.patch.object(gateway, "read_leases", return_value=leases), \
                mock.patch.object(gateway.os, "kill") as alive, \
                mock.patch.object(gateway.socket, "create_connection", return_value=mock.MagicMock()), \
                mock.patch.object(gateway, "verify_exit") as verified:
            self.assertTrue(gateway.check(self.config, local=True)["ready"])
        self.assertEqual(alive.call_args_list, [mock.call(1001, 0), mock.call(1002, 0), mock.call(1003, 0)])
        verified.assert_not_called()
        with mock.patch.object(gateway, "read_leases", return_value=leases), \
                mock.patch.object(gateway.os, "kill", side_effect=[None, ProcessLookupError("WireGuard exited")]), \
                mock.patch.object(gateway.socket, "create_connection") as connection:
            with self.assertRaises(ProcessLookupError):
                gateway.check(self.config, local=True)
        connection.assert_not_called()

    def test_full_health_failure_closes_gates_when_packet_exit_changes(self):
        leases = self.live_ready()
        with mock.patch.object(gateway, "read_leases", return_value=leases), \
                mock.patch.object(gateway.os, "kill"), \
                mock.patch.object(gateway.socket, "create_connection", return_value=mock.MagicMock()), \
                mock.patch.object(gateway, "verify_exit", side_effect=ValueError("wrong exit")), \
                mock.patch.object(gateway, "block") as closed:
            with self.assertRaisesRegex(ValueError, "wrong exit"):
                gateway.check(self.config)
        closed.assert_called_once_with()

    def test_service_cannot_mark_ready_when_wireguard_process_exits(self):
        packet = mock.Mock()
        carrier = mock.Mock(pid=1003)
        carrier.poll.return_value = None
        packet.start_stream.return_value = carrier
        wireguard, transport = mock.Mock(pid=1002), mock.Mock(pid=1001)
        wireguard.poll.return_value = 1
        transport.poll.return_value = None
        packet.start_wireguard.return_value = wireguard
        stopping = mock.Mock()
        stopping.is_set.return_value = False
        stopping.wait.return_value = True
        with mock.patch.object(gateway, "packet_module", return_value=packet), \
                mock.patch.object(gateway, "install_firewall"), mock.patch.object(gateway, "command"), \
                mock.patch.object(gateway, "renew_lease"), \
                mock.patch.object(gateway.subprocess, "Popen", return_value=transport), \
                mock.patch.object(gateway.threading, "Event", return_value=stopping), \
                mock.patch.object(gateway.socket, 'create_connection', return_value=mock.MagicMock()), \
                mock.patch.object(gateway.signal, "signal"), \
                mock.patch.object(gateway, "verify_exit") as verified, \
                mock.patch.object(gateway, "write_state") as state, \
                mock.patch.object(gateway, "block") as closed:
            gateway.serve(self.config)
        verified.assert_not_called()
        self.assertFalse(any(call.args[0] == "ready.json" for call in state.call_args_list))
        closed.assert_called_once_with("gateway stopped or verification failed")
        transport.terminate.assert_called_once()

    def test_running_wireguard_death_closes_gates_before_any_further_health_or_renewal(self):
        packet = mock.Mock()
        carrier = mock.Mock(pid=1003)
        carrier.poll.return_value = None
        packet.start_stream.return_value = carrier
        wireguard, transport = mock.Mock(pid=1002), mock.Mock(pid=1001)
        wireguard.poll.side_effect = [None, 1, 1]
        transport.poll.return_value = None
        packet.start_wireguard.return_value = wireguard
        stopping = mock.Mock()
        stopping.is_set.return_value = False
        stopping.wait.side_effect = [False, True]
        with mock.patch.object(gateway, "packet_module", return_value=packet), \
                mock.patch.object(gateway, "install_firewall"), mock.patch.object(gateway, "command"), \
                mock.patch.object(gateway, "renew_lease") as renewed, \
                mock.patch.object(gateway.subprocess, "Popen", return_value=transport), \
                mock.patch.object(gateway.threading, "Event", return_value=stopping), \
                mock.patch.object(gateway.socket, 'create_connection', return_value=mock.MagicMock()), \
                mock.patch.object(gateway.signal, "signal"), \
                mock.patch.object(gateway, "verify_exit", return_value=self.config.exit_ip) as verified, \
                mock.patch.object(gateway, "write_state") as state, \
                mock.patch.object(gateway, "block") as closed:
            gateway.serve(self.config)
        verified.assert_called_once_with(self.config)
        self.assertEqual(renewed.call_args_list, [mock.call(self.config, initial=True), mock.call(self.config),
                                                mock.call(self.config, guest=True, initial=True)])
        ready = next(call.args[1] for call in state.call_args_list if call.args[0] == "ready.json")
        self.assertEqual(ready["wireguard_pid"], 1002)
        self.assertEqual(ready["mihomo_pid"], 1001)
        closed.assert_called_once_with("gateway stopped or verification failed")
        transport.terminate.assert_called_once()

    def stream_service(self, carriers, stopping, verified=None, monotonic=1):
        packet = mock.Mock()
        packet.start_wireguard.return_value = mock.Mock(pid=1002)
        packet.start_wireguard.return_value.poll.return_value = None
        packet.start_stream.side_effect = carriers
        proxy = mock.Mock(pid=1001)
        proxy.poll.return_value = None
        with mock.patch.object(gateway, "packet_module", return_value=packet), \
                mock.patch.object(gateway, "install_firewall"), mock.patch.object(gateway, "command"), \
                mock.patch.object(gateway, "renew_lease") as renewed, \
                mock.patch.object(gateway.subprocess, "Popen", return_value=proxy), \
                mock.patch.object(gateway.threading, "Event", return_value=stopping), \
                mock.patch.object(gateway.signal, "signal"), \
                mock.patch.object(gateway.socket, "create_connection", return_value=mock.MagicMock()), \
                mock.patch.object(gateway.time, "monotonic", side_effect=monotonic if isinstance(monotonic, list) else None,
                                  return_value=monotonic if not isinstance(monotonic, list) else None), \
                mock.patch.object(gateway, "verify_exit", return_value=self.config.exit_ip,
                                  side_effect=verified) as verified_exit, \
                mock.patch.object(gateway, "write_state") as state, \
                mock.patch.object(gateway, "block") as closed:
            gateway.serve(self.config)
        return packet, renewed, state, closed, verified_exit

    def test_cold_carrier_retry_does_not_open_guest_until_full_packet_exit_verified(self):
        dead, live = mock.Mock(pid=1003), mock.Mock(pid=1004)
        dead.poll.return_value = 1
        live.poll.return_value = None
        stopping = mock.Mock()
        stopping.is_set.return_value = False
        stopping.wait.side_effect = [False, True]
        packet, renewed, state, closed, verified = self.stream_service([dead, live], stopping)
        self.assertEqual(packet.start_stream.call_count, 2)
        dead.wait.assert_called_once_with(timeout=3)
        verified.assert_called_once_with(self.config)
        ready = next(call.args[1] for call in state.call_args_list if call.args[0] == "ready.json")
        self.assertEqual(ready["stream_pid"], 1004)
        self.assertEqual(renewed.call_args_list, [mock.call(self.config, initial=True), mock.call(self.config), mock.call(self.config),
                                                mock.call(self.config, guest=True, initial=True)])

    def test_startup_deadline_closes_without_retrying_or_granting_guest_lease(self):
        carrier = mock.Mock(pid=1003)
        carrier.poll.return_value = 1
        stopping = mock.Mock()
        stopping.is_set.return_value = False
        stopping.wait.return_value = True
        packet, renewed, state, closed, verified = self.stream_service([carrier], stopping, monotonic=[1, 1, 122])
        packet.start_stream.assert_called_once()
        verified.assert_not_called()
        self.assertFalse(any(call.args[0] == "ready.json" for call in state.call_args_list))
        self.assertFalse(any(call.kwargs.get("guest") for call in renewed.call_args_list))
        closed.assert_called_once_with("gateway stopped or verification failed")

    def test_carrier_failure_after_readiness_never_reconnects(self):
        carrier = mock.Mock(pid=1003)
        carrier.poll.side_effect = [None, 1, 1]
        stopping = mock.Mock()
        stopping.is_set.return_value = False
        stopping.wait.side_effect = [False, True]
        packet, renewed, state, closed, verified = self.stream_service([carrier], stopping)
        packet.start_stream.assert_called_once()
        verified.assert_called_once_with(self.config)
        closed.assert_called_once_with("gateway stopped or verification failed")


if __name__ == "__main__":
    unittest.main()
