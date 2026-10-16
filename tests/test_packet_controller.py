"""Recovery exercises real lease/token transitions with simulated nft and children."""
import base64
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock

from vm.config import RouteConfig
from vm.route_contract import GUEST_IP


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("packet_controller_test", ROOT / "gateway/controller.py")
gateway = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gateway)
FIRST = {"tap": "vm0", "guest_cidr": "10.77.0.2/30", "gateway_cidr": "10.77.0.1/30"}
SECOND = {"tap": "vm1", "guest_cidr": "10.77.0.6/30", "gateway_cidr": "10.77.0.5/30"}


class Kernel:
    def __init__(self):
        self.transactions = []
        self.before_transaction = None
        self.install()

    def install(self, *args, **kwargs):
        self.sets = {"guest_ready": [], "transport_ready": [], "recovery_allowed": [1]}

    def command(self, args, *, input_text=None):
        if args[:2] == ["nft", "-j"]:
            return json.dumps({"nftables": [{"set": {"name": name, "elem": values}}
                                           for name, values in self.sets.items()]})
        if input_text is not None:
            if self.before_transaction is not None:
                self.before_transaction()
            # Validate existence before applying any statement, as one nft
            # transaction must reject an authorization that expired in flight.
            for statement in input_text.splitlines():
                match = re.match(r"delete element inet \w+ (\w+) \{ (.*) \}$", statement)
                if match:
                    live = {item["elem"]["val"] for item in self.sets[match[1]] if item["elem"]["expires"] > 0}
                    if any(address not in live for address in match[2].split(", ")):
                        raise RuntimeError("expired element")
            self.transactions.append(input_text)
            for statement in input_text.splitlines():
                match = re.match(r"flush set inet \w+ (\w+)$", statement)
                if match:
                    self.sets[match[1]] = []
                match = re.match(r"add element inet \w+ (\w+) \{ (.*) \}$", statement)
                if match and match[1] in ("transport_ready", "guest_ready"):
                    self.sets[match[1]] = [{"elem": {"val": address, "expires": int(seconds)}}
                                         for address, seconds in re.findall(r"([\d.]+) timeout (\d+)s", match[2])]
        return ""

    def transport(self, address, seconds=20):
        self.sets["transport_ready"] = [{"elem": {"val": address, "expires": seconds}}]


class StopEvent:
    def __init__(self, state, *, checks=1):
        self.state = state
        self.checks = checks
        self.stopped = False
        self.waits = []

    def is_set(self):
        return self.stopped

    def set(self):
        self.stopped = True

    def wait(self, seconds):
        self.waits.append(seconds)
        if seconds == gateway.CHECK_INTERVAL and (self.state / "ready.json").exists():
            self.checks -= 1
            if self.checks == 0:
                self.stopped = True
        if seconds == 1 and (self.state / "blocked.json").exists():
            if not json.loads((self.state / "blocked.json").read_text()).get("recovery_token"):
                self.stopped = True
        return self.stopped


def process(pid):
    child = mock.Mock(pid=pid)
    child.poll.return_value = None
    child.terminate.side_effect = lambda: setattr(child.poll, "return_value", -15)
    return child


class PacketControllerTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="lemon-packet-controller-")
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name)
        data = json.loads((ROOT / "route.example.json").read_text())
        for node in data["network"].values():
            if isinstance(node, dict):
                node["password"] = "fixture-only-hysteria-password"
        data["wireguard"] = {"client_private_key": base64.b64encode(bytes(range(32))).decode(),
                             "server_public_key": base64.b64encode(bytes(range(32, 64))).decode()}
        route = RouteConfig.from_dict(data)
        proxy, wireguard = self.state / "proxy.json", self.state / "wireguard.json"
        route.render_proxy(proxy)
        route.render_wireguard(wireguard)
        self.config = gateway.Config(route.gateway_env() | {"LEMON_PROXY_CONFIG": str(proxy),
                                                          "LEMON_WIREGUARD_CONFIG": str(wireguard)})
        self.config.uplink = "tap0"
        self.patch(gateway, "STATE", self.state)
        self.patch(gateway, "discover_uplink")
        gateway.write_state("guests.json", {"guests": [FIRST]})
        self.kernel = Kernel()
        self.patch(gateway, "command", side_effect=self.kernel.command)
        self.real_install_firewall = gateway.install_firewall
        self.patch(gateway, "install_firewall", side_effect=self.kernel.install)
        self.packet = mock.Mock()
        real_packet = gateway.packet_module()
        self.packet._stop.side_effect = real_packet._stop
        self.packet.guest_records.side_effect = real_packet.guest_records
        self.packet.guest_record.side_effect = real_packet.guest_record
        self.packet.registration_elements.side_effect = real_packet.registration_elements
        self.patch(gateway, "packet_module", return_value=self.packet)

    def patch(self, target, name, *args, **kwargs):
        patch = mock.patch.object(target, name, *args, **kwargs)
        result = patch.start()
        self.addCleanup(patch.stop)
        return result

    def live_ready(self):
        gateway.write_state("ready.json", {"mihomo_pid": 1001, "wireguard_pid": 1002, "stream_pid": 1003})
        self.kernel.transport(self.config.first_ip)
        self.kernel.sets["guest_ready"] = [{"elem": {"val": GUEST_IP, "expires": 20}}]

    def service(self, *, checks=1, wireguards=None, carriers=None, verify=None, health=None):
        self.packet.start_wireguard.side_effect = wireguards or [process(1002), process(1012)]
        self.packet.start_stream.side_effect = carriers or [process(1003), process(1013)]
        proxies = [process(1001), process(1011), process(1021), process(1031), process(1041)]
        self.patch(gateway.subprocess, "Popen", side_effect=proxies)
        self.patch(gateway.socket, "create_connection", return_value=mock.MagicMock())
        self.patch(gateway.signal, "signal")
        event = StopEvent(self.state, checks=checks)
        self.patch(gateway.threading, "Event", return_value=event)
        verified = self.patch(gateway, "verify_exit", side_effect=verify, return_value=self.config.exit_ip)
        self.patch(gateway, "verify_health", side_effect=health, return_value=self.config.exit_ip)
        writes = self.patch(gateway, "write_state", wraps=gateway.write_state)
        gateway.serve(self.config)
        return event, verified, writes, proxies

    def test_local_health_requires_all_live_children_and_kernel_leases(self):
        self.live_ready()
        alive = self.patch(gateway.os, "kill")
        self.patch(gateway.socket, "create_connection", return_value=mock.MagicMock())
        self.assertTrue(gateway.check(self.config, local=True)["ready"])
        self.assertEqual(alive.call_args_list, [mock.call(1001, 0), mock.call(1002, 0), mock.call(1003, 0)])
        alive.side_effect = [None, ProcessLookupError("WireGuard exited")]
        with self.assertRaises(ProcessLookupError):
            gateway.check(self.config, local=True)

    def test_full_check_wrong_exit_is_terminal_but_io_failure_requests_recovery(self):
        self.live_ready()
        self.patch(gateway.os, "kill")
        self.patch(gateway.socket, "create_connection", return_value=mock.MagicMock())
        verification = self.patch(gateway, "verify_exit", side_effect=OSError("offline"))
        with self.assertRaises(OSError):
            gateway.check(self.config)
        self.assertTrue(json.loads((self.state / "blocked.json").read_text())["recovery_token"])
        self.assertEqual(self.kernel.sets["guest_ready"], [])
        self.live_ready()
        (self.state / "blocked.json").unlink()
        verification.side_effect = ValueError("wrong exit")
        with self.assertRaises(ValueError):
            gateway.check(self.config)
        self.assertEqual(self.kernel.sets["recovery_allowed"], [])
        self.assertNotIn("recovery_token", json.loads((self.state / "blocked.json").read_text()))

    def test_expired_runtime_lease_recovers_same_route_without_touching_guest_taps(self):
        event, verified, writes, proxies = self.service(checks=2, health=OSError("kernel lease expired"))
        healthy = [call.args[1] for call in writes.call_args_list
                   if call.args[0] == "recovery.json" and call.args[1]["status"] == "healthy"]
        self.assertEqual(len(healthy), 2)
        self.assertEqual(verified.call_count, 2)
        self.assertEqual(self.packet.start_wireguard.call_count, 2)
        self.assertEqual(gateway.registered_guests(), [FIRST])
        self.packet.create_guest.assert_not_called()
        self.packet.delete_guest.assert_not_called()
        proxies[0].terminate.assert_called_once()
        transactions = self.kernel.transactions
        self.assertEqual(sum("10.77.0.2 timeout 30s" in text for text in transactions), 2)
        for text in transactions:
            if "10.77.0.2 timeout 30s" in text:
                self.assertIn("flush set inet lemon_vm transport_ready", text)
        self.assertIn(5, event.waits)

    def test_three_failed_attempts_alert_and_slow_retry_still_self_heals(self):
        event, verified, writes, _ = self.service(wireguards=[OSError("offline")] * 3 + [process(1042)])
        states = [call.args[1] for call in writes.call_args_list if call.args[0] == "recovery.json"]
        self.assertTrue(any(value["status"] == "failed" and value["attempts"] == 3 for value in states))
        self.assertTrue(any(value["status"] == "healthy" and value["attempts"] == 4 for value in states))
        self.assertEqual(self.packet.start_wireguard.call_count, 4)
        self.assertIn(60, event.waits)
        verified.assert_called_once()

    def test_wrong_exit_stays_shut_without_retrying(self):
        _, verified, writes, _ = self.service(verify=ValueError("private detail must not be persisted"))
        verified.assert_called_once()
        self.packet.start_wireguard.assert_called_once()
        self.assertFalse(any(call.args[0] == "ready.json" for call in writes.call_args_list))
        self.assertEqual(json.loads((self.state / "recovery.json").read_text())["status"], "failed")
        self.assertNotIn("private detail", (self.state / "recovery.json").read_text())
        self.assertEqual(self.kernel.sets["guest_ready"], [])

    def test_operator_block_during_probe_cannot_be_undone_by_recovery(self):
        def operator_block(*args, **kwargs):
            gateway.block("operator test or shutdown")
            return self.config.exit_ip
        _, _, writes, _ = self.service(verify=operator_block)
        self.assertFalse(any(call.args[0] == "ready.json" for call in writes.call_args_list))
        self.packet.start_wireguard.assert_called_once()
        self.assertEqual(self.kernel.sets["guest_ready"], [])
        self.assertEqual(json.loads((self.state / "recovery.json").read_text())["status"], "blocked")

    def test_cold_carrier_retry_keeps_guest_gate_closed_until_native_verification(self):
        dead, live = process(1003), process(1004)
        dead.poll.return_value = 1
        def verified(*args, **kwargs):
            self.assertEqual(self.kernel.sets["guest_ready"], [])
            self.assertFalse((self.state / "ready.json").exists())
            return self.config.exit_ip
        self.service(carriers=[dead, live], verify=verified)
        self.assertEqual(self.packet.start_stream.call_count, 2)
        dead.wait.assert_called_once_with(timeout=3)

    def test_guest_detach_during_probe_is_not_restored_by_publication(self):
        gateway.write_state("guests.json", {"guests": [FIRST, SECOND]})
        def detached(*args, **kwargs):
            gateway.change_guest(self.config, SECOND, remove=True)
            return self.config.exit_ip
        self.service(verify=detached)
        self.assertEqual(gateway.registered_guests(), [FIRST])
        publications = [text for text in self.kernel.transactions if "10.77.0.2 timeout 30s" in text]
        self.assertEqual(len(publications), 1)
        self.assertNotIn("10.77.0.6", publications[0])
        self.packet.delete_guest.assert_called_once_with(SECOND)

    def test_expired_bootstrap_or_superseded_token_cannot_publish(self):
        children = {"proxy": process(1), "wireguard": process(2), "carrier": process(3)}
        token = gateway.close_for_recovery()
        for expiry in (0, gateway.NFT_TIMEOUT + 1, 30000):
            self.kernel.transport(self.config.first_ip, expiry)
            count = len(self.kernel.transactions)
            with self.assertRaisesRegex(OSError, "bootstrap lease expired"):
                gateway.publish_ready(self.config, token, children, 1)
            self.assertEqual(len(self.kernel.transactions), count)
            self.assertEqual(self.kernel.sets["guest_ready"], [])
        self.kernel.transport(self.config.first_ip)
        gateway.write_state("blocked.json", {"recovery_token": "newer-attempt"})
        with self.assertRaises(gateway.RecoveryBlocked):
            gateway.publish_ready(self.config, token, children, 1)

    def test_kernel_terminal_guard_revokes_token_when_state_storage_fails(self):
        token = gateway.close_for_recovery()
        self.patch(gateway, "write_state", side_effect=OSError("full state filesystem"))
        gateway.block("operator test or shutdown")
        self.assertEqual(json.loads((self.state / "blocked.json").read_text())["recovery_token"], token)
        with self.assertRaises(gateway.RecoveryBlocked):
            gateway.renew_lease(self.config, initial=True, recovery_token=token)
        with self.assertRaises(gateway.RecoveryBlocked):
            gateway.close_for_recovery()
        self.assertEqual(self.kernel.sets["transport_ready"], [])

    def test_expiry_between_userspace_check_and_nft_commit_cannot_open_guest(self):
        token = gateway.close_for_recovery()
        self.kernel.transport(self.config.first_ip)
        children = {"proxy": process(1), "wireguard": process(2), "carrier": process(3)}
        self.kernel.before_transaction = lambda: self.kernel.transport(self.config.first_ip, 0)
        with self.assertRaisesRegex(RuntimeError, "expired element"):
            gateway.publish_ready(self.config, token, children, 1)
        self.assertEqual(self.kernel.sets["guest_ready"], [])
        self.assertFalse((self.state / "ready.json").exists())

    def test_unreaped_child_stops_all_children_and_alerts_without_restart(self):
        def stop(child):
            if child.pid == 1003:
                raise gateway.subprocess.TimeoutExpired("fixture child", 3)
            child.terminate()
        self.packet._stop.side_effect = stop
        _, _, writes, proxies = self.service(verify=ValueError("wrong exit"))
        self.assertEqual(self.packet._stop.call_count, 3)
        proxies[0].terminate.assert_called_once()
        self.packet.start_wireguard.assert_called_once()
        status = json.loads((self.state / "recovery.json").read_text())
        self.assertEqual(status["reason"], "transport_cleanup_failed")
        self.assertFalse(status["retrying"])

    def test_controller_reexec_cannot_restore_a_revoked_existing_kernel_guard(self):
        token = gateway.close_for_recovery()
        self.kernel.sets["recovery_allowed"] = []
        self.patch(gateway.subprocess, "run", return_value=mock.Mock(returncode=0))
        before = len(self.kernel.transactions)
        with self.assertRaises(gateway.RecoveryBlocked):
            self.real_install_firewall(self.config, initial=True)
        self.assertEqual(len(self.kernel.transactions), before)
        self.assertEqual(json.loads((self.state / "blocked.json").read_text())["recovery_token"], token)

    def test_kernel_guard_accepts_only_one_sized_mark_in_nft_json(self):
        for values in ([1], ["0x00000001"], [{"elem": {"val": "0x00000001"}}]):
            self.kernel.sets["recovery_allowed"] = values
            self.assertTrue(gateway.recovery_authorized())
        for values in ([], [True], [0], [2], ["1"], ["0x00000002"], [{"elem": {"val": True}}]):
            self.kernel.sets["recovery_allowed"] = values
            self.assertFalse(gateway.recovery_authorized())

    def test_delayed_retry_status_cannot_leave_operator_block_marked_retrying(self):
        def raced(*args, **kwargs):
            gateway.block("operator test or shutdown")
            # A status write computed before block() can arrive after it.
            gateway.recovery_state("recovering", 1, reason="same_route_retry")
            return self.config.exit_ip
        self.service(verify=raced)
        status = json.loads((self.state / "recovery.json").read_text())
        self.assertEqual(status["status"], "blocked")
        self.assertFalse(status["retrying"])
        self.assertEqual(status["reason"], "recovery_superseded")
        self.assertEqual(self.kernel.sets["guest_ready"], [])

    def test_cas_rejection_preserves_valid_terminal_failure_status(self):
        gateway.recovery_state("failed", 2, reason="fixed_route_validation_failed", error_type="ValueError")
        original = (self.state / "recovery.json").read_text()
        gateway.recovery_stopped(3)
        self.assertEqual((self.state / "recovery.json").read_text(), original)


if __name__ == "__main__":
    unittest.main()
