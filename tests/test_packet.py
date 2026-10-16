"""Packet routing invariants, private-key handling and bounded startup failures."""

import base64
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("gateway_packet", ROOT / "gateway/packet.py")
packet = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packet)


def fixture():
    return {"client_private_key": base64.b64encode(b"\x01" * 32).decode(),
            "server_public_key": base64.b64encode(b"\x02" * 32).decode(),
            "client_address": "10.78.0.2/30", "server_address": "10.78.0.1",
            "endpoint_port": 51821, "mtu": 1500,
            "transport": "stream", "stream_port": 51822}


class PacketSettingsTests(unittest.TestCase):
    def test_settings_require_explicit_stream_schema_and_reject_udp_carrier(self):
        stream = packet.PacketSettings.from_mapping(fixture())
        self.assertEqual((stream.transport, stream.mtu), ("stream", 1500))
        for override in ({"transport": "udp"}, {"transport": "direct"}, {"stream_port": True}, {"stream_port": 15080}):
            with self.assertRaises(ValueError):
                packet.PacketSettings.from_mapping(fixture() | override)
        for field in ('transport', 'stream_port'):
            data = fixture()
            del data[field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                packet.PacketSettings.from_mapping(data)

    def test_malformed_or_zero_keys_are_rejected_without_echoing_them(self):
        for value in (None, "secret-value", "!" * 44,
                      base64.b64encode(b"\x00" * 32).decode(),
                      base64.b64encode(b"\x01" * 31).decode()):
            for name in ("client_private_key", "server_public_key"):
                with self.subTest(key=name, value_type=type(value).__name__):
                    data = fixture() | {name: value}
                    with self.assertRaises(ValueError) as error:
                        packet.PacketSettings.from_mapping(data)
                    if isinstance(value, str):
                        self.assertNotIn(value, str(error.exception))

    def test_tunnel_addresses_are_generated_internal_contract_values(self):
        with self.assertRaisesRegex(ValueError, "route contract"):
            packet.PacketSettings.from_mapping(fixture() | {
                "client_address": "172.20.0.2/30", "server_address": "172.20.0.1"})

    def test_file_requires_private_permissions_and_refuses_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wireguard.json"
            path.write_text(json.dumps(fixture()))
            path.chmod(0o600)
            packet.PacketSettings.from_file(path)
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                packet.PacketSettings.from_file(path)
            path.chmod(0o600)
            link = Path(directory) / "link"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                packet.PacketSettings.from_file(link)


class PacketFirewallTests(unittest.TestCase):
    def setUp(self):
        self.config = SimpleNamespace(tap="vm0", guest="10.77.0.2",
                                      gateway=ipaddress.IPv4Interface("10.77.0.1/30"),
                                      first_ip="198.51.100.28", first_port=8443, uplink="tap0")
        self.settings = packet.PacketSettings.from_mapping(fixture())
        self.records = [{"tap":"vm0","guest_cidr":"10.77.0.2/30","gateway_cidr":"10.77.0.1/30"}, {"tap":"vm1","guest_cidr":"10.77.0.6/30","gateway_cidr":"10.77.0.5/30"}]
        self.rules = packet.firewall(self.config, self.settings, self.records)

    def chain(self, name):
        return re.search(r"chain " + name + r" \{(.*?)\n  \}", self.rules, re.S).group(1)

    def test_packets_keep_native_tcp_and_snat_only_registered_guest_addresses(self):
        for prohibited in ("tproxy", "redirect", "dnat", "masquerade", "15081"):
            self.assertNotIn(prohibited, self.rules)
        forward = self.chain("forward")
        self.assertIn('iifname . ip saddr @guest_sources oifname "wg0"', forward)
        self.assertIn('iifname "wg0" oifname . ip daddr @guest_sources', forward)
        nat = self.chain("guest_nat")
        self.assertIn('oifname "wg0" ip saddr @guest_addresses ct mark 113 snat ip to 10.77.0.2', nat)
        self.assertIn("meta l4proto { tcp, udp, icmp }", forward)

    def test_all_forward_accepts_require_guest_lease_and_exact_interfaces(self):
        forward = self.chain("forward")
        self.assertIn("policy drop", forward)
        accepts = [line for line in forward.splitlines() if "accept" in line]
        self.assertEqual(len(accepts), 2)
        for line in accepts:
            self.assertIn("@guest_ready", line)
            self.assertIn("@guest_sources", line)
            self.assertIn('"wg0"', line)
            self.assertIn("ct mark 113", line)
        replies = accepts[1]
        self.assertLess(replies.index("@guest_ready"), replies.index("ct state established,related"))
        self.assertNotIn(self.config.first_ip, forward)

    def test_mss_clamp_covers_syn_and_synack_only_in_both_leased_interface_directions(self):
        forward = self.chain("forward")
        clamps = [line for line in forward.splitlines() if "maxseg size set" in line]
        self.assertEqual(len(clamps), 2)
        self.assertIn('iifname . ip saddr @guest_sources oifname "wg0" ip saddr @guest_ready', clamps[0])
        self.assertIn('iifname "wg0" oifname . ip daddr @guest_sources ip daddr @guest_ready', clamps[1])
        for line in clamps:
            # Testing the SYN bit also includes SYN+ACK while leaving data/ACK
            # packets alone. The rewrite itself never grants forwarding.
            self.assertIn("tcp flags & syn == syn", line)
            self.assertIn("tcp option maxseg size > 1460", line)
            self.assertIn("tcp option maxseg size set 1460 counter", line)
            self.assertNotIn("accept", line)
            self.assertNotIn("ip6", line)
        self.assertLess(forward.index("ct state invalid counter drop"), forward.index(clamps[0]))
        self.assertLess(forward.index(clamps[1]), forward.index("counter accept"))

    def test_source_spoof_ipv6_and_private_destinations_drop_before_forwarding(self):
        ingress = self.chain("guest_ingress")
        ipv4 = ingress.index("meta nfproto != ipv4 counter drop")
        source = ingress.index("iifname . ip saddr != @guest_sources counter drop")
        private = ingress.index("169.254.0.0/16")
        public = ingress.index("ip saddr @guest_ready")
        self.assertLess(ipv4, source)
        self.assertLess(source, private)
        self.assertLess(private, public)
        for block in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4"):
            self.assertIn(block, ingress)

    def test_only_existing_marked_management_reply_bypasses_private_drop(self):
        ingress = self.chain("guest_ingress")
        exception = [line for line in ingress.splitlines() if "tcp sport 22" in line]
        self.assertEqual(len(exception), 1)
        for constraint in ("ip daddr @guest_gateways", "tcp sport 22", "ct mark 114",
                           "ct state established,related"):
            self.assertIn(constraint, exception[0])
        self.assertLess(ingress.index(exception[0]), ingress.index("169.254.0.0/16"))

    def test_physical_output_and_replies_are_lease_bound_to_single_hop(self):
        for chain, address, port in (("output", "daddr", "dport"), ("input", "saddr", "sport")):
            rules = [line for line in self.chain(chain).splitlines()
                     if self.config.first_ip in line and "accept" in line]
            self.assertEqual(len(rules), 1)
            line = rules[0]
            self.assertIn(f"ip {address} @transport_ready", line)
            self.assertIn(f"udp {port} 8443", line)
            self.assertIn('name "tap0"', line)
        self.assertNotIn("ct state established", self.chain("output").split("ip daddr @transport_ready")[1])

    def test_health_is_source_bound_to_tunnel_and_guest_pmtu_errors_are_permitted(self):
        output = self.chain("output")
        self.assertIn('oifname "wg0" ip saddr 10.78.0.2', output)
        errors = [line for line in output.splitlines() if "meta l4proto icmp" in line]
        self.assertEqual(len(errors), 1)
        self.assertIn("oifname . ip daddr @guest_sources", errors[0])
        self.assertIn("ip daddr @guest_ready", errors[0])
        self.assertIn("ct state related", errors[0])


class PacketStartupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self.tmp.name)
        self.settings = packet.PacketSettings.from_mapping(fixture())
        self.state = mock.patch.object(packet, "STATE", self.directory / "state")
        self.wgstate = mock.patch.object(packet, "WIREGUARD_STATE", self.directory / "wireguard")
        self.state.start()
        self.wgstate.start()
        packet.WIREGUARD_STATE.mkdir()

    def tearDown(self):
        self.wgstate.stop()
        self.state.stop()
        self.tmp.cleanup()

    def ready_socket(self):
        (packet.WIREGUARD_STATE / "wg0.sock").touch()

    def test_private_key_uses_temporary_600_file_and_never_process_arguments(self):
        self.ready_socket()
        process = mock.Mock()
        process.poll.return_value = None

        def configure(args):
            self.assertEqual(args[:3], ["wg", "setconf", "wg0"])
            path = Path(args[3])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            contents = path.read_text()
            self.assertIn(self.settings.client_private_key, contents)
            self.assertIn("Endpoint = 127.0.0.1:51821", contents)
            self.assertIn("AllowedIPs = 0.0.0.0/0", contents)
            self.assertNotIn(self.settings.client_private_key, repr(args))

        with mock.patch.object(packet.subprocess, "Popen", return_value=process) as launch, \
                mock.patch.object(packet, "command", side_effect=configure):
            self.assertIs(packet.start_wireguard(self.settings), process)
        self.assertEqual(launch.call_args.args[0], ["wireguard-go", "-f", "wg0"])
        self.assertNotIn(self.settings.client_private_key, repr(launch.call_args))
        self.assertEqual(list(packet.STATE.glob("wireguard-*.conf")), [])
        process.terminate.assert_not_called()

    def test_configuration_failure_cleans_key_file_and_stops_untracked_process(self):
        self.ready_socket()
        process = mock.Mock()
        process.poll.return_value = None
        with mock.patch.object(packet.subprocess, "Popen", return_value=process), \
                mock.patch.object(packet, "command", side_effect=RuntimeError("wg failed")):
            with self.assertRaisesRegex(RuntimeError, "wg failed"):
                packet.start_wireguard(self.settings)
        self.assertEqual(list(packet.STATE.glob("wireguard-*.conf")), [])
        process.terminate.assert_called_once()
        process.wait.assert_called_once_with(timeout=3)

    def test_startup_timeout_is_bounded_and_escalates_if_process_will_not_stop(self):
        process = mock.Mock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("wireguard-go", 3), None]
        with mock.patch.object(packet.subprocess, "Popen", return_value=process), \
                mock.patch.object(packet.time, "monotonic", side_effect=[0, 11]), \
                mock.patch.object(packet.time, "sleep") as sleep:
            with self.assertRaisesRegex(OSError, "startup timed out"):
                packet.start_wireguard(self.settings)
        sleep.assert_not_called()
        process.terminate.assert_called_once()
        process.kill.assert_called_once()
        self.assertEqual(process.wait.call_count, 2)

    def test_network_routes_guest_and_bound_health_without_replacing_physical_default(self):
        def read_setting(path, *args, **kwargs):
            return "1" if str(path).endswith("/ip_forward") else "0"

        with mock.patch.object(packet, "command") as run, \
                mock.patch.object(packet.Path, "read_text", new=read_setting):
            packet.setup_network(self.settings)
        calls = [call.args[0] for call in run.call_args_list]
        routes = [args for args in calls if args[:3] == ["ip", "route", "add"]]
        self.assertEqual(routes, [["ip", "route", "add", "default", "dev", "wg0", "table", "177"]])
        self.assertIn(["ip", "rule", "add", "priority", "177", "fwmark", "113", "lookup", "177"], calls)
        self.assertIn(["ip", "rule", "add", "priority", "178", "from", "10.78.0.2", "lookup", "177"], calls)
        self.assertNotIn("local", " ".join(" ".join(args) for args in calls))

    def test_wrong_forwarding_sysctl_fails_closed(self):
        with mock.patch.object(packet, "command"), \
                mock.patch.object(packet.Path, "read_text", return_value="0"):
            with self.assertRaisesRegex(OSError, "ip_forward must be configured as1"):
                packet.setup_network(self.settings)

    def test_recovery_reset_deletes_only_tunnel_and_exact_owned_policy_rules(self):
        self.ready_socket()
        links = json.dumps([{"ifname": "lo"}, {"ifname": "wg0"}, {"ifname": "vm0"}, {"ifname": "vm1"}])
        with mock.patch.object(packet, "command", return_value=links) as run, \
                mock.patch.object(packet.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as rules:
            packet.reset_network(self.settings)
        self.assertEqual(run.call_args_list, [mock.call(["ip", "-j", "link", "show"]),
                                              mock.call(["ip", "link", "del", "dev", "wg0"])])
        selectors = [call.args[0] for call in rules.call_args_list]
        self.assertEqual(selectors, [
            ["ip", "rule", "del", "priority", "177", "fwmark", "113", "lookup", "177"],
            ["ip", "rule", "del", "priority", "178", "from", "10.78.0.2", "lookup", "177"]])
        self.assertFalse((packet.WIREGUARD_STATE / "wg0.sock").exists())

    def test_signal_during_wireguard_startup_reaps_child_promptly(self):
        child = mock.Mock()
        child.poll.return_value = None
        stopping = mock.Mock()
        stopping.is_set.return_value = True
        with mock.patch.object(packet.subprocess, "Popen", return_value=child):
            with self.assertRaisesRegex(OSError, "startup stopped"):
                packet.start_wireguard(self.settings, stopping=stopping)
        child.terminate.assert_called_once()
        stopping.wait.assert_not_called()

    def test_failed_wg_command_does_not_expose_private_diagnostics(self):
        result = SimpleNamespace(returncode=1, stderr=self.settings.client_private_key, stdout="")
        with mock.patch.object(packet.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(RuntimeError, "^wg failed$") as error:
                packet.command(["wg", "setconf", "wg0", "private.conf"])
        self.assertNotIn(self.settings.client_private_key, str(error.exception))


if __name__ == "__main__":
    unittest.main()
