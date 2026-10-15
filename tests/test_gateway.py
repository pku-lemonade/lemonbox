"""Gateway regressions with mocked nft/ip/proxy commands and private fixtures."""
import base64
import copy
import errno
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
spec = importlib.util.spec_from_file_location("gateway_controller", ROOT / "gateway/controller.py")
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        data = json.loads((ROOT / "route.example.json").read_text())
        data["wireguard"] = {
            "client_private_key": base64.b64encode(b"\x01" * 32).decode(),
            "server_public_key": base64.b64encode(b"\x02" * 32).decode(),
        }
        user_config = RouteConfig.from_dict(data, allow_placeholder=True)
        self.profile = user_config.mihomo_profile()
        for node in self.profile["proxies"]:
            node["password"] = "fixture-credential-never-real"
        self.path = self.root / "proxy.json"
        self.write()
        self.route_env = user_config.gateway_env()
        self.wireguard_path = self.root / "wireguard.json"
        user_config.render_wireguard(self.wireguard_path)
        environment = self.route_env | {"LEMON_PROXY_CONFIG": str(self.path),
                                        "LEMON_WIREGUARD_CONFIG": str(self.wireguard_path)}
        self.config = gateway.Config(environment)
        self.config.uplink = "tap0"
        self.state = mock.patch.object(gateway, "STATE", self.root / "state")
        self.state.start()
        registry = mock.patch.object(gateway, "registered_guests", return_value=[{"tap":"vm0","guest_cidr":"10.77.0.2/30","gateway_cidr":"10.77.0.1/30"}])
        registry.start(); self.addCleanup(registry.stop)
        uplink = mock.patch.object(gateway, "discover_uplink")
        uplink.start(); self.addCleanup(uplink.stop)

    def tearDown(self):
        self.state.stop()
        self.tmp.cleanup()

    def write(self):
        self.path.write_text(json.dumps(self.profile))
        self.path.chmod(0o600)

    def test_missing_route_settings_never_use_a_legacy_or_implicit_endpoint(self):
        for key in ("LEMON_FIRST_HOP_IP", "LEMON_FIRST_HOP_PORT", "LEMON_FINAL_HOP_IP",
                    "LEMON_FINAL_HOP_PORT", "LEMON_EXPECTED_EXIT_IP"):
            with self.subTest(setting=key):
                incomplete = dict(self.route_env)
                del incomplete[key]
                with self.assertRaisesRegex(ValueError, "Missing fixed route"):
                    gateway.Config(incomplete)
        with self.assertRaisesRegex(ValueError, "Missing fixed route"):
            gateway.Config({})

    def test_alternate_hops_and_port_hopping_are_rejected(self):
        baseline = copy.deepcopy(self.profile)
        for node_index, key, value in ((0, "server", "203.0.113.99"), (1, "port", 444),
                                       (0, "dialer-proxy", "VIRCS"), (1, "dialer-proxy", "DIRECT"),
                                       (0, "ports", "8443-8444"), (1, "type", "direct"),
                                       (0, "obfs", "unsupported"), (1, "fingerprint", "unsupported")):
            with self.subTest(key=key, node_index=node_index):
                self.profile = copy.deepcopy(baseline)
                self.profile["proxies"][node_index][key] = value
                self.write()
                with self.assertRaises(ValueError):
                    self.config.validate_profile()

    def test_mutable_global_routing_and_direct_rules_are_rejected(self):
        baseline = copy.deepcopy(self.profile)
        for key, value in (("rules", ["MATCH,DIRECT"]), ("external-controller", "0.0.0.0:9090"),
                           ("proxy-groups", [{"name": "pool", "type": "fallback"}]),
                           ("proxy-providers", {"subscription": {}}), ("ipv6", True)):
            self.profile = copy.deepcopy(baseline)
            self.profile[key] = value
            self.write()
            with self.assertRaises(ValueError):
                self.config.validate_profile()

    def test_initial_transport_lease_does_not_authorize_guest(self):
        with mock.patch.object(gateway, "command") as command:
            gateway.renew_lease(self.config, initial=True)
        payload = command.call_args.kwargs["input_text"]
        self.assertIn("transport_ready", payload)
        self.assertNotIn("guest_ready", payload)
        self.assertIn("timeout 30s", payload)

    def test_guest_and_transport_lease_updates_are_one_nft_transaction(self):
        live = {"guest_ready": [{"elem": {"val": GUEST_IP, "expires": 20}}],
                "transport_ready": [{"elem": {"val": self.config.first_ip, "expires": 20}}]}
        with mock.patch.object(gateway, "read_leases", return_value=live), mock.patch.object(gateway, "command") as command:
            gateway.renew_lease(self.config, guest=True)
        command.assert_called_once()
        self.assertEqual(command.call_args.args[0], ["nft", "-f", "-"])
        payload = command.call_args.kwargs["input_text"]
        self.assertIn("flush set inet lemon_vm guest_ready", payload)
        self.assertIn(GUEST_IP + " timeout 30s", payload)
        self.assertIn(self.config.first_ip + " timeout 30s", payload)

    def test_expired_running_lease_cannot_be_reopened_after_monitor_resume(self):
        for leases in ({}, {"guest_ready": [{"elem": {"val": GUEST_IP, "expires": 0}}],
                            "transport_ready": [{"elem": {"val": self.config.first_ip, "expires": 20}}]}):
            with mock.patch.object(gateway, "read_leases", return_value=leases), mock.patch.object(gateway, "command") as command:
                with self.assertRaises(OSError):
                    gateway.renew_lease(self.config, guest=True)
                command.assert_not_called()

    def test_explicit_initial_startup_can_open_guest_gate_after_verification(self):
        bootstrap = {"transport_ready": [{"elem": {"val": self.config.first_ip, "expires": 20}}]}
        with mock.patch.object(gateway, "read_leases", return_value=bootstrap) as read, mock.patch.object(gateway, "command") as command:
            gateway.renew_lease(self.config, guest=True, initial=True)
        read.assert_called_once()
        command.assert_called_once()
        self.assertIn("guest_ready", command.call_args.kwargs["input_text"])

    def test_missing_or_expired_bootstrap_transport_cannot_open_initial_guest_gate(self):
        for leases in ({}, {"transport_ready": [{"elem": {"val": self.config.first_ip, "expires": 0}}]},
                       {"transport_ready": [{"elem": {"val": "203.0.113.99", "expires": 20}}]}):
            with mock.patch.object(gateway, "read_leases", return_value=leases), mock.patch.object(gateway, "command") as command:
                with self.assertRaises(OSError):
                    gateway.renew_lease(self.config, guest=True, initial=True)
                command.assert_not_called()

    def test_running_transport_renewal_cannot_reopen_expired_or_cleared_sets(self):
        for leases in ({}, {"transport_ready": [{"elem": {"val": self.config.first_ip, "expires": 0}}]}):
            with mock.patch.object(gateway, "read_leases", return_value=leases), mock.patch.object(gateway, "command") as command:
                with self.assertRaises(OSError):
                    gateway.renew_lease(self.config)
                command.assert_not_called()

    def test_block_closes_existing_flow_leases_and_latches_against_renewal(self):
        gateway.STATE.mkdir()
        (gateway.STATE / "ready.json").write_text("{}")
        with mock.patch.object(gateway, "command") as command:
            gateway.block("fixture fault")
        self.assertTrue((gateway.STATE / "blocked.json").exists())
        self.assertFalse((gateway.STATE / "ready.json").exists())
        payload = command.call_args.kwargs["input_text"]
        self.assertIn("flush set inet lemon_vm guest_ready", payload)
        self.assertIn("flush set inet lemon_vm transport_ready", payload)
        with mock.patch.object(gateway, "command") as command:
            with self.assertRaises(OSError):
                gateway.renew_lease(self.config, guest=True)
            command.assert_not_called()

    def test_full_state_filesystem_still_closes_kernel_gates_before_reporting(self):
        gateway.STATE.mkdir()
        (gateway.STATE / "ready.json").write_text("{}")
        events = []
        def persisted(name, value):
            events.append("state")
            raise OSError(errno.ENOSPC, "fixture state disk full")
        def executed(args, **kwargs):
            events.append("kernel")
        with mock.patch.object(gateway, "write_state", side_effect=persisted), \
             mock.patch.object(gateway, "command", side_effect=executed) as command:
            gateway.block("fixture fault")
        self.assertEqual(events, ["kernel", "state"])
        command.assert_called_once()
        payload = command.call_args.kwargs["input_text"]
        self.assertIn("flush set inet lemon_vm guest_ready", payload)
        self.assertIn("flush set inet lemon_vm transport_ready", payload)
        self.assertFalse((gateway.STATE / "ready.json").exists())
        self.assertFalse((gateway.STATE / "blocked.json").exists())
        for guest in (False, True):
            with mock.patch.object(gateway, "read_leases", return_value={}), mock.patch.object(gateway, "command") as command:
                with self.assertRaises(OSError):
                    gateway.renew_lease(self.config, guest=guest)
                command.assert_not_called()

    def test_wrong_exit_never_tries_another_endpoint_or_renews_a_lease(self):
        with mock.patch.object(gateway, "observed_exit", return_value="203.0.113.99") as observed:
            with self.assertRaises(ValueError):
                gateway.verify_exit(self.config)
        observed.assert_called_once()

    def test_verification_endpoint_outage_can_retry_same_pinned_proxy(self):
        with mock.patch.object(gateway, "observed_exit", side_effect=[OSError("offline"), self.config.exit_ip]) as observed:
            self.assertEqual(gateway.verify_exit(self.config), self.config.exit_ip)
        self.assertEqual(observed.call_count, 2)

    def test_two_verification_endpoints_share_one_bounded_budget(self):
        clock = [0]
        deadlines = []

        def observed(config, host, *, deadline):
            deadlines.append(deadline)
            if len(deadlines) == 1:
                clock[0] = deadline
                raise TimeoutError("first endpoint used its budget")
            clock[0] = deadline - .05
            return config.exit_ip

        with mock.patch.object(gateway.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(gateway, "observed_exit", side_effect=observed):
            self.assertEqual(gateway.verify_exit(self.config), self.config.exit_ip)
        self.assertEqual(deadlines, [12, 20])
        self.assertLess(clock[0], gateway.VERIFY_SECONDS)

    def test_late_correct_ip_cannot_pass_an_exhausted_total_budget(self):
        clock = [0]

        def observed(config, host, *, deadline):
            clock[0] = 21
            return config.exit_ip

        with mock.patch.object(gateway.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(gateway, "observed_exit", side_effect=observed) as probe:
            with self.assertRaisesRegex(OSError, "could not be verified"):
                gateway.verify_exit(self.config)
        probe.assert_called_once()

    def test_health_deadline_preserves_kernel_time_for_nft_renewal(self):
        clock = [100]
        leases = {"transport_ready": [{"elem": {"val": self.config.first_ip, "expires": 20}}],
                  "guest_ready": [{"elem": {"val": GUEST_IP, "expires": 15}}]}

        def read():
            clock[0] = 102
            return leases

        with mock.patch.object(gateway.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(gateway, "read_leases", side_effect=read), \
                mock.patch.object(gateway, "verify_exit", return_value=self.config.exit_ip) as verify:
            self.assertEqual(gateway.verify_health(self.config), self.config.exit_ip)
        verify.assert_called_once_with(self.config, deadline=110)

    def test_insufficient_kernel_renewal_margin_stops_before_external_probe(self):
        leases = {"transport_ready": [{"elem": {"val": self.config.first_ip, "expires": 4}}],
                  "guest_ready": [{"elem": {"val": GUEST_IP, "expires": 20}}]}
        with mock.patch.object(gateway.time, "monotonic", return_value=100), \
                mock.patch.object(gateway, "read_leases", return_value=leases), \
                mock.patch.object(gateway, "verify_exit") as verify:
            with self.assertRaises(TimeoutError):
                gateway.verify_health(self.config)
        verify.assert_not_called()

    def test_expiry_schema_requires_seconds_from_the_pinned_nftables_release(self):
        leases = {"transport_ready": [{"elem": {"val": self.config.first_ip, "expires": 20000}}],
                  "guest_ready": [{"elem": {"val": GUEST_IP, "expires": 20000}}]}
        with mock.patch.object(gateway.time, "monotonic", return_value=100), \
                mock.patch.object(gateway, "read_leases", return_value=leases), \
                mock.patch.object(gateway, "verify_exit") as verify:
            with self.assertRaisesRegex(OSError, "kernel lease expired"):
                gateway.verify_health(self.config)
        verify.assert_not_called()

    def test_verification_failure_records_fixed_stage_codes_without_private_error_text(self):
        with mock.patch.object(gateway.time, 'monotonic', return_value=1), \
                mock.patch.object(gateway.subprocess, 'run', side_effect=gateway.subprocess.TimeoutExpired('curl', 12, output='private diagnostic material')):
            with self.assertRaises(OSError) as raised:
                gateway.verify_exit(self.config)
        error = raised.exception
        self.assertEqual(error.probe_budget_seconds, 20)
        self.assertEqual([value['stage'] for value in error.probe_failures], ['native_curl', 'native_curl'])
        self.assertEqual([value['error_type'] for value in error.probe_failures], ['TimeoutError', 'TimeoutError'])
        self.assertNotIn('private diagnostic material', str(error) + json.dumps(error.probe_failures))

    def test_native_curl_binds_wireguard_and_verifies_a_fixed_tls_hostname(self):
        response = mock.Mock(returncode=0, stdout="ip=203.0.113.20\nloc=US\n\n200")
        with mock.patch.object(gateway.time, "monotonic", return_value=3), \
                mock.patch.object(gateway.subprocess, "run", return_value=response) as run:
            self.assertEqual(gateway.observed_exit(self.config, deadline=10), self.config.exit_ip)
        args = run.call_args.args[0]
        self.assertEqual(args[:2], ["curl", "-q"])
        self.assertEqual(args[args.index("--interface") + 1], "10.78.0.2")
        self.assertEqual(args[args.index("--noproxy") + 1], "*")
        self.assertEqual(args[args.index("--resolve") + 1], "one.one.one.one:443:1.1.1.1")
        self.assertEqual(args[args.index("--max-time") + 1], "7")
        self.assertLessEqual(run.call_args.kwargs["timeout"], 7.1)
        self.assertEqual(args[args.index("--max-filesize") + 1], "65536")
        for unsafe in ("-k", "--insecure", "--location"):
            self.assertNotIn(unsafe, args)

    def test_curl_failures_redirects_and_malformed_ip_bodies_cannot_pass(self):
        responses = [(60, "ip=203.0.113.20\n\n200"), (0, "ip=203.0.113.20\n\n302"),
                     (0, "ip=203.0.113.20\nip=203.0.113.20\n\n200"),
                     (0, "ip=not-an-address\n\n200"), (0, "x" * 65541)]
        for code, body in responses:
            with self.subTest(code=code, length=len(body)), \
                    mock.patch.object(gateway.time, "monotonic", return_value=3), \
                    mock.patch.object(gateway.subprocess, "run", return_value=mock.Mock(returncode=code, stdout=body)):
                with self.assertRaises((OSError, ValueError)):
                    gateway.observed_exit(self.config, deadline=10)

    def test_live_kernel_lease_requires_exact_address_and_positive_expiry(self):
        live = [{"elem": {"val": GUEST_IP, "expires": 26}}]
        self.assertTrue(gateway.lease_live(live, GUEST_IP))
        for entries in ([], [{"elem": {"val": GUEST_IP, "expires": 0}}],
                        [{"elem": {"val": "203.0.113.99", "expires": 26}}],
                        [{"elem": {"val": GUEST_IP}}]):
            self.assertFalse(gateway.lease_live(entries, GUEST_IP))

    def test_firewall_replace_is_atomic_and_starts_with_empty_leases(self):
        with mock.patch.object(gateway.subprocess, "run", return_value=mock.Mock(returncode=0)), \
             mock.patch.object(gateway, "command") as command:
            gateway.install_firewall(self.config)
        command.assert_called_once()
        payload = command.call_args.kwargs["input_text"]
        self.assertTrue(payload.startswith("delete table inet lemon_vm\n"))
        self.assertIn("flags timeout; timeout 30s", payload)
        for name in ("transport_ready", "guest_ready"):
            declaration = re.search(r"set " + name + r" \{([^}]+)\}", payload).group(1)
            self.assertNotIn("elements =", declaration)


if __name__ == "__main__":
    unittest.main()
