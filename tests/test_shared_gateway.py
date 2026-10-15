"""Shared route registration cannot authorize another VM's address or reopen a lease."""
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("shared_controller_test", ROOT / "gateway/controller.py")
gateway = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gateway)
packet = gateway.packet_module()
FIRST = {"tap": "vm0", "guest_cidr": "10.77.0.2/30", "gateway_cidr": "10.77.0.1/30"}
SECOND = {"tap": "vm1", "guest_cidr": "10.77.0.6/30", "gateway_cidr": "10.77.0.5/30"}


class SharedGatewayTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name)
        patch = mock.patch.object(gateway, "STATE", self.state)
        patch.start(); self.addCleanup(patch.stop)
        gateway.write_state("guests.json", {"guests": []})
        gateway.write_state("ready.json", {"uplink": "tap0", "mihomo_pid": 101,
                                          "wireguard_pid": 102, "stream_pid": 103})
        self.config = SimpleNamespace(first_ip="198.51.100.10", first_port=8443,
                                      exit_ip="203.0.113.20", packet_settings=object())
        self.leases = {"transport_ready": [{"elem": {"val": self.config.first_ip, "expires": 25}}],
                       "guest_ready": [{"elem": {"val": "10.77.0.2", "expires": 20}},
                                       {"elem": {"val": "10.77.0.6", "expires": 20}}]}

    def test_allocations_are_unique_canonical_pool_hosts(self):
        self.assertEqual(packet.guest_records([FIRST, SECOND]), [FIRST, SECOND])
        invalid = [FIRST | {"tap": "wg0"}, FIRST | {"tap": "vm0\naccept"},
                   FIRST | {"guest_cidr": "10.77.0.1/30"}, FIRST | {"guest_cidr": "10.78.0.2/30"},
                   FIRST | {"gateway_cidr": "10.77.0.5/30"}, FIRST | {"owner": 0}]
        for record in invalid:
            with self.subTest(record=record), self.assertRaises(ValueError):
                packet.guest_record(record)
        for records in ([FIRST, FIRST], [FIRST, SECOND | {"tap": "vm0"}]):
            with self.assertRaises(ValueError):
                packet.guest_records(records)

    def test_uplink_is_discovered_from_the_fixed_first_hop_route(self):
        with mock.patch.object(gateway, "command", return_value='[{"dev":"tap0"}]') as run:
            gateway.discover_uplink(self.config)
        self.assertEqual(self.config.uplink, "tap0")
        run.assert_called_once_with(["ip", "-j", "route", "get", self.config.first_ip])
        for interface in ("lo", "wg0", "invalid\nname"):
            with mock.patch.object(gateway, "command", return_value=json.dumps([{"dev": interface}])):
                with self.assertRaises(OSError):
                    gateway.discover_uplink(self.config)

    def test_zero_guests_still_requires_all_live_transport_children(self):
        leases = dict(self.leases, guest_ready=[])
        with mock.patch.object(gateway, "read_leases", return_value=leases), \
                mock.patch.object(gateway.os, "kill") as alive, \
                mock.patch.object(gateway.socket, "create_connection", return_value=mock.MagicMock()):
            report = gateway.check(self.config, local=True)
        self.assertTrue(report["ready"])
        self.assertEqual(report["guests"], [])
        self.assertEqual(alive.call_args_list, [mock.call(101, 0), mock.call(102, 0), mock.call(103, 0)])

    def test_register_two_guests_then_remove_one_preserves_the_other(self):
        with mock.patch.object(gateway, "read_leases", return_value=self.leases), \
                mock.patch.object(gateway, "command") as run, \
                mock.patch.object(packet, "create_guest") as create, \
                mock.patch.object(packet, "delete_guest") as delete:
            gateway.change_guest(self.config, FIRST)
            gateway.change_guest(self.config, SECOND)
            both = run.call_args.kwargs["input_text"]
            self.assertIn('"vm0" . 10.77.0.2', both)
            self.assertIn('"vm1" . 10.77.0.6', both)
            self.assertIn("10.77.0.2 timeout 24s", both)
            self.assertIn("10.77.0.6 timeout 24s", both)
            self.assertNotIn("flush set inet lemon_vm transport_ready", both)
            gateway.change_guest(self.config, SECOND, remove=True)
            remaining = run.call_args.kwargs["input_text"]
        self.assertEqual(gateway.registered_guests(), [FIRST])
        self.assertIn('"vm0" . 10.77.0.2', remaining)
        self.assertNotIn("10.77.0.6", remaining)
        create.assert_has_calls([mock.call(FIRST), mock.call(SECOND)])
        delete.assert_called_once_with(SECOND)

    def test_existing_guest_is_idempotent_and_collisions_do_not_change_devices(self):
        gateway.write_state("guests.json", {"guests": [FIRST]})
        with mock.patch.object(packet, "verify_guest") as verify, \
                mock.patch.object(packet, "create_guest") as create, mock.patch.object(gateway, "command") as run:
            self.assertTrue(gateway.change_guest(self.config, FIRST)["registered"])
            with self.assertRaises(ValueError):
                gateway.change_guest(self.config, SECOND | {"tap": "vm0"})
        verify.assert_called_once_with(FIRST)
        create.assert_not_called(); run.assert_not_called()

    def test_closed_transport_never_creates_a_guest_or_opens_any_gate(self):
        for expires in (0, 4):
            leases = dict(self.leases, transport_ready=[{"elem": {"val": self.config.first_ip, "expires": expires}}])
            with self.subTest(expires=expires), mock.patch.object(gateway, "read_leases", return_value=leases), \
                    mock.patch.object(packet, "create_guest") as create, mock.patch.object(gateway, "command") as run:
                with self.assertRaises(OSError):
                    gateway.change_guest(self.config, FIRST)
            create.assert_not_called(); run.assert_not_called()

    def test_failed_atomic_policy_update_closes_both_gates(self):
        with mock.patch.object(gateway, "read_leases", return_value=self.leases), \
                mock.patch.object(packet, "create_guest"), \
                mock.patch.object(gateway, "command", side_effect=[RuntimeError("nft failed"), ""]) as run:
            with self.assertRaises(RuntimeError):
                gateway.change_guest(self.config, FIRST)
        self.assertTrue((self.state / "blocked.json").exists())
        self.assertIn("flush set inet lemon_vm guest_ready", run.call_args.kwargs["input_text"])
        self.assertIn("flush set inet lemon_vm transport_ready", run.call_args.kwargs["input_text"])

    def test_removing_a_guest_from_a_closed_route_does_not_reopen_leases(self):
        gateway.write_state("guests.json", {"guests": [FIRST, SECOND]})
        with mock.patch.object(gateway, "read_leases", return_value={}), \
                mock.patch.object(packet, "delete_guest"), mock.patch.object(gateway, "command") as run:
            gateway.change_guest(self.config, SECOND, remove=True)
        self.assertEqual(gateway.registered_guests(), [FIRST])
        self.assertNotIn("timeout", run.call_args.kwargs["input_text"])


if __name__ == "__main__":
    unittest.main()
