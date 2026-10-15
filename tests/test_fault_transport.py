"""A chosen fault must kill its recorded child without substituting another."""
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
with mock.patch.object(sys, "path", [str(ROOT / "tests"), *sys.path]):
    spec = importlib.util.spec_from_file_location("fault_transport_validation", ROOT / "tests/validate_faults.py")
    fault = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fault)


class TransportFaultTests(unittest.TestCase):
    def test_stream_kill_targets_the_bridge_while_other_children_are_recorded(self):
        args = SimpleNamespace(fault="stream-kill")
        ready = {"mihomo_pid": 101, "wireguard_pid": 202, "stream_pid": 303}
        with mock.patch.object(fault, "operation", side_effect=[json.dumps(ready), ""]) as operation:
            result = fault.kill_transport(args)
        self.assertEqual(result, {"child": "stream_pid", "signal": "SIGKILL"})
        self.assertEqual(operation.call_args_list[-1], mock.call(args, ["kill", "-KILL", "303"]))
        # An absent or process-group PID must not fall back to another child.
        for pid in (None, 0):
            with mock.patch.object(fault, "operation", return_value=json.dumps(ready | {"stream_pid": pid})) as operation:
                with self.assertRaises(RuntimeError):
                    fault.kill_transport(args)
            self.assertEqual(operation.call_count, 1)


class KernelClosureTests(unittest.TestCase):
    def policy(self, guest=None, transport=None):
        return json.dumps({"nftables": [
            {"set": {"name": "guest_ready", "elem": [] if guest is None else guest}},
            {"set": {"name": "transport_ready", "elem": [] if transport is None else transport}},
        ]})

    def test_closure_requires_both_sets_empty_despite_rounded_zero_expiry(self):
        expired = [{"elem": {"val": "10.77.0.2", "expires": 0}}]
        active = [{"elem": {"val": "198.51.100.10", "expires": 1}}]
        with mock.patch.object(fault, "operation", return_value=self.policy()):
            self.assertTrue(fault.kernel_gates_closed(object()))
        with mock.patch.object(fault, "operation", return_value=self.policy(guest=expired)):
            self.assertFalse(fault.kernel_gates_closed(object()))
        with mock.patch.object(fault, "operation", return_value=self.policy(guest=expired, transport=active)):
            self.assertFalse(fault.kernel_gates_closed(object()))

    def test_missing_gate_and_unexpired_unstructured_entries_cannot_look_closed(self):
        with mock.patch.object(fault, "operation", return_value='{"nftables": []}'):
            with self.assertRaises(RuntimeError):
                fault.kernel_gates_closed(object())
        for elements in (["198.51.100.10"], [{"elem": {"val": "198.51.100.10"}}]):
            with mock.patch.object(fault, "operation", return_value=self.policy(transport=elements)):
                self.assertFalse(fault.kernel_gates_closed(object()))

    def test_late_or_still_open_gate_is_failure_not_a_delayed_pass(self):
        with mock.patch.object(fault, "kernel_gates_closed", return_value=True), \
             mock.patch.object(fault.time, "monotonic", side_effect=[34.9, 35.1]):
            with self.assertRaises(RuntimeError):
                fault.wait_for_gate_closure(object(), 0)
        with mock.patch.object(fault, "kernel_gates_closed", return_value=False), \
             mock.patch.object(fault.time, "monotonic", side_effect=[34.8, 34.9, 35]), \
             mock.patch.object(fault.time, "sleep"):
            with self.assertRaises(RuntimeError):
                fault.wait_for_gate_closure(object(), 0)


if __name__ == "__main__":
    unittest.main()
