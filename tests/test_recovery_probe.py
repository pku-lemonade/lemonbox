"""Operator recovery probes stay bounded, pinned, and credential-free offline."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
with mock.patch.object(sys, "path", [str(ROOT / "tests"), *sys.path]):
    spec = importlib.util.spec_from_file_location("recovery_validation", ROOT / "tests/validate_recovery.py")
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)


class RecoveryProbeTests(unittest.TestCase):
    def setUp(self):
        self.args = SimpleNamespace(gateway="lemonbox-gateway", ssh_config="/private/ssh-config",
                                    ssh_target="lemonbox", expected_exit_ip="203.0.113.8", fault="stream-kill")
        self.children = {"mihomo_pid": 101, "wireguard_pid": 202, "stream_pid": 303}
        self.boot = "f3ddfb22-8a21-4e51-9ca2-385274099baa"

    def completed(self, stdout="", code=0):
        return subprocess.CompletedProcess([], code, stdout, "private configuration must never be reported")

    def policy(self, guest=None, transport=None):
        return json.dumps({"nftables": [
            {"set": {"name": "guest_ready", "elem": [] if guest is None else guest}},
            {"set": {"name": "transport_ready", "elem": [] if transport is None else transport}},
        ]})

    def test_transport_may_bootstrap_while_guest_gate_is_empty(self):
        policy = self.policy(transport=[{"elem": {"val": "198.51.100.2", "expires": 15}}])
        with mock.patch.object(probe, "operation", return_value=self.completed(policy)), \
             mock.patch.object(probe, "guest_boot_id", return_value=self.boot), \
             mock.patch.object(probe.time, "monotonic", return_value=1):
            boot, closure = probe.wait_for_guest_closure(self.args, 0)
        self.assertEqual(boot, self.boot)
        self.assertTrue(closure["transport_gate_open_at_observation"])

    def test_rounded_expiry_and_missing_guest_gate_cannot_prove_closure(self):
        with mock.patch.object(probe, "operation", return_value=self.completed(
                self.policy(guest=[{"elem": {"val": "10.77.0.2", "expires": 0}}]))):
            self.assertTrue(probe.gate_state(self.args)["guest_ready"])
        with mock.patch.object(probe, "operation", return_value=self.completed('{"nftables": []}')):
            with self.assertRaises(probe.ProbeFailure):
                probe.gate_state(self.args)

    def test_kill_uses_only_the_exact_chosen_readiness_pid(self):
        for fault, key in probe.CHILDREN.items():
            with self.subTest(fault=fault):
                self.args.fault = fault
                with mock.patch.object(probe, "read_ready", return_value=self.children), \
                     mock.patch.object(probe, "operation") as operation:
                    probe.induce_fault(self.args, self.children)
                operation.assert_called_once_with(self.args, ["kill", "-KILL", str(self.children[key])])
        with mock.patch.object(probe, "read_ready", return_value=self.children | {"stream_pid": 404}), \
             mock.patch.object(probe, "operation") as operation:
            with self.assertRaises(probe.ProbeFailure):
                probe.induce_fault(self.args, self.children)
        operation.assert_not_called()

    def test_absent_boolean_and_group_pids_are_rejected(self):
        for value in (None, False, True, 0, 1, -303, "303"):
            with self.subTest(pid=value), mock.patch.object(probe, "operation", return_value=self.completed(
                    json.dumps(self.children | {"stream_pid": value}))):
                with self.assertRaises(probe.ProbeFailure):
                    probe.read_ready(self.args)

    def test_native_https_uses_pinned_ssh_without_proxies_or_payload_transfer(self):
        with mock.patch.object(probe.subprocess, "run", return_value=self.completed(self.args.expected_exit_ip)) as run:
            self.assertEqual(probe.guest_exit(self.args), self.args.expected_exit_ip)
        command = run.call_args.args[0]
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertIn("ControlPath=none", command)
        self.assertIn("ConnectTimeout=5", command)
        self.assertIn("curl -q -4", command[-1])
        self.assertIn("--noproxy '*' --proxy ''", command[-1])
        self.assertIn("-u HTTPS_PROXY", command[-1])
        self.assertIn("https://api.ipify.org", command[-1])
        self.assertNotIn("input", run.call_args.kwargs)
        self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertLessEqual(run.call_args.kwargs["timeout"], 20)

    def test_healthy_old_child_does_not_pass_and_recovery_deadline_is_hard(self):
        states = []
        with mock.patch.object(probe, "recovery_status", return_value={"status": "healthy"}), \
             mock.patch.object(probe, "local_health", return_value=True), \
             mock.patch.object(probe, "read_ready", return_value=self.children), \
             mock.patch.object(probe.time, "sleep"), \
             mock.patch.object(probe.time, "monotonic", side_effect=[0, 0, 0, 0, 0, 180]):
            with self.assertRaises(probe.ProbeFailure):
                probe.wait_for_recovery(self.args, self.children, 0, states)

    def test_terminal_recovery_failure_is_preserved_without_free_form_details(self):
        value = {"schema": 1, "status": "failed", "attempts": 3,
                 "retrying": False,
                 "reason": "secret-password", "private_profile": {"password": "secret-password"}}
        states = []
        with mock.patch.object(probe, "operation", return_value=self.completed(json.dumps(value))):
            with self.assertRaisesRegex(probe.ProbeFailure, "gateway_recovery_failed"):
                probe.wait_for_recovery(self.args, self.children, probe.time.monotonic(), states)
        self.assertNotIn("secret-password", json.dumps(states))
        self.assertEqual(states[0]["status"], "failed")
        self.assertFalse(states[0]["retrying"])

    def test_slow_retry_after_fast_failures_can_recover_within_original_deadline(self):
        values = [{"schema": 1, "status": "failed", "attempts": 3, "retrying": True},
                  {"schema": 1, "status": "recovering", "attempts": 4, "retrying": True},
                  {"schema": 1, "status": "healthy", "attempts": 4, "retrying": False}]
        states = []
        replaced = self.children | {"stream_pid": 404}
        with mock.patch.object(probe, "operation", side_effect=[self.completed(json.dumps(value)) for value in values]), \
             mock.patch.object(probe, "local_health", return_value=True), \
             mock.patch.object(probe, "read_ready", return_value=replaced), \
             mock.patch.object(probe.time, "sleep"):
            children, elapsed = probe.wait_for_recovery(self.args, self.children, probe.time.monotonic(), states)
        self.assertEqual(children, replaced)
        self.assertLess(elapsed, probe.RECOVERY_SECONDS)
        self.assertEqual([state["status"] for state in states], ["failed", "recovering", "healthy"])
        self.assertEqual([state["retrying"] for state in states], [True, True, False])

    def test_blocked_status_remains_terminal_even_if_marked_retrying(self):
        with mock.patch.object(probe, "recovery_status", return_value={"status": "blocked", "retrying": True}):
            with self.assertRaisesRegex(probe.ProbeFailure, "gateway_recovery_blocked"):
                probe.wait_for_recovery(self.args, self.children, probe.time.monotonic(), [])

    def test_slow_retry_cannot_extend_the_original_recovery_deadline(self):
        with mock.patch.object(probe, "recovery_status", return_value={"status": "failed", "retrying": True}), \
             mock.patch.object(probe.time, "monotonic", side_effect=[0, 0, 180]):
            with self.assertRaisesRegex(probe.ProbeFailure, "recovery_deadline_expired"):
                probe.wait_for_recovery(self.args, self.children, 0, [])

    def test_success_preserves_guest_boot_and_requires_native_exit_after_recovery(self):
        replaced = self.children | {"stream_pid": 404}
        with mock.patch.object(probe, "local_health", return_value=True), \
             mock.patch.object(probe, "recovery_status", return_value={"status": "healthy"}), \
             mock.patch.object(probe, "read_ready", return_value=self.children), \
             mock.patch.object(probe, "guest_boot_id", return_value=self.boot), \
             mock.patch.object(probe, "guest_exit", return_value=self.args.expected_exit_ip) as exit_probe, \
             mock.patch.object(probe, "induce_fault", return_value={"child": "stream_pid"}), \
             mock.patch.object(probe, "wait_for_guest_closure", return_value=(self.boot, {})), \
             mock.patch.object(probe, "wait_for_recovery", return_value=(replaced, 12.5)):
            report = probe.run(self.args)
        self.assertTrue(report["passed"])
        self.assertTrue(report["checks"]["chosen_child_replaced"])
        self.assertEqual(report["guest_boot_id_before"], report["guest_boot_id_after"])
        self.assertEqual(exit_probe.call_count, 2)

    def test_changed_guest_boot_fails_even_when_the_gateway_recovers(self):
        with mock.patch.object(probe, "local_health", return_value=True), \
             mock.patch.object(probe, "recovery_status", return_value={"status": "healthy"}), \
             mock.patch.object(probe, "read_ready", return_value=self.children), \
             mock.patch.object(probe, "guest_boot_id", side_effect=[self.boot, "different-boot"]), \
             mock.patch.object(probe, "guest_exit", return_value=self.args.expected_exit_ip), \
             mock.patch.object(probe, "induce_fault", return_value={}), \
             mock.patch.object(probe, "wait_for_guest_closure", return_value=(self.boot, {})), \
             mock.patch.object(probe, "wait_for_recovery", return_value=(self.children | {"stream_pid": 404}, 12.5)):
            report = probe.run(self.args)
        self.assertFalse(report["passed"])
        self.assertFalse(report["checks"]["guest_boot_preserved"])

    def test_interruption_resumes_paused_parent_and_retains_failure_report(self):
        self.args.fault = "lease-expiry"
        watchdog = mock.Mock()
        with mock.patch.object(probe, "local_health", return_value=True), \
             mock.patch.object(probe, "recovery_status", return_value={"status": "healthy"}), \
             mock.patch.object(probe, "read_ready", return_value=self.children), \
             mock.patch.object(probe, "guest_boot_id", return_value=self.boot), \
             mock.patch.object(probe, "guest_exit", return_value=self.args.expected_exit_ip), \
             mock.patch.object(probe, "start_pause", return_value=watchdog), \
             mock.patch.object(probe, "wait_for_guest_closure", side_effect=KeyboardInterrupt), \
             mock.patch.object(probe, "finish_pause", return_value=True) as finish:
            report = probe.run(self.args)
        finish.assert_called_once_with(self.args, watchdog)
        self.assertFalse(report["passed"])
        self.assertEqual(report["error"], "validation_interrupted")
        self.assertTrue(report["checks"]["gateway_parent_resumed"])

    def test_detached_watchdog_resumes_after_timeout_or_interruption(self):
        # A fake executable records signals; this never invokes real podman.
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            log = directory / "signals.jsonl"
            fake_podman = directory / "podman"
            fake_podman.write_text("#!" + sys.executable + "\nimport json, os, sys\n"
                                   "with open(os.environ['RECOVERY_WATCHDOG_TEST_LOG'], 'a') as output:\n"
                                   "    output.write(json.dumps(sys.argv[1:]) + '\\n')\n")
            fake_podman.chmod(0o700)
            env = os.environ | {"PATH": temporary, "RECOVERY_WATCHDOG_TEST_LOG": str(log)}
            # Independent timer fires even when its validator does no cleanup.
            completed = subprocess.run([sys.executable, "-c", probe.PAUSE_WATCHDOG,
                                        self.args.gateway, ".01"], env=env, text=True,
                                       capture_output=True, timeout=5)
            self.assertEqual(completed.returncode, 0)
            self.assertEqual(json.loads(completed.stdout), {"stopped": True})
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertEqual(calls, [["kill", "--signal", "STOP", self.args.gateway],
                                     ["kill", "--signal", "CONT", self.args.gateway]])
            # The same cleanup path runs when the operator interrupts it early.
            with mock.patch.dict(os.environ, env):
                watchdog = probe.start_pause(self.args)
                self.assertEqual(os.getsid(watchdog.pid), watchdog.pid)
                try:
                    watchdog.terminate()
                    watchdog.wait(timeout=5)
                finally:
                    if watchdog.poll() is None:
                        watchdog.kill()
                        watchdog.wait(timeout=5)
                    watchdog.stdout.close()
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertEqual(calls[-2:], [["kill", "--signal", "STOP", self.args.gateway],
                                         ["kill", "--signal", "CONT", self.args.gateway]])


if __name__ == "__main__":
    unittest.main()
