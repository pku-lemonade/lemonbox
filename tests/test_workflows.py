"""Verify native readiness, argument transport, and localhost desktop access."""
import contextlib
import io
import json
from pathlib import Path
import runpy
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from vm.workflows import Workflow


READINESS_SCRIPT = Path(__file__).resolve().parent.parent / "guest/readiness.py"


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="lemon-workflows-")
        self.addCleanup(temporary.cleanup)
        self.vm = Mock()
        self.vm.state = Path(temporary.name)
        self.vm.machine = "test-machine"
        self.vm.gateway = "test-gateway"
        self.vm.ssh_config.return_value = self.vm.state / "ssh config"
        self.vm.info.return_value = {"State": {"Status": "running"}}
        self.vm.health.return_value = True
        (self.vm.state / "guest.json").write_text(json.dumps({"profile": {
            "username": "debian", "desktop": True, "docker": True}}))
        self.workflow = Workflow(self.vm)

    @staticmethod
    def complete(**changes):
        result = {"cloud_status": "done", "cloud_complete": True,
                  "cloud_failed": False, "system_ready": True, "system_state": "running",
                  "ssh_ready": True, "docker_ready": True, "claude_ready": True,
                  "claude_version": "2.1.296 (Claude Code)"}
        result.update(changes)
        return subprocess.CompletedProcess([], 0, json.dumps(result), "")

    def test_ready_requires_all_genuine_services_and_gateway(self):
        with patch.object(self.workflow, "remote", return_value=self.complete()) as remote:
            result = self.workflow.ready(timeout=10)
        self.assertTrue(result["cloud_complete"])
        self.assertEqual(remote.call_args.args[0][:2], ["python3", "-c"])
        self.assertEqual(json.loads(remote.call_args.args[0][3]), {"require_docker": True})
        self.vm.health.assert_called_once()

    def test_cloud_init_failure_is_not_misreported_as_ready(self):
        with patch.object(self.workflow, "remote", return_value=self.complete(cloud_failed=True)), \
                self.assertRaisesRegex(RuntimeError, "provisioning failed"):
            self.workflow.ready(timeout=10)
        self.vm.health.assert_not_called()

    def test_bad_probe_stdout_and_ssh_errors_are_retried_then_native_success(self):
        results = [subprocess.CompletedProcess([], 255, "", "sensitive native error"),
                   subprocess.CompletedProcess([], 0, "warning: not JSON", ""),
                   subprocess.CompletedProcess([], 0, "[]", ""), self.complete()]
        output, diagnostics = io.StringIO(), io.StringIO()
        with patch.object(self.workflow, "remote", side_effect=results) as remote, \
                patch("vm.workflows.time.sleep"), contextlib.redirect_stdout(output), \
                contextlib.redirect_stderr(diagnostics):
            self.workflow.ready(timeout=10)
        self.assertEqual(remote.call_count, 4)
        self.assertEqual(output.getvalue(), "")
        self.assertNotIn("sensitive", diagnostics.getvalue())

    def test_timeout_cannot_become_success_without_claude(self):
        now = [0]

        def sleep(seconds):
            now[0] += seconds

        with patch("vm.workflows.time.monotonic", side_effect=lambda: now[0]), \
                patch("vm.workflows.time.sleep", side_effect=sleep), \
                patch.object(self.workflow, "remote", return_value=self.complete(claude_ready=False)), \
                contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaisesRegex(RuntimeError, "not ready.*claude"):
            self.workflow.ready(timeout=5)
        self.assertGreater(self.vm.health.call_count, 0)

    def test_closed_route_during_cloud_init_fails_without_waiting_for_deadline(self):
        incomplete = self.complete(cloud_status='running', cloud_complete=False, claude_ready=False)
        self.vm.health.side_effect = [True, False]
        with patch.object(self.workflow, 'remote', return_value=incomplete) as remote, \
                patch('vm.workflows.time.sleep') as sleep, contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaisesRegex(RuntimeError, 'fixed route is closed.*shell remains available'):
            self.workflow.ready(timeout=900)
        self.assertEqual(remote.call_count, 2)
        self.assertEqual(sleep.call_count, 1)

    def test_closed_route_with_ssh_unavailable_is_actionable(self):
        self.vm.health.return_value = False
        with patch.object(self.workflow, 'remote', return_value=subprocess.CompletedProcess([], 255, '', 'SSH unavailable')), \
                patch('vm.workflows.time.sleep') as sleep, \
                self.assertRaisesRegex(RuntimeError, 'fixed route is closed'):
            self.workflow.ready(timeout=900)
        sleep.assert_not_called()

    def test_stopped_vm_fails_before_attempting_ssh(self):
        self.vm.info.return_value = None
        with patch.object(self.workflow, "remote") as remote, \
                self.assertRaisesRegex(RuntimeError, "VM is stopped"):
            self.workflow.ready(timeout=10)
        remote.assert_not_called()

    def test_runtime_change_during_probe_aborts_readiness(self):
        guard = Mock(side_effect=[None, RuntimeError('VM restarted while waiting')])
        with patch.object(self.workflow, 'remote', return_value=self.complete()), \
                self.assertRaisesRegex(RuntimeError, 'restarted while waiting'):
            self.workflow.ready(timeout=10, check_current=guard)
        self.vm.health.assert_not_called()

    def test_native_probe_rejects_cloud_init_done_with_nonzero_status(self):
        output = io.StringIO()

        def operation(argv, **kwargs):
            if argv[:2] == ["cloud-init", "status"]:
                return subprocess.CompletedProcess(argv, 2, '{"status":"done","errors":[]}', "")
            if argv[:2] == ["systemctl", "is-system-running"]:
                return subprocess.CompletedProcess(argv, 0, "running", "")
            return subprocess.CompletedProcess(argv, 0, "2.1.296", "")

        with patch("subprocess.run", side_effect=operation), contextlib.redirect_stdout(output), \
                patch("sys.argv", [str(READINESS_SCRIPT), '{"require_docker": true}']):
            runpy.run_path(str(READINESS_SCRIPT), run_name="__main__")
        actual = json.loads(output.getvalue())
        self.assertFalse(actual["cloud_complete"])
        self.assertTrue(actual["cloud_failed"])

    def docker_snapshot(self, client_present):
        def operation(argv, **kwargs):
            if argv[:2] == ['cloud-init', 'status']:
                return subprocess.CompletedProcess(argv, 0, '{"status":"done","errors":[]}', '')
            if argv == ['docker', '--version']:
                if not client_present:
                    raise FileNotFoundError('docker is absent')
                return subprocess.CompletedProcess(argv, 0, 'Docker version 26.1.5', '')
            return subprocess.CompletedProcess(argv, 0, 'running', '')
        with patch('subprocess.run', side_effect=operation), contextlib.redirect_stdout(io.StringIO()) as output, \
                patch("sys.argv", [str(READINESS_SCRIPT), '{"require_docker": true}']):
            runpy.run_path(str(READINESS_SCRIPT), run_name="__main__")
        return json.loads(output.getvalue())

    def test_native_probe_rejects_active_docker_daemon_without_client(self):
        snapshot = self.docker_snapshot(client_present=False)
        self.assertTrue(snapshot['docker_daemon_ready'])
        self.assertFalse(snapshot['docker_client_ready'])
        self.assertFalse(snapshot['docker_ready'])

    def test_native_probe_rejects_malformed_cloud_init_json(self):
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, "[]", "")), \
                contextlib.redirect_stdout(io.StringIO()) as output, \
                patch("sys.argv", [str(READINESS_SCRIPT), '{"require_docker": false}']):
            runpy.run_path(str(READINESS_SCRIPT), run_name="__main__")
        actual = json.loads(output.getvalue())
        self.assertFalse(actual["cloud_complete"])
        self.assertEqual(actual["cloud_status"], "unavailable")

    def test_unrelated_failed_unit_does_not_block_native_claude(self):
        with patch.object(self.workflow, "remote", return_value=self.complete(system_ready=False, system_state="degraded")):
            result = self.workflow.ready(timeout=10)
        self.assertEqual(result["system_state"], "degraded")

    def test_repair_access_ignores_provisioning_and_route_health(self):
        self.vm.health.return_value = False
        with patch.object(self.workflow, "remote", return_value=subprocess.CompletedProcess([], 0)) as remote:
            self.workflow.accessible(timeout=10)
        remote.assert_called_once_with(["true"], capture=True, timeout=unittest.mock.ANY)
        self.vm.health.assert_not_called()

    def test_remote_argv_and_project_name_do_not_become_shell_code(self):
        project = "/home/debian/project with 'quotes'; touch /tmp/unwanted"
        workflow = Workflow(self.vm, workdir=project)
        args = ["printf", "%s", "hello world", "$(touch /tmp/unwanted)", "a'b", "--"]
        command = workflow.ssh_command(workflow._guest_command(args))
        shell_argv = shlex.split(command[-1])
        self.assertEqual(shell_argv[:2], ["/bin/bash", "-lc"])
        words = shlex.split(shell_argv[2])
        self.assertEqual(words[:5], ["cd", "--", project, "&&", "exec"])
        self.assertEqual(words[5:], args)
        self.assertEqual(command[:4], ["ssh", "-F", str(self.vm.state / "ssh config"), "-T"])

    def test_execute_streams_output_and_preserves_remote_exit_code(self):
        with patch("vm.workflows.subprocess.run", return_value=subprocess.CompletedProcess([], 42)) as run:
            self.assertEqual(self.workflow.execute(["bash", "-c", "exit 42"]), 42)
        self.assertFalse(run.call_args.kwargs["capture_output"])
        self.assertNotIn("stdin", run.call_args.kwargs)
        self.assertIn("-T", run.call_args.args[0])

    def test_management_probe_cannot_consume_piped_guest_command_input(self):
        with patch("vm.workflows.subprocess.run", return_value=subprocess.CompletedProcess([], 0, '{}', '')) as run:
            self.workflow.remote(['python3', '-c', 'print("ready")'], capture=True, timeout=10)
        self.assertEqual(run.call_args.kwargs['stdin'], subprocess.DEVNULL)

    def test_operator_script_and_json_arguments_remain_separate_from_user_stdin(self):
        source = "import json, sys; print(json.loads(sys.argv[1]))\n"
        payload = json.dumps({"path": "/home/debian/a'b; $(touch /tmp/unwanted)"})
        with patch("vm.workflows.subprocess.run", return_value=subprocess.CompletedProcess([], 0, '{}', '')) as run:
            self.workflow.run_script(source, args=(payload,), sudo=True, timeout=30)
        self.assertEqual(shlex.split(run.call_args.args[0][-1]),
                         ["sudo", "-n", "python3", "-", payload])
        self.assertEqual(run.call_args.kwargs["input"], source)
        self.assertEqual(run.call_args.kwargs["timeout"], 30)
        self.assertTrue(run.call_args.kwargs["capture_output"])

    def test_shell_allocates_pty_only_for_real_terminal(self):
        with patch.object(self.workflow, "_interactive", return_value=True), \
                patch("vm.workflows.subprocess.run", return_value=subprocess.CompletedProcess([], 0)) as run:
            self.workflow.shell()
        self.assertIn("-t", run.call_args.args[0])
        self.assertEqual(run.call_args.args[0][4], "lemonbox")
        self.assertNotIn("stdin", run.call_args.kwargs)
        with patch.object(self.workflow, "_interactive", return_value=False), \
                patch("vm.workflows.subprocess.run", return_value=subprocess.CompletedProcess([], 0)) as run:
            self.workflow.shell()
        self.assertIn("-T", run.call_args.args[0])
        self.assertEqual(run.call_args.args[0][4], "lemonbox")
        self.assertNotIn("stdin", run.call_args.kwargs)

    def test_shell_starts_in_workspace_with_home_fallback_and_explicit_override(self):
        home = self.vm.state / 'home'
        home.mkdir()
        self.workflow.home = str(home)
        observed = []

        def remote(argv, **kwargs):
            result = subprocess.run(argv, cwd=home, input='pwd\n', text=True, capture_output=True)
            observed.append(result)
            return result

        with patch.object(self.workflow, 'remote', side_effect=remote):
            self.assertEqual(self.workflow.shell(), 0)
            self.assertEqual(observed[-1].stdout.strip(), str(home))
            workspace = home / 'workspace'
            workspace.mkdir()
            self.assertEqual(self.workflow.shell(), 0)
            self.assertEqual(observed[-1].stdout.strip(), str(workspace))
            selected = home / "project with 'quotes'"
            selected.mkdir()
            self.workflow.workdir = str(selected)
            self.assertEqual(self.workflow.shell(), 0)
            self.assertEqual(observed[-1].stdout.strip(), str(selected))
            self.workflow.workdir = str(home / 'missing')
            self.assertNotEqual(self.workflow.shell(), 0)

    def test_claude_print_uses_absolute_guest_binary_without_pty(self):
        with patch.object(self.workflow, "_interactive", return_value=True), \
                patch("vm.workflows.subprocess.run", return_value=subprocess.CompletedProcess([], 7)) as run:
            self.assertEqual(self.workflow.claude(["--print", "a 'quoted' prompt"]), 7)
        command = run.call_args.args[0]
        self.assertNotIn("stdin", run.call_args.kwargs)
        self.assertIn("-T", command)
        self.assertEqual(shlex.split(command[-1]),
                         ["/home/debian/.local/bin/claude", "--print", "a 'quoted' prompt"])

    def test_claude_interactive_mode_uses_pty(self):
        with patch.object(self.workflow, "_interactive", return_value=True), \
                patch("vm.workflows.subprocess.run", return_value=subprocess.CompletedProcess([], 0)) as run:
            self.workflow.claude(["--resume"])
        self.assertIn("-t", run.call_args.args[0])

    def test_vnc_starts_desktop_and_binds_only_localhost(self):
        tunnel = Mock()
        tunnel.wait.return_value = 0
        tunnel.poll.return_value = 0
        with patch.object(self.workflow, "remote", return_value=subprocess.CompletedProcess([], 0)) as remote, \
                patch.object(self.workflow, "_wait_desktop") as wait, \
                patch.object(self.workflow, "_wait_tunnel") as forward, \
                patch("vm.workflows.subprocess.Popen", return_value=tunnel) as popen, \
                patch.object(self.workflow, "_viewer") as viewer, \
                contextlib.redirect_stderr(io.StringIO()) as output:
            self.assertEqual(self.workflow.vnc(port=5907), 0)
        self.assertEqual(remote.call_args.args[0],
                         ["sudo", "-n", "systemctl", "start", "lemon-desktop.service"])
        wait.assert_called_once()
        forward.assert_called_once_with(tunnel, 5907)
        command = popen.call_args.args[0]
        self.assertIn("127.0.0.1:5907:127.0.0.1:5900", command)
        self.assertIn("ExitOnForwardFailure=yes", command)
        self.assertIn("Ctrl-C", output.getvalue())
        viewer.assert_not_called()

    def test_vnc_stop_never_opens_a_tunnel(self):
        with patch.object(self.workflow, "remote", return_value=subprocess.CompletedProcess([], 0)) as remote, \
                patch("vm.workflows.subprocess.Popen") as popen, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.workflow.vnc(stop=True), 0)
        self.assertEqual(remote.call_args.args[0][3], "stop")
        popen.assert_not_called()

    def test_vnc_viewer_is_opened_only_after_tunnel_is_ready(self):
        tunnel = Mock()
        tunnel.wait.return_value = 0
        tunnel.poll.return_value = 0
        viewer = ["/usr/bin/vncviewer", "127.0.0.1::5901"]
        events = []

        def launch(argv):
            events.append(argv)
            return tunnel

        with patch.object(self.workflow, "remote", return_value=subprocess.CompletedProcess([], 0)), \
                patch.object(self.workflow, "_wait_desktop"), \
                patch.object(self.workflow, "_wait_tunnel", side_effect=lambda *_: events.append("ready")), \
                patch.object(self.workflow, "_viewer", return_value=viewer), \
                patch("vm.workflows.subprocess.Popen", side_effect=launch), \
                contextlib.redirect_stderr(io.StringIO()):
            self.workflow.vnc(open_viewer=True)
        self.assertEqual(events[1:], ["ready", viewer])

    def test_vnc_tunnel_is_reaped_on_ctrl_c(self):
        tunnel = Mock()
        tunnel.wait.side_effect = [KeyboardInterrupt(), 0]
        tunnel.poll.return_value = None
        with patch.object(self.workflow, "remote", return_value=subprocess.CompletedProcess([], 0)), \
                patch.object(self.workflow, "_wait_desktop"), \
                patch.object(self.workflow, "_wait_tunnel"), \
                patch("vm.workflows.subprocess.Popen", return_value=tunnel), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.workflow.vnc(), 130)
        tunnel.terminate.assert_called_once()
        self.assertEqual(tunnel.wait.call_count, 2)

    def test_vnc_reports_no_success_before_forwarding_failure(self):
        tunnel = Mock()
        tunnel.poll.return_value = 255
        with patch.object(self.workflow, "remote", return_value=subprocess.CompletedProcess([], 0)), \
                patch.object(self.workflow, "_wait_desktop"), \
                patch("vm.workflows.subprocess.Popen", return_value=tunnel), \
                contextlib.redirect_stderr(io.StringIO()) as output, \
                self.assertRaisesRegex(RuntimeError, "VNC tunnel failed"):
            self.workflow.vnc()
        self.assertNotIn("VNC: ", output.getvalue())
        tunnel.terminate.assert_not_called()

    def test_vnc_cleans_up_tunnel_after_readiness_timeout(self):
        tunnel = Mock()
        tunnel.poll.return_value = None
        with patch.object(self.workflow, "remote", return_value=subprocess.CompletedProcess([], 0)), \
                patch.object(self.workflow, "_wait_desktop"), \
                patch.object(self.workflow, "_wait_tunnel", side_effect=RuntimeError("tunnel timed out")), \
                patch("vm.workflows.subprocess.Popen", return_value=tunnel), \
                self.assertRaisesRegex(RuntimeError, "tunnel timed out"):
            self.workflow.vnc()
        tunnel.terminate.assert_called_once()
        tunnel.wait.assert_called_once_with(timeout=5)


if __name__ == "__main__":
    unittest.main()
