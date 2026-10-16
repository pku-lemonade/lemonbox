"""Owner-visible recovery progress and alerts remain independent of route health."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from vm import cli, gateway_runtime


class RecoveryStatusTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.gateway = gateway_runtime.SharedGateway(state=Path(directory.name) / 'gateway')

    def test_missing_old_runtime_state_does_not_break_status(self):
        with patch.object(gateway_runtime, 'run', return_value=subprocess.CompletedProcess([], 1, '', '')):
            self.assertIsNone(self.gateway.recovery_status())
        with patch.object(gateway_runtime, 'run', side_effect=subprocess.TimeoutExpired([], 5)):
            self.assertIsNone(self.gateway.recovery_status())

    def test_only_valid_bounded_lifecycle_state_is_exposed(self):
        value = {'schema': 1, 'status': 'recovering', 'attempts': 2, 'time': 123,
                 'error_type': 'TimeoutError', 'unrelated_private_field': 'discard me'}
        with patch.object(gateway_runtime, 'run', return_value=subprocess.CompletedProcess([], 0, json.dumps(value), '')):
            self.assertEqual(self.gateway.recovery_status(),
                             {k: value[k] for k in ('status', 'attempts', 'time', 'error_type')})
        for invalid in (value | {'status': 'unknown'}, value | {'attempts': True},
                        value | {'attempts': -1}, value | {'schema': 2}, []):
            with self.subTest(invalid=invalid), patch.object(
                    gateway_runtime, 'run', return_value=subprocess.CompletedProcess([], 0, json.dumps(invalid), '')):
                self.assertIsNone(self.gateway.recovery_status())

    def vm(self):
        state = self.gateway.state.parent / 'default'
        return SimpleNamespace(
            profile='default', state=state, config_path=state / 'config.json', config_error=None,
            config=SimpleNamespace(vm={'username': 'debian'}), gateway='lemonbox-gateway',
            machine='lemonbox-default-machine', shared_gateway=self.gateway,
            route_config=SimpleNamespace(network={'expected_exit_ip': '203.0.113.20'}),
            info=lambda name: {'State': {'Status': 'running'}})

    def test_failed_recovery_keeps_alert_and_shell_guidance_visible(self):
        with patch.object(self.gateway, 'recovery_status', return_value={'status': 'failed', 'attempts': 3, 'retrying': True}), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.status(self.vm()), 0)
        self.assertIn('automatic recovery retries', output.getvalue())
        self.assertIn('attempt 3', output.getvalue())
        self.assertIn('ALERT:', output.getvalue())
        self.assertIn('slower retries continue', output.getvalue())
        self.assertIn('Shell access remains available', output.getvalue())

    def test_json_status_includes_live_recovery_alert(self):
        recovery = {'status': 'blocked', 'attempts': 1}
        with patch.object(self.gateway, 'recovery_status', return_value=recovery), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            cli.status(self.vm(), json_output=True)
        report = json.loads(output.getvalue())
        self.assertFalse(report['gateway_healthy'])
        self.assertEqual(report['recovery'], recovery)
        self.assertEqual(report['alert']['status'], 'active')
        self.assertFalse(report['alert']['retrying'])

    def test_terminal_failure_does_not_claim_it_is_retrying(self):
        with patch.object(self.gateway, 'recovery_status', return_value={'status': 'failed', 'attempts': 1, 'retrying': False}), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            cli.status(self.vm())
        self.assertIn('needs attention', output.getvalue())
        self.assertNotIn('automatic recovery retries', output.getvalue())

    def test_missing_recovery_state_with_unhealthy_route_warns(self):
        with patch.object(self.gateway, 'recovery_status', return_value=None), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            cli.status(self.vm())
        self.assertIn('route status unavailable', output.getvalue())
        self.assertNotIn('Internet is closed', output.getvalue())
        self.assertIn('ALERT:', output.getvalue())

    def test_backend_outage_shows_live_alert(self):
        vm = self.vm()
        def unavailable(name):
            raise RuntimeError('backend is unavailable')
        vm.info = unavailable
        with contextlib.redirect_stdout(io.StringIO()) as output:
            cli.status(vm)
        self.assertIn('VM unavailable', output.getvalue())
        self.assertIn('ALERT:', output.getvalue())

    def test_alert_clears_on_next_healthy_status_without_saved_state(self):
        vm = self.vm()
        with patch.object(self.gateway, 'recovery_status', side_effect=[
                {'status': 'failed', 'attempts': 3, 'retrying': True},
                {'status': 'healthy', 'attempts': 4, 'retrying': False}]):
            with contextlib.redirect_stdout(io.StringIO()) as failed:
                cli.status(vm, json_output=True)
            with contextlib.redirect_stdout(io.StringIO()) as restored:
                cli.status(vm, json_output=True)
        self.assertIsNotNone(json.loads(failed.getvalue())['alert'])
        self.assertIsNone(json.loads(restored.getvalue())['alert'])

    def test_other_commands_warn_on_stderr_and_keep_native_result(self):
        vm = self.vm()
        def payload(*args):
            print('native command output')
            return 37
        with patch.object(cli, 'VM', return_value=vm), \
                patch.object(cli, 'selected_target', return_value={'kind': 'vm', 'profile': 'default'}), \
                patch.object(cli, 'dispatch', side_effect=payload), \
                patch.object(self.gateway, 'info', return_value={'State': {'Status': 'running'}}), \
                patch.object(self.gateway, 'health', side_effect=AssertionError('Commands must only read reports')) as health, \
                patch.object(self.gateway, 'recovery_status', return_value={'status': 'failed', 'attempts': 3, 'retrying': True}), \
                contextlib.redirect_stdout(io.StringIO()) as stdout, \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(cli.main(['--profile', 'default', 'exec', '--', 'true']), 37)
        self.assertEqual(stdout.getvalue(), 'native command output\n')
        self.assertIn('ALERT:', stderr.getvalue())
        health.assert_not_called()


if __name__ == '__main__':
    unittest.main()
