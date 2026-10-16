"""CLI alerts present gateway reports without running health checks."""
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from vm import alerts, gateway_runtime
from vm.config import write_private_json


class RouteAlertTests(unittest.TestCase):
    def test_healthy_and_inactive_routes_have_no_alert(self):
        failure = {'status': 'failed', 'attempts': 3}
        self.assertIsNone(alerts.route_alert(recovery={'status': 'healthy', 'attempts': 1}))
        self.assertIsNone(alerts.route_alert(recovery=failure, active=False))

    def test_early_recovery_waits_but_exhausted_fast_retries_alert(self):
        self.assertIsNone(alerts.route_alert(recovery={
            'status': 'recovering', 'attempts': 2, 'retrying': True}))
        alert = alerts.route_alert(recovery={
            'status': 'failed', 'attempts': 3, 'retrying': True})
        self.assertEqual(alert['status'], 'active')
        self.assertEqual(alert['attempts'], 3)
        self.assertTrue(alert['retrying'])
        self.assertIn('slower retries continue', alert['reason'])

    def test_terminal_and_blocked_failures_require_attention(self):
        for phase in ('failed', 'blocked'):
            with self.subTest(phase=phase):
                alert = alerts.route_alert(recovery={
                    'status': phase, 'attempts': 1, 'retrying': False})
                self.assertIn('attention', alert['reason'])
                self.assertFalse(alert['retrying'])

    def test_missing_report_is_unavailable_without_diagnosing_the_route(self):
        for recovery in (None, {}, {'status': 'unknown', 'attempts': 0}):
            with self.subTest(recovery=recovery):
                alert = alerts.route_alert(recovery=recovery)
                self.assertIn('status is unavailable', alert['reason'])
                self.assertNotIn('Internet is closed', alert['reason'])
                self.assertFalse(alert['retrying'])

    def test_stopped_gateway_overrides_recovering_file(self):
        alert = alerts.route_alert(gateway_status='exited',
                                   recovery={'status': 'recovering', 'attempts': 2})
        self.assertIn('stopped', alert['reason'])
        self.assertEqual(alert['attempts'], 0)

    def test_arbitrary_fields_never_enter_the_alert(self):
        for attempts in (True, -1, 1000001, 'private token'):
            alert = alerts.route_alert(recovery={
                'status': 'blocked', 'attempts': attempts, 'retrying': 'secret',
                'reason': 'password=SECRET', 'error_type': 'password=SECRET'})
            self.assertNotIn('SECRET', str(alert))
            self.assertEqual(alert['attempts'], 0)
            self.assertFalse(alert['retrying'])


class GatewayAlertTests(unittest.TestCase):
    def gateway(self):
        return Mock(info=Mock(return_value={'State': {'Status': 'running'}}),
                    health=Mock(return_value=False), recovery_status=Mock(return_value=None))

    def test_inactive_never_probes(self):
        gateway = self.gateway()
        self.assertIsNone(alerts.gateway_alert(gateway, active=False))
        gateway.info.assert_not_called()

    def test_published_health_is_reported_without_a_health_check(self):
        gateway = self.gateway()
        gateway.health.side_effect = AssertionError('The CLI must not run a health check')
        gateway.recovery_status.return_value = {'status': 'healthy', 'attempts': 1}
        self.assertIsNone(alerts.gateway_alert(gateway))
        gateway.recovery_status.assert_called_once()
        gateway.health.assert_not_called()

    def test_gateway_recovery_is_classified_live(self):
        gateway = self.gateway()
        gateway.recovery_status.return_value = {'status': 'recovering', 'attempts': 1}
        self.assertIsNone(alerts.gateway_alert(gateway))
        gateway.recovery_status.return_value = {'status': 'failed', 'attempts': 3, 'retrying': True}
        self.assertTrue(alerts.gateway_alert(gateway)['retrying'])

    def test_inaccessible_backend_alerts_without_raw_exception(self):
        for operation in ('info', 'recovery_status'):
            for error in (RuntimeError('password=SECRET'), OSError('password=SECRET'),
                          subprocess.TimeoutExpired('password=SECRET', 5)):
                with self.subTest(operation=operation, error=type(error).__name__):
                    gateway = self.gateway()
                    getattr(gateway, operation).side_effect = error
                    alert = alerts.gateway_alert(gateway)
                    self.assertIn('status is unavailable', alert['reason'])
                    self.assertNotIn('SECRET', str(alert))

    def test_missing_stopped_and_malformed_gateway_are_visible(self):
        for info in (None, {'State': {'Status': 'exited'}}, {}, []):
            with self.subTest(info=info):
                gateway = self.gateway()
                gateway.info.return_value = info
                self.assertIsNotNone(alerts.gateway_alert(gateway))
                gateway.health.assert_not_called()

    def test_unreadable_report_does_not_trigger_a_health_check(self):
        gateway = self.gateway()
        gateway.recovery_status.side_effect = ValueError('password=SECRET')
        alert = alerts.gateway_alert(gateway)
        self.assertIn('status is unavailable', alert['reason'])
        self.assertNotIn('SECRET', str(alert))
        gateway.health.assert_not_called()


class ConnectionAlertTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        home = patch.object(Path, 'home', return_value=self.home)
        home.start()
        self.addCleanup(home.stop)
        self.gateway = gateway_runtime.SharedGateway()
        self.connection = SimpleNamespace(invitation={'host': 'localhost', 'port': 2223})

    def allocate(self):
        self.gateway.state.mkdir(mode=0o700, parents=True)
        write_private_json(self.gateway.allocations_path, {'version': 1, 'profiles': {
            str(self.home / '.local/share/lemonbox/work'): {'profile': 'work', 'slot': 1}}})

    def test_ssh_only_clients_do_not_probe_owner_backend(self):
        for host in ('localhost', '127.0.0.1', '::1', 'remote.example'):
            self.connection.invitation['host'] = host
            with self.subTest(host=host), patch.object(gateway_runtime, 'run') as backend:
                self.assertIsNone(alerts.connection_alert(self.connection))
                backend.assert_not_called()
        self.assertFalse(self.gateway.state.exists())

    def test_only_matching_allocated_loopback_relays_map_to_owner(self):
        self.allocate()
        for host in ('localhost', '127.0.0.1', '::1'):
            self.connection.invitation['host'] = host
            with self.subTest(host=host), patch.object(gateway_runtime, 'run') as backend:
                owner = alerts.owner_gateway_for_connection(self.connection)
                self.assertEqual(owner.state, self.gateway.state)
                self.assertIsNone(owner.vm)
                backend.assert_not_called()
        for invitation in ({'host': 'remote.example', 'port': 2223},
                           {'host': 'localhost', 'port': 2222}):
            self.connection.invitation = invitation
            self.assertIsNone(alerts.owner_gateway_for_connection(self.connection))

    def test_mapped_owner_receives_live_gateway_alert(self):
        self.allocate()
        alert = {'status': 'active', 'reason': 'Fixed message.', 'attempts': 1, 'retrying': False}
        with patch.object(alerts, 'gateway_alert', return_value=alert) as probe:
            self.assertEqual(alerts.connection_alert(self.connection), alert)
        self.assertEqual(probe.call_args.args[0].state, self.gateway.state)

    def test_invalid_and_nonprivate_registries_do_not_authorize_owner_probe(self):
        self.allocate()
        path = self.gateway.allocations_path
        for invalid in ({'version': 1, 'profiles': {'relative': {'profile': 'work', 'slot': 1}}},
                        {'version': 1, 'profiles': {str(self.home / 'work'): {'profile': 'work', 'slot': 0}}}):
            with self.subTest(invalid=invalid), patch.object(gateway_runtime, 'run') as backend:
                write_private_json(path, invalid)
                self.assertIsNone(alerts.connection_alert(self.connection))
                backend.assert_not_called()
        write_private_json(path, {'version': 1, 'profiles': {
            str(self.home / '.local/share/lemonbox/work'): {'profile': 'work', 'slot': 1}}})
        path.chmod(0o644)
        self.assertIsNone(alerts.owner_gateway_for_connection(self.connection))
        path.chmod(0o600)
        self.gateway.state.chmod(0o755)
        self.assertIsNone(alerts.owner_gateway_for_connection(self.connection))


if __name__ == '__main__':
    unittest.main()
