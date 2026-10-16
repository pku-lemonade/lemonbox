"""CLI and lifecycle consumers read reports produced by the gateway controller."""
import ast
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from vm import gateway_runtime


MISSING = object()


class GatewayReportingTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.gateway = gateway_runtime.SharedGateway(state=Path(directory.name) / 'gateway')
        self.now = 1000
        self.healthy = {'schema': 1, 'status': 'healthy', 'time': self.now,
                        'attempts': 1, 'retrying': False}
        self.calls = []
        self.reads = []

    def read_status(self, recovery, health=MISSING, *, use_health=False):
        files = {'/run/lemon/recovery.json': recovery}
        if health is not MISSING:
            files['/run/lemon/last-health.json'] = health

        def open_report(path, mode):
            self.reads.append(path)
            self.assertEqual(mode, 'rb')
            if path not in files:
                raise FileNotFoundError(path)
            value = files[path]
            return io.BytesIO(value if isinstance(value, bytes) else json.dumps(value).encode())

        def backend(argv, **kwargs):
            self.calls.append((argv, kwargs))
            self.assertEqual(argv[:5], ['podman', 'exec', self.gateway.name, 'python3', '-c'])
            self.assertEqual(len(argv), 6)
            output = io.StringIO()
            try:
                with patch('builtins.open', side_effect=open_report), contextlib.redirect_stdout(output):
                    exec(compile(argv[-1], '<published gateway status>', 'exec'), {})
            except (OSError, ValueError, TypeError):
                return subprocess.CompletedProcess(argv, 1, '', '')
            return subprocess.CompletedProcess(argv, 0, output.getvalue(), '')

        with patch.object(gateway_runtime, 'run', side_effect=backend), \
                patch.object(gateway_runtime.time, 'time', return_value=self.now):
            return self.gateway.health() if use_health else self.gateway.recovery_status()

    def parse_status(self, value):
        result = subprocess.CompletedProcess([], 0, json.dumps(value), '')
        with patch.object(gateway_runtime, 'run', return_value=result), \
                patch.object(gateway_runtime.time, 'time', return_value=self.now):
            return self.gateway.recovery_status()

    def test_health_reads_only_bounded_published_files(self):
        self.assertTrue(self.read_status(self.healthy, {'time': self.now}, use_health=True))
        self.assertEqual(self.reads, ['/run/lemon/recovery.json', '/run/lemon/last-health.json'])
        argv, options = self.calls[0]
        self.assertEqual(options, {'check': False, 'timeout': 5})
        imports = {alias.name for node in ast.walk(ast.parse(argv[-1]))
                   if isinstance(node, ast.Import) for alias in node.names}
        self.assertEqual(imports, {'json', 'math'})
        self.assertNotIn('controller', argv[-1])
        self.assertNotIn('socket', argv[-1])
        self.assertNotIn('nft', argv[-1])
        self.assertIn('handle.read(4097)', argv[-1])

    def test_initial_healthy_publication_needs_no_heartbeat(self):
        report = self.read_status(self.healthy)
        self.assertEqual(report['status'], 'healthy')
        self.assertEqual(report['last_verified'], self.now)

    def test_old_healthy_publication_uses_fresh_controller_heartbeat(self):
        report = self.read_status(self.healthy | {'time': self.now - 500}, {'time': self.now - 5})
        self.assertEqual(report['last_verified'], self.now - 5)

    def test_older_heartbeat_does_not_replace_new_healthy_publication(self):
        report = self.read_status(self.healthy, {'time': self.now - 500})
        self.assertEqual(report['last_verified'], self.now)

    def test_healthy_report_expires_at_the_kernel_lease_interval(self):
        expired = self.healthy | {'time': self.now - gateway_runtime.LEASE_SECONDS}
        self.assertIsNone(self.read_status(expired))
        self.assertFalse(self.read_status(expired, use_health=True))
        self.assertIsNone(self.read_status(expired, {'time': expired['time'] - 1}))

    def test_recovery_phases_are_retained_without_requiring_a_heartbeat(self):
        for phase in ('recovering', 'failed', 'blocked'):
            with self.subTest(phase=phase):
                self.reads.clear()
                value = self.healthy | {'status': phase, 'time': self.now - 500,
                                        'retrying': phase != 'blocked'}
                report = self.read_status(value, {'time': self.now})
                self.assertEqual(report['status'], phase)
                self.assertNotIn('last_verified', report)
                self.assertEqual(self.reads, ['/run/lemon/recovery.json'])
                self.assertFalse(self.read_status(value, use_health=True))

    def test_invalid_public_timestamps_are_unavailable(self):
        for stamp in (None, True, '1000', -1, float('nan'), float('inf'), self.now + 2):
            for field in ('time', 'last_verified'):
                with self.subTest(stamp=stamp, field=field):
                    self.assertIsNone(self.parse_status(self.healthy | {field: stamp}))
        self.assertIsNone(self.parse_status({key: value for key, value in self.healthy.items() if key != 'time'}))

    def test_invalid_heartbeat_is_unavailable_without_replacing_it_with_a_probe(self):
        for health in ({}, {'time': True}, {'time': float('nan')}, {'time': self.now + 2}, b'bad json'):
            with self.subTest(health=health):
                self.assertIsNone(self.read_status(self.healthy, health))

    def test_tiny_clock_skew_is_accepted(self):
        report = self.read_status(self.healthy | {'time': self.now + .5})
        self.assertEqual(report['last_verified'], self.now + .5)

    def test_oversized_or_invalid_files_are_unavailable(self):
        for payload in (b' ' * 4097, b'invalid json', b'[]'):
            with self.subTest(payload=payload[:20]):
                self.assertIsNone(self.read_status(payload))
                self.assertIsNone(self.read_status(self.healthy, payload))

    def test_only_public_metadata_is_returned(self):
        report = self.read_status(self.healthy | {'private': 'discard me', 'reason': 'private reason'})
        self.assertEqual(set(report), {'status', 'time', 'attempts', 'retrying', 'last_verified'})

    def test_nonhealthy_status_requires_a_valid_timestamp_too(self):
        for phase in ('recovering', 'failed', 'blocked'):
            with self.subTest(phase=phase):
                self.assertIsNone(self.parse_status(self.healthy | {'status': phase, 'time': float('nan')}))

    def test_boolean_schema_is_rejected(self):
        self.assertIsNone(self.parse_status(self.healthy | {'schema': True}))

    def test_existing_gateway_start_uses_one_published_snapshot(self):
        applied = {'runtime_image_id': 'sha256:' + 'a' * 64, 'network_sha256': 'b' * 64}
        info = {'State': {'Status': 'running'}, 'Image': applied['runtime_image_id'],
                'Config': {'Labels': {gateway_runtime.ROUTE_LABEL: applied['network_sha256']}}}
        for report in ({'status': 'healthy'}, {'status': 'recovering', 'attempts': 1, 'retrying': True},
                       {'status': 'failed', 'attempts': 3, 'retrying': False}, None):
            with self.subTest(report=report), \
                    patch.object(self.gateway, 'private', return_value=applied), \
                    patch.object(self.gateway, 'info', return_value=info), \
                    patch.object(self.gateway, 'recovery_status', return_value=report) as read, \
                    patch.object(self.gateway, 'health', side_effect=AssertionError('unexpected extra health read')):
                if report and report['status'] == 'healthy':
                    self.assertEqual(self.gateway.ensure_running(), applied['runtime_image_id'])
                else:
                    reason = 'status is unavailable' if report is None else 'shared route is closed'
                    with self.assertRaisesRegex(ValueError, reason):
                        self.gateway.ensure_running()
                read.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()
