"""Diagnostics require positive evidence and clean up their remote listener."""
import errno
import importlib.util
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from vm import diagnostics


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('diagnostic_packet_probe', ROOT / 'tests/packet_guest.py')
packet = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(packet)


class PrivateDiagnosticTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.vm = SimpleNamespace(gateway='fixture-gateway', state=Path(temporary.name))
        (self.vm.state / 'guest.json').write_text(json.dumps({'profile': {'gateway': '10.77.0.1'}}))
        self.listener = mock.Mock()
        self.listener.stdout = io.StringIO('43123\n')
        self.listener.wait.return_value = 0
        self.workflow = mock.Mock()
        self.workflow.run_script.return_value = SimpleNamespace(returncode=0, stdout='{"connected":false}')

    def probe(self, *, counts=(4, 5), control_error=None):
        self.listener.stdout = io.StringIO('43123\n')
        with mock.patch.object(diagnostics.subprocess, 'Popen', return_value=self.listener) as launch, \
                mock.patch.object(diagnostics.select, 'select', return_value=([self.listener.stdout], [], [])), \
                mock.patch.object(diagnostics, 'command', side_effect=control_error) as control, \
                mock.patch.object(diagnostics, 'private_drop_count', side_effect=counts), \
                mock.patch.object(diagnostics, 'Workflow', return_value=self.workflow):
            result = diagnostics.controlled_private_check(self.vm)
        return result, launch, control

    def test_live_control_and_policy_drop_evidence_are_both_required(self):
        result, launch, control = self.probe()
        self.assertEqual(result['status'], 'pass')
        self.assertEqual(result['detail'], {'listener_positive_control': True,
                                           'guest_connected': False, 'policy_drop_packets': 1})
        self.assertIn('127.0.0.1', control.call_args.args[0][-1])
        self.assertIn('10.77.0.1', self.workflow.run_script.call_args.args[0])
        self.assertEqual(self.workflow.run_script.call_args.kwargs['timeout'], 15)
        self.assertIs(launch.call_args.kwargs['stdin'], subprocess.PIPE)
        self.listener.stdin.close.assert_called_once()
        self.listener.wait.assert_called_once_with(timeout=5)

    def test_private_probe_uses_the_selected_vm_gateway(self):
        (self.vm.state / 'guest.json').write_text(json.dumps({'profile': {'gateway': '10.77.0.5'}}))
        result, _, _ = self.probe()
        self.assertEqual(result['status'], 'pass')
        self.assertIn('10.77.0.5', self.workflow.run_script.call_args.args[0])

    def test_refusal_or_timeout_without_a_matching_drop_is_a_failure(self):
        for response in ('{"connected":false}', '{}', '[]', '{"connected":0}'):
            with self.subTest(response=response):
                self.workflow.run_script.return_value.stdout = response
                result, _, _ = self.probe(counts=(4, 4))
                self.assertEqual(result['status'], 'fail')

    def test_successful_guest_connection_cannot_pass_despite_an_increased_counter(self):
        self.workflow.run_script.return_value.stdout = '{"connected":true}'
        result, _, _ = self.probe()
        self.assertEqual(result['status'], 'fail')
        self.assertIs(result['detail']['guest_connected'], True)

    def test_failed_positive_control_never_runs_a_guest_negative_probe(self):
        with self.assertRaisesRegex(RuntimeError, 'listener unreachable'):
            self.probe(control_error=RuntimeError('listener unreachable'))
        self.workflow.run_script.assert_not_called()
        self.listener.stdin.close.assert_called_once()
        self.listener.wait.assert_called_once_with(timeout=5)

    def test_listener_start_timeout_closes_stdin_and_reaps_the_exec_process(self):
        with mock.patch.object(diagnostics.subprocess, 'Popen', return_value=self.listener), \
                mock.patch.object(diagnostics.select, 'select', return_value=([], [], [])):
            with self.assertRaisesRegex(RuntimeError, 'listener did not start'):
                diagnostics.controlled_private_check(self.vm)
        self.listener.stdin.close.assert_called_once()
        self.listener.wait.assert_called_once_with(timeout=5)

    def test_stalled_exec_cleanup_is_bounded_and_uses_kill_as_last_step(self):
        self.listener.wait.side_effect = [subprocess.TimeoutExpired('exec', 5),
                                         subprocess.TimeoutExpired('exec', 5), 0]
        result, _, _ = self.probe()
        self.assertEqual(result['status'], 'pass')
        self.listener.stdin.close.assert_called_once()
        self.listener.terminate.assert_called_once()
        self.listener.kill.assert_called_once()

    def test_remote_listener_exits_on_eof_with_a_real_socket_and_process(self):
        """Run the gateway helper locally to prove EOF closes its process."""
        native_popen = subprocess.Popen
        children = []

        def launch(argv, **kwargs):
            child = native_popen([sys.executable, '-u', '-c', argv[-1]], **kwargs)
            children.append(child)
            return child

        def positive(argv, **kwargs):
            child = native_popen([sys.executable, '-c', argv[-1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = child.communicate(timeout=5)
            self.assertEqual(child.returncode, 0, err.decode())
            return SimpleNamespace(returncode=0, stdout=out.decode())

        with mock.patch.object(diagnostics.subprocess, 'Popen', side_effect=launch), \
                mock.patch.object(diagnostics, 'command', side_effect=positive), \
                mock.patch.object(diagnostics, 'private_drop_count', side_effect=[4, 5]), \
                mock.patch.object(diagnostics, 'Workflow', return_value=self.workflow):
            result = diagnostics.controlled_private_check(self.vm)
        self.assertEqual(result['status'], 'pass')
        self.assertEqual(len(children), 1)
        self.assertEqual(children[0].returncode, 0)
        self.assertTrue(children[0].stdin.closed)
        children[0].stdout.close()

    def test_policy_counter_selects_the_actual_private_destination_rule(self):
        wrong = {'chain': 'guest_ingress', 'expr': [{'match': {'left': {'payload': {'field': 'saddr'}}}},
                                                   {'counter': {'packets': 80}}, {'drop': None}]}
        expected = {'chain': 'guest_ingress', 'expr': [{'match': {'left': {'payload': {'field': 'daddr'}}}},
                                                      {'counter': {'packets': 7}}, {'drop': None}]}
        data = {'nftables': [{'rule': wrong}, {'rule': expected}]}
        with mock.patch.object(diagnostics, 'command', return_value=SimpleNamespace(stdout=json.dumps(data))):
            self.assertEqual(diagnostics.private_drop_count(self.vm), 7)


class PacketEvidenceTests(unittest.TestCase):
    def ttl(self, output, *, code=1, error=None):
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        connection.connect.side_effect = error or ConnectionRefusedError(errno.ECONNREFUSED, 'closed')
        with mock.patch.object(packet.socket, 'socket', return_value=connection), \
                mock.patch.object(packet, 'DEADLINE', 100), \
                mock.patch.object(packet.time, 'monotonic', return_value=1), \
                mock.patch.object(packet.subprocess, 'run', return_value=SimpleNamespace(returncode=code, stdout=output)):
            return packet.ttl_one()

    def test_timeout_refusal_or_other_unreachable_error_is_not_ttl_expiry(self):
        for error in (TimeoutError('no reply'), ConnectionRefusedError(errno.ECONNREFUSED, 'closed'),
                      OSError(errno.ENETUNREACH, 'unreachable')):
            with self.subTest(error=type(error).__name__):
                self.assertEqual(self.ttl('1 packets transmitted, 0 received\n', error=error)['status'], 'fail')

    def test_ttl_probe_requires_an_actual_expiry_from_the_guest_gateway(self):
        output = 'From 10.77.0.1 icmp_seq=1 Time to live exceeded\n'
        self.assertEqual(self.ttl(output)['status'], 'pass')
        self.assertEqual(self.ttl(output.replace('10.77.0.1', '10.77.0.10'))['status'], 'fail')
        self.assertEqual(self.ttl(output, code=2)['status'], 'fail')

    def test_low_rtt_is_valid_measurement_without_a_geographical_minimum(self):
        raw = mock.MagicMock()
        raw.__enter__.return_value = raw
        info = bytearray(104)
        struct.pack_into('=I', info, packet.TCP_INFO_RTT_OFFSET, 125)
        raw.getsockopt.return_value = bytes(info)
        tls = mock.MagicMock()
        tls.__enter__.return_value = tls
        context = mock.Mock()
        context.wrap_socket.return_value = tls
        response = mock.Mock(status=200)
        response.read.return_value = b'ip=203.0.113.20\n'
        with mock.patch.object(packet.socket, 'socket', return_value=raw), \
                mock.patch.object(packet, 'DEADLINE', 100), \
                mock.patch.object(packet.time, 'monotonic', return_value=1), \
                mock.patch.object(packet.ssl, 'create_default_context', return_value=context), \
                mock.patch.object(packet.http.client, 'HTTPResponse', return_value=response):
            checks = packet.tcp_trace('203.0.113.20')
        self.assertEqual(checks[0]['status'], 'pass')
        self.assertEqual(checks[0]['detail']['rtt_ms'], .125)
        self.assertIs(checks[0]['detail']['measurement_only'], True)
        self.assertEqual(checks[1]['status'], 'pass')


class DiagnosticReportTests(unittest.TestCase):
    def test_a_valid_failed_guest_report_keeps_specific_check_results(self):
        with tempfile.TemporaryDirectory() as directory:
            vm = SimpleNamespace(state=Path(directory), private=mock.Mock(),
                route_config=SimpleNamespace(network={'expected_exit_ip':'203.0.113.7'}),
                config=SimpleNamespace(vm={'timezone':'UTC','docker':False}))
            (vm.state / 'guest.json').write_text(json.dumps({'profile': {'gateway': '10.77.0.5'}}))
            report = {'schema':1,'passed':False,'checks':[{'name':'native_claude','status':'fail','detail':{}}]}
            completed = subprocess.CompletedProcess([],1,json.dumps(report),'')
            with mock.patch.object(diagnostics,'Workflow') as workflow, \
                    mock.patch.object(diagnostics,'controlled_private_check',return_value={
                        'name':'private_destination_enforced','status':'pass','detail':{}}), \
                    mock.patch('builtins.print'):
                workflow.return_value.run_script.return_value=completed
                self.assertEqual(diagnostics.run(vm),1)
            stored=json.loads((vm.state/'validation/diagnose.json').read_text())
            self.assertFalse(stored['passed'])
            self.assertEqual(stored['checks'][0]['name'],'native_claude')
            self.assertEqual(stored['checks'][0]['status'],'fail')


if __name__ == '__main__':
    unittest.main()
