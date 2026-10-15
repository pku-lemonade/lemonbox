"""VM settings mutation, route separation and owned-container failures."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from vm.config import Config, write_private_json
from vm import gateway_runtime, runtime


def config():
    return Config.load(runtime.ROOT / 'config.example.json', require_private=False)


class VMSettingsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='lemon-vm-settings-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.state = self.directory / 'test'
        self.state.mkdir(mode=0o700)
        self.config = config()
        self.config.write(self.state / 'config.json')
        self.vm = runtime.VM(argparse.Namespace(profile='test', state_dir=self.state,
                                               gateway_state=self.directory / 'gateway'))

    def changed(self):
        data = self.config.as_dict()
        data['vm']['cpus'] += 1
        return Config.from_dict(data)

    def test_invalid_mutated_settings_fail_without_replacing_saved_config_or_stopping_vm(self):
        original = self.vm.config_path.read_bytes()
        candidate = self.changed()
        candidate.vm['cpus'] = 0
        with patch.object(self.vm, 'down') as stop, patch.object(self.vm, 'up') as start:
            with self.assertRaisesRegex(ValueError, 'cpus'):
                self.vm.apply_config(candidate)
        stop.assert_not_called()
        start.assert_not_called()
        self.assertEqual(self.vm.config_path.read_bytes(), original)

    def test_stale_editor_cannot_overwrite_settings_saved_by_another_process(self):
        revision = self.vm.profile_state.revision()
        self.vm.save_config(self.changed())
        with patch.object(self.vm, 'down') as stop, patch.object(self.vm, 'up') as start:
            with self.assertRaisesRegex(ValueError, 'changed while'):
                self.vm.apply_config(self.config, expected_revision=revision)
        stop.assert_not_called()
        start.assert_not_called()
        self.assertEqual(Config.load(self.vm.config_path).vm['cpus'], self.changed().vm['cpus'])

    def test_existing_running_vm_restart_failure_keeps_new_settings_and_reports_failure(self):
        machine = {'State': {'Status': 'running'}, 'Config': {'Labels': {}}}
        with patch.object(self.vm, 'info', return_value=machine), \
                patch.object(self.vm, 'down') as stop, patch.object(self.vm, 'up', side_effect=RuntimeError('launch failed')):
            with self.assertRaisesRegex(RuntimeError, 'launch failed'):
                self.vm.apply_config(self.changed())
        stop.assert_called()
        self.assertEqual(Config.load(self.vm.config_path).vm['cpus'], self.changed().vm['cpus'])

    def test_guest_cannot_start_on_another_profiles_tap_from_mistyped_metadata(self):
        allocation = self.vm.shared_gateway.allocation()
        metadata = allocation | {'tap': 'vm0'}
        (self.state / 'guest.json').write_text(json.dumps({'profile': metadata}))
        with patch.object(self.vm, 'private'), patch.object(self.vm.shared_gateway, 'attach') as attach, \
                patch.object(runtime, 'run') as backend:
            with self.assertRaisesRegex(ValueError, 'assigned private network'):
                self.vm.up()
        attach.assert_not_called()
        backend.assert_not_called()

    def test_gateway_stop_waits_for_qemu_creation_then_rejects_running_vm(self):
        gateway = self.vm.shared_gateway
        metadata = self.config.vm | gateway.allocation()
        write_private_json(self.state / 'guest.json', {'profile': metadata})
        paused, release, running = threading.Event(), threading.Event(), threading.Event()
        attempted, completed = threading.Event(), threading.Event()
        errors = []
        stopped = []

        def backend(argv, **kwargs):
            output = ''
            if argv[:2] == ['podman', 'ps']:
                output = self.vm.machine if running.is_set() else ''
            elif argv[:2] == ['podman', 'inspect']:
                output = json.dumps([{
                    'Id': 'owned-gateway', 'State': {'Status': 'running'},
                    'Config': {'Labels': {
                        gateway_runtime.PROJECT_LABEL: str(runtime.ROOT),
                        gateway_runtime.STATE_LABEL: str(gateway.state),
                        gateway_runtime.ROLE_LABEL: 'gateway',
                    }},
                }])
            elif argv[:2] == ['podman', 'stop']:
                stopped.append(argv)
            return subprocess.CompletedProcess(argv, 0, output, '')

        def create_qemu(*args):
            paused.set()
            if not release.wait(5):
                raise RuntimeError('Startup fixture was not released')
            running.set()

        def start_vm():
            try:
                with self.vm.profile_state.lock():
                    self.vm.up()
            except Exception as error:
                errors.append(('startup', error))

        def stop_gateway():
            attempted.set()
            try:
                gateway.stop()
            except Exception as error:
                errors.append(('gateway', error))
            finally:
                completed.set()

        with patch.object(gateway_runtime, 'run', side_effect=backend), \
                patch.object(gateway, 'image', return_value='a' * 64), \
                patch.object(gateway, 'ensure_running'), patch.object(self.vm, 'info', return_value=None), \
                patch.object(self.vm, '_launch_qemu', side_effect=create_qemu), \
                patch.object(self.vm, 'ssh_config'), patch.object(self.vm, 'start_access'), \
                patch.object(runtime.os, 'access', return_value=True):
            startup = threading.Thread(target=start_vm)
            competing = threading.Thread(target=stop_gateway)
            startup.start()
            try:
                self.assertTrue(paused.wait(5))
                competing.start()
                self.assertTrue(attempted.wait(5))
                self.assertFalse(completed.wait(.2), 'Gateway changed between TAP attachment and QEMU creation')
            finally:
                release.set()
                startup.join(5)
                if competing.ident is not None:
                    competing.join(5)
        self.assertFalse(startup.is_alive())
        self.assertFalse(competing.is_alive())
        self.assertEqual([operation for operation, _ in errors], ['gateway'])
        self.assertIsInstance(errors[0][1], ValueError)
        self.assertIn('Stop every VM', str(errors[0][1]))
        self.assertEqual(stopped, [])


class BackendFailureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='lemon-vm-backend-')
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        self.vm = runtime.VM(argparse.Namespace(profile='test', state_dir=directory / 'test',
                                               gateway_state=directory / 'gateway'))

    def test_storage_failure_is_not_reported_as_absent_or_stopped(self):
        with patch.object(runtime, 'run', return_value=subprocess.CompletedProcess([], 125, '', 'database error')):
            with self.assertRaisesRegex(RuntimeError, 'backend'):
                self.vm.info(self.vm.machine)

    def test_unrelated_container_state_is_never_adopted(self):
        labels = {runtime.LABEL: str(runtime.ROOT), runtime.PROFILE_LABEL: self.vm.profile,
                  runtime.STATE_LABEL: str(self.vm.state)}
        for changed in (runtime.LABEL, runtime.PROFILE_LABEL, runtime.STATE_LABEL):
            record = {'Config': {'Labels': labels | {changed: 'another-owner'}}}
            with self.subTest(label=changed), patch.object(runtime, 'run', side_effect=[
                    subprocess.CompletedProcess([], 0, '', ''),
                    subprocess.CompletedProcess([], 0, json.dumps([record]), '')]):
                with self.assertRaises(ValueError):
                    self.vm.info(self.vm.machine)


if __name__ == '__main__':
    unittest.main()
