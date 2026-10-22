"""VNC credentials stay private, stable, and outside process arguments."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from vm.desktop import Desktop


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('guest_desktop', ROOT / 'guest/desktop.py')
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)


class DesktopTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='lemon-desktop-')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.vm = SimpleNamespace(state=self.root / 'first')
        self.desktop = Desktop(self.vm)

    def test_password_survives_reloads_and_is_unique_and_private_per_vm(self):
        first = self.desktop.password()
        self.assertRegex(first, r'^[A-Za-z0-9]{8}$')
        self.assertEqual(Desktop(self.vm).password(), first)
        second = Desktop(SimpleNamespace(state=self.root / 'second')).password()
        self.assertNotEqual(first, second)
        self.assertEqual(self.desktop.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.vm.state.stat().st_mode & 0o777, 0o700)

    def test_password_query_never_creates_credentials_or_profile_state(self):
        with self.assertRaisesRegex(ValueError, 'No VNC password'):
            self.desktop.password(create=False)
        self.assertFalse(self.vm.state.exists())
        password = self.desktop.password()
        before = {p.name: p.read_bytes() for p in self.vm.state.iterdir()}
        self.assertEqual(self.desktop.password(create=False), password)
        self.assertEqual({p.name: p.read_bytes() for p in self.vm.state.iterdir()}, before)

    def test_public_symlinked_and_malformed_credentials_are_not_overwritten(self):
        original = self.desktop.password()
        self.desktop.path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'private file'):
            self.desktop.password()
        self.desktop.path.chmod(0o600)
        for value in ({'version': True, 'password': original},
                      {'version': 1, 'password': 'too-long-password'}, [],
                      {'version': 1, 'password': 'bad\npass'}):
            self.desktop.path.write_text(json.dumps(value))
            before = self.desktop.path.read_bytes()
            with self.assertRaises(ValueError):
                self.desktop.password()
            self.assertEqual(self.desktop.path.read_bytes(), before)
        self.desktop.path.unlink()
        target = self.root / 'unrelated'
        target.write_text('keep this file')
        self.desktop.path.symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.desktop.password()
        self.assertEqual(target.read_text(), 'keep this file')

    def test_configuration_sends_credentials_only_on_pinned_ssh_stdin(self):
        password = self.desktop.password()
        workflow = Mock(username='debian')
        workflow.ssh_command.side_effect = lambda argv: ['ssh', '-F', 'pinned-config', 'lemonbox', *argv]
        with patch('vm.desktop.subprocess.run', return_value=subprocess.CompletedProcess([], 0, '{"changed": true}')) as run:
            self.assertTrue(self.desktop.configure(workflow))
        command = run.call_args.args[0]
        self.assertNotIn(password, ' '.join(command))
        request = json.loads(run.call_args.kwargs['input'])
        self.assertEqual(request['password'], password)
        self.assertEqual(request['username'], 'debian')
        self.assertIn('-passwdfile', request['script'])
        self.assertIn('pinned-config', command)

    def test_configuration_failures_do_not_echo_credentials(self):
        password = self.desktop.password()
        workflow = Mock(username='debian')
        for result in (subprocess.CompletedProcess([], 1, password, password),
                       subprocess.CompletedProcess([], 0, 'invalid JSON', ''),
                       subprocess.CompletedProcess([], 0, '{"changed": "yes"}', '')):
            with self.subTest(result=result.returncode), \
                    patch('vm.desktop.subprocess.run', return_value=result), \
                    self.assertRaises(RuntimeError) as error:
                self.desktop.configure(workflow)
            self.assertNotIn(password, str(error.exception))

    def test_guest_password_write_is_private_atomic_and_idempotent(self):
        path = self.root / 'vnc-password'
        options = {'mode': 0o600, 'uid': os.getuid(), 'gid': os.getgid()}
        self.assertTrue(guest.write_file(path, 'testpass\n', **options))
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.read_text(), 'testpass\n')
        self.assertFalse(guest.write_file(path, 'testpass\n', **options))
        path.unlink()
        target = self.root / 'unrelated'
        target.write_text('keep')
        path.symlink_to(target)
        with self.assertRaises(ValueError):
            guest.write_file(path, 'testpass\n', **options)
        self.assertEqual(target.read_text(), 'keep')
        self.assertFalse(list(self.root.glob('.lemon-desktop-*')))

    def test_guest_rejects_invalid_requests_before_touching_files(self):
        request = {'username': 'debian', 'password': 'testpass',
                   'script': '#!/bin/bash\nexit 0\n'}
        for changes in ({'username': 'root'}, {'username': '../debian'},
                        {'password': 'longpassword'}, {'password': 'test\nkey'},
                        {'script': 'not a desktop script'}):
            with self.subTest(changes=changes), patch.object(guest, 'write_file') as write, \
                    self.assertRaises(ValueError):
                guest.configure(request | changes)
            write.assert_not_called()


if __name__ == '__main__':
    unittest.main()
