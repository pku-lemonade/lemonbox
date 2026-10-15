import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from vm import sharing


class SharingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='lemon-share-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / 'private'
        self.state.mkdir()
        self.project = self.root / 'a project, with spaces'
        self.project.mkdir()

    def normalized(self, **kwargs):
        return sharing.validate_shares([{'name': 'project', 'source': str(self.project),
                                         **kwargs}], state_dir=self.state)

    def test_private_state_and_its_ancestors_and_descendants_are_rejected(self):
        child = self.state / 'nested'
        child.mkdir()
        for directory in [self.root, self.state, child]:
            with self.subTest(directory=directory), self.assertRaisesRegex(ValueError, 'private'):
                sharing.validate_shares([{'name': 'bad', 'source': str(directory)}],
                                        state_dir=self.state)

    def test_symlink_to_private_state_cannot_escape_boundary(self):
        shortcut = self.project / 'shortcut'
        shortcut.symlink_to(self.state, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'private'):
            sharing.validate_shares([{'name': 'bad', 'source': str(shortcut)}], state_dir=self.state)

    def test_operator_authentication_directory_is_rejected(self):
        home = self.root / 'operator'
        auth = home / '.ssh'
        auth.mkdir(parents=True)
        with patch.object(Path, 'home', return_value=home), self.assertRaisesRegex(ValueError, 'private'):
            sharing.validate_shares([{'name': 'bad', 'source': str(auth)}], state_dir=self.state)

    def test_another_profiles_private_state_is_never_shared(self):
        home = self.root / 'operator'
        other_profile = home / '.local/share/lemonbox/another-profile'
        other_profile.mkdir(parents=True)
        with patch.object(Path, 'home', return_value=home), self.assertRaisesRegex(ValueError, 'private'):
            sharing.validate_shares([{'name': 'bad', 'source': str(other_profile)}], state_dir=self.state)

    def test_duplicate_or_nested_sources_are_rejected(self):
        child = self.project / 'nested'
        child.mkdir()
        for second in [self.project, child]:
            with self.subTest(second=second), self.assertRaisesRegex(ValueError, 'overlap'):
                sharing.validate_shares([{'name': 'first', 'source': str(self.project)},
                                        {'name': 'second', 'source': str(second)}], state_dir=self.state)

    def test_invalid_names_and_targets_cannot_inject_qemu_or_mount_options(self):
        for name in ['../private', 'foo,readonly=off', 'UpperCase', 'x\ny']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                sharing.validate_shares([{'name': name, 'source': str(self.project)}], state_dir=self.state)
        with self.assertRaisesRegex(ValueError, 'target'):
            self.normalized(target='/etc')
        with self.assertRaisesRegex(ValueError, 'boolean'):
            self.normalized(read_only='false')

    def test_missing_or_non_directory_source_is_rejected(self):
        file = self.project / 'file'
        file.touch()
        for source in [self.project / 'missing', file]:
            with self.subTest(source=source), self.assertRaises(ValueError):
                sharing.validate_shares([{'name': 'bad', 'source': str(source)}], state_dir=self.state)

    def test_deleted_source_can_be_loaded_for_removal_without_weakening_start(self):
        self.project.rmdir()
        record = {'name': 'project', 'source': str(self.project)}
        self.assertEqual(sharing.validate_shares([record], state_dir=self.state,
                                               require_sources=False)[0]['source'], str(self.project))
        with self.assertRaisesRegex(ValueError, 'does not exist'):
            sharing.validate_shares([record], state_dir=self.state)

    def test_readonly_is_enforced_at_host_bind_and_qemu_export(self):
        shares = self.normalized(read_only=True)
        self.assertEqual(sharing.podman_mount_args(shares), ['-v', str(self.project) + ':/shared/project:ro'])
        arguments = sharing.qemu_args(shares)
        self.assertIn('readonly=on', arguments[1])
        self.assertIn('security_model=none', arguments[1])
        self.assertEqual(arguments[-1], 'virtio-9p-pci,fsdev=lemshare_project,mount_tag=lemshare_project')

    def test_shared_ssh_umask_is_only_selected_for_default_writable_workspace(self):
        source = self.root / 'workspaces/default'
        source.mkdir(parents=True)
        record = {'name': 'workspace', 'source': str(source), 'target': '/home/debian/workspace',
                  'read_only': False}
        with patch.object(sharing, 'ROOT', self.root):
            request = sharing.guest_mount_request(iter([record]))
            self.assertTrue(request['shared_workspace'])
            self.assertNotIn(str(source), json.dumps(request))
            self.assertFalse(sharing.guest_mount_request([dict(record, read_only=True)])['shared_workspace'])
            self.assertFalse(sharing.guest_mount_request([dict(record, source=str(self.project))])['shared_workspace'])


class GuestReconciliationTests(unittest.TestCase):
    """Execute the guest program with an isolated filesystem and fake mounts."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='lemon-share-guest-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.etc = self.root / 'etc'
        self.etc.mkdir()
        self.fstab = self.etc / 'fstab'
        self.fstab.write_text('UUID=native-root / ext4 defaults 0 1\n')
        self.fstab.chmod(0o644)
        self.pam = self.etc / 'pam.d/sshd'
        self.pam.parent.mkdir()
        self.pam.write_text('@include common-session\n')
        self.home = self.root / 'home/debian'
        self.home.mkdir(parents=True)
        self.share_home = self.home
        self.calls = []

    def execute(self, shares, *, prepare_restart=False, shared_workspace=False):
        native_path = Path
        native_mkstemp = tempfile.mkstemp
        source = (Path(__file__).resolve().parents[1] / 'guest/shares.py').read_text()
        request = (sharing.guest_prepare_restart_request(shares) if prepare_restart
                   else sharing.guest_mount_request(shares))
        request['shared_workspace'] = shared_workspace

        def mapped_path(value):
            candidate = native_path(value)
            if candidate == native_path('/etc/fstab'):
                return self.fstab
            if candidate == native_path('/etc/pam.d/sshd'):
                return self.pam
            if candidate == native_path('/home/debian') or native_path('/home/debian') in candidate.parents:
                return self.root / candidate.relative_to('/')
            return candidate

        def mkstemp(*args, **kwargs):
            if kwargs.get('dir') == '/etc':
                kwargs['dir'] = self.etc
            return native_mkstemp(*args, **kwargs)

        def command(args, **kwargs):
            self.calls.append(args)
            return subprocess.CompletedProcess(args, 0, '', '')

        output = io.StringIO()
        with patch('pathlib.Path', side_effect=mapped_path), \
                patch('tempfile.mkstemp', side_effect=mkstemp), \
                patch('pwd.getpwnam', return_value=SimpleNamespace(pw_uid=1000, pw_gid=1000)), \
                patch('os.chown'), patch('os.path.ismount', return_value=False), \
                patch('subprocess.run', side_effect=command), \
                patch.object(sys, 'argv', ['shares.py', json.dumps(request)]), \
                contextlib.redirect_stdout(output):
            try:
                exec(source, {})
            except SystemExit as stop:
                self.assertEqual(stop.code, 0)
        return json.loads(output.getvalue())

    def share(self, name='project', readonly=False):
        return {'name': name, 'target': '/home/debian/' + name,
                'source': '/host/never-in-guest', 'read_only': readonly}

    def test_native_fstab_survives_and_readonly_mount_persists(self):
        self.execute([self.share(readonly=True)])
        contents = self.fstab.read_text()
        self.assertTrue(contents.startswith('UUID=native-root / ext4 defaults 0 1\n'))
        self.assertIn('lemshare_project', contents)
        self.assertIn('nofail,ro', contents)
        self.assertNotIn('/host', contents)
        mounts = [call for call in self.calls if call[0] == 'mount']
        self.assertEqual(len(mounts), 1)
        self.assertEqual(mounts[0][-2], 'lemshare_project')
        self.assertIn('nofail,ro', mounts[0][4])
        self.assertEqual(os.stat(self.fstab).st_mode & 0o777, 0o644)

    def test_remove_restores_native_fstab_and_preserves_guest_files(self):
        self.execute([self.share()])
        local_file = self.share_home / 'project/local.txt'
        local_file.write_text('ordinary guest-owned file')
        self.calls.clear()
        self.execute([])
        self.assertEqual(self.fstab.read_text(), 'UUID=native-root / ext4 defaults 0 1\n')
        self.assertEqual(local_file.read_text(), 'ordinary guest-owned file')
        self.assertFalse(any(call[0] == 'mount' for call in self.calls))

    def test_nonempty_guest_directory_is_never_hidden_by_mount(self):
        target = self.share_home / 'project'
        target.mkdir(parents=True)
        (target / 'work.txt').write_text('do not hide this')
        with self.assertRaisesRegex(RuntimeError, 'contains guest files'):
            self.execute([self.share()])
        self.assertFalse(any(call[0] == 'mount' for call in self.calls))
        self.assertEqual(self.fstab.read_text(), 'UUID=native-root / ext4 defaults 0 1\n')

    def test_symlink_home_cannot_redirect_mount_into_guest_system(self):
        self.home.rmdir()
        self.share_home.symlink_to(self.etc, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, 'symlink'):
            self.execute([self.share()])
        self.assertFalse(any(call[0] == 'mount' for call in self.calls))

    def test_invalid_managed_fstab_block_does_not_replace_original(self):
        original = self.fstab.read_text() + '# lemonbox shares begin\n'
        self.fstab.write_text(original)
        with self.assertRaisesRegex(RuntimeError, 'managed shares block'):
            self.execute([])
        self.assertEqual(self.fstab.read_text(), original)

    def test_restart_preparation_prunes_only_removed_entries_and_does_not_mount_additions(self):
        self.execute([self.share('keep', True), self.share('remove')])
        local_file = self.share_home / 'remove/work.txt'
        local_file.write_text('open guest work')
        self.calls.clear()
        with local_file.open() as opened:
            result = self.execute([self.share('keep', True), self.share('add')], prepare_restart=True)
            self.assertEqual(opened.read(), 'open guest work')
        self.assertEqual(result, {'prepared_for_restart': True, 'retained_mounts': 1})
        self.assertIn('lemshare_keep', self.fstab.read_text())
        self.assertNotIn('lemshare_remove', self.fstab.read_text())
        self.assertNotIn('lemshare_add', self.fstab.read_text())
        self.assertFalse((self.share_home / 'add').exists())
        self.assertEqual(local_file.read_text(), 'open guest work')
        self.assertTrue(all(call == ('systemctl', 'daemon-reload') for call in self.calls))

    def test_restart_preparation_prunes_changed_readonly_mode_without_touching_files(self):
        self.execute([self.share()])
        self.calls.clear()
        result = self.execute([self.share(readonly=True)], prepare_restart=True)
        self.assertEqual(result['retained_mounts'], 0)
        self.assertEqual(self.fstab.read_text(), 'UUID=native-root / ext4 defaults 0 1\n')
        self.assertTrue((self.share_home / 'project').is_dir())
        self.assertTrue(all(call == ('systemctl', 'daemon-reload') for call in self.calls))

    def test_default_workspace_sets_shared_ssh_umask_and_removal_restores_pam(self):
        original = self.pam.read_text()
        self.execute([self.share('workspace')], shared_workspace=True)
        self.assertIn('user != debian', self.pam.read_text())
        self.assertIn('pam_umask.so umask=000', self.pam.read_text())
        self.assertTrue(self.pam.read_text().startswith(original))
        before = self.pam.read_bytes()
        self.execute([self.share('workspace')], shared_workspace=True)
        self.assertEqual(self.pam.read_bytes(), before)
        self.execute([])
        self.assertEqual(self.pam.read_text(), original)

    def test_no_shares_never_creates_directories_or_changes_home_permissions(self):
        self.home.chmod(0o700)
        before = list(self.home.iterdir())
        self.execute([])
        self.assertEqual(list(self.home.iterdir()), before)
        self.assertEqual(self.home.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.fstab.read_text(), 'UUID=native-root / ext4 defaults 0 1\n')
        self.assertFalse(self.calls)


if __name__ == '__main__':
    unittest.main()
