"""Real POSIX ACLs keep host workspaces usable behind each VM's access gate."""
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from vm.config import Config
from vm.local_access import LocalAccess
from vm.state import ProfileState
from vm import workspace_access


@unittest.skipUnless(shutil.which('setfacl') and shutil.which('getfacl'), 'POSIX ACL tools are unavailable')
class WorkspaceAccessTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='lemon-workspace-acl-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.checkout = self.root / 'checkout'
        self.source = self.checkout / 'workspaces/default'
        self.source.mkdir(parents=True, mode=0o700)
        self.state = self.root / 'state'
        self.state.mkdir(mode=0o700)
        self.vm = SimpleNamespace(state=self.state, profile='default', profile_state=ProfileState(self.state))
        Config.from_dict({'version': 1, 'shares': [{'name': 'workspace', 'source': str(self.source)}]}).write(
            self.state / 'config.json')
        replacement = patch.object(workspace_access, 'ROOT', self.checkout)
        replacement.start()
        self.addCleanup(replacement.stop)
        self.uid = os.getuid() + 10000

    def acl(self, path):
        return subprocess.run(['getfacl', '-cpn', str(path)], text=True, capture_output=True, check=True).stdout

    def test_access_is_gated_at_root_and_new_files_inherit_shared_permissions(self):
        workspace_access.sync_workspace_access(self.vm, [{'uid': self.uid}])
        self.assertIn('user:' + str(self.uid) + ':rwx', self.acl(self.source))
        self.assertIn('other::---', self.acl(self.source))
        self.assertIn('user:' + str(self.uid) + ':--x', self.acl(self.source.parent))
        self.assertEqual(stat.S_IMODE(self.source.stat().st_mode) & 0o007, 0)
        previous = os.umask(0o077)
        try:
            child = self.source / 'project'
            child.mkdir()
            file = child / 'file.txt'
            file.write_text('shared')
        finally:
            os.umask(previous)
        self.assertEqual(stat.S_IMODE(child.stat().st_mode), 0o777)
        self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o666)
        workspace_access.sync_workspace_access(self.vm, [{'uid': self.uid + 1}])
        self.assertNotIn('user:' + str(self.uid) + ':', self.acl(self.source))
        self.assertIn('user:' + str(self.uid + 1) + ':rwx', self.acl(self.source))
        workspace_access.sync_workspace_access(self.vm, [])
        self.assertEqual(stat.S_IMODE(self.source.stat().st_mode), 0o700)

    def test_existing_private_tree_is_shared_without_following_symlinks(self):
        child = self.source / 'project'
        child.mkdir(mode=0o700)
        file = child / 'data'
        file.write_text('existing data')
        file.chmod(0o600)
        executable = child / 'script'
        executable.write_text('executable')
        executable.chmod(0o700)
        private = self.root / 'outside'
        private.write_text('private')
        private.chmod(0o600)
        (child / 'link').symlink_to(private)
        workspace_access.sync_workspace_access(self.vm, [{'uid': self.uid}])
        self.assertEqual(stat.S_IMODE(child.stat().st_mode), 0o777)
        self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o666)
        self.assertEqual(stat.S_IMODE(executable.stat().st_mode), 0o777)
        self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o600)
        (child / 'later').write_text('new data')
        self.assertEqual(stat.S_IMODE((child / 'later').stat().st_mode), 0o666)

    def test_revocation_closes_host_access_even_when_guest_ssh_is_unavailable(self):
        manager = LocalAccess(self.vm)
        with patch('vm.local_access.pwd.getpwnam', return_value=SimpleNamespace(pw_uid=self.uid)):
            manager.grant('colleague')
        self.assertIn('user:' + str(self.uid) + ':rwx', self.acl(self.source))
        native = Mock()
        native.listkeys.side_effect = RuntimeError('guest unavailable')
        with patch('vm.local_access.Access', return_value=native), \
                self.assertRaisesRegex(RuntimeError, 'SSH key removal failed'):
            manager.revoke('colleague')
        self.assertEqual(manager.users(), [])
        self.assertNotIn('user:' + str(self.uid) + ':', self.acl(self.source))

    def test_failed_host_grant_rolls_back_local_approval(self):
        manager = LocalAccess(self.vm)
        user = pwd.getpwuid(os.getuid())
        with patch('vm.local_access.sync_workspace_access', side_effect=RuntimeError('ACL unavailable')), \
                self.assertRaisesRegex(RuntimeError, 'ACL unavailable'):
            manager.grant(user.pw_name)
        self.assertEqual(manager.users(), [])
