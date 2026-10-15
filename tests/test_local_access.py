"""Same-host UID authorization, key ownership and the real Unix transport."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import pwd
import socket
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid

from vm.config import write_private_json
from vm.local_access import LocalAccess, _request, discover, listener, peer_uid, register, serve_connection, socket_path
from vm.state import ProfileState


class LocalAccessTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='lemon-local-access-')
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name)
        self.user = pwd.getpwuid(os.getuid())
        self.vm = SimpleNamespace(state=self.state, profile='local-test-' + uuid.uuid4().hex[:8],
                                  profile_state=ProfileState(self.state))
        self.keys = []
        self.public = self.key('member')
        self.other = self.key('other')
        self.invitation = {'version': 1, 'host': '127.0.0.1', 'port': 2222,
                           'username': 'debian', 'host_key': self.public}
        write_private_json(self.state / 'guest.json', {'profile': {'hostname': 'lemonbox'}})
        self.native = Mock()
        self.native.invitation.return_value = self.invitation
        self.native.listkeys.side_effect = lambda: list(self.keys)
        self.native.add.side_effect = self.add_key
        self.native.revoke.side_effect = lambda name: self.keys.__setitem__(
            slice(None), [entry for entry in self.keys if entry['name'] != name])
        replacement = patch('vm.local_access.Access', return_value=self.native)
        replacement.start()
        self.addCleanup(replacement.stop)
        self.manager = LocalAccess(self.vm)

    def key(self, name):
        path = self.state / name
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(path)], check=True)
        return ' '.join(path.with_suffix('.pub').read_text().split()[:2])

    def add_key(self, name, key):
        existing = next((entry for entry in self.keys if entry['name'] == name), None)
        if existing:
            self.assertEqual(existing['public_key'], key)
        else:
            self.keys.append({'name': name, 'public_key': key})

    @contextmanager
    def server(self):
        stopped = threading.Event()
        with listener(self.vm) as server:
            server.settimeout(0.02)
            def run():
                while not stopped.is_set():
                    try:
                        client, _ = server.accept()
                    except socket.timeout:
                        continue
                    serve_connection(self.vm, client)
            worker = threading.Thread(target=run)
            worker.start()
            try:
                yield
            finally:
                stopped.set()
                worker.join(timeout=6)
                self.assertFalse(worker.is_alive())

    def test_grant_records_native_uid_and_rejects_reused_username(self):
        self.assertEqual(self.manager.grant(self.user.pw_name),
                         {'username': self.user.pw_name, 'uid': os.getuid()})
        self.assertEqual(self.manager.users(), [{'username': self.user.pw_name, 'uid': os.getuid()}])
        self.assertEqual((self.state / 'local-users.json').stat().st_mode & 0o777, 0o600)
        write_private_json(self.state / 'local-users.json', {self.user.pw_name: os.getuid() + 1})
        with self.assertRaisesRegex(ValueError, 'different UID'):
            self.manager.grant(self.user.pw_name)
        with self.assertRaisesRegex(ValueError, 'not granted'):
            self.manager.info(os.getuid())

    def test_actual_peer_authenticated_discovery_register_rotation_and_revoke(self):
        self.manager.grant(self.user.pw_name)
        with self.server():
            entries = [entry for entry in discover() if entry['profile'] == self.vm.profile]
            self.assertEqual(len(entries), 1)
            entry = entries[0]
            self.assertEqual(entry['owner_uid'], os.getuid())
            self.assertEqual(entry['invitation'], self.invitation)
            self.assertEqual(entry['hostname'], 'lemonbox')
            self.assertEqual(register(entry, self.public), entry)
            self.assertEqual(register(entry, self.public), entry)
            self.assertEqual(len(self.keys), 1)
            register(entry, self.other)
            self.assertEqual(self.keys, [{'name': 'local:' + self.user.pw_name + ':' + str(os.getuid()),
                                         'public_key': self.other}])
            self.manager.revoke(self.user.pw_name)
            self.assertEqual(self.keys, [])
            with self.assertRaisesRegex(ValueError, 'grant your Linux username'):
                register(entry, self.public)
            self.assertFalse(any(item['profile'] == self.vm.profile for item in discover()))
        self.assertFalse(socket_path(os.getuid(), self.vm.profile).exists())

    def test_kernel_identity_cannot_be_overridden_in_request(self):
        self.manager.grant(self.user.pw_name)
        with self.server():
            entry = next(entry for entry in discover() if entry['profile'] == self.vm.profile)
            with self.assertRaisesRegex(ValueError, 'Could not join'):
                _request(entry, {'action': 'register', 'public_key': self.public, 'username': 'root'}, 2)
            self.assertEqual(self.keys, [])
            for hostname in ('lemonbox\nOwner: root', '\x1b[2Jlemonbox', 'x' * 64):
                with self.subTest(hostname=repr(hostname)):
                    write_private_json(self.state / 'guest.json', {'profile': {'hostname': hostname}})
                    with self.assertRaisesRegex(ValueError, 'hostname'):
                        _request(entry, {'action': 'info'}, 2)
                    self.assertFalse(any(item['profile'] == self.vm.profile for item in discover()))
            self.manager.path.unlink()
            with self.assertRaisesRegex(ValueError, 'Could not join'):
                _request(entry, {'action': 'register', 'public_key': self.public}, 2)
            self.assertEqual(self.keys, [])

    def test_additional_keys_preserve_join_identity_and_are_revoked_with_user(self):
        self.manager.grant(self.user.pw_name)
        third = self.key('third')
        with self.server():
            entry = next(entry for entry in discover() if entry['profile'] == self.vm.profile)
            register(entry, self.public)
            original = dict(self.keys[0])
            self.assertEqual(register(entry, self.other, additional=True), entry)
            register(entry, third, additional=True)
            before = list(self.keys)
            register(entry, self.other, additional=True)
            register(entry, self.public, additional=True)
            register(entry, self.public)
            self.assertEqual(self.keys, before)
            self.assertEqual(self.keys[0], original)
            self.assertEqual({key['public_key'] for key in self.keys}, {self.public, self.other, third})
            self.manager.revoke(self.user.pw_name)
            self.assertEqual(self.keys, [])
            with self.assertRaisesRegex(ValueError, 'grant your Linux username'):
                register(entry, self.other, additional=True)

    def test_additional_key_cannot_take_over_another_connections_key(self):
        self.manager.grant(self.user.pw_name)
        self.manager.register(os.getuid(), self.public)
        self.keys.append({'name': 'Another person', 'public_key': self.other})
        before = list(self.keys)
        with self.assertRaisesRegex(ValueError, 'another guest connection'):
            self.manager.register(os.getuid(), self.other, additional=True)
        self.assertEqual(self.keys, before)

    def test_additional_keys_are_grouped_under_their_local_user(self):
        from vm.cli import access_people
        self.manager.grant(self.user.pw_name)
        self.manager.register(os.getuid(), self.public)
        self.manager.register(os.getuid(), self.other, additional=True)
        with patch('vm.access.Access', return_value=self.native):
            self.assertEqual(access_people(self.vm), [
                {'name': self.user.pw_name, 'kind': 'local', 'id': self.user.pw_name}])
            write_private_json(self.manager.path, {})
            self.assertEqual({person['kind'] for person in access_people(self.vm)}, {'unregistered'})
        self.manager.revoke(self.user.pw_name)
        self.assertEqual(self.keys, [])

    def test_native_peer_credentials_and_wrong_server_uid_rejection(self):
        local, peer = socket.socketpair()
        with local, peer:
            self.assertEqual(peer_uid(local), os.getuid())
        self.manager.grant(self.user.pw_name)
        with self.server():
            entry = next(entry for entry in discover() if entry['profile'] == self.vm.profile)
            with patch('vm.local_access.peer_uid', return_value=os.getuid() + 1), \
                    self.assertRaisesRegex(ValueError, 'another user'):
                _request(entry, {'action': 'info'}, 2)

    def test_endpoint_symlink_and_writable_directory_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = directory / 'vm.sock'
            target = directory / 'target'
            target.write_text('do not change')
            path.symlink_to(target)
            entry = {'owner_uid': os.getuid(), 'profile': 'vm', 'socket': str(path)}
            with patch('vm.local_access.socket_path', return_value=path), self.assertRaises(ValueError):
                _request(entry, {'action': 'info'}, 2)
            self.assertEqual(target.read_text(), 'do not change')
            path.unlink()
            directory.chmod(0o777)
            with patch('vm.local_access.socket_path', return_value=path), self.assertRaisesRegex(ValueError, 'not writable'):
                _request(entry, {'action': 'info'}, 2)

    def test_registration_endpoint_is_public_under_private_cli_umask(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'public' / 'vm.sock'
            previous = os.umask(0o077)
            try:
                with patch('vm.local_access.socket_path', return_value=path), listener(self.vm):
                    self.assertEqual(path.parent.stat().st_mode & 0o777, 0o755)
                    self.assertEqual(path.stat().st_mode & 0o777, 0o666)
            finally:
                os.umask(previous)

    def test_registration_and_revocation_serialize_without_key_reappearing(self):
        self.manager.grant(self.user.pw_name)
        entered, release = threading.Event(), threading.Event()
        original = self.native.add.side_effect
        def delayed(name, key):
            entered.set()
            self.assertTrue(release.wait(timeout=3))
            original(name, key)
        self.native.add.side_effect = delayed
        registration = threading.Thread(target=self.manager.register, args=(os.getuid(), self.public))
        registration.start()
        self.assertTrue(entered.wait(timeout=3))
        revocation = threading.Thread(target=self.manager.revoke, args=(self.user.pw_name,))
        revocation.start()
        release.set()
        registration.join(timeout=3)
        revocation.join(timeout=3)
        self.assertFalse(registration.is_alive() or revocation.is_alive())
        self.assertEqual(self.manager.users(), [])
        self.assertEqual(self.keys, [])
        with self.assertRaisesRegex(ValueError, 'not granted'):
            self.manager.register(os.getuid(), self.public)

    def test_failed_key_removal_keeps_enrollment_revoked_and_cleanup_can_retry(self):
        self.manager.grant(self.user.pw_name)
        self.manager.register(os.getuid(), self.public)
        self.native.revoke.side_effect = RuntimeError('Guest SSH unavailable')
        with self.assertRaisesRegex(RuntimeError, 'enrollment is blocked.*key removal failed'):
            self.manager.revoke(self.user.pw_name)
        self.assertEqual(self.manager.users(), [])
        self.assertEqual(len(self.keys), 1)
        with self.assertRaisesRegex(ValueError, 'not granted'):
            self.manager.register(os.getuid(), self.other)
        self.native.revoke.side_effect = lambda name: self.keys.__setitem__(
            slice(None), [entry for entry in self.keys if entry['name'] != name])
        self.manager.revoke(self.user.pw_name)
        self.assertEqual(self.keys, [])

    def test_oversized_and_extra_requests_never_change_keys(self):
        self.manager.grant(self.user.pw_name)
        with self.server():
            for payload in (b'{' + b'x' * 32768, b'{"action":"info"}\n{"action":"info"}\n'):
                with self.subTest(payload=payload[:30]), socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.settimeout(2)
                    client.connect(str(socket_path(os.getuid(), self.vm.profile)))
                    client.sendall(payload)
                    self.assertIn('error', json.loads(client.recv(32768)))
            self.assertEqual(self.keys, [])


if __name__ == '__main__':
    unittest.main()
