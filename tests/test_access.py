"""Native SSH authorization and real localhost relay behavior without a VM."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import pwd
import socket
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from vm import cli
from vm.access import Access, Relay, _process, forward_connection, parse_public_key, validate_invitation
from vm.config import write_private_json
from vm.local_access import LocalAccess
from vm.state import ProfileState


class AccessTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='lemon-access-test-')
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name)
        (self.state / 'ssh').mkdir(mode=0o700)
        self.owner_key = self.key(self.state / 'ssh/id_ed25519')
        self.member_key = self.key(self.state / 'member')
        self.other_key = self.key(self.state / 'other')
        self.vm = SimpleNamespace(state=self.state, profile='access-test', profile_state=ProfileState(self.state),
                                  gateway='lemonbox-gateway')
        write_private_json(self.state / 'guest.json', {'profile': {'username': 'debian', 'hostname': 'lemonbox', 'guest_ip': '10.77.0.2', 'ssh_port': 2222},
                                                     'guest_host_public_key': self.owner_key})
        self.guest = self.state / 'guest-home'
        self.guest.mkdir(mode=0o700)
        (self.guest / '.ssh').mkdir(mode=0o700)
        self.authorized = self.guest / '.ssh/authorized_keys'
        self.original = self.owner_key + ' owner\nno-agent-forwarding ' + self.other_key + ' existing\n# comment\n'
        self.authorized.write_text(self.original)
        self.authorized.chmod(0o600)
        self.workflow = Mock()
        self.workflow.run_script.side_effect = self.run_guest
        workflow = patch('vm.workflows.Workflow', return_value=self.workflow)
        workflow.start()
        self.addCleanup(workflow.stop)

    @staticmethod
    def key(path):
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(path)], check=True)
        return parse_public_key(path.with_suffix('.pub').read_text())['key']

    def run_guest(self, source, **kwargs):
        output = io.StringIO()
        with patch.object(Path, 'home', return_value=self.guest), redirect_stdout(output), \
                patch.object(sys, 'argv', ['authorized_keys.py', *kwargs['args']]):
            try:
                exec(compile(source, 'authorized_keys.py', 'exec'), {'__name__': '__main__'})
            except SystemExit as error:
                return subprocess.CompletedProcess([], error.code, output.getvalue(), '')
            except Exception as error:
                return subprocess.CompletedProcess([], 1, output.getvalue(), str(error))
        return subprocess.CompletedProcess([], 0, output.getvalue(), '')

    def test_add_list_revoke_preserves_owner_and_unmanaged_native_entries(self):
        access = Access(self.vm)
        name = 'Alice\'s "laptop"'
        result = access.add(name, self.member_key + ' member-comment')
        self.assertEqual(result[0]['name'], name)
        self.assertEqual(result[0]['public_key'], self.member_key)
        self.assertRegex(result[0]['fingerprint'], r'^SHA256:')
        self.assertEqual(access.listkeys(), result)
        self.assertEqual(self.authorized.stat().st_mode & 0o777, 0o600)
        self.assertIn(self.original, self.authorized.read_text())
        self.assertEqual(access.revoke(name), [])
        self.assertEqual(self.authorized.read_text(), self.original)

    def test_named_add_is_idempotent_but_rename_conflicts_are_actionable(self):
        access = Access(self.vm)
        first = access.add('Alice', self.member_key)
        content = self.authorized.read_bytes()
        self.assertEqual(access.add('Alice', self.member_key), first)
        self.assertEqual(self.authorized.read_bytes(), content)
        with self.assertRaisesRegex(ValueError, 'another key'):
            access.add('Alice', self.other_key)
        with self.assertRaisesRegex(ValueError, 'another name'):
            access.add('Bob', self.member_key)
        self.assertEqual(self.authorized.read_bytes(), content)

    def test_owner_and_preexisting_unmanaged_keys_cannot_be_given_revokeable_names(self):
        access = Access(self.vm)
        with self.assertRaisesRegex(ValueError, 'owner access key'):
            access.add('Owner', self.owner_key)
        with self.assertRaisesRegex(ValueError, 'already authorized outside'):
            access.add('Existing', self.other_key)
        with self.assertRaisesRegex(ValueError, 'No managed key'):
            access.revoke('Missing')
        self.assertEqual(self.authorized.read_text(), self.original)

    def test_managed_owner_marker_never_authorizes_owner_revocation(self):
        self.authorized.write_text(self.owner_key + ' lemonbox-access:Owner\n')
        with self.assertRaisesRegex(ValueError, 'owner access key cannot be revoked'):
            Access(self.vm).revoke('Owner')
        self.assertIn(self.owner_key, self.authorized.read_text())

    def test_failed_guest_ssh_does_not_create_a_host_key_registry_or_claim_success(self):
        self.workflow.run_script.side_effect = None
        for stderr in ('SSH refused', 'This name already belongs to another key'):
            with self.subTest(stderr=stderr):
                self.workflow.run_script.return_value = subprocess.CompletedProcess([], 255, '', stderr)
                with self.assertRaisesRegex(RuntimeError, 'lemonbox start'):
                    Access(self.vm).add('Alice', self.member_key)
        self.assertFalse((self.state / 'access.json').exists())
        self.assertEqual(self.authorized.read_text(), self.original)

    def test_guest_error_code_does_not_depend_on_message_wording(self):
        self.workflow.run_script.side_effect = None
        failure = {'error': 'name_conflict', 'message': 'Choose another collaborator name'}
        self.workflow.run_script.return_value = subprocess.CompletedProcess([], 2, json.dumps(failure), '')
        with self.assertRaisesRegex(ValueError, 'Choose another collaborator name'):
            Access(self.vm).add('Alice', self.member_key)
        self.assertEqual(self.authorized.read_text(), self.original)

    def test_local_guide_grants_username_then_registration_and_removal_preserve_owner(self):
        username = pwd.getpwuid(os.getuid()).pw_name
        output = io.StringIO()
        with patch.object(cli.sys.stdin, 'isatty', return_value=True), \
                patch.object(cli, 'repair_access') as repair, patch('vm.access.Relay') as relay, \
                patch.object(cli, '_answer', side_effect=['1', username]), \
                patch.object(cli, '_confirm', return_value=True), \
                redirect_stdout(output), redirect_stderr(io.StringIO()):
            self.assertEqual(cli.access_command(self.vm, cli.parse_arguments(['--profile', 'default', 'access'])), 0)
        repair.assert_called_once_with(self.vm)
        relay.return_value.start.assert_called_once()
        self.assertTrue(Access(self.vm).settings()['enabled'])
        self.assertEqual(LocalAccess(self.vm).users(), [{'username': username, 'uid': os.getuid()}])
        self.assertEqual(self.authorized.read_text(), self.original)
        self.assertIn('lemonbox join', output.getvalue())
        self.assertNotIn('VM fingerprint', output.getvalue())
        self.assertNotIn('host_key', output.getvalue())
        self.assertNotIn('OPENSSH PRIVATE KEY', output.getvalue())
        LocalAccess(self.vm).register(os.getuid(), self.member_key)
        with patch.object(cli.sys.stdin, 'isatty', return_value=True), \
                patch.object(cli, 'repair_access'), \
                patch.object(cli, '_answer', side_effect=['3', '1']), \
                patch.object(cli, '_confirm', return_value=True), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(cli.access_command(self.vm, cli.parse_arguments(['--profile', 'default', 'access'])), 0)
        self.assertEqual(self.authorized.read_text(), self.original)
        self.assertEqual(LocalAccess(self.vm).users(), [])

    def test_remote_guide_keeps_connection_details_separate_and_allows_deferred_approval(self):
        output = io.StringIO()
        with patch.object(cli.sys.stdin, 'isatty', return_value=True), \
                patch.object(cli, 'repair_access'), patch('vm.access.Relay') as relay, \
                patch.object(cli, '_answer', side_effect=['4', '']), \
                redirect_stdout(output), redirect_stderr(io.StringIO()):
            self.assertEqual(cli.access_command(self.vm, cli.parse_arguments(['--profile', 'default', 'access'])), 0)
        relay.return_value.start.assert_called_once()
        self.assertTrue(Access(self.vm).settings()['enabled'])
        self.assertEqual(self.authorized.read_text(), self.original)
        self.assertIn('1. Send connection details', output.getvalue())
        self.assertIn('2. Approve their public key', output.getvalue())
        self.assertIn('Return to Remote access', output.getvalue())

    def test_stopping_sharing_requires_confirmation_and_retains_authorized_keys(self):
        manager = Access(self.vm)
        manager.enable()
        manager.add('Alice', self.member_key)
        content = self.authorized.read_bytes()
        for confirmed in (False, True):
            with self.subTest(confirmed=confirmed), patch.object(cli.sys.stdin, 'isatty', return_value=True), \
                    patch('vm.access.Relay') as relay, patch.object(cli, '_answer', return_value='5'), \
                    patch.object(cli, '_confirm', return_value=confirmed), \
                    redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(cli.access_command(self.vm, cli.parse_arguments(['--profile', 'default', 'access'])), 0)
            self.assertEqual(manager.settings()['enabled'], not confirmed)
            self.assertEqual(self.authorized.read_bytes(), content)
            self.assertEqual(relay.return_value.stop.call_count, int(confirmed))

    def test_public_invitation_has_only_native_ssh_connection_information(self):
        access = Access(self.vm)
        access.enable()
        invitation = access.invitation()
        self.assertEqual(set(invitation), {'version', 'host', 'port', 'username', 'host_key'})
        self.assertEqual((invitation['host'], invitation['port'], invitation['username']), ('127.0.0.1', 2222, 'debian'))
        self.assertNotIn(str(self.state), json.dumps(invitation))
        self.assertNotIn('private', json.dumps(invitation))
        self.assertEqual((self.state / 'access.json').stat().st_mode & 0o777, 0o600)

    def test_default_relay_port_uses_this_vms_allocated_endpoint(self):
        write_private_json(self.state / 'guest.json', {'profile': {'username': 'debian',
                                                                 'guest_ip': '10.77.0.6', 'ssh_port': 2223},
                                                      'guest_host_public_key': self.owner_key})
        access = Access(self.vm)
        self.assertEqual(access.settings()['port'], 2223)
        access.enable()
        self.assertEqual(access.invitation()['port'], 2223)

    def test_invalid_guest_endpoint_cannot_silently_forward_to_default_guest(self):
        write_private_json(self.state / 'guest.json', {'profile': {'username': 'debian',
                                                                 'guest_ip': '10.77.0.5', 'ssh_port': 2223}})
        with self.assertRaisesRegex(ValueError, 'invalid allocated SSH endpoint'):
            Access(self.vm).settings()

    def test_public_key_validation_rejects_private_material_and_option_injection(self):
        for text in ((self.state / 'member').read_text(), 'command="sh" ' + self.member_key,
                     self.member_key + '\n' + self.other_key, 'ssh-ed25519 AAAA'):
            with self.subTest(text=text[:16]), self.assertRaises(ValueError):
                parse_public_key(text)
        data = {'version': 1, 'host': '127.0.0.1', 'port': 2222, 'username': 'debian', 'host_key': self.member_key}
        for override in ({'host': 'x\nProxyCommand sh'}, {'port': True}, {'username': '-oProxyCommand=x'},
                         {'password': 'fixture-not-allowed'}):
            with self.subTest(override=override), self.assertRaises(ValueError):
                validate_invitation(data | override)

    def test_guest_authorized_key_symlink_cannot_overwrite_another_file(self):
        target = self.guest / 'other-file'
        target.write_text('do not modify')
        self.authorized.unlink()
        self.authorized.symlink_to(target)
        with self.assertRaises(RuntimeError):
            Access(self.vm).add('Alice', self.member_key)
        self.assertEqual(target.read_text(), 'do not modify')


class RelayTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='lemon-relay-test-')
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name)
        self.vm = SimpleNamespace(state=self.state, profile='relay-test', profile_state=ProfileState(self.state),
                                  gateway='lemonbox-gateway')
        write_private_json(self.state / 'guest.json', {'profile': {'username': 'debian',
                                                                'guest_ip': '10.77.0.6', 'ssh_port': 2223}})
        self.relay = Relay(self.vm)
        self.addCleanup(self.relay.stop)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            self.port = listener.getsockname()[1]
        commands = self.state / 'commands'
        commands.mkdir(mode=0o700)
        binary = commands / 'podman'
        binary.write_text('''#!/usr/bin/env python3
import json,os,pathlib,sys
path=pathlib.Path(os.environ['LEMON_TEST_RELAY_CHILD'])
ticks=int(pathlib.Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19])
path.write_text(json.dumps({'pid':os.getpid(),'ticks':ticks,'argv':sys.argv[1:]}))
os.write(1,b'SSH-2.0-test-relay\\r\\n')
while data:=os.read(0,65536):
    os.write(1,data)
''')
        binary.chmod(0o700)
        environment = patch.dict(os.environ, {'PATH': str(commands) + ':' + os.environ['PATH'],
                                              'LEMON_TEST_RELAY_CHILD': str(self.state / 'forwarder.json')})
        environment.start()
        self.addCleanup(environment.stop)

    def test_disabled_access_does_not_launch_any_relay(self):
        self.assertFalse(self.relay.start())
        self.assertFalse((self.state / 'access-relay.json').exists())

    def test_actual_localhost_relay_transfers_ssh_bytes_and_stops_with_open_client(self):
        Access(self.vm).enable(self.port)
        self.assertTrue(self.relay.start())
        before = json.loads((self.state / 'access-relay.json').read_text())
        self.assertTrue(self.relay.start())
        self.assertEqual(json.loads((self.state / 'access-relay.json').read_text()), before)
        client = socket.create_connection(('127.0.0.1', self.port), timeout=5)
        self.addCleanup(client.close)
        banner = client.recv(1024)
        self.assertEqual(banner, b'SSH-2.0-test-relay\r\n')
        payload = b'opaque-ssh-bytes\0' * 128
        client.sendall(payload)
        echoed = b''
        while len(echoed) < len(payload):
            echoed += client.recv(len(payload) - len(echoed))
        self.assertEqual(echoed, payload)
        child = json.loads((self.state / 'forwarder.json').read_text())
        self.assertEqual(child['argv'], ['exec', '-i', self.vm.gateway, 'nc', '-N', '10.77.0.6', '22'])
        self.assertTrue(self.relay.stop())
        self.assertFalse(self.relay.running())
        self.assertFalse((self.state / 'access-relay.json').exists())
        current = _process(child['pid'])
        self.assertTrue(current is None or current['ticks'] != child['ticks'], 'Forwarding process must be reaped')
        self.assertEqual(client.recv(1), b'')
        with self.assertRaises(OSError):
            socket.create_connection(('127.0.0.1', self.port), timeout=0.2)

    def test_an_unrelated_live_pid_in_stale_state_is_never_signaled(self):
        process = _process(os.getpid())
        write_private_json(self.state / 'access-relay.json', {'pid': os.getpid(), 'start_ticks': process['ticks'],
                                                            'nonce': 'a' * 32, 'port': self.port})
        with patch('vm.access.os.kill') as kill:
            self.assertTrue(self.relay.stop())
        kill.assert_not_called()
        self.assertFalse((self.state / 'access-relay.json').exists())

    def test_busy_port_is_actionable_and_never_replaces_the_listener(self):
        Access(self.vm).enable(self.port)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', self.port))
            listener.listen()
            with self.assertRaisesRegex(RuntimeError, 'unused port'):
                self.relay.start()
            self.assertEqual(listener.getsockname(), ('127.0.0.1', self.port))
        self.assertFalse((self.state / 'access-relay.json').exists())

    def test_accepted_connection_queued_at_shutdown_never_starts_a_forwarder(self):
        local, peer = socket.socketpair()
        self.addCleanup(local.close)
        self.addCleanup(peer.close)
        mutex = threading.Lock()
        shutdown = threading.Event()
        children = set()
        marker = self.state / 'unexpected-forwarder'
        command = [sys.executable, '-c', 'from pathlib import Path; Path(' + repr(str(marker)) + ').write_text("started")']
        mutex.acquire()
        worker = threading.Thread(target=forward_connection, args=(local, command),
                                  kwargs={'processes': children, 'process_lock': mutex, 'stop_event': shutdown})
        worker.start()
        shutdown.set()
        mutex.release()
        worker.join(timeout=5)
        self.assertFalse(worker.is_alive())
        self.assertFalse(marker.exists())
        self.assertEqual(children, set())
        self.assertEqual(peer.recv(1), b'')


if __name__ == '__main__':
    unittest.main()
