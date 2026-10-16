"""SSH-only clients preserve native transport and cannot enter owner controls."""
import contextlib
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from vm import cli
from vm.access import parse_public_key
from vm.connections import Connection, RemoteWorkflow


class ConnectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='lemon-client-test-')
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.home_patch = patch.object(Path, 'home', return_value=self.home)
        self.home_patch.start()
        self.addCleanup(self.home_patch.stop)
        self.identity = self.home / 'identity-key'
        self.host = self.home / 'host-key'
        for path in (self.identity, self.host):
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(path)], check=True)
        self.invitation = {'version': 1, 'host': 'localhost', 'port': 2223, 'username': 'debian',
                           'host_key': parse_public_key(self.host.with_suffix('.pub').read_text())['key']}
        self.connection = Connection.create('shared', self.invitation, self.identity)

    def test_metadata_and_derived_files_are_private_outside_vm_state(self):
        self.assertEqual(self.connection.state, self.home / '.local/share/lemonbox/connections/shared')
        for name in ('connection.json', 'known_hosts', 'ssh-config'):
            self.assertEqual((self.connection.state / name).stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.connection.state.stat().st_mode & 0o777, 0o700)
        data = json.loads((self.connection.state / 'connection.json').read_text())
        self.assertEqual(set(data), {'version', 'host', 'port', 'username', 'host_key', 'identity'})
        self.assertNotIn('OPENSSH PRIVATE KEY', json.dumps(data))

    def test_native_config_pins_exact_invited_key_without_proxycommand(self):
        config = self.connection.ssh_config().read_text()
        self.assertIn('StrictHostKeyChecking yes', config)
        self.assertIn('GlobalKnownHostsFile /dev/null', config)
        self.assertIn('HostKeyAlias "lemonbox-connection-shared"', config)
        self.assertIn('Port "2223"', config)
        self.assertNotIn('ProxyCommand', config)
        self.assertNotIn('podman', config)
        self.assertEqual((self.connection.state / 'known_hosts').read_text(),
                         'lemonbox-connection-shared ' + self.invitation['host_key'] + '\n')

    def test_symlink_private_identity_and_generated_file_are_rejected(self):
        alias = self.home / 'alias'
        alias.symlink_to(self.identity)
        with self.assertRaisesRegex(ValueError, 'private regular file'):
            Connection.create('unsafe', self.invitation, alias)
        known = self.connection.state / 'known_hosts'
        known.unlink()
        known.symlink_to(self.home / 'unrelated')
        with self.assertRaisesRegex(ValueError, 'symlinks'):
            self.connection.ssh_config()

    def test_claude_native_arguments_and_stdin_transport_are_reused(self):
        workflow = RemoteWorkflow(self.connection, workdir='/home/debian/a b')
        with patch('vm.workflows.subprocess.run', return_value=subprocess.CompletedProcess([], 37)) as run:
            self.assertEqual(workflow.claude(['--print', "a'b", '$HOME']), 37)
        argv = shlex.split(run.call_args.args[0][-1])
        self.assertEqual(argv[:2], ['/bin/bash', '-lc'])
        self.assertIn("/home/debian/a b", shlex.split(argv[2]))
        self.assertNotIn('stdin', run.call_args.kwargs)
        self.assertFalse(run.call_args.kwargs['capture_output'])

    def test_selected_client_claude_never_constructs_vm_or_refreshes_kvm(self):
        cli.select_connection('shared')
        workflow = MagicMock()
        workflow.claude.return_value = 9
        with patch.object(cli, 'VM') as vm, \
                patch('vm.connections.RemoteWorkflow', return_value=workflow):
            self.assertEqual(cli.main(['claude', '--version']), 9)
        vm.assert_not_called()
        workflow.claude.assert_called_once_with(['--version'])

    def test_joined_status_displays_on_demand_gateway_alert(self):
        alert = {'status': 'active', 'reason': 'The fixed route needs attention.'}
        cli.select_connection('shared')
        with patch.object(Connection, 'reachable', return_value=True), \
                patch.object(cli, 'connection_alert', return_value=alert), \
                patch('vm.gateway_runtime.run') as backend, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.main(['status']), 0)
        self.assertIn('ALERT: The fixed route needs attention.', output.getvalue())
        backend.assert_not_called()

    def test_joined_exec_warns_on_stderr_without_changing_native_exit(self):
        cli.select_connection('shared')
        workflow = MagicMock()
        workflow.execute.return_value = 29
        with patch('vm.connections.RemoteWorkflow', return_value=workflow), \
                patch.object(cli, 'connection_alert', return_value={'status': 'active', 'reason': 'Gateway recovery needs attention.'}), \
                contextlib.redirect_stderr(io.StringIO()) as output:
            self.assertEqual(cli.main(['exec', '--', 'true']), 29)
        self.assertIn('ALERT: Gateway recovery needs attention.', output.getvalue())
        workflow.execute.assert_called_once_with(['true'])

    def test_joined_mode_hides_owner_help_and_rejects_controls(self):
        cli.select_connection('shared')
        with contextlib.redirect_stdout(io.StringIO()) as output, self.assertRaises(SystemExit):
            cli.parse_arguments(['--help'])
        help_text = output.getvalue()
        for action in ('settings', 'files', 'access', 'desktop', 'start', 'stop', 'setup', 'update'):
            self.assertNotIn('    ' + action + ' ', help_text)
            with patch.object(cli, 'VM') as vm, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main([action]), 1)
            vm.assert_not_called()

    def test_forwarded_native_profile_option_does_not_change_joined_target(self):
        cli.select_connection('shared')
        for arguments in (['claude', '--profile', 'native'], ['exec', '--', 'echo', '--profile', 'native']):
            args = cli.parse_arguments(arguments)
            self.assertEqual(args.connection, 'shared')
            self.assertIn('--profile', args.arguments)
        args = cli.parse_arguments(['--state-dir', 'join', '--profile', 'owner', 'status'])
        self.assertIsNone(args.connection)
        self.assertEqual(args.profile, 'owner')

    def test_explicit_profile_overrides_joined_selection_and_help(self):
        cli.select_connection('shared')
        for option in (['--profile', 'default'], ['--profile=default']):
            args = cli.parse_arguments([*option, 'status'])
            self.assertIsNone(args.connection)
            self.assertEqual(args.profile, 'default')
            with contextlib.redirect_stdout(io.StringIO()) as output, self.assertRaises(SystemExit):
                cli.parse_arguments([*option, '--help'])
            self.assertIn('    access ', output.getvalue())

    def test_first_run_join_does_not_construct_vm(self):
        with patch.object(cli, 'VM') as vm, patch.object(cli.sys.stdin, 'isatty', return_value=True), \
                patch.object(cli, '_answer', return_value='1'), patch.object(cli, 'join_command', return_value=0) as join, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main([]), 0)
        join.assert_called_once()
        vm.assert_not_called()

    def test_noninteractive_join_persists_exact_pin_and_prints_only_public_key(self):
        invitation = self.home / 'invitation.json'
        details = dict(self.invitation, port=2224)
        invitation.write_text(json.dumps(details))
        with patch.object(cli.sys.stdin, 'isatty', return_value=False), patch.object(cli, 'VM') as vm, \
                contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(['join', '--invitation', str(invitation),
                                      '--identity', str(self.identity), '--trust']), 0)
        vm.assert_not_called()
        self.assertIn('ssh-ed25519 ', output.getvalue())
        self.assertNotIn('OPENSSH PRIVATE KEY', output.getvalue())
        self.assertIn('debian@localhost:2224', output.getvalue())
        self.assertEqual(cli.selected_target(), {'kind': 'connection', 'name': 'shared-2'})
        self.assertEqual(Connection.load('shared-2').invitation['host_key'], self.invitation['host_key'])

    def test_remote_join_automatically_saves_connection_and_reuses_generated_identity(self):
        shutil.rmtree(self.connection.state)
        invitation = self.home / 'invitation.json'
        invitation.write_text(json.dumps(self.invitation))
        arguments = ['join', '--invitation', str(invitation)]
        answers = ['', '', '2']
        with patch.object(cli.sys.stdin, 'isatty', return_value=True), \
                patch.object(cli, '_answer', side_effect=answers), patch.object(cli, '_confirm', return_value=True), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(arguments), 0)
        saved = Connection.load('shared')
        identity = saved.identity.read_bytes()
        metadata = (saved.state / 'connection.json').read_bytes()
        cli.select_profile('default')
        with patch.object(cli.sys.stdin, 'isatty', return_value=True), \
                patch.object(cli, '_answer', side_effect=['', '']) as answer, \
                patch.object(cli, '_confirm', return_value=True), \
                patch.object(cli.subprocess, 'run', wraps=subprocess.run) as run, \
                contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(arguments), 0)
        self.assertEqual(answer.call_count, 2)
        self.assertEqual(saved.identity.read_bytes(), identity)
        self.assertEqual((saved.state / 'connection.json').read_bytes(), metadata)
        self.assertEqual(cli.selected_target(), {'kind': 'connection', 'name': 'shared'})
        self.assertEqual(list(saved.state.parent.iterdir()), [saved.state])
        self.assertIn(saved.identity.with_suffix('.pub').read_text().split()[1], output.getvalue())
        for call in run.call_args_list:
            self.assertNotIn('-t', call.args[0])

    def test_repeat_reuses_normalized_pin_and_requires_explicit_identity_to_match(self):
        invitation = self.home / 'invitation.json'
        invitation.write_text(json.dumps(dict(self.invitation, host_key=self.invitation['host_key'] + ' owner-comment')))
        with patch.object(cli.sys.stdin, 'isatty', return_value=False), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(['join', '--invitation', str(invitation),
                                      '--identity', str(self.identity), '--trust']), 0)
            self.assertEqual(cli.selected_target()['name'], 'shared')
            self.assertEqual(cli.main(['join', '--invitation', str(invitation), '--trust']), 0)
            self.assertEqual(cli.selected_target()['name'], 'shared')
            self.assertEqual(cli.main(['join', '--invitation', str(invitation),
                                      '--identity', str(self.host), '--trust']), 0)
        self.assertEqual(cli.selected_target()['name'], 'shared-2')
        self.assertEqual(Connection.load('shared-2').identity, self.host)
        self.assertEqual(Connection.load('shared').identity, self.identity)

    def test_join_never_reuses_different_endpoint_user_or_host_pin(self):
        other_key = parse_public_key(self.identity.with_suffix('.pub').read_text())['key']
        for change in ({'host': '127.0.0.1'}, {'port': 2224}, {'username': 'someone'}, {'host_key': other_key}):
            with self.subTest(change=change):
                self.assertIsNone(Connection.find(dict(self.invitation, **change)))
        invitation = self.home / 'invitation.json'
        invitation.write_text(json.dumps(dict(self.invitation, host_key=other_key)))
        saved = (self.connection.state / 'connection.json').read_bytes()
        pinned = (self.connection.state / 'known_hosts').read_bytes()
        with patch.object(cli.sys.stdin, 'isatty', return_value=False), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(['join', '--name', 'shared', '--invitation', str(invitation),
                                      '--identity', str(self.identity), '--trust']), 1)
        self.assertEqual((self.connection.state / 'connection.json').read_bytes(), saved)
        self.assertEqual((self.connection.state / 'known_hosts').read_bytes(), pinned)

    def test_automatic_label_skips_existing_directory_without_overwriting_it(self):
        reserved = self.connection.state.parent / 'shared-2'
        reserved.mkdir()
        marker = reserved / 'id_ed25519'
        marker.write_text('unfinished key')
        stale = self.connection.state.parent / 'stale'
        stale.mkdir(mode=0o700)
        record = stale / 'connection.json'
        record.write_text(json.dumps(dict(self.invitation, identity=str(self.home / 'missing-key'))))
        record.chmod(0o600)
        stale_data = record.read_bytes()
        invitation = self.home / 'invitation.json'
        invitation.write_text(json.dumps(dict(self.invitation, port=2224)))
        with patch.object(cli.sys.stdin, 'isatty', return_value=False), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(['join', '--invitation', str(invitation),
                                      '--identity', str(self.identity), '--trust']), 0)
        self.assertEqual(cli.selected_target()['name'], 'shared-3')
        self.assertEqual(marker.read_text(), 'unfinished key')
        self.assertEqual(record.read_bytes(), stale_data)
        self.assertEqual(Connection.load('shared').invitation, self.invitation)

    def test_interactive_join_cancel_does_not_generate_or_save_key(self):
        invitation = self.home / 'invitation.json'
        invitation.write_text(json.dumps(self.invitation))
        answers = ['', '']
        with patch.object(cli.sys.stdin, 'isatty', return_value=True), \
                patch.object(cli, '_answer', side_effect=answers), patch.object(cli, '_confirm', return_value=False), \
                patch.object(cli.subprocess, 'run', wraps=subprocess.run) as run, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.join_command(cli.parse_arguments(['join', '--invitation', str(invitation)])), 130)
        self.assertFalse((self.home / '.local/share/lemonbox/connections/shared-2').exists())
        # Host fingerprint validation uses the backend's real ssh-keygen helper;
        # no private key generation/derivation is reached after cancellation.
        for call in run.call_args_list:
            self.assertNotIn('-y', call.args[0])
            self.assertNotIn('-t', call.args[0])

    def local_entry(self, **changes):
        return dict({'owner': 'owner', 'owner_uid': os.getuid(), 'profile': 'default',
                     'hostname': 'lemonbox', 'invitation': self.invitation,
                     'socket': self.home / 'access.sock'}, **changes)

    def test_local_join_creates_private_identity_and_pins_vm_after_owner_confirmation(self):
        shutil.rmtree(self.connection.state)
        entry = self.local_entry()
        with patch('vm.local_access.discover', return_value=[entry]), \
                patch('vm.local_access.register', return_value=entry) as register, \
                patch.object(cli.sys.stdin, 'isatty', return_value=True), patch.object(cli, 'VM') as vm, \
                patch.object(cli, '_answer', return_value=''), \
                patch.object(cli, '_confirm', return_value=True) as confirm, \
                patch.object(Connection, 'reachable', return_value=True), \
                contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(['join']), 0)
        vm.assert_not_called()
        confirm.assert_called_once_with("Join owner's VM?")
        saved = Connection.load('shared')
        self.assertEqual(saved.identity, saved.state / 'id_ed25519')
        self.assertEqual(saved.identity.stat().st_uid, os.getuid())
        self.assertEqual(saved.identity.stat().st_mode & 0o777, 0o600)
        self.assertEqual(saved.invitation, self.invitation)
        self.assertEqual(register.call_args.args[0], entry)
        self.assertEqual(register.call_args.args[1], parse_public_key(saved.identity.with_suffix('.pub').read_text())['key'])
        self.assertEqual(cli.selected_target(), {'kind': 'connection', 'name': 'shared'})
        self.assertIn('Joined lemonbox (owner: owner).', output.getvalue())
        self.assertNotIn('ssh-ed25519 ', output.getvalue())
        self.assertNotIn('OPENSSH PRIVATE KEY', output.getvalue())

    def test_local_repeat_join_reuses_identity_and_connection_without_generating_key(self):
        entry = self.local_entry()
        before = (self.connection.state / 'connection.json').read_bytes()
        with patch('vm.local_access.discover', return_value=[entry]), \
                patch('vm.local_access.register', return_value=entry) as register, \
                patch.object(cli.sys.stdin, 'isatty', return_value=True), \
                patch.object(cli, '_answer', return_value='') as answer, \
                patch.object(cli, '_confirm', side_effect=AssertionError('Unexpected confirmation')), \
                patch.object(cli.subprocess, 'run', wraps=subprocess.run) as run, \
                patch.object(Connection, 'reachable', return_value=True), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(['join']), 0)
        self.assertEqual((self.connection.state / 'connection.json').read_bytes(), before)
        answer.assert_called_once()
        self.assertEqual(list(self.connection.state.parent.iterdir()), [self.connection.state])
        self.assertEqual(register.call_args.args[1], parse_public_key(self.identity.with_suffix('.pub').read_text())['key'])
        for call in run.call_args_list:
            self.assertNotIn('-t', call.args[0])

    def test_local_join_adds_public_keys_without_replacing_saved_identity(self):
        entry = self.local_entry()
        before = (self.connection.state / 'connection.json').read_bytes()
        extra = parse_public_key(self.host.with_suffix('.pub').read_text())
        arguments = ['join', '--public-key', str(self.host.with_suffix('.pub')),
                     '--public-key', extra['key']]
        with patch('vm.local_access.discover', return_value=[entry]), \
                patch('vm.local_access.register', return_value=entry) as register, \
                patch.object(cli.sys.stdin, 'isatty', return_value=True), \
                patch.object(cli, '_answer', side_effect=AssertionError('Unexpected prompt')), \
                patch.object(cli, '_confirm', side_effect=AssertionError('Unexpected confirmation')), \
                patch.object(Connection, 'reachable', return_value=True), \
                contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(arguments), 0)
        self.assertEqual(register.call_count, 3)
        self.assertEqual(register.call_args_list[0].args,
                         (entry, parse_public_key(self.identity.with_suffix('.pub').read_text())['key']))
        for call in register.call_args_list[1:]:
            self.assertEqual(call.args, (entry, extra['key']))
            self.assertEqual(call.kwargs, {'additional': True})
        self.assertEqual((self.connection.state / 'connection.json').read_bytes(), before)
        self.assertIn(extra['fingerprint'], output.getvalue())

    def test_repeat_local_join_prompts_for_extra_key_and_keeps_existing_private_key(self):
        entry = self.local_entry()
        before = (self.connection.state / 'connection.json').read_bytes()
        identity = self.identity.read_bytes()
        extra = parse_public_key(self.host.with_suffix('.pub').read_text())
        with patch('vm.local_access.discover', return_value=[entry]), \
                patch('vm.local_access.register', return_value=entry) as register, \
                patch.object(cli.sys.stdin, 'isatty', return_value=True), \
                patch.object(cli, '_answer', return_value=extra['key']) as answer, \
                patch.object(cli, '_confirm', side_effect=AssertionError('Unexpected confirmation')), \
                patch.object(Connection, 'reachable', return_value=True), \
                contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(['join']), 0)
        answer.assert_called_once()
        self.assertIn('PUBLIC key', answer.call_args.args[0])
        self.assertEqual(register.call_count, 2)
        self.assertEqual(register.call_args.args, (entry, extra['key']))
        self.assertEqual(register.call_args.kwargs, {'additional': True})
        self.assertEqual(self.identity.read_bytes(), identity)
        self.assertEqual((self.connection.state / 'connection.json').read_bytes(), before)
        self.assertIn(str(self.identity), output.getvalue())
        self.assertIn(extra['fingerprint'], output.getvalue())

    def test_invalid_additional_key_does_not_generate_identity_or_register_any_key(self):
        shutil.rmtree(self.connection.state)
        invalid = self.home / 'invalid.pub'
        invalid.write_text('not a public key')
        with patch('vm.local_access.discover', return_value=[self.local_entry()]), \
                patch('vm.local_access.register') as register, \
                patch.object(cli.sys.stdin, 'isatty', return_value=True), \
                patch.object(cli, '_confirm', return_value=True), \
                patch.object(cli.subprocess, 'run', wraps=subprocess.run) as run, \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(['join', '--public-key', str(invalid)]), 1)
        register.assert_not_called()
        self.assertFalse(self.connection.state.exists())
        for call in run.call_args_list:
            self.assertNotIn('-t', call.args[0])

    def test_additional_public_keys_cannot_silently_enter_remote_join(self):
        for terminal, arguments in ((True, ['--invitation', str(self.home / 'missing.json')]),
                                    (False, [])):
            with self.subTest(terminal=terminal), \
                    patch.object(cli.sys.stdin, 'isatty', return_value=terminal), \
                    patch('vm.local_access.discover') as discover, \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as error:
                self.assertEqual(cli.main(['join', '--public-key', str(self.host.with_suffix('.pub')),
                                          *arguments]), 1)
            discover.assert_not_called()
            self.assertIn('on this host', error.getvalue())
        with patch.object(cli.sys.stdin, 'isatty', return_value=True), \
                patch('vm.local_access.discover', return_value=[]), \
                patch.object(cli, '_confirm', side_effect=AssertionError('Unexpected remote fallback')), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as error:
            self.assertEqual(cli.main(['join', '--public-key', str(self.host.with_suffix('.pub'))]), 1)
        self.assertIn('local VM grant', error.getvalue())

    def test_local_join_saves_pending_connection_without_claiming_ssh_success(self):
        entry = self.local_entry()
        with patch('vm.local_access.discover', return_value=[entry]), \
                patch('vm.local_access.register', return_value=entry), \
                patch.object(cli.sys.stdin, 'isatty', return_value=True), \
                patch.object(cli, '_answer', return_value=''), \
                patch.object(Connection, 'reachable', return_value=False), \
                contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(['join']), 1)
        self.assertEqual(cli.selected_target(), {'kind': 'connection', 'name': 'shared'})
        self.assertIn('Access saved', output.getvalue())
        self.assertIn('SSH is unavailable', output.getvalue())
        self.assertNotIn('Joined', output.getvalue())

    def test_local_join_selects_vm_by_owner_and_hostname(self):
        first = self.local_entry()
        second = self.local_entry(owner='other', hostname='workbox',
                                  invitation=dict(self.invitation, port=2224))
        with patch('vm.local_access.discover', return_value=[first, second]), \
                patch('vm.local_access.register', return_value=second) as register, \
                patch.object(cli.sys.stdin, 'isatty', return_value=True), \
                patch.object(cli, '_answer', side_effect=['2', '']) as answer, \
                patch.object(cli, '_confirm', return_value=True) as confirm, \
                patch.object(Connection, 'reachable', return_value=True), \
                contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(io.StringIO()) as menu:
            self.assertEqual(cli.main(['join']), 0)
        self.assertEqual(answer.call_count, 2)
        confirm.assert_called_once_with("Join other's VM?")
        self.assertEqual(register.call_args.args[0], second)
        self.assertIn('owner / lemonbox', menu.getvalue())
        self.assertIn('other / workbox', menu.getvalue())
        self.assertIn('Joined workbox (owner: other).', output.getvalue())
        self.assertEqual(Connection.load('shared-2').invitation['port'], 2224)

    def test_local_join_declined_owner_creates_no_key_or_connection_state(self):
        shutil.rmtree(self.connection.state)
        before = sorted(path.relative_to(self.home) for path in self.home.rglob('*'))
        target = cli.selected_target()
        with patch('vm.local_access.discover', return_value=[self.local_entry()]), \
                patch('vm.local_access.register') as register, \
                patch.object(cli.sys.stdin, 'isatty', return_value=True), \
                patch.object(cli, '_confirm', return_value=False) as confirm, \
                patch.object(cli.subprocess, 'run') as run, \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as output:
            self.assertEqual(cli.main(['join']), 0)
        confirm.assert_called_once_with("Join owner's VM?")
        register.assert_not_called()
        run.assert_not_called()
        self.assertEqual(sorted(path.relative_to(self.home) for path in self.home.rglob('*')), before)
        self.assertIn('lemonbox · Owner: owner', output.getvalue())
        self.assertEqual(cli.selected_target(), target)

    def test_local_join_without_grant_does_not_enter_remote_flow_by_default(self):
        with patch('vm.local_access.discover', return_value=[]), \
                patch.object(cli.sys.stdin, 'isatty', return_value=True), \
                patch.object(cli, '_answer', side_effect=AssertionError('Unexpected prompt')), \
                patch.object(cli, '_confirm', return_value=False) as confirm, \
                patch.object(cli.subprocess, 'run') as run, \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as output:
            self.assertEqual(cli.main(['join']), 0)
        confirm.assert_called_once_with('Connect to a VM on another computer?')
        run.assert_not_called()
        self.assertIn('No VM access is available', output.getvalue())
        self.assertIn('lemonbox access', output.getvalue())

    def test_invitation_without_explicit_trust_requires_terminal_confirmation(self):
        invitation = self.home / 'invitation.json'
        invitation.write_text(json.dumps(self.invitation))
        with patch.object(cli.sys.stdin, 'isatty', return_value=False), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(['join', '--name', 'other', '--invitation', str(invitation),
                                      '--identity', str(self.identity)]), 1)
        self.assertFalse((self.home / '.local/share/lemonbox/connections/other/connection.json').exists())


if __name__ == '__main__':
    unittest.main()
