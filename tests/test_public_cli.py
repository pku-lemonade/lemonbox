"""The supported short CLI and guided first-run contract."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch

from vm import cli
from vm.config import Config


class ArgumentsTests(unittest.TestCase):
    def setUp(self):
        self.selection = patch.object(cli, 'selected_target', return_value={'kind': 'vm', 'profile': 'default'})
        self.selection.start()
        self.addCleanup(self.selection.stop)

    def test_native_claude_options_and_argument_order_are_preserved(self):
        for argv, expected in (
            (['claude', '--version'], ['--version']),
            (['claude', '--help'], ['--help']),
            (['claude', '-h'], ['-h']),
            (['claude', '--model', 'opus', '--print', 'a prompt'], ['--model', 'opus', '--print', 'a prompt']),
            (['claude', '--', '--model', 'opus', '--print', 'a prompt'], ['--model', 'opus', '--print', 'a prompt']),
            (['claude', '--version', '--', '--model', 'opus'], ['--version', '--model', 'opus']),
            (['claude', '--', '--', 'literal'], ['--', 'literal']),
        ):
            with self.subTest(argv=argv):
                self.assertEqual(cli.parse_arguments(argv).arguments, expected)

    def test_workdir_and_shell_arguments_are_not_expanded(self):
        arguments = ['printf', '%s\n', 'a b', "a'b", '$HOME', '$(touch unwanted)']
        args = cli.parse_arguments(['exec', '--workdir', '/a b', '--', *arguments])
        self.assertEqual(args.arguments, arguments)
        self.assertEqual(args.workdir, '/a b')

    def test_wrapper_flags_do_not_abbreviate_or_ignore_positionals(self):
        for argv in (['desktop', '--por', '5902'], ['shell', 'ignored'], ['shell', '--project', 'x']):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                cli.parse_arguments(argv)
        args = cli.parse_arguments(['claude', '--work', 'native-option'])
        self.assertIsNone(args.workdir)
        self.assertEqual(args.arguments, ['--work', 'native-option'])

    def test_invalid_ports_and_timeout_fail_before_runtime_construction(self):
        for argv in (['desktop', '--port', '0'], ['desktop', '--port', '65536'], ['start', '--timeout', '0'],
                     ['--profile', '', 'stop'], ['--connection', '', 'shell']):
            with patch.object(cli, 'VM') as vm, contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                cli.main(argv)
            vm.assert_not_called()


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='lemon-public-')
        self.addCleanup(self.temporary.cleanup)
        self.state = Path(self.temporary.name)
        self.vm = MagicMock()
        self.vm.state = self.state
        self.vm.profile = 'default'
        self.vm.config_path = self.state / 'config.json'
        self.vm.config_error = None
        self.vm.config = MagicMock()
        self.vm.config.desktop = {'port': 5908}
        self.vm.profile_state.revision.return_value = 'revision'
        self.workflow = MagicMock()
        self.workflow.execute.return_value = 42
        self.selection = patch.object(cli, 'selected_target', return_value={'kind': 'vm', 'profile': 'default'})
        self.selection.start()
        self.addCleanup(self.selection.stop)

    def test_exec_and_shell_use_repair_access(self):
        with patch.object(cli, 'VM', return_value=self.vm), patch.object(cli, 'repair_access', return_value=self.workflow) as repair, \
                patch.object(cli, 'ensure_running') as full_ready:
            self.assertEqual(cli.main(['--profile', 'default', 'exec', '--', 'bash', '-c', 'exit 42']), 42)
            cli.main(['--profile', 'default', 'shell'])
        self.workflow.execute.assert_called_once_with(['bash', '-c', 'exit 42'])
        self.assertEqual(repair.call_count, 2)
        full_ready.assert_not_called()

    def test_desktop_stop_ignores_gateway_health(self):
        self.vm.info.return_value = {'State': {'Status': 'running'}}
        with patch.object(cli, 'VM', return_value=self.vm), patch.object(cli, 'Workflow', return_value=self.workflow), \
                patch.object(cli, 'ensure_running') as ready:
            cli.main(['--profile', 'default', 'desktop', '--stop'])
        self.workflow.vnc.assert_called_once_with(5908, stop=True)
        ready.assert_not_called()
        self.vm.health.assert_not_called()

    def test_tailnet_desktop_uses_the_selected_vm_and_saved_port(self):
        with patch.object(cli, 'VM', return_value=self.vm), \
                patch.object(cli, 'ensure_running', return_value=self.workflow):
            cli.main(['--profile', 'second', 'desktop', '--tailnet'])
        self.workflow.vnc.assert_called_once_with(5908, open_viewer=True, tailnet=True)

    def test_desktop_password_is_available_without_starting_the_vm_or_tailscale(self):
        self.workflow.desktop_password.return_value = 'testpass'
        with patch.object(cli, 'VM', return_value=self.vm), \
                patch.object(cli, 'Workflow', return_value=self.workflow), \
                patch.object(cli, 'ensure_running') as ready, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.main(['desktop', '--show-password']), 0)
        self.assertEqual(output.getvalue(), 'testpass\n')
        ready.assert_not_called()
        self.workflow.vnc.assert_not_called()

    def test_stopped_desktop_does_not_start_vm(self):
        self.vm.info.return_value = None
        with patch.object(cli, 'VM', return_value=self.vm), patch.object(cli, 'Workflow') as workflow, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(['--profile', 'default', 'desktop', '--stop']), 0)
        workflow.assert_not_called()
        self.vm.up.assert_not_called()

    def test_access_list_does_not_start_a_stopped_vm(self):
        self.workflow.accessible.side_effect = RuntimeError('VM is stopped')
        with patch.object(cli, 'VM', return_value=self.vm), \
                patch.object(cli, 'Workflow', return_value=self.workflow), \
                patch.object(cli, 'repair_access') as repair, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(['access', 'list']), 1)
        self.workflow.accessible.assert_called_once()
        repair.assert_not_called()
        self.vm.up.assert_not_called()

    def test_nonterminal_noargs_prints_help_without_starting(self):
        with patch.object(cli, 'VM', return_value=self.vm), patch.object(cli.sys.stdin, 'isatty', return_value=False), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cli.main(['--state-dir', str(self.state)]), 0)
        self.assertIn('COMMAND', output.getvalue())
        self.vm.up.assert_not_called()

    def test_invalid_settings_are_not_probed_with_defaults(self):
        with patch.object(cli, 'VM', return_value=self.vm), patch.object(cli, 'prerequisites', return_value=0), \
                patch.object(cli.Config, 'load', side_effect=ValueError('Invalid configuration')), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(['diagnose']), 1)
        self.vm.validate.assert_not_called()

    def test_stop_backend_error_is_not_reported_as_success(self):
        self.vm.down.side_effect = RuntimeError('Container backend failed')
        with patch.object(cli, 'VM', return_value=self.vm), contextlib.redirect_stderr(io.StringIO()) as output:
            self.assertEqual(cli.main(['--profile', 'default', 'stop']), 1)
        self.assertIn('Container backend failed', output.getvalue())
        self.vm.profile_state.lock.return_value.__exit__.assert_called_once()


class SettingsAndFilesTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='lemon-settings-')
        self.addCleanup(self.temporary.cleanup)
        self.state = Path(self.temporary.name) / 'profile'
        self.state.mkdir(mode=0o700)
        self.project = Path(self.temporary.name) / 'project'
        self.project.mkdir()
        data = json.loads((cli.ROOT / 'config.example.json').read_text())
        self.config = Config.from_dict(data)
        self.path = self.state / 'config.json'
        self.config.write(self.path)
        self.vm = MagicMock()
        self.vm.state, self.vm.config_path = self.state, self.path
        self.vm.config = self.config
        self.vm.profile = 'default'
        self.vm.profile_state.revision.return_value = 'revision'

    def test_files_add_defaults_to_folder_name_and_stages_read_only(self):
        args = cli.parse_arguments(['files', 'add', str(self.project), '--read-only'])
        with patch.object(cli, 'ensure_running'), contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.files_command(self.vm, args), 0)
        candidate = self.vm.apply_config.call_args.args[0]
        self.assertEqual(candidate.shares, [{'name': 'project', 'source': str(self.project),
                         'target': '/home/' + self.config.vm['username'] + '/project', 'read_only': True}])
        self.assertEqual(self.vm.apply_config.call_args.kwargs['expected_revision'], 'revision')
        self.assertEqual(Config.load(self.path).shares, [])

    def test_failed_files_apply_does_not_report_success_or_start(self):
        self.vm.apply_config.side_effect = RuntimeError('runtime failure')
        args = cli.parse_arguments(['files', 'add', str(self.project)])
        with patch.object(cli, 'ensure_running') as ready, contextlib.redirect_stderr(io.StringIO()), \
                contextlib.redirect_stdout(io.StringIO()) as output, self.assertRaisesRegex(RuntimeError, 'runtime failure'):
            cli.files_command(self.vm, args)
        ready.assert_not_called()
        self.assertEqual(output.getvalue(), '')

    def test_guided_settings_uses_fresh_file_instead_of_cached_vm_config(self):
        newer = self.config.as_dict()
        newer['vm']['cpus'] = 6
        Config.from_dict(newer).write(self.path)
        received = []
        def guide(data, state):
            received.append(data['vm']['cpus'])
            return Config.from_dict(data)
        with patch.object(cli.sys.stdin, 'isatty', return_value=True), patch.object(cli, '_answer', return_value='1'), \
                patch.object(cli, 'guided', side_effect=guide), patch.object(cli, 'ensure_running'), \
                contextlib.redirect_stderr(io.StringIO()):
            cli.settings_command(self.vm, cli.parse_arguments(['settings']))
        self.assertEqual(received, [6])
        self.assertEqual(self.vm.apply_config.call_args.kwargs['expected_revision'], 'revision')


class ReadinessConcurrencyTests(unittest.TestCase):
    def test_repair_and_stop_can_proceed_while_first_boot_waits(self):
        self.check_readiness_concurrency('start')

    def test_setup_does_not_hold_outer_lock_during_first_boot_wait(self):
        self.check_readiness_concurrency('setup')

    def test_restart_does_not_hold_outer_lock_during_first_boot_wait(self):
        self.check_readiness_concurrency('restart')

    def check_readiness_concurrency(self, action):
        from vm.state import ProfileState
        with tempfile.TemporaryDirectory(prefix='lemon-ready-lock-') as directory:
            vm = MagicMock()
            vm.state = Path(directory)
            vm.profile_state = ProfileState(vm.state)
            vm.shared_gateway.config_path = vm.state / 'absent-route.json'
            vm.shared_gateway.applied.return_value = None
            (vm.state / 'config.json').write_text('{}')
            vm.machine = 'test-machine'
            current = {'Id': 'machine-1', 'State': {'Status': 'running'}}
            vm.info.side_effect = lambda *args: current
            workflow = MagicMock()
            waiting, release, repair_done, stopped = (threading.Event() for _ in range(4))
            errors = []

            def ready(*args, check_current=None, **kwargs):
                check_current()
                waiting.set()
                if not release.wait(5):
                    raise RuntimeError('Test readiness was not released')
                check_current()

            def start():
                try:
                    if action == 'setup':
                        cli.setup(vm, cli.parse_arguments(['setup']))
                    elif action == 'restart':
                        cli.restart(vm)
                    else:
                        cli.ensure_running(vm)
                except Exception as error:
                    errors.append(error)

            def repair():
                cli.repair_access(vm)
                repair_done.set()

            def down():
                current['State']['Status'] = 'exited'
                stopped.set()

            vm.down.side_effect = down
            vm.up.side_effect = lambda: current['State'].update(Status='running')
            workflow.ready.side_effect = ready
            with patch.object(cli, 'Workflow', return_value=workflow), patch.object(cli, 'reconcile') as reconcile, \
                    patch.object(cli, 'initial_config', return_value=MagicMock()), \
                    patch.object(cli, 'initial_route', return_value=MagicMock()), \
                    contextlib.redirect_stderr(io.StringIO()):
                starter = threading.Thread(target=start)
                starter.start()
                repairer = None
                try:
                    self.assertTrue(waiting.wait(2), 'First boot never entered readiness')
                    repairer = threading.Thread(target=repair)
                    repairer.start()
                    self.assertTrue(repair_done.wait(2), 'Repair blocked on the first-boot lock')
                    cli.dispatch(vm, cli.parse_arguments(['stop']))
                    self.assertTrue(stopped.is_set())
                finally:
                    release.set()
                    starter.join(5)
                    if repairer:
                        repairer.join(5)
                self.assertFalse(starter.is_alive())
                reconcile.assert_not_called()
            workflow.accessible.assert_called_once()
            self.assertEqual(len(errors), 1)
            self.assertRegex(str(errors[0]), 'VM stopped, restarted or settings changed')

    def test_ready_target_detects_same_configuration_runtime_replacement(self):
        from vm.state import ProfileState
        with tempfile.TemporaryDirectory(prefix='lemon-ready-target-') as directory:
            vm = MagicMock()
            vm.state = Path(directory)
            vm.profile_state = ProfileState(vm.state)
            vm.machine = 'test-machine'
            vm.info.return_value = {'Id': 'original', 'State': {'Status': 'running'}}
            with vm.profile_state.lock(), patch.object(cli, 'Workflow'):
                _, guard = cli.launch_locked(vm)
            vm.info.return_value = {'Id': 'replacement', 'State': {'Status': 'running'}}
            with self.assertRaisesRegex(RuntimeError, 'restarted'):
                guard()


class TargetOutputTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='lemon-target-output-')
        self.addCleanup(directory.cleanup)
        self.home = Path(directory.name)
        home = patch.object(cli.Path, 'home', return_value=self.home)
        home.start()
        self.addCleanup(home.stop)
        self.vm, self.workflow = MagicMock(), MagicMock()
        for replacement in (patch.object(cli, 'VM', return_value=self.vm),
                            patch.object(cli, 'warn_gateway'),
                            patch.object(cli, 'Workflow', return_value=self.workflow),
                            patch.object(cli, 'repair_access', return_value=self.workflow)):
            replacement.start()
            self.addCleanup(replacement.stop)

    def test_remembered_vm_is_announced_without_changing_guest_stdout_or_exit_status(self):
        cli.select_profile('work')

        def execute(arguments):
            print('guest output')
            return 7

        self.workflow.execute.side_effect = execute
        with patch.object(cli.sys.stdin, 'isatty', return_value=True), \
                patch.object(cli, '_confirm', return_value=True), \
                contextlib.redirect_stdout(io.StringIO()) as output, \
                contextlib.redirect_stderr(io.StringIO()) as diagnostics:
            self.assertEqual(cli.main(['exec', '--', 'some-command']), 7)
        self.assertEqual(output.getvalue(), 'guest output\n')
        self.assertIn('==> Lemonbox VM: work [remembered selection]', diagnostics.getvalue())
        self.assertEqual(cli.VM.call_args.args[0].profile, 'work')

    def test_explicit_override_is_announced_without_changing_saved_selection_or_password_output(self):
        cli.select_profile('work')
        saved = cli.selection_path().read_bytes()
        self.workflow.desktop_password.return_value = 'testpass'
        with contextlib.redirect_stdout(io.StringIO()) as output, \
                contextlib.redirect_stderr(io.StringIO()) as diagnostics:
            self.assertEqual(cli.main(['--profile', 'other', 'desktop', '--show-password']), 0)
        self.assertEqual(output.getvalue(), 'testpass\n')
        self.assertIn('==> Lemonbox VM: other', diagnostics.getvalue())
        self.assertNotIn('[remembered selection]', diagnostics.getvalue())
        self.assertEqual(cli.selection_path().read_bytes(), saved)

    def test_target_banner_leaves_json_stdout_parseable(self):
        cli.select_profile('work')
        with patch.object(cli, 'status', side_effect=lambda *_: print('{"profile":"work"}')), \
                contextlib.redirect_stdout(io.StringIO()) as output, \
                contextlib.redirect_stderr(io.StringIO()) as diagnostics:
            cli.main(['status', '--json'])
        self.assertEqual(json.loads(output.getvalue()), {'profile': 'work'})
        self.assertIn('VM: work [remembered selection]', diagnostics.getvalue())

    def test_stop_all_announces_all_vms_instead_of_only_the_remembered_profile(self):
        cli.select_profile('work')
        with contextlib.redirect_stderr(io.StringIO()) as diagnostics:
            cli.main(['--profile', 'work', 'stop', '--all'])
        self.vm.stop_all.assert_called_once()
        self.assertIn('all local VMs and the shared gateway', diagnostics.getvalue())
        self.assertNotIn('VM: work', diagnostics.getvalue())
        self.assertNotIn('[remembered selection]', diagnostics.getvalue())

    def test_queries_use_remembered_selection_without_confirmation(self):
        cli.select_profile('work')
        for arguments in (['status'], ['status', '--json'], ['logs'], ['logs', '--guest'],
                          ['diagnose'], ['diagnose', '--host'], ['settings', '--path'],
                          ['settings', '--route', '--path'], ['files', 'list'], ['access', 'list'],
                          ['desktop', '--show-password']):
            with self.subTest(arguments=arguments), \
                    patch.object(cli, '_confirm', side_effect=AssertionError('Query prompted')), \
                    patch.object(cli, 'dispatch', return_value=0) as dispatch, \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(arguments), 0)
            self.assertEqual(dispatch.call_args.args[1].profile, 'work')

    def test_noninteractive_changes_cannot_construct_a_vm_or_consume_piped_input(self):
        cli.select_profile('work')
        for arguments in (['start'], ['stop'], ['restart'], ['setup'], ['update'], ['stop', '--all'],
                          ['settings'], ['settings', '--apply'], ['settings', '--route', '--apply'],
                          ['settings', '--save-template', 'copy'], ['files'], ['files', 'remove', 'project'],
                          ['files', 'add', '/some/folder'], ['access'], ['access', 'add', 'alice'],
                          ['access', 'remove', 'alice'], ['access', 'stop'], ['desktop'],
                          ['desktop', '--stop'], ['desktop', '--tailnet'], ['shell'], ['claude'],
                          ['exec', '--', 'touch', '/tmp/file'], ['claude', '--profile', 'other'],
                          ['exec', '--', 'echo', '--profile', 'other']):
            cli.VM.reset_mock()
            stream = io.StringIO('guest command input\n')
            with self.subTest(arguments=arguments), patch.object(cli.sys, 'stdin', stream), \
                    patch.object(cli, '_confirm', side_effect=AssertionError('Piped input prompted')), \
                    contextlib.redirect_stdout(io.StringIO()) as output, \
                    contextlib.redirect_stderr(io.StringIO()) as diagnostics:
                self.assertEqual(cli.main(arguments), 1)
            cli.VM.assert_not_called()
            self.assertEqual(stream.tell(), 0)
            self.assertEqual(output.getvalue(), '')
            self.assertIn('--profile work', diagnostics.getvalue())

    def test_interactive_changes_require_yes_and_cancellation_never_constructs_a_vm(self):
        class TerminalInput(io.StringIO):
            def isatty(self):
                return True

        cli.select_profile('work')
        for answer in ('yes\n', 'no\n', '\n', ''):
            cli.VM.reset_mock()
            self.vm.down.reset_mock()
            with self.subTest(answer=answer), patch.object(cli.sys, 'stdin', TerminalInput(answer)), \
                    contextlib.redirect_stdout(io.StringIO()) as output, \
                    contextlib.redirect_stderr(io.StringIO()) as diagnostics:
                result = cli.main(['stop'])
            self.assertIn('Run stop on VM: work? [y/N]: ', diagnostics.getvalue())
            self.assertEqual(output.getvalue(), '')
            if answer == 'yes\n':
                self.assertEqual(result, 0)
                self.vm.down.assert_called_once()
            else:
                self.assertEqual(result, 130)
                cli.VM.assert_not_called()
                self.vm.down.assert_not_called()

    def test_default_profile_also_requires_confirmation_for_changes(self):
        with patch.object(cli.sys, 'stdin', io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()) as diagnostics:
            self.assertEqual(cli.main(['start']), 1)
        cli.VM.assert_not_called()
        self.assertIn('--profile default', diagnostics.getvalue())

    def test_explicit_target_allows_noninteractive_changes_and_preserves_selection(self):
        cli.select_profile('work')
        with patch.object(cli.sys, 'stdin', io.StringIO()), \
                patch.object(cli, '_confirm', side_effect=AssertionError('Explicit target prompted')), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(['--profile', 'other', 'stop']), 0)
        self.vm.down.assert_called_once()
        self.assertEqual(cli.selected_target(), {'kind': 'vm', 'profile': 'work'})

    def test_selection_changes_during_confirmation_do_not_redirect_the_command(self):
        cli.select_profile('work')

        def confirm(prompt):
            cli.select_profile('other')
            return True

        with patch.object(cli.sys.stdin, 'isatty', return_value=True), \
                patch.object(cli, '_confirm', side_effect=confirm), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(['stop']), 0)
        self.assertEqual(cli.VM.call_args.args[0].profile, 'work')
        self.vm.down.assert_called_once()
        self.assertEqual(cli.selected_target(), {'kind': 'vm', 'profile': 'other'})

    def test_menu_action_counts_as_explicit_selection(self):
        cli.select_profile('work')
        state = self.home / '.local/share/lemonbox/work'
        state.mkdir()
        self.vm.profile, self.vm.state = 'work', state
        self.vm.config_path = state / 'config.json'
        self.vm.config_path.write_text('{}')
        with patch.object(cli.sys.stdin, 'isatty', return_value=True), \
                patch.object(cli, '_answer', return_value='8'), \
                patch.object(cli, '_confirm', side_effect=AssertionError('Menu action prompted twice')), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main([]), 0)
        self.vm.down.assert_called_once()


class SelectionTests(unittest.TestCase):
    def test_selected_vm_is_remembered_privately(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(cli.Path, 'home', return_value=Path(directory)):
            self.assertEqual(cli.selected_target()['profile'], 'default')
            cli.select_profile('work')
            self.assertEqual(cli.selected_target()['profile'], 'work')
            self.assertEqual(cli.parse_arguments(['shell']).profile, 'work')
            self.assertEqual(cli.selection_path().stat().st_mode & 0o777, 0o600)
            self.assertEqual(cli.parse_arguments(['--profile', 'other', 'shell']).profile, 'other')


if __name__ == '__main__':
    unittest.main()
