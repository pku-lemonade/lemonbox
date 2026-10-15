"""Shared routing must be ready before this VM boots; setup never fetches tools."""
import contextlib
import io
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch

from vm import cli


class LocalSetupTests(unittest.TestCase):
    def vm(self):
        vm = MagicMock()
        vm.state = Path('/private/state')
        vm.profile = 'default'
        vm.profile_state.revision.return_value = 'revision'
        gateway = vm.shared_gateway
        gateway.config_path = Path('/nonexistent/private/gateway/config.json')
        gateway.applied.return_value = None
        gateway.profile_state.revision.return_value = 'route-revision'
        return vm

    def test_route_failure_cannot_prepare_or_boot_guest(self):
        vm = self.vm()
        vm.shared_gateway.apply_config.side_effect = RuntimeError('invalid packet keys')
        with patch.object(cli, 'initial_route', return_value=MagicMock()), \
                patch.object(cli, 'initial_config', return_value=MagicMock()), \
                patch.object(cli, 'launch_locked') as launch, self.assertRaisesRegex(RuntimeError, 'invalid packet keys'):
            cli.setup(vm, cli.parse_arguments(['setup']))
        vm.prepare.assert_not_called()
        launch.assert_not_called()

    def test_setup_applies_shared_route_before_local_vm_then_waits_unlocked(self):
        vm, events = self.vm(), []
        vm.shared_gateway.apply_config.side_effect = lambda *a, **k: events.append('route')
        vm.apply_config.side_effect = lambda *a, **k: events.append('vm')
        vm.prepare.side_effect = lambda: events.append('prepare')
        candidate = MagicMock()
        with patch.object(cli, 'initial_route', return_value=MagicMock()), \
                patch.object(cli, 'initial_config', return_value=candidate), \
                patch.object(cli, 'launch_locked', side_effect=lambda *a: events.append('boot')), \
                patch.object(cli, 'finish_start', side_effect=lambda *a: events.append('ready')), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.setup(vm, cli.parse_arguments(['setup'])), 0)
        self.assertEqual(events, ['route', 'vm', 'prepare', 'boot', 'ready'])
        vm.apply_config.assert_called_once_with(candidate, restart=False, expected_revision='revision')

    def test_stop_all_does_not_hold_selected_profile_lock(self):
        vm = self.vm()
        self.assertEqual(cli.dispatch(vm, cli.parse_arguments(['stop', '--all'])), 0)
        vm.stop_all.assert_called_once()
        vm.profile_state.lock.assert_not_called()


if __name__ == '__main__':
    unittest.main()
