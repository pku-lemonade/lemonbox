"""Guided VM settings and shared secrets remain separate and validated."""
import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import warnings

from vm import onboarding
from vm.config import Config, RouteConfig

ROOT = Path(__file__).resolve().parents[1]


class OnboardingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        self.state = self.home / 'default'
        self.state.mkdir(mode=0o700)
        self.path = self.state / 'config.json'
        self.config = Config.load(ROOT / 'config.example.json', require_private=False)
        self.config.write(self.path)
        self.original = self.path.read_bytes()
        self.vm = MagicMock(state=self.state, config_path=self.path, profile='default')
        self.checkout = self.home / 'code/lemonbox'
        self.addCleanup(patch.stopall)
        patch.object(onboarding.Path, 'home', return_value=self.home).start()
        patch.object(onboarding, 'ROOT', self.checkout).start()
        patch('vm.workspace_access.sync_workspace_access').start()
        patch.object(onboarding, '_say').start()

    def route(self):
        data = json.loads((ROOT / 'route.example.json').read_text())
        for hop in ('first_hop', 'exit_hop'):
            data['network'][hop]['password'] = 'private-' + hop
        data['wireguard'] = {'client_private_key': base64.b64encode(bytes(range(32))).decode(),
                             'server_public_key': base64.b64encode(bytes(range(32,64))).decode()}
        return RouteConfig.from_dict(data)

    def test_template_keeps_vm_settings_without_shares_or_route_credentials(self):
        folder = self.home / 'project'
        folder.mkdir()
        data = self.config.as_dict()
        data['shares'] = [{'name': 'project', 'source': str(folder)}]
        Config.from_dict(data).write(self.path)
        path = onboarding.save_template(self.path, 'current')
        saved = Config.load(path)
        self.assertEqual(saved.shares, [])
        self.assertEqual(saved.vm, self.config.vm)
        self.assertEqual(set(saved.as_dict()), {'version', 'vm', 'desktop', 'shares'})
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)

    def test_template_names_and_symlinks_are_rejected(self):
        for name in ('../escape', '/tmp/escape', 'Upper', ''):
            with self.subTest(name=name), self.assertRaises(ValueError):
                onboarding.save_template(self.path, name)
        path = onboarding.template_path('current')
        path.parent.mkdir(parents=True, mode=0o700)
        path.symlink_to(self.path)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            onboarding.save_template(self.path, 'current')
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_creation_settings_cannot_change_existing_disk(self):
        (self.state / 'guest.json').write_text(json.dumps({'profile': self.config.vm}))
        changed = self.config.as_dict()
        changed['vm']['hostname'] = 'other'
        with self.assertRaisesRegex(ValueError, 'creation settings cannot be edited'):
            onboarding.validate_candidate(changed, self.state)

    def test_fresh_setup_uses_host_username_and_does_not_save_before_apply(self):
        self.vm.config_path = self.state / 'new.json'
        with patch.object(onboarding.sys.stdin, 'isatty', return_value=True), \
                patch.object(onboarding.getpass, 'getuser', return_value='alice'), \
                patch.object(onboarding, 'guided', side_effect=lambda data, *a, **kw: Config.from_dict(data)):
            candidate = onboarding.initial_config(self.vm, ROOT / 'config.example.json')
        self.assertEqual(candidate.vm['username'], 'alice')
        self.assertFalse(self.vm.config_path.exists())
        self.assertEqual(candidate.shares, [{
            'name': 'workspace', 'source': str(self.checkout / 'workspaces/default'),
            'target': '/home/alice/workspace', 'read_only': False}])
        self.assertEqual((self.checkout / 'workspaces/default').stat().st_mode & 0o777, 0o700)

    def test_cancelled_creation_does_not_create_a_workspace(self):
        self.vm.config_path = self.state / 'new.json'
        with patch.object(onboarding.sys.stdin, 'isatty', return_value=True), \
                patch.object(onboarding, 'guided', return_value=None):
            self.assertIsNone(onboarding.initial_config(self.vm, ROOT / 'config.example.json'))
        self.assertFalse((self.checkout / 'workspaces').exists())

    def test_new_profiles_from_template_get_separate_workspaces(self):
        onboarding.save_template(self.path, 'current')
        candidates = []
        for name in ('first', 'second'):
            vm = MagicMock(profile=name, state=self.home / name, config_path=self.home / name / 'config.json')
            with patch.object(onboarding.sys.stdin, 'isatty', return_value=True), \
                    patch.object(onboarding, '_answer', return_value=''), \
                    patch.object(onboarding, 'guided', side_effect=lambda data, *a, **kw: Config.from_dict(data)):
                candidates.append(onboarding.initial_config(vm, ROOT / 'config.example.json'))
        first, second = (Path(candidate.shares[0]['source']) for candidate in candidates)
        (first / 'first-only.txt').write_text('profile data')
        self.assertFalse((second / 'first-only.txt').exists())
        self.assertEqual(first, self.checkout / 'workspaces/first')
        self.assertEqual(second, self.checkout / 'workspaces/second')
        self.assertEqual(Config.load(onboarding.template_path('current')).shares, [])

    def test_existing_unprepared_config_gets_workspace_without_saving_early(self):
        candidate = onboarding.initial_config(self.vm, ROOT / 'config.example.json')
        self.assertEqual(candidate.shares[0]['name'], 'workspace')
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_prepared_vm_keeps_its_existing_share_settings(self):
        (self.state / 'guest.json').write_text(json.dumps({'profile': self.config.vm}))
        candidate = onboarding.initial_config(self.vm, ROOT / 'config.example.json')
        self.assertEqual(candidate.shares, [])
        self.assertFalse((self.checkout / 'workspaces').exists())

    def test_explicit_workspace_is_preserved_and_private_symlink_is_rejected_before_creation(self):
        selected = self.home / 'selected'
        selected.mkdir()
        data = self.config.as_dict()
        data['shares'] = [{'name': 'workspace', 'source': str(selected), 'read_only': True}]
        chosen = onboarding.with_default_workspace(self.vm, Config.from_dict(data))
        self.assertEqual(chosen.shares[0]['source'], str(selected))
        self.assertTrue(chosen.shares[0]['read_only'])
        self.assertFalse((self.checkout / 'workspaces').exists())
        private = self.home / '.ssh'
        private.mkdir()
        self.checkout.mkdir(parents=True)
        (self.checkout / 'workspaces').symlink_to(private, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'private'):
            onboarding.with_default_workspace(self.vm, self.config)
        self.assertFalse((private / 'default').exists())

    def test_shared_secrets_use_hidden_input_and_invalid_values_do_not_leak(self):
        data = self.route().as_dict()
        with patch.object(onboarding.getpass, 'getpass', side_effect=['secret\ninvalid', 'secret-valid']), \
                patch.object(onboarding, '_answer') as ordinary:
            onboarding._field(data, ('network', 'first_hop'), 'password', 'Password', secret=True, validator=RouteConfig)
        ordinary.assert_not_called()
        self.assertEqual(data['network']['first_hop']['password'], 'secret-valid')
        self.assertNotIn('secret', str(onboarding._say.call_args_list))

    def test_password_prompt_refuses_echoing_fallback(self):
        def unavailable(prompt):
            warnings.warn('may echo', onboarding.getpass.GetPassWarning)
        with patch.object(onboarding.getpass, 'getpass', side_effect=unavailable), self.assertRaisesRegex(ValueError, 'hidden'):
            onboarding._field(self.route().as_dict(), ('network', 'first_hop'), 'password', 'Password',
                              secret=True, validator=RouteConfig)

    def test_initial_shared_route_is_reused_and_first_configuration_requires_terminal(self):
        gateway = MagicMock(config_path=self.home / 'route.json')
        with patch.object(onboarding.sys.stdin, 'isatty', return_value=False), self.assertRaisesRegex(ValueError, 'terminal'):
            onboarding.initial_route(gateway, ROOT / 'route.example.json')
        route = self.route()
        route.write(gateway.config_path)
        with patch.object(onboarding, 'guided_route') as guide:
            self.assertEqual(onboarding.initial_route(gateway, ROOT / 'route.example.json').as_dict(), route.as_dict())
        guide.assert_not_called()


if __name__ == '__main__':
    unittest.main()
