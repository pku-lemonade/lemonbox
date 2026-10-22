"""Exercise the installer's real filesystem behavior without privileged writes."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location('launcher_install', Path(__file__).resolve().parents[1] / 'scripts/install-launcher.py')
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)


class LauncherTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='lemon-launcher-', dir='/tmp')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        root.chmod(0o755)
        for filename in ('lemonbox', 'config.example.json', 'route.example.json'):
            (root / filename).write_text('readable')
            (root / filename).chmod(0o755 if filename == 'lemonbox' else 0o644)
        for name in ('vm', 'guest', 'scripts'):
            (root / name).mkdir()
            (root / name).chmod(0o755)
        for path in ('scripts/guest-prepare.py', 'guest/provision.sh', 'guest/desktop.sh', 'guest/desktop.py',
                     'guest/firefox-privacy.js', 'guest/readiness.py',
                     'guest/authorized_keys.py', 'guest/shares.py', 'vm/__init__.py'):
            (root / path).write_text('readable')
            (root / path).chmod(0o644)
        replacement = patch.object(INSTALLER, 'ROOT', root)
        replacement.start()
        self.addCleanup(replacement.stop)

    def test_installed_link_follows_the_stable_checkout_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / 'lemonbox'
            INSTALLER.install(target)
            self.assertEqual(target.resolve(), INSTALLER.ROOT / 'lemonbox')
            INSTALLER.install(target)
            self.assertTrue(target.is_symlink())

    def test_an_unrelated_existing_command_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / 'lemonbox'
            target.write_text('another command')
            with self.assertRaisesRegex(ValueError, 'another installation'):
                INSTALLER.install(target)
            self.assertEqual(target.read_text(), 'another command')

    def test_private_package_directory_is_rejected_but_search_only_ancestor_is_valid(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            parent.chmod(0o711)
            root = parent / 'checkout'
            root.mkdir(mode=0o755)
            root.chmod(0o755)
            for filename in ('lemonbox', 'config.example.json', 'route.example.json'):
                (root / filename).write_text('readable')
                (root / filename).chmod(0o755 if filename == 'lemonbox' else 0o644)
            package = root / 'vm'
            package.mkdir(mode=0o700)
            for name in ('guest', 'scripts'):
                (root / name).mkdir()
                (root / name).chmod(0o755)
            (package / '__init__.py').write_text('')
            (package / '__init__.py').chmod(0o644)
            for path in ('scripts/guest-prepare.py', 'guest/provision.sh', 'guest/desktop.sh', 'guest/desktop.py',
                         'guest/firefox-privacy.js', 'guest/readiness.py',
                         'guest/authorized_keys.py', 'guest/shares.py'):
                (root / path).write_text('readable')
                (root / path).chmod(0o644)
            target = parent / 'command'
            with patch.object(INSTALLER, 'ROOT', root):
                with self.assertRaisesRegex(ValueError, 'readable and searchable'):
                    INSTALLER.install(target)
                self.assertFalse(target.is_symlink())
                package.chmod(0o755)
                INSTALLER.install(target)
                self.assertEqual(target.resolve(), root / 'lemonbox')


if __name__ == '__main__':
    unittest.main()
