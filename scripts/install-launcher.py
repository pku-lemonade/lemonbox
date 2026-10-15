#!/usr/bin/env python3
"""Install the shared command once; updates use the same readable checkout."""
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
DESTINATION = Path('/usr/local/bin/lemonbox')


def install(destination=DESTINATION):
    source = ROOT / 'lemonbox'
    if not source.is_file() or not source.stat().st_mode & 0o001:
        raise ValueError('The checkout launcher must be executable')
    package = ROOT / 'vm'
    files = [source, ROOT / 'config.example.json', ROOT / 'route.example.json',
             ROOT / 'scripts/guest-prepare.py', ROOT / 'guest/provision.sh',
             ROOT / 'guest/desktop.sh', ROOT / 'guest/firefox-privacy.js',
             ROOT / 'guest/readiness.py', ROOT / 'guest/authorized_keys.py',
             ROOT / 'guest/shares.py',
             *package.glob('*.py')]
    for path in files:
        if not path.is_file() or not path.stat().st_mode & 0o004:
            raise ValueError('Production files must be readable by other users: ' + str(path))
    for directory in (ROOT, package, ROOT / 'scripts', ROOT / 'guest'):
        if not directory.is_dir() or directory.stat().st_mode & 0o005 != 0o005:
            raise ValueError('Production directories must be readable and searchable by other users: ' + str(directory))
    for directory in ROOT.parents:
        if not directory.stat().st_mode & 0o001:
            raise ValueError('Checkout directories must be searchable by other users: ' + str(directory))
    if destination.is_symlink() and destination.resolve() == source:
        return
    if destination.exists() or destination.is_symlink():
        raise ValueError(str(destination) + ' already belongs to another installation')
    destination.symlink_to(source)


def main():
    if len(sys.argv) != 1:
        raise ValueError('Run install-launcher.py without arguments')
    if os.geteuid() != 0:
        return subprocess.run(['sudo', '--', sys.executable, str(Path(__file__).resolve())]).returncode
    install()
    print('Installed lemonbox in /usr/local/bin. Keep this checkout at ' + str(ROOT) + '.')
    print('Future checkout updates take effect immediately; no reinstall is needed.')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
