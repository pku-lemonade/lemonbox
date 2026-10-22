"""Persistent per-VM VNC credentials and native desktop configuration."""
import json
import os
from pathlib import Path
import re
import secrets
import string
import subprocess

from .config import write_private_json
from .state import ProfileState


class Desktop:
    def __init__(self, vm):
        self.vm = vm
        self.path = vm.state / 'desktop.json'
        self.state = ProfileState(vm.state)

    def _read_password(self):
        if self.path.is_symlink():
            raise ValueError('Desktop credentials must not be a symlink')
        if not self.path.exists():
            return None
        info = self.path.stat()
        if not self.path.is_file() or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError('Desktop credentials must be a private file owned by you')
        data = json.loads(self.path.read_text())
        if (not isinstance(data, dict) or set(data) != {'version', 'password'}
                or type(data['version']) is not int or data['version'] != 1
                or not isinstance(data['password'], str)
                or not re.fullmatch(r'[A-Za-z0-9]{8}', data['password'])):
            raise ValueError('Invalid desktop credentials')
        return data['password']

    def password(self, *, create=True):
        if not create:
            password = self._read_password()
            if password is None:
                raise ValueError('No VNC password is configured; start the desktop first')
            return password
        with self.state.lock():
            password = self._read_password()
            if password is not None:
                return password
            password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))
            write_private_json(self.path, {'version': 1, 'password': password})
            return password

    def configure(self, workflow):
        root = Path(__file__).resolve().parents[1]
        with self.state.lock():
            request = {'username': workflow.username, 'password': self.password(),
                       'script': (root / 'guest/desktop.sh').read_text()}
            # Credentials travel over pinned SSH on stdin, never in command arguments.
            command = workflow.ssh_command(['sudo', '-n', 'python3', '-c',
                                            (root / 'guest/desktop.py').read_text()])
            result = subprocess.run(command, input=json.dumps(request), text=True,
                                    capture_output=True, timeout=45)
            if result.returncode:
                raise RuntimeError('Could not configure desktop authentication; inspect guest SSH and sudo access')
            try:
                report = json.loads(result.stdout)
                changed = report['changed']
                if type(changed) is not bool:
                    raise ValueError()
            except (ValueError, TypeError, KeyError):
                raise RuntimeError('Guest returned invalid desktop configuration status') from None
            return changed
