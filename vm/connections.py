"""Private SSH-only client connections, independent of VM and Podman state."""
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from .config import write_private_json, write_private_text
from .onboarding import private_directory
from .workflows import Workflow, working_directory


NAME = re.compile(r'[a-z0-9][a-z0-9_-]{0,31}')


def connection_directory(name):
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise ValueError('Connection name must be short lowercase text, numbers, hyphens or underscores')
    return Path.home() / '.local/share/lemonbox/connections' / name


def next_connection_name():
    name, number = 'shared', 2
    while connection_directory(name).exists() or connection_directory(name).is_symlink():
        name, number = 'shared-' + str(number), number + 1
    return name


def private_file(path, label):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError(label + ' must be a private regular file')
    info = path.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) not in (0o400, 0o600):
        raise ValueError(label + ' must be owned by you with mode 0400 or 0600')
    return path


class Connection:
    def __init__(self, name, data):
        from .access import validate_invitation
        if not isinstance(data, dict) or set(data) != {'version', 'host', 'port', 'username', 'host_key', 'identity'}:
            raise ValueError('Invalid saved SSH connection')
        self.name = name
        self.state = connection_directory(name)
        self.invitation = validate_invitation({key: value for key, value in data.items() if key != 'identity'})
        identity = data['identity']
        if not isinstance(identity, str) or not Path(identity).is_absolute() or any(ord(char) < 32 or ord(char) == 127 for char in identity):
            raise ValueError('SSH identity must be an absolute local path')
        self.identity = private_file(identity, 'SSH identity')
        self.username = self.invitation['username']

    @classmethod
    def load(cls, name):
        directory = connection_directory(name)
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError('No saved connection named ' + name)
        info = directory.stat()
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError('Connection directory must be owned by you with mode 0700')
        path = private_file(directory / 'connection.json', 'Saved connection')
        try:
            data = json.loads(path.read_text())
        except (UnicodeError, json.JSONDecodeError):
            raise ValueError('Saved connection must contain valid UTF-8 JSON') from None
        return cls(name, data)

    @classmethod
    def create(cls, name, invitation, identity):
        directory = connection_directory(name)
        if (directory / 'connection.json').exists():
            raise ValueError('This connection already exists; choose another name')
        data = dict(invitation, identity=str(Path(identity).expanduser().absolute()))
        result = cls(name, data)
        private_directory(directory.parent)
        private_directory(directory)
        write_private_json(directory / 'connection.json', data)
        result.ssh_config()
        return result

    @classmethod
    def find(cls, invitation, identity=None):
        """Reuse a previously pinned endpoint, preserving its private identity."""
        directory = connection_directory('shared').parent
        if not directory.exists():
            return None
        for path in sorted(directory.iterdir()):
            if not NAME.fullmatch(path.name):
                continue
            if not (path / 'connection.json').exists():
                continue
            try:
                candidate = cls.load(path.name)
            except (OSError, ValueError):
                continue
            if candidate.invitation == invitation and (identity is None or candidate.identity == identity):
                return candidate
        return None

    @property
    def address(self):
        host = self.invitation['host']
        if ':' in host:
            host = '[' + host + ']'
        return self.username + '@' + host + ':' + str(self.invitation['port'])

    @property
    def fingerprint(self):
        from .access import parse_public_key
        return parse_public_key(self.invitation['host_key'])['fingerprint']

    def ssh_config(self):
        private_directory(self.state)
        known = self.state / 'known_hosts'
        config = self.state / 'ssh-config'
        for path in (known, config):
            if path.is_symlink() or (path.exists() and not path.is_file()):
                raise ValueError('Generated SSH connection files must not be symlinks')
        alias = 'lemonbox-connection-' + self.name
        write_private_text(known, alias + ' ' + self.invitation['host_key'] + '\n')
        fields = {
            'HostName': self.invitation['host'], 'Port': str(self.invitation['port']),
            'User': self.username, 'IdentityFile': str(self.identity),
            'UserKnownHostsFile': str(known), 'HostKeyAlias': alias,
        }
        text = 'Host lemonbox\n' + ''.join('  ' + name + ' ' + json.dumps(value.replace('%', '%%') if name in ('IdentityFile', 'UserKnownHostsFile') else value, ensure_ascii=False) + '\n'
                                         for name, value in fields.items())
        text += ('  GlobalKnownHostsFile /dev/null\n  StrictHostKeyChecking yes\n'
                 '  IdentitiesOnly yes\n  ConnectTimeout 10\n'
                 '  ServerAliveInterval 15\n  ServerAliveCountMax 3\n')
        write_private_text(config, text)
        return config

    def reachable(self):
        command = ['ssh', '-F', str(self.ssh_config()), '-o', 'BatchMode=yes', '-T', 'lemonbox', 'true']
        try:
            return subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                                  timeout=15).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False


class RemoteWorkflow(Workflow):
    """Reuse native argv/stdin transport without owning a VM lifecycle."""
    def __init__(self, connection, workdir=None):
        self.vm = connection
        self.username = connection.username
        self.home = '/home/' + self.username
        self.workdir = working_directory(workdir)
