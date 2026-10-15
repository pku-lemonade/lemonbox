"""Same-host grants authenticated by Linux Unix-socket peer credentials."""
from contextlib import contextmanager, suppress
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import struct
import subprocess

from .access import Access, _private_json, parse_public_key, validate_invitation
from .config import _hostname, write_private_json
from .workspace_access import sync_workspace_access


MAX_MESSAGE = 32768
PROFILE = re.compile(r'[a-z0-9][a-z0-9_-]{0,31}')


def _label(username, uid):
    return 'local:' + username + ':' + str(uid)


def key_owner(name):
    parts = name.split(':')
    if (len(parts) in (3, 4) and parts[0] == 'local' and parts[1] and parts[2].isdecimal()
            and (len(parts) == 3 or re.fullmatch(r'[a-f0-9]{12}', parts[3]))):
        return parts[1], int(parts[2])
    return None


class LocalAccess:
    def __init__(self, vm):
        self.vm = vm
        self.path = vm.state / 'local-users.json'

    def _grants(self):
        value = _private_json(self.path)
        if value is None:
            return {}
        if (not isinstance(value, dict) or any(not isinstance(name, str) or not name
                or type(uid) is not int or uid < 0 for name, uid in value.items())):
            raise ValueError('Invalid local user grants')
        return value

    def grant(self, username):
        try:
            user = pwd.getpwnam(username)
        except KeyError:
            raise ValueError('No Linux user named ' + username) from None
        with self.vm.profile_state.lock():
            grants = self._grants()
            if username in grants and grants[username] != user.pw_uid:
                raise ValueError('This username belongs to a different UID; remove its old grant first')
            previous = dict(grants)
            grants[username] = user.pw_uid
            write_private_json(self.path, grants)
            try:
                sync_workspace_access(self.vm, self.users())
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                write_private_json(self.path, previous)
                raise
        return {'username': username, 'uid': user.pw_uid}

    def users(self):
        return [{'username': name, 'uid': uid} for name, uid in sorted(self._grants().items())]

    def revoke(self, username):
        with self.vm.profile_state.lock():
            grants = self._grants()
            granted = username in grants
            if granted:
                grants.pop(username)
                write_private_json(self.path, grants)
            host_error = None
            try:
                sync_workspace_access(self.vm, self.users())
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                host_error = error
            manager = Access(self.vm)
            try:
                names = [entry['name'] for entry in manager.listkeys()
                         if (owner := key_owner(entry['name'])) is not None and owner[0] == username]
                for name in names:
                    manager.revoke(name)
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                message = ('Local enrollment is blocked for ' + username +
                           ', but SSH key removal failed. Retry lemonbox access remove ' +
                           username + ' when guest SSH is available.')
                if host_error:
                    message += ' Host workspace access could not be revoked either: ' + str(host_error)
                raise RuntimeError(message) from None
            if host_error:
                raise RuntimeError('VM SSH keys were removed, but host workspace access could not be revoked. '
                                   'Retry lemonbox access remove ' + username + ': ' + str(host_error)) from None
            if not granted and not names:
                raise ValueError('No local grant or SSH key for ' + username)

    def _allowed(self, uid):
        try:
            username = pwd.getpwuid(uid).pw_name
        except KeyError:
            raise ValueError('This Linux account no longer exists') from None
        if self._grants().get(username) != uid:
            raise ValueError('The VM owner has not granted your Linux user access')
        return username

    def info(self, uid):
        self._allowed(uid)
        metadata = json.loads((self.vm.state / 'guest.json').read_text())
        owner = pwd.getpwuid(os.getuid()).pw_name
        return {'owner': owner, 'owner_uid': os.getuid(), 'profile': self.vm.profile,
                'hostname': metadata['profile']['hostname'],
                'invitation': Access(self.vm).invitation(),
                'socket': str(socket_path(os.getuid(), self.vm.profile))}

    def register(self, uid, public_key, *, additional=False):
        self._allowed(uid)
        public_key = parse_public_key(public_key)['key']
        with self.vm.profile_state.lock():
            username = self._allowed(uid)
            manager = Access(self.vm)
            name = _label(username, uid)
            if additional:
                name += ':' + hashlib.sha256(public_key.encode()).hexdigest()[:12]
            entries = manager.listkeys()
            for entry in entries:
                if entry['public_key'] == public_key and entry['name'] != name:
                    if additional and key_owner(entry['name']) == (username, uid):
                        return self.info(uid)
                    raise ValueError('This key already belongs to another guest connection')
            existing = next((entry for entry in entries if entry['name'] == name), None)
            if not additional and existing is not None and existing['public_key'] != public_key:
                manager.revoke(name)
            manager.add(name, public_key)
            return self.info(uid)


def socket_path(owner_uid, profile):
    if type(owner_uid) is not int or owner_uid < 0 or not isinstance(profile, str) or not PROFILE.fullmatch(profile):
        raise ValueError('Invalid local VM endpoint')
    return Path('/tmp') / ('lemonbox-' + str(owner_uid)) / (profile + '.sock')


def _directory(path, owner_uid, *, create=False):
    if create:
        try:
            path.mkdir(mode=0o755)
        except FileExistsError:
            pass
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner_uid or info.st_mode & 0o022:
        raise ValueError('Local VM endpoint directory must be owned by its owner and not writable by others')
    if create:
        path.chmod(0o755)


def peer_uid(connection):
    return struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]


def _receive(connection):
    data = bytearray()
    while b'\n' not in data:
        chunk = connection.recv(min(4096, MAX_MESSAGE + 1 - len(data)))
        if not chunk:
            raise ValueError('Incomplete local access request')
        data.extend(chunk)
        if len(data) > MAX_MESSAGE:
            raise ValueError('Local access request is too large')
    line, trailing = data.split(b'\n', 1)
    if trailing:
        raise ValueError('Send one local access request')
    value = json.loads(line)
    if not isinstance(value, dict):
        raise ValueError('Invalid local access request')
    return value


def _send(connection, value):
    data = json.dumps(value, separators=(',', ':')).encode() + b'\n'
    if len(data) > MAX_MESSAGE:
        raise ValueError('Local access response is too large')
    connection.sendall(data)


def serve_connection(vm, connection):
    """Only the kernel-supplied UID can select a grant or managed guest key."""
    with connection:
        connection.settimeout(5)
        try:
            uid = peer_uid(connection)
            request = _receive(connection)
            manager = LocalAccess(vm)
            if request == {'action': 'info'}:
                result = manager.info(uid)
            elif set(request) == {'action', 'public_key'} and request['action'] in ('register', 'add-key'):
                result = manager.register(uid, request['public_key'], additional=request['action'] == 'add-key')
            else:
                raise ValueError('Unsupported local access request')
            _send(connection, {'result': result})
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            with suppress(OSError):
                _send(connection, {'error': 'Could not join this VM. Ask its owner to grant your Linux username access and keep the VM running.'})


@contextmanager
def listener(vm):
    path = socket_path(os.getuid(), vm.profile)
    _directory(path.parent, os.getuid(), create=True)
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError('An unrelated file occupies the local VM endpoint')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
            probe.settimeout(0.2)
            try:
                probe.connect(str(path))
            except ConnectionRefusedError:
                path.unlink()
            else:
                raise ValueError('Local access is already running for this VM')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(path))
        identity = path.lstat()
        try:
            path.chmod(0o666)
            server.listen(32)
            server.settimeout(0.5)
            yield server
        finally:
            if path.exists() and path.lstat().st_ino == identity.st_ino:
                path.unlink()


def _request(entry, request, timeout):
    owner_uid = entry['owner_uid']
    path = socket_path(owner_uid, entry['profile'])
    if str(path) != entry['socket']:
        raise ValueError('Invalid local VM endpoint')
    _directory(path.parent, owner_uid)
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != owner_uid:
        raise ValueError('Local VM endpoint belongs to another user')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        connection.connect(str(path))
        if peer_uid(connection) != owner_uid:
            raise ValueError('Local VM server belongs to another user')
        _send(connection, request)
        response = _receive(connection)
    if 'error' in response:
        raise ValueError(response['error'])
    result = response['result']
    if (set(result) != {'owner', 'owner_uid', 'profile', 'hostname', 'invitation', 'socket'}
            or result['owner_uid'] != owner_uid or result['profile'] != entry['profile']
            or result['socket'] != str(path) or result['owner'] != pwd.getpwuid(owner_uid).pw_name):
        raise ValueError('Invalid local VM connection details')
    _hostname(result['hostname'], 'VM hostname', 63)
    result['invitation'] = validate_invitation(result['invitation'])
    return result


def discover():
    if not hasattr(socket, 'SO_PEERCRED'):
        return []
    result = []
    for directory in sorted(Path('/tmp').glob('lemonbox-*')):
        suffix = directory.name.removeprefix('lemonbox-')
        if not suffix.isdecimal():
            continue
        owner_uid = int(suffix)
        try:
            _directory(directory, owner_uid)
            paths = sorted(directory.glob('*.sock'))
        except (OSError, ValueError):
            continue
        for path in paths:
            entry = {'owner_uid': owner_uid, 'profile': path.stem, 'socket': str(path)}
            try:
                result.append(_request(entry, {'action': 'info'}, timeout=0.5))
            except (OSError, ValueError, KeyError, TypeError):
                continue
    return result


def register(entry, public_key, *, additional=False):
    action = 'add-key' if additional else 'register'
    result = _request(entry, {'action': action, 'public_key': parse_public_key(public_key)['key']}, timeout=40)
    if result['invitation'] != entry['invitation']:
        raise ValueError('The VM identity changed; run lemonbox join again')
    return result
