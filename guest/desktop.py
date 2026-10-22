"""Apply the managed desktop script and VNC password from private SSH stdin."""
import json
import os
from pathlib import Path
import pwd
import re
import sys
import tempfile


DESKTOP_SCRIPT = Path('/usr/local/lib/lemon/desktop.sh')


def write_file(path, text, *, mode, uid, gid):
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError('Managed desktop paths must be regular files')
    data = text.encode()
    if path.exists():
        info = path.stat()
        if (path.read_bytes() == data and info.st_mode & 0o777 == mode
                and info.st_uid == uid and info.st_gid == gid):
            return False
    descriptor, temporary = tempfile.mkstemp(prefix='.lemon-desktop-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as destination:
            destination.write(data)
            os.fchmod(destination.fileno(), mode)
            os.fchown(destination.fileno(), uid, gid)
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return True


def configure(request):
    if not isinstance(request, dict) or set(request) != {'username', 'password', 'script'}:
        raise ValueError('Invalid desktop request')
    username, password, script = request['username'], request['password'], request['script']
    if (not isinstance(username, str) or username == 'root'
            or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', username)
            or not isinstance(password, str) or not re.fullmatch(r'[A-Za-z0-9]{8}', password)
            or not isinstance(script, str) or not script.startswith('#!/bin/bash\n')):
        raise ValueError('Invalid desktop request')
    user = pwd.getpwnam(username)
    home = Path(user.pw_dir)
    if home.is_symlink() or not home.is_dir():
        raise ValueError('Desktop home must be a directory')
    for directory in (home / '.config', home / '.config/lemonbox'):
        if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
            raise ValueError('Desktop configuration paths must be directories')
        created = not directory.exists()
        directory.mkdir(mode=0o700, exist_ok=True)
        if created or directory.name == 'lemonbox':
            os.chown(directory, user.pw_uid, user.pw_gid)
            os.chmod(directory, 0o700)
    changed = write_file(home / '.config/lemonbox/vnc-password', password + '\n',
                         mode=0o600, uid=user.pw_uid, gid=user.pw_gid)
    changed = write_file(DESKTOP_SCRIPT, script, mode=0o755, uid=0, gid=0) or changed
    return {'changed': changed}


if __name__ == '__main__':
    try:
        print(json.dumps(configure(json.load(sys.stdin))))
    except (OSError, ValueError, KeyError):
        print('Could not configure desktop authentication', file=sys.stderr)
        raise SystemExit(1)
