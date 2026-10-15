"""Reconcile native guest 9p mounts; the first argument is the JSON request."""
import json
import os
import pathlib
import pwd
import re
import subprocess
import sys
import tempfile

request = json.loads(sys.argv[1])
shares = request["shares"]
preparing = request["prepare_restart"]
user = pwd.getpwnam(request["username"])
home = pathlib.Path(request["home"])
begin, end = '# lemonbox shares begin', '# lemonbox shares end'


def command(*args):
    result = subprocess.run(args, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(' '.join(args) + ': ' + (result.stderr.strip() or 'command failed'))
    return result


def safe_directory(path, *, create=False):
    if path.is_symlink():
        raise RuntimeError('Shared home cannot be a symlink: ' + str(path))
    if create:
        path.mkdir(mode=0o755, exist_ok=True)
    if not path.is_dir():
        raise RuntimeError('Shared home is not a directory: ' + str(path))


def configure_workspace_umask():
    path = pathlib.Path('/etc/pam.d/sshd')
    enabled = request.get('shared_workspace', False)
    if not path.is_file():
        if enabled:
            raise RuntimeError('Shared workspace permissions require the native SSH PAM configuration')
        return
    text = path.read_text()
    first, last = '# lemonbox workspace begin', '# lemonbox workspace end'
    lines = text.splitlines()
    if lines.count(first) != lines.count(last) or lines.count(first) > 1:
        raise RuntimeError('Invalid workspace permissions block in SSH PAM configuration')
    if first in lines:
        start, stop = lines.index(first), lines.index(last)
        if stop < start:
            raise RuntimeError('Invalid workspace permissions block in SSH PAM configuration')
        del lines[start:stop + 1]
    if enabled:
        lines += [first,
                  'session [success=1 default=ignore] pam_succeed_if.so quiet user != ' + request['username'],
                  'session optional pam_umask.so umask=000', last]
    replacement = '\n'.join(lines).rstrip() + '\n'
    if replacement != text:
        descriptor, temporary = tempfile.mkstemp(prefix='.lemon-workspace-', dir=str(path.parent))
        try:
            with os.fdopen(descriptor, 'w') as destination:
                destination.write(replacement)
                destination.flush()
                os.fsync(destination.fileno())
            os.chmod(temporary, path.stat().st_mode & 0o777)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


if shares and not preparing:
    safe_directory(home)
fstab = pathlib.Path('/etc/fstab')
original = fstab.read_text() if fstab.exists() else ''
lines = original.splitlines()
if lines.count(begin) != lines.count(end) or lines.count(begin) > 1:
    raise RuntimeError('Invalid managed shares block in /etc/fstab')
previous = []
previous_records = []
if begin in lines:
    first, last = lines.index(begin), lines.index(end)
    if last < first:
        raise RuntimeError('Invalid managed shares block in /etc/fstab')
    for line in lines[first + 1:last]:
        parts = line.split()
        if len(parts) >= 3 and parts[0].startswith('lemshare_') and parts[2] == '9p':
            candidate = pathlib.Path(parts[1])
            if candidate.parent == home and re.fullmatch('[a-z0-9][a-z0-9_-]{0,31}', candidate.name):
                previous.append(candidate)
                previous_records.append(line)
    lines[first:last + 1] = []


def replace_fstab(records):
    result = lines + ([begin, *records, end] if records else [])
    replacement = '\n'.join(result).rstrip() + '\n'
    if replacement != original:
        fd, temporary = tempfile.mkstemp(prefix='.fstab-lemon-', dir='/etc')
        try:
            with os.fdopen(fd, 'w') as destination:
                destination.write(replacement)
                destination.flush()
                os.fsync(destination.fileno())
            os.chmod(temporary, fstab.stat().st_mode & 0o777 if fstab.exists() else 0o644)
            os.replace(temporary, fstab)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        command('systemctl', 'daemon-reload')


if preparing:
    wanted = {('lemshare_' + item['name'], str(pathlib.Path(item['target']))): item['read_only']
              for item in shares}
    retained = []
    for line in previous_records:
        fields = line.split()
        key = (fields[0], fields[1])
        if len(fields) >= 4 and key in wanted and ('ro' in fields[3].split(',')) == wanted[key]:
            retained.append(line)
    replace_fstab(retained)
    print(json.dumps({'prepared_for_restart': True, 'retained_mounts': len(retained)}))
    sys.exit(0)
desired = {pathlib.Path(item['target']) for item in shares}
for path in previous:
    if path not in desired:
        if path.is_symlink() or not path.exists():
            continue
        if not path.is_dir():
            continue
        if os.path.ismount(path):
            command('umount', str(path))
        try:
            path.rmdir()
        except OSError:
            pass
records = []
for item in shares:
    name = item['name']
    target = pathlib.Path(item['target'])
    if (target.parent != home or target.name != name
            or not re.fullmatch('[a-z0-9][a-z0-9_-]{0,31}', name)):
        raise RuntimeError('Invalid managed share target')
    safe_directory(target, create=True)
    if not os.path.ismount(target):
        if any(target.iterdir()):
            raise RuntimeError('Share mount point contains guest files: ' + str(target))
        os.chown(target, user.pw_uid, user.pw_gid)
    tag = 'lemshare_' + name
    mode = 'ro' if item['read_only'] else 'rw'
    options = 'trans=virtio,version=9p2000.L,msize=262144,cache=none,nofail,' + mode
    records.append(f'{tag} {target} 9p {options} 0 0')
replace_fstab(records)
if shares:
    command('modprobe', '9pnet_virtio')
    command('modprobe', '9p')
for item, line in zip(shares, records):
    target = pathlib.Path(item['target'])
    tag, _, _, options, _, _ = line.split()
    if os.path.ismount(target):
        details = command('findmnt', '-n', '-o', 'SOURCE,FSTYPE,OPTIONS',
                          '--target', str(target)).stdout.strip().split()
        if len(details) != 3 or details[0] != tag or details[1] != '9p':
            raise RuntimeError('Another filesystem occupies share mount point: ' + str(target))
        modes = details[2].split(',')
        if ('ro' in modes) != item['read_only']:
            command('mount', '-o', 'remount,' + ('ro' if item['read_only'] else 'rw'), str(target))
    else:
        command('mount', '-t', '9p', '-o', options, tag, str(target))
configure_workspace_umask()
print(json.dumps({'home': str(home), 'shares': shares}, indent=2))
