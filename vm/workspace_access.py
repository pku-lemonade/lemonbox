"""Host workspace access follows the VM's local user grants."""
import os
from pathlib import Path
import shutil
import stat
import subprocess

from .config import Config


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ACL = 'user::rwx\ngroup::rwx\nother::rwx\n'


def _acl(arguments, *, input=None, pass_fds=()):
    result = subprocess.run(arguments, input=input, pass_fds=pass_fds,
                            text=True, capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError('Could not update host workspace permissions: ' + result.stderr.strip()[-500:])
    return result.stdout


def sync_workspace_access(vm, users, *, source=None):
    """The workspace root gates access; files beneath it inherit shared modes.

    Keeping the user list at the root makes revocation effective even for files
    owned by another host user. The parent grants traversal, never directory listing.
    Only Lemonbox's default checkout workspace is managed here.
    """
    workspace_root = ROOT / 'workspaces'
    if source is None:
        path = vm.state / 'config.json'
        if not path.is_file():
            return
        config = Config.load(path, require_sources=False)
        expected = workspace_root / vm.profile
        source = next((Path(share['source']) for share in config.shares
                       if share['name'] == 'workspace'
                       and Path(share['source']).resolve() == expected.resolve()), None)
        if source is None:
            return
    else:
        expected = workspace_root / vm.profile
    source = Path(source).resolve()
    if (workspace_root.is_symlink() or expected.is_symlink() or source != expected.resolve()
            or not source.is_dir() or source.stat().st_uid != os.getuid()):
        raise ValueError('The default host workspace must be owned by the VM owner')
    if not all(shutil.which(name) for name in ('setfacl', 'getfacl')):
        raise RuntimeError('Host workspace sharing requires setfacl and getfacl; install the acl package')
    uids = sorted({user['uid'] for user in users} - {os.getuid()})
    before = _acl(['getfacl', '-cpn', str(source)])
    if 'default:other::rwx' not in before.splitlines():
        # Migrate existing workspace contents before opening the root to users.
        # Symlinks never change permissions outside the exported directory.
        for directory, folders, files, directory_fd in os.fwalk(source, follow_symlinks=False):
            for name in folders + files:
                metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
                    continue
                descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                     dir_fd=directory_fd)
                try:
                    metadata = os.fstat(descriptor)
                    if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
                        continue
                    mode = stat.S_IMODE(metadata.st_mode) | 0o666
                    if stat.S_ISDIR(metadata.st_mode) or mode & 0o111:
                        mode |= 0o111
                    os.fchmod(descriptor, mode)
                    if stat.S_ISDIR(metadata.st_mode):
                        _acl(['setfacl', '-d', '--set-file=-', '/proc/self/fd/' + str(descriptor)],
                             input=DEFAULT_ACL, pass_fds=(descriptor,))
                finally:
                    os.close(descriptor)
    if uids:
        _acl(['setfacl', '-m', ','.join('u:' + str(uid) + ':--x' for uid in uids), str(source.parent)])
    entries = ['user::rwx', *('user:' + str(uid) + ':rwx' for uid in uids),
               'group::---', 'other::---',
               'default:user::rwx', 'default:group::rwx', 'default:other::rwx']
    _acl(['setfacl', '--set-file=-', str(source)], input='\n'.join(entries) + '\n')
