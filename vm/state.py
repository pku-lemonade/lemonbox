"""Private settings locks and stale-edit detection."""
from contextlib import contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import threading



UNSPECIFIED = object()
_locks = {}
_registry_lock = threading.Lock()


class ProfileState:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.config_path = self.directory / 'config.json'
        with _registry_lock:
            self._lock, self._local = _locks.setdefault(
                str(self.directory.resolve()), (threading.RLock(), threading.local()))

    @contextmanager
    def lock(self):
        """Serialize mutations across processes; nested calls reuse the lock."""
        self.directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        if (self.directory.is_symlink() or self.directory.stat().st_uid != os.getuid()
                or self.directory.stat().st_mode & 0o077):
            raise ValueError('Profile directory must be owned by you with mode 0700')
        with self._lock:
            depth = getattr(self._local, 'depth', 0)
            if depth:
                self._local.depth += 1
                try:
                    yield
                finally:
                    self._local.depth -= 1
                return
            fd = os.open(self.directory / '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            try:
                if os.fstat(fd).st_uid != os.getuid():
                    raise ValueError('Profile lock must be owned by you')
                os.fchmod(fd, 0o600)
                fcntl.flock(fd, fcntl.LOCK_EX)
                self._local.depth = 1
                yield
            finally:
                self._local.depth = 0
                os.close(fd)

    def revision(self):
        return hashlib.sha256(self.config_path.read_bytes()).hexdigest() if self.config_path.exists() else None

    def save_config(self, config, *, expected_revision=UNSPECIFIED):
        with self.lock():
            if expected_revision is not UNSPECIFIED and expected_revision != self.revision():
                raise ValueError('Settings changed while you were editing. Reopen settings and try again.')
            config.write(self.config_path)
            return self.revision()
