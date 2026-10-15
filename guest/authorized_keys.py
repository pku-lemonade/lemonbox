"""Manage native guest SSH keys from a JSON argument over pinned SSH."""
import fcntl
import json
import os
from pathlib import Path
import sys
import tempfile


def reject(code, message):
    print(json.dumps({"error": code, "message": message}))
    raise SystemExit(2)


def manage(request):
    key_types = request["key_types"]
    marker = request["marker"]
    directory = Path.home() / ".ssh"
    if directory.is_symlink():
        raise RuntimeError("SSH directory must not be a symbolic link")
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.stat().st_uid != os.getuid() or directory.stat().st_mode & 0o077:
        raise RuntimeError("SSH directory must be private and owned by the guest user")
    path = directory / "authorized_keys"
    descriptor = os.open(directory / ".authorized_keys.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        if os.fstat(descriptor).st_uid != os.getuid():
            raise RuntimeError("SSH lock must be owned by the guest user")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise RuntimeError("authorized_keys must be a regular file")
        text = path.read_text() if path.exists() else ""
        if len(text) > 1048576:
            raise RuntimeError("authorized_keys is too large")
        entries = []
        unmanaged = []
        for line in text.splitlines():
            parts = line.strip().split(None, 2)
            if len(parts) == 3 and parts[0] in key_types and parts[2].startswith(marker):
                name = parts[2][len(marker):]
                if not name or len(name) > 64 or any(ord(c) < 32 or ord(c) == 127 for c in name):
                    raise RuntimeError("Invalid managed key name")
                entries.append({"name": name, "public_key": " ".join(parts[:2])})
            else:
                unmanaged.append(line)
        if len({entry["name"] for entry in entries}) != len(entries):
            raise RuntimeError("Managed key names must be unique")
        if request["action"] == "add":
            if request["public_key"] == request["owner_key"]:
                reject("owner_key", "The owner access key is already protected")
            found = next((entry for entry in entries if entry["name"] == request["name"]), None)
            if found and found["public_key"] != request["public_key"]:
                reject("name_conflict", "This name already belongs to another key")
            if any(entry["public_key"] == request["public_key"] and entry["name"] != request["name"] for entry in entries):
                reject("key_conflict", "This public key already has another name")
            if any(request["public_key"] in line for line in unmanaged):
                reject("unmanaged_key", "This public key is already authorized outside Lemonbox")
            if not found:
                entries.append({"name": request["name"], "public_key": request["public_key"]})
        elif request["action"] == "revoke":
            if not any(entry["name"] == request["name"] for entry in entries):
                reject("missing_key", "No managed key has this name")
            if any(entry["name"] == request["name"] and entry["public_key"] == request["owner_key"] for entry in entries):
                reject("owner_key", "The owner access key cannot be revoked")
            entries = [entry for entry in entries if entry["name"] != request["name"]]
        elif request["action"] != "list":
            raise RuntimeError("Unknown access operation")
        if request["action"] != "list":
            # Preserve owner access, including an owner key carrying a managed marker.
            if not any(" ".join(line.strip().split()[:2]) == request["owner_key"] for line in unmanaged):
                unmanaged.append(request["owner_key"])
            fd, temporary = tempfile.mkstemp(prefix=".authorized_keys-", dir=directory)
            try:
                with os.fdopen(fd, "w") as handle:
                    handle.write("\n".join(unmanaged + [entry["public_key"] + " " + marker + entry["name"] for entry in entries]) + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, path)
            finally:
                Path(temporary).unlink(missing_ok=True)
        print(json.dumps(entries))
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    manage(json.loads(sys.argv[1]))
