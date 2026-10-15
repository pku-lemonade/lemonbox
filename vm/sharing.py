"""Explicit host-directory sharing over virtio 9p, without a host network route."""
from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Iterable


NAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}\Z")
USER_PATTERN = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
TAG_PREFIX = "lemshare_"
ROOT = Path(__file__).resolve().parents[1]


def home_path(username: str = "debian") -> str:
    if not USER_PATTERN.fullmatch(username):
        raise ValueError("Invalid guest username")
    return f"/home/{username}"


def _overlap(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def validate_shares(shares: Iterable[dict], *, state_dir: Path | None = None,
                    username: str = "debian",
                    protected_paths: Iterable[Path] = (),
                    require_sources: bool = True) -> list[dict]:
    """Normalize designated shares and keep VM state and operator credentials private.

    Existing projects and the source repository are valid share directories. VM
    creation designates a default workspace; additional shares are explicit.
    Resolve symlinks before checking boundaries.
    """
    home = home_path(username)
    if not isinstance(shares, (list, tuple)):
        raise ValueError("Shares must be a list")
    private = [Path.home() / ".ssh", Path.home() / ".codex",
               Path.home() / ".claude", Path.home() / ".config/lemonbox",
               Path.home() / ".local/share/lemonbox",
               *(Path(item).expanduser().resolve() for item in protected_paths)]
    if state_dir is not None:
        private.append(Path(state_dir).expanduser().resolve())
    normalized = []
    names = set()
    for item in shares:
        if not isinstance(item, dict) or set(item) - {"name", "source", "target", "read_only"}:
            raise ValueError("Each share must contain name, source, target and read_only")
        name = item.get("name")
        if not isinstance(name, str) or not NAME_PATTERN.fullmatch(name):
            raise ValueError("Share name must be a short lowercase name")
        if name in names:
            raise ValueError("Duplicate share name: " + name)
        names.add(name)
        source_value = item.get("source")
        if not isinstance(source_value, (str, os.PathLike)):
            raise ValueError("Share source must be a directory path")
        source_text = os.fspath(source_value)
        if (not isinstance(source_text, str) or not source_text or len(source_text) > 4096
                or any(ord(character) < 32 or ord(character) == 127 for character in source_text)):
            raise ValueError("Share source must be nonempty text without control characters")
        source_path = Path(source_value)
        if not source_path.is_absolute() or ".." in source_path.parts:
            raise ValueError("Share source must be an absolute host directory")
        try:
            source = source_path.resolve(strict=require_sources)
        except (OSError, RuntimeError) as error:
            raise ValueError("Share source directory does not exist: " + str(source_value)) from error
        if require_sources and not source.is_dir():
            raise ValueError("Share source is not a directory: " + str(source))
        if any(character in str(source) for character in (":", "\n", "\r", "\0")):
            raise ValueError("Share path cannot contain a colon, newline or null byte")
        if any(_overlap(source, path.resolve()) for path in private):
            raise ValueError("Share overlaps private VM state or operator credentials: " + str(source))
        if any(_overlap(source, Path(other["source"])) for other in normalized):
            raise ValueError("Shared source directories must not overlap")
        read_only = item.get("read_only", False)
        if not isinstance(read_only, bool):
            raise ValueError("Share read_only must be a boolean")
        if require_sources and not os.access(source, os.R_OK | os.X_OK):
            raise ValueError("Share directory is not readable by this user: " + str(source))
        if require_sources and not read_only and not os.access(source, os.W_OK):
            raise ValueError("Share directory is not writable; use --read-only: " + str(source))
        target = item.get("target", home + "/" + name)
        if target != home + "/" + name:
            raise ValueError("Share target must be " + home + "/" + name)
        normalized.append({"name": name, "source": str(source), "target": target,
                           "read_only": read_only})
    return sorted(normalized, key=lambda item: item["name"])


def podman_mount_args(shares: Iterable[dict]) -> list[str]:
    return [value for item in shares for value in
            ("-v", f"{item['source']}:/shared/{item['name']}:{'ro' if item['read_only'] else 'rw'}")]


def qemu_args(shares: Iterable[dict]) -> list[str]:
    """Use native host files; QEMU must run as guest uid 1000 with keep-id mapping.

    The unprivileged process cannot chown host files. The 'none' model ignores
    those failures while preserving native host symlinks. Read-only shares are
    enforced both by the host bind mount and by the QEMU export.
    """
    arguments = []
    for share in shares:
        identifier = TAG_PREFIX + share["name"]
        export = (f"local,id={identifier},path=/shared/{share['name']},"
                  "security_model=none,multidevs=remap")
        if share["read_only"]:
            export += ",readonly=on"
        arguments.extend(["-fsdev", export, "-device",
                          f"virtio-9p-pci,fsdev={identifier},mount_tag={identifier}"])
    return arguments


def guest_prepare_restart_request(shares: Iterable[dict], *, username: str = "debian") -> dict:
    """Prune stale fstab entries before shutdown, leaving mounted files untouched."""
    return guest_mount_request(shares, username=username, prepare_restart=True)


def guest_mount_request(shares: Iterable[dict], *, username: str = "debian",
                        prepare_restart: bool = False) -> dict:
    """Build the JSON request for guest/shares.py; no host paths enter the guest.

    It manages only its own fstab block and mount points. Native mounts persist
    across guest reboots; re-running the script leaves active matching mounts alone.
    """
    home = home_path(username)
    shares = list(shares)
    selected = [{key: item[key] for key in ("name", "target", "read_only")}
                for item in shares]
    shared_workspace = any(item['name'] == 'workspace' and not item['read_only']
                           and Path(item['source']).resolve().parent == (ROOT / 'workspaces').resolve()
                           for item in shares)
    return {"shares": selected, "username": username, "home": home,
            "prepare_restart": prepare_restart, "shared_workspace": shared_workspace}
