"""Save private reports for the explicitly invoked live network probes."""
import json
import os
from pathlib import Path


def private_report(path, report):
    destination = Path(path)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", closefd=False) as handle:
            json.dump(report, handle, sort_keys=True, indent=2)
            handle.write("\n")
        os.replace(temporary, destination)
    finally:
        os.close(fd)
