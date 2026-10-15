"""Named native SSH keys and an owner-managed localhost relay for one VM."""
from contextlib import suppress
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid

from .config import write_private_json
from .route_contract import GUEST_POOL, MAX_GUESTS


ROOT = Path(__file__).resolve().parents[1]
KEY_TYPES = {"ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
             "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"}
MARKER = "lemonbox-access:"
_spawned = {}


def parse_public_key(text):
    """Accept a standard public key; return its normalized value and fingerprint."""
    if not isinstance(text, str) or len(text) > 16384:
        raise ValueError("Provide one SSH public key")
    text = text.strip()
    if not text or any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise ValueError("Provide one SSH public key on a single line")
    fields = text.split()
    if len(fields) < 2 or fields[0] not in KEY_TYPES:
        raise ValueError("Provide a public key, such as an ed25519 .pub file")
    normalized = " ".join(fields[:2])
    with tempfile.TemporaryDirectory(prefix="lemon-public-key-") as directory:
        path = Path(directory) / "key.pub"
        path.write_text(normalized + "\n")
        result = subprocess.run(["ssh-keygen", "-E", "sha256", "-lf", str(path)],
                                text=True, capture_output=True, check=False, timeout=10)
    if result.returncode:
        raise ValueError("Invalid SSH public key")
    fingerprint = result.stdout.split()[1]
    if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]+", fingerprint):
        raise ValueError("Invalid SSH public key fingerprint")
    return {"key": normalized, "fingerprint": fingerprint}


def validate_invitation(data):
    """Public connection information contains no operator paths or credentials."""
    if (not isinstance(data, dict) or set(data) != {"version", "host", "port", "username", "host_key"}
            or type(data["version"]) is not int or data["version"] != 1):
        raise ValueError("Invalid Lemonbox connection details")
    host = data["host"]
    if not isinstance(host, str) or len(host) > 253:
        raise ValueError("Set an SSH hostname or address")
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        if not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                   for label in host.split(".")):
            raise ValueError("Set a valid SSH hostname or address") from None
    if type(data["port"]) is not int or not 1 <= data["port"] <= 65535:
        raise ValueError("Set an SSH port from 1 to 65535")
    if not isinstance(data["username"], str) or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", data["username"]):
        raise ValueError("Set the guest's Linux username")
    return data | {"host": host, "host_key": parse_public_key(data["host_key"])["key"]}


def _name(value):
    if (not isinstance(value, str) or not value.strip() or len(value.strip()) > 64
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError("Use a name of up to 64 characters without control characters")
    return value.strip()


def _private_json(path):
    if not path.exists() and not path.is_symlink():
        return None
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("Access state must be a private regular file owned by you")
    if info.st_size > 16384:
        raise ValueError("Access state is too large")
    return json.loads(path.read_text())


def guest_endpoint(state):
    """Use the allocated guest address and relay port from native VM metadata."""
    metadata = _private_json(Path(state) / 'guest.json')
    profile = metadata.get('profile') if isinstance(metadata, dict) else None
    if not isinstance(profile, dict):
        raise ValueError('Prepare the VM before enabling SSH access')
    try:
        address = ipaddress.IPv4Address(profile['guest_ip'])
        pool = ipaddress.IPv4Network(GUEST_POOL)
        offset = int(address) - int(pool.network_address)
        slot = offset // 4
        port = profile['ssh_port']
    except (KeyError, ValueError, TypeError):
        raise ValueError('VM metadata lacks a valid allocated SSH endpoint') from None
    if address not in pool or offset % 4 != 2 or not 0 <= slot < MAX_GUESTS or type(port) is not int or port != 2222 + slot:
        raise ValueError('VM metadata has an invalid allocated SSH endpoint')
    return {'guest_ip': str(address), 'ssh_port': port}


class Access:
    def __init__(self, vm):
        self.vm = vm
        self.path = vm.state / "access.json"

    def settings(self):
        value = _private_json(self.path)
        if value is None:
            return {"version": 1, "enabled": False, "port": guest_endpoint(self.vm.state)["ssh_port"]}
        if (not isinstance(value, dict) or set(value) != {"version", "enabled", "port"}
                or type(value["version"]) is not int or value["version"] != 1
                or type(value["enabled"]) is not bool or type(value["port"]) is not int
                or not 1024 <= value["port"] <= 65535):
            raise ValueError("Invalid local SSH access settings")
        return value

    def enable(self, port=None):
        port = self.settings()["port"] if port is None else port
        if type(port) is not int or not 1024 <= port <= 65535:
            raise ValueError("Use a local SSH port from 1024 to 65535")
        with self.vm.profile_state.lock():
            write_private_json(self.path, {"version": 1, "enabled": True, "port": port})
        return self.settings()

    def disable(self):
        with self.vm.profile_state.lock():
            value = self.settings() | {"enabled": False}
            write_private_json(self.path, value)
            Relay(self.vm).stop()
        return value

    def _keys(self, action, *, name=None, public_key=None):
        from .workflows import Workflow
        owner = self.vm.state / "ssh/id_ed25519.pub"
        if owner.is_symlink() or not owner.is_file():
            raise ValueError("The VM owner access key is missing")
        request = {"action": action, "owner_key": parse_public_key(owner.read_text())["key"],
                   "key_types": sorted(KEY_TYPES), "marker": MARKER}
        if name is not None:
            request["name"] = _name(name)
        if public_key is not None:
            request["public_key"] = parse_public_key(public_key)["key"]
        source = (ROOT / "guest/authorized_keys.py").read_text()
        with self.vm.profile_state.lock():
            workflow = Workflow(self.vm)
            result = workflow.run_script(source, args=[json.dumps(request)], timeout=30)
            if result.returncode:
                try:
                    failure = json.loads(result.stdout)
                except ValueError:
                    failure = None
                if (result.returncode == 2 and isinstance(failure, dict)
                        and failure.get("error") in {"owner_key", "name_conflict", "key_conflict", "unmanaged_key", "missing_key"}
                        and isinstance(failure.get("message"), str)):
                    raise ValueError(failure["message"])
                raise RuntimeError("Could not update guest SSH keys; run lemonbox start and retry access")
            try:
                entries = json.loads(result.stdout)
                if not isinstance(entries, list) or len(entries) > 1024:
                    raise ValueError
                normalized = [{"name": _name(entry["name"]), **parse_public_key(entry["public_key"])}
                              for entry in entries]
            except (ValueError, KeyError, TypeError):
                raise RuntimeError("The guest did not confirm its managed SSH keys") from None
        return [{"name": entry["name"], "public_key": entry["key"], "fingerprint": entry["fingerprint"]}
                for entry in normalized]

    def add(self, name, keytext):
        return self._keys("add", name=name, public_key=keytext)

    def listkeys(self):
        return self._keys("list")

    def revoke(self, name):
        return self._keys("revoke", name=name)

    def invitation(self):
        settings = self.settings()
        if not settings["enabled"]:
            raise ValueError("Run lemonbox access and choose Add local user or Remote access first")
        metadata = json.loads((self.vm.state / "guest.json").read_text())
        return validate_invitation({"version": 1, "host": "127.0.0.1", "port": settings["port"],
                                    "username": metadata["profile"]["username"],
                                    "host_key": metadata["guest_host_public_key"]})


def _process(pid):
    try:
        directory = Path("/proc") / str(pid)
        status = (directory / "status").read_text()
        uid = next(line.split()[1:] for line in status.splitlines() if line.startswith("Uid:"))
        if any(int(value) != os.getuid() for value in uid):
            return None
        ticks = int((directory / "stat").read_text().rsplit(")", 1)[1].split()[19])
        argv = (directory / "cmdline").read_bytes().split(b"\0")
        return {"ticks": ticks, "argv": [value.decode() for value in argv if value]}
    except (OSError, ValueError, StopIteration, UnicodeError):
        return None


class Relay:
    def __init__(self, vm):
        self.vm = vm
        self.path = vm.state / "access-relay.json"

    def _info(self):
        value = _private_json(self.path)
        if value is None:
            return None
        if (not isinstance(value, dict) or set(value) != {"pid", "start_ticks", "nonce", "port"}
                or type(value["pid"]) is not int or value["pid"] <= 1
                or type(value["start_ticks"]) is not int or value["start_ticks"] <= 0
                or not isinstance(value["nonce"], str) or not re.fullmatch(r"[a-f0-9]{32}", value["nonce"])
                or type(value["port"]) is not int or not 1024 <= value["port"] <= 65535):
            raise ValueError("Invalid local SSH relay state")
        return value

    def _owned(self, info):
        process = _process(info["pid"])
        expected = ["-m", "vm.access", "relay", str(self.vm.state), self.vm.gateway,
                    guest_endpoint(self.vm.state)["guest_ip"], str(info["port"]), info["nonce"], self.vm.profile]
        return bool(process and process["ticks"] == info["start_ticks"] and process["argv"][1:] == expected)

    def running(self):
        info = self._info()
        return bool(info and self._owned(info))

    def start(self):
        with self.vm.profile_state.lock():
            settings = Access(self.vm).settings()
            if not settings["enabled"]:
                return False
            old = self._info()
            if old and self._owned(old) and old["port"] == settings["port"]:
                return True
            self.stop()
            nonce = uuid.uuid4().hex
            argv = [sys.executable, "-m", "vm.access", "relay", str(self.vm.state),
                    self.vm.gateway, guest_endpoint(self.vm.state)["guest_ip"], str(settings["port"]), nonce,
                    self.vm.profile]
            child = subprocess.Popen(argv, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True)
            _spawned[str(self.vm.state)] = child
            deadline = time.monotonic() + 5
            while child.poll() is None and time.monotonic() < deadline:
                info = self._info()
                if info and info["nonce"] == nonce and self._owned(info):
                    return True
                time.sleep(0.05)
            # Only this newly spawned child can be terminated here.
            if child.poll() is None:
                child.terminate()
                with suppress(subprocess.TimeoutExpired):
                    child.wait(timeout=5)
            _spawned.pop(str(self.vm.state), None)
            raise RuntimeError("Cannot open localhost SSH access; choose an unused port in lemonbox access")

    def stop(self):
        with self.vm.profile_state.lock():
            info = self._info()
            if info is None:
                return False
            if self._owned(info):
                with suppress(ProcessLookupError):
                    os.kill(info["pid"], signal.SIGTERM)
                deadline = time.monotonic() + 10
                while self._owned(info) and time.monotonic() < deadline:
                    time.sleep(0.05)
                if self._owned(info):
                    with suppress(ProcessLookupError):
                        os.kill(info["pid"], signal.SIGKILL)
            # Stale PID files never authorize killing an unrelated process.
            if self.path.exists():
                current = self._info()
                if current == info:
                    self.path.unlink()
            child = _spawned.get(str(self.vm.state))
            if child and child.pid == info["pid"]:
                with suppress(subprocess.TimeoutExpired):
                    child.wait(timeout=3)
                if child.poll() is not None:
                    _spawned.pop(str(self.vm.state), None)
            return True


def forward_connection(client, command, *, processes, process_lock, stop_event):
    """Forward raw SSH bytes; authentication remains entirely inside the guest."""
    with process_lock:
        if stop_event.is_set():
            client.close()
            return
        try:
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, bufsize=0, close_fds=True)
        except OSError:
            client.close()
            return
        processes.add(process)
    def incoming():
        try:
            while data := client.recv(65536):
                remaining = memoryview(data)
                while remaining:
                    remaining = remaining[process.stdin.write(remaining):]
        except (OSError, ValueError):
            pass
        finally:
            with suppress(OSError, ValueError):
                process.stdin.close()
    reader = threading.Thread(target=incoming, daemon=True)
    reader.start()
    try:
        while data := process.stdout.read(65536):
            client.sendall(data)
    except (OSError, ValueError):
        pass
    finally:
        with suppress(OSError):
            client.shutdown(socket.SHUT_RDWR)
        client.close()
        with suppress(OSError):
            process.stdout.close()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        reader.join(timeout=3)
        with process_lock:
            processes.discard(process)


def serve(state, gateway, guest_ip, port, nonce, profile):
    """Own loopback SSH forwarding and same-host public-key registration."""
    from types import SimpleNamespace
    from .local_access import listener as local_listener, serve_connection
    from .runtime import VM

    state = Path(state)
    if (state.is_symlink() or not state.is_dir() or state.stat().st_uid != os.getuid()
            or state.stat().st_mode & 0o077 or not re.fullmatch(r"[a-f0-9]{32}", nonce)
            or gateway != "lemonbox-gateway"
            or guest_endpoint(state)["guest_ip"] != guest_ip
            or not 1024 <= port <= 65535):
        raise ValueError("Invalid owned relay settings")
    vm = VM(SimpleNamespace(profile=profile, state_dir=state))
    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stop.set())
    clients = set()
    processes = set()
    workers = set()
    mutex = threading.Lock()
    limit = threading.BoundedSemaphore(32)
    command = ["podman", "exec", "-i", gateway, "nc", "-N", guest_ip, "22"]
    path = state / "access-relay.json"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener, local_listener(vm) as local:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(32)
        listener.settimeout(0.5)
        info = {"pid": os.getpid(), "start_ticks": _process(os.getpid())["ticks"], "nonce": nonce, "port": port}
        write_private_json(path, info)
        try:
            while not stop.is_set():
                ready, _, _ = select.select([listener, local], [], [], 0.5)
                if not ready:
                    continue
                for accepted in ready:
                    client, _ = accepted.accept()
                    if not limit.acquire(blocking=False):
                        client.close()
                        continue
                    with mutex:
                        clients.add(client)
                    def forward(connection, registration):
                        try:
                            if registration:
                                serve_connection(vm, connection)
                            else:
                                forward_connection(connection, command, processes=processes,
                                                   process_lock=mutex, stop_event=stop)
                        finally:
                            with mutex:
                                clients.discard(connection)
                                workers.discard(threading.current_thread())
                            limit.release()
                    worker = threading.Thread(target=forward, args=(client, accepted is local))
                    with mutex:
                        workers.add(worker)
                    worker.start()
        finally:
            stop.set()
            with mutex:
                for client in clients:
                    with suppress(OSError):
                        client.shutdown(socket.SHUT_RDWR)
                    client.close()
                active = list(processes)
                threads = list(workers)
            for process in active:
                if process.poll() is None:
                    with suppress(ProcessLookupError):
                        process.terminate()
            deadline = time.monotonic() + 3
            for process in active:
                try:
                    process.wait(timeout=max(0.01, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            deadline = time.monotonic() + 3
            for worker in threads:
                worker.join(timeout=max(0.01, deadline - time.monotonic()))
            if _private_json(path) == info:
                path.unlink()


if __name__ == "__main__":
    if len(sys.argv) != 8 or sys.argv[1] != "relay":
        raise SystemExit("This module runs the owner's local SSH relay")
    serve(sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]), sys.argv[6], sys.argv[7])
