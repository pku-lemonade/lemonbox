"""Everyday guest access over the VM's pinned SSH connection.

The CLI ensures the runtime is running and reconciles shared directories before
calling shell, claude, execute, or vnc. No host environment or account credential
is forwarded to the guest.
"""
from contextlib import contextmanager
import ipaddress
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import time

from .desktop import Desktop


READY_TIMEOUT = 3600


def tailnet_address():
    """Discover an address on the host's running Tailscale network interface."""
    try:
        result = subprocess.run(["tailscale", "status", "--json"], stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        raise RuntimeError("Install Tailscale on this host before using desktop --tailnet") from None
    except subprocess.TimeoutExpired:
        raise RuntimeError("Tailscale status timed out; check tailscale status on this host") from None
    if result.returncode:
        raise RuntimeError("Could not read Tailscale status; check tailscale status on this host")
    try:
        status = json.loads(result.stdout)
    except ValueError:
        raise RuntimeError("Tailscale returned invalid status") from None
    if not isinstance(status, dict):
        raise RuntimeError("Tailscale returned invalid status")
    if status.get("BackendState") != "Running":
        raise RuntimeError("Connect this host to Tailscale before using desktop --tailnet")
    if status.get("TUN") is not True:
        raise RuntimeError("Desktop --tailnet requires Tailscale's network interface; userspace networking is unsupported")
    addresses = status.get("TailscaleIPs")
    for value in addresses if isinstance(addresses, list) else []:
        try:
            address = ipaddress.IPv4Address(value)
        except (ValueError, TypeError):
            continue
        if address in ipaddress.IPv4Network("100.64.0.0/10"):
            return str(address)
    raise RuntimeError("Tailscale has no usable IPv4 address on this host")


@contextmanager
def _tunnel_signals():
    """Run tunnel cleanup when a foreground command loses its terminal or stops."""
    previous = {}

    def stop(signum, frame):
        raise SystemExit(128 + signum)

    try:
        for signum in (signal.SIGHUP, signal.SIGTERM):
            previous[signum] = signal.signal(signum, stop)
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def working_directory(value):
    if value is None:
        return None
    value = str(value)
    if not value.startswith('/') or '\0' in value:
        raise ValueError('Guest working directory must be an absolute path')
    return str(PurePosixPath(value))


class Workflow:
    """User operations; return remote exit codes rather than hiding failures."""

    def __init__(self, vm, workdir=None):
        self.vm = vm
        metadata = json.loads((vm.state / "guest.json").read_text())
        self.profile = metadata["profile"]
        self.username = self.profile["username"]
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", self.username):
            raise ValueError("Invalid guest username in VM metadata")
        self.home = "/home/" + self.username
        self.workdir = working_directory(workdir)

    def ssh_command(self, argv=None, *, tty=False):
        result = ["ssh", "-F", str(self.vm.ssh_config()), "-t" if tty else "-T", "lemonbox"]
        if argv is not None:
            result.append(shlex.join([str(arg) for arg in argv]))
        return result

    def remote(self, argv, *, capture=False, timeout=None, tty=False):
        options = {'text': True, 'capture_output': capture, 'timeout': timeout}
        if capture:
            # Readiness and desktop probes must not consume input intended for
            # the subsequent interactive command or a piped Claude prompt.
            options['stdin'] = subprocess.DEVNULL
        return subprocess.run(self.ssh_command(argv, tty=tty), **options)

    @staticmethod
    def _interactive():
        return sys.stdin.isatty() and sys.stdout.isatty()

    def ready(self, timeout=READY_TIMEOUT, *, check_current=None):
        """Wait for genuine cloud-init completion and the shipped native services."""
        if timeout <= 0:
            raise ValueError("Readiness timeout must be positive")
        machine = self.vm.info(self.vm.machine)
        gateway = self.vm.info(self.vm.gateway)
        if not machine or machine["State"]["Status"] != "running":
            raise RuntimeError("VM is stopped; run lemonbox start")
        if not gateway or gateway["State"]["Status"] != "running":
            raise RuntimeError("Shared gateway is stopped; run lemonbox settings")
        script = (Path(__file__).resolve().parent.parent / "guest/readiness.py").read_text()
        request = json.dumps({"require_docker": bool(self.profile.get("docker"))})
        deadline = time.monotonic() + timeout
        progress_at = 0
        last_state = "waiting for SSH"
        while time.monotonic() < deadline:
            if check_current:
                check_current()
            try:
                remaining = max(0.1, deadline - time.monotonic())
                proc = self.remote(["python3", "-c", script, request], capture=True,
                                    timeout=min(55, remaining))
                snapshot = json.loads(proc.stdout) if proc.returncode == 0 else None
                if not isinstance(snapshot, dict):
                    snapshot = None
            except (ValueError, subprocess.TimeoutExpired):
                snapshot = None
            if check_current:
                check_current()
            if snapshot and snapshot.get("cloud_failed"):
                raise RuntimeError("Guest provisioning failed; run lemonbox shell and inspect cloud-init status")
            if not self.vm.health():
                raise RuntimeError("The gateway is not reporting a ready fixed route. Run lemonbox status for automatic recovery and alert details; lemonbox shell remains available")
            if snapshot:
                last_state = "cloud-init " + str(snapshot.get("cloud_status", "unavailable"))
                required = ("cloud_complete", "ssh_ready", "docker_ready", "claude_ready")
                if all(snapshot.get(key) is True for key in required):
                    return snapshot
                if snapshot.get("cloud_complete"):
                    missing = [key.removesuffix("_ready").replace("system", "systemd")
                               for key in required[1:] if snapshot.get(key) is not True]
                    last_state = "waiting for " + ", ".join(missing)
            now = time.monotonic()
            if now >= progress_at:
                print("Preparing VM: " + last_state + ". First boot downloads software; timing depends on your connection.", file=sys.stderr)
                progress_at = now + 15
            time.sleep(min(2, max(0, deadline - now)))
        raise RuntimeError("VM was not ready within " + str(timeout) + " seconds (" + last_state
                           + "); run lemonbox logs --guest")

    def accessible(self, timeout=60):
        """Wait only for SSH so a failed service or closed route can be repaired."""
        if timeout <= 0:
            raise ValueError("SSH timeout must be positive")
        machine = self.vm.info(self.vm.machine)
        if not machine or machine["State"]["Status"] != "running":
            raise RuntimeError("VM is stopped; run lemonbox start")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remaining = max(0.1, deadline - time.monotonic())
            try:
                if self.remote(["true"], capture=True, timeout=min(10, remaining)).returncode == 0:
                    return
            except (OSError, subprocess.TimeoutExpired):
                pass
            time.sleep(min(1, max(0, deadline - time.monotonic())))
        raise RuntimeError("Guest SSH is unavailable; run lemonbox logs --guest")

    def run_script(self, script, *, args=(), sudo=False, timeout=45):
        """Run an operator script without consuming the user's command stdin."""
        argv = (["sudo", "-n"] if sudo else []) + ["python3", "-", *args]
        return subprocess.run(self.ssh_command(argv), input=script, text=True,
                              capture_output=True, timeout=timeout)

    def _guest_command(self, argv):
        if self.workdir is None:
            return argv
        script = "exec " + shlex.join([str(arg) for arg in argv])
        script = "cd -- " + shlex.quote(self.workdir) + " && " + script
        return ["/bin/bash", "-lc", script]

    def shell(self):
        if self.workdir is None:
            workspace = shlex.quote(self.home + '/workspace')
            command = ['/bin/bash', '-lc',
                       'if [ -d ' + workspace + ' ]; then cd -- ' + workspace +
                       ' || exit; fi; exec /bin/bash --login']
        else:
            command = self._guest_command(["/bin/bash", "--login"])
        return self.remote(command,
                            tty=self._interactive()).returncode

    def claude(self, argv=()):
        noninteractive = any(arg in ("-p", "--print", "-h", "--help", "-v", "--version")
                             or arg.startswith("--print=") for arg in argv)
        return self.remote(self._guest_command([self.home + "/.local/bin/claude", *argv]),
                            tty=self._interactive() and not noninteractive).returncode

    def execute(self, argv):
        if not argv:
            raise ValueError("Provide a command, for example: lemonbox exec git status")
        return self.remote(self._guest_command(argv)).returncode

    def desktop_password(self):
        if not self.profile.get("desktop"):
            raise ValueError("This VM was prepared without the desktop")
        return Desktop(self.vm).password(create=False)

    def vnc(self, port=5901, *, stop=False, open_viewer=False, tailnet=False):
        """Expose the optional desktop through a local or tailnet SSH tunnel."""
        if not self.profile.get("desktop"):
            raise ValueError("This VM was prepared without the desktop")
        if not 1 <= port <= 65535:
            raise ValueError("VNC port must be between 1 and 65535")
        host = tailnet_address() if tailnet and not stop else "127.0.0.1"
        changed = Desktop(self.vm).configure(self) if not stop else False
        action = "stop" if stop else "restart" if changed else "start"
        proc = self.remote(["sudo", "-n", "systemctl", action, "lemon-desktop.service"],
                            capture=True, timeout=45)
        if proc.returncode:
            raise RuntimeError("Could not " + action + " the desktop; inspect sudo systemctl status lemon-desktop inside the VM")
        if stop:
            print("Desktop stopped.", file=sys.stderr)
            return 0
        self._wait_desktop()
        command = ["ssh", "-F", str(self.vm.ssh_config()), "-T", "-N",
                   "-o", "ExitOnForwardFailure=yes", "-L",
                   host + ":" + str(port) + ":127.0.0.1:5900", "lemonbox"]
        open_viewer = open_viewer and not tailnet
        viewer = self._viewer(port) if open_viewer else None
        with _tunnel_signals():
            tunnel = subprocess.Popen(command)
            try:
                self._wait_tunnel(tunnel, port, host=host)
                print("VNC: " + host + ":" + str(port) + " (TigerVNC: " + host + "::" + str(port)
                      + "). Keep this terminal open; Ctrl-C closes the tunnel.", file=sys.stderr)
                print("Use desktop --show-password with the same VM selection to display its VNC password.",
                      file=sys.stderr)
                if tailnet:
                    print("Connect from a device on your tailnet. Tailnet access rules also apply.",
                          file=sys.stderr)
                if open_viewer and not viewer:
                    print("No supported VNC viewer found. Open the address above in your viewer.", file=sys.stderr)
                if viewer:
                    subprocess.Popen(viewer)
                return tunnel.wait()
            except KeyboardInterrupt:
                return 130
            finally:
                if tunnel.poll() is None:
                    tunnel.terminate()
                    try:
                        tunnel.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        tunnel.kill()
                        tunnel.wait()

    def _wait_desktop(self, timeout=45):
        script = "import socket; socket.create_connection(('127.0.0.1',5900),timeout=1).close()"
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remaining = max(0.1, deadline - time.monotonic())
            try:
                if self.remote(["python3", "-c", script], capture=True,
                                timeout=min(12, remaining)).returncode == 0:
                    return
            except subprocess.TimeoutExpired:
                pass
            time.sleep(min(1, max(0, deadline - time.monotonic())))
        raise RuntimeError("Desktop did not open its VNC listener; run lemonbox logs --guest")

    @staticmethod
    def _viewer(port):
        for name in ("vncviewer", "tigervncviewer"):
            path = shutil.which(name)
            if path:
                return [path, "127.0.0.1::" + str(port)]
        for name in ("gvncviewer", "remote-viewer"):
            path = shutil.which(name)
            if path:
                address = "127.0.0.1:" + str(port)
                return [path, "vnc://" + address if name == "remote-viewer" else address]
        return None

    @staticmethod
    def _wait_tunnel(tunnel, port, timeout=15, *, host="127.0.0.1"):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if tunnel.poll() is not None:
                raise RuntimeError("VNC tunnel failed; check whether the local port is already in use")
            try:
                with socket.create_connection((host, port), timeout=0.25):
                    return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("VNC SSH tunnel did not become ready")
