#!/usr/bin/env python3
"""External VM gateway: fixed transport, packet tunnel, expiring kernel lease."""

import argparse
import contextlib
import fcntl
import ipaddress
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
import math

from vm.route_contract import (
    GATEWAY_NFT_TABLE, LEASE_SECONDS, SOCKS_PORT,
)

STATE = Path("/run/lemon")
TABLE = GATEWAY_NFT_TABLE
PROBE_SECONDS = 12
VERIFY_SECONDS = 20
CHECK_INTERVAL = 5
NFT_TIMEOUT = 2
RENEWAL_MARGIN = 2 * NFT_TIMEOUT + 1
RECOVERY_DELAYS = (5, 15)
SLOW_RECOVERY_SECONDS = 60
RECOVERY_ALERT_SECONDS = 180
RECOVERY_STABLE_SECONDS = 300


class RecoveryBlocked(OSError):
    """An operator or a security check superseded this recovery attempt."""


def packet_module():
    name = "lemon_packet_gateway"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name("packet.py"))
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


class Config:
    def __init__(self, env=None):
        env = os.environ if env is None else env
        supported = {"LEMON_PROXY_CONFIG", "LEMON_MIHOMO_BINARY", "LEMON_FIRST_HOP_IP", "LEMON_FIRST_HOP_PORT",
                     "LEMON_FINAL_HOP_IP", "LEMON_FINAL_HOP_PORT", "LEMON_EXPECTED_EXIT_IP",
                     "LEMON_STARTUP_TIMEOUT", "LEMON_WIREGUARD_CONFIG"}
        if any(name.startswith("LEMON_") and name not in supported for name in env):
            raise ValueError("unsupported gateway setting")
        self.proxy_path = Path(env.get("LEMON_PROXY_CONFIG", "/etc/lemon/private/proxy.json"))
        self.binary = env.get("LEMON_MIHOMO_BINARY", "/etc/lemon/private/mihomo")
        self.uplink = None
        route_settings = ("LEMON_FIRST_HOP_IP", "LEMON_FIRST_HOP_PORT", "LEMON_FINAL_HOP_IP",
                          "LEMON_FINAL_HOP_PORT", "LEMON_EXPECTED_EXIT_IP")
        if any(not env.get(name) for name in route_settings):
            raise ValueError("Missing fixed route settings; launch the gateway through lemonbox")
        self.first_ip = str(ipaddress.IPv4Address(env["LEMON_FIRST_HOP_IP"]))
        self.first_port = int(env["LEMON_FIRST_HOP_PORT"])
        self.exit_ip = str(ipaddress.IPv4Address(env["LEMON_EXPECTED_EXIT_IP"]))
        self.final_ip = str(ipaddress.IPv4Address(env["LEMON_FINAL_HOP_IP"]))
        self.final_port = int(env["LEMON_FINAL_HOP_PORT"])
        if not all(1 <= p <= 65535 for p in (self.first_port, self.final_port)):
            raise ValueError("invalid proxy port")
        self.startup_seconds = int(env.get("LEMON_STARTUP_TIMEOUT", "120"))
        if not 15 <= self.startup_seconds <= 600:
            raise ValueError("startup timeout must be between15 and600 seconds")
        path = Path(env.get("LEMON_WIREGUARD_CONFIG", "/etc/lemon/private/wireguard.json"))
        self.packet_settings = packet_module().PacketSettings.from_file(path)

    def validate_profile(self):
        """Reject routing features capable of changing either pinned hop."""
        data = json.loads(self.proxy_path.read_text())
        allowed = {"socks-port", "bind-address", "allow-lan", "mode", "log-level", "ipv6", "dns",
                   "proxies", "rules"}
        if not isinstance(data, dict) or set(data) - allowed:
            raise ValueError("proxy profile contains unsupported global settings")
        required = {"socks-port": SOCKS_PORT, "bind-address": "127.0.0.1", "allow-lan": False,
                    "mode": "rule", "ipv6": False, "rules": ["MATCH,VIRCS"]}
        if any(data.get(key) != value for key, value in required.items()):
            raise ValueError("proxy profile does not use the isolated fixed routing policy")
        if data.get("dns") != {"enable": False}:
            raise ValueError("proxy internal DNS must be disabled")
        nodes = data.get("proxies")
        if not isinstance(nodes, list) or len(nodes) != 2 or not all(isinstance(node, dict) for node in nodes):
            raise ValueError("exactly two pinned HY2 nodes are required")
        by_name = {node.get("name"): node for node in nodes}
        if set(by_name) != {"usproxy", "VIRCS"}:
            raise ValueError("proxy names must be usproxy and VIRCS")
        node_keys = {"name", "type", "server", "port", "password", "sni", "skip-cert-verify", "udp", "dialer-proxy"}
        for name, ip, port, dialer in (("usproxy", self.first_ip, self.first_port, None),
                                       ("VIRCS", self.final_ip, self.final_port, "usproxy")):
            node = by_name[name]
            if (set(node) - node_keys or node.get("type") != "hysteria2" or node.get("server") != ip
                    or node.get("port") != port or node.get("dialer-proxy") != dialer
                    or not isinstance(node.get("password"), str) or not node["password"]
                    or "REPLACE_" in node["password"]):
                raise ValueError("proxy node violates the fixed chain")
        return data


def command(args, *, input_text=None):
    timeout = NFT_TIMEOUT if args[0] == "nft" else 10
    result = subprocess.run(args, input=input_text, text=True, capture_output=True, check=False, timeout=timeout)
    if result.returncode:
        # Never include arbitrary Mihomo/config output, which can contain credentials.
        if args[0] in ("ip", "nft"):
            raise RuntimeError(f"{args[0]} failed: {result.stderr.strip()[:500]}")
        raise RuntimeError(f"{Path(args[0]).name} failed")
    return result.stdout


def write_state(name, value):
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = STATE / (name + ".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True) + "\n")
    temporary.chmod(0o600)
    temporary.replace(STATE / name)


@contextlib.contextmanager
def state_lock():
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (STATE / "state.lock").open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def install_firewall(config, *, initial=False):
    exists = subprocess.run(["nft", "list", "table", "inet", TABLE], capture_output=True).returncode == 0
    if initial and exists and not recovery_authorized():
        raise RecoveryBlocked("existing kernel recovery authorization was revoked")
    prefix = f"delete table inet {TABLE}\n" if exists else ""
    policy = packet_module().firewall(config, config.packet_settings, registered_guests())
    command(["nft", "-f", "-"], input_text=prefix + policy)


def renew_lease(config, *, guest=False, initial=False, recovery_token=None):
    commands = [f"flush set inet {TABLE} transport_ready",
                f"add element inet {TABLE} transport_ready {{ {config.first_ip} timeout {LEASE_SECONDS}s }}"]
    with state_lock():
        guests = registered_guests()
        addresses = [record["guest_cidr"].split("/")[0] for record in guests]
        if guest:
            commands.append(f"flush set inet {TABLE} guest_ready")
            if addresses:
                commands.append(f"add element inet {TABLE} guest_ready {{ " + ", ".join(
                    address + f" timeout {LEASE_SECONDS}s" for address in addresses) + " }")
        if recovery_token is not None:
            require_recovery(recovery_token)
        elif (STATE / "blocked.json").exists():
            raise OSError("gateway is latched closed")
        if not initial or guest:
            leases = read_leases()
            if not lease_live(leases.get("transport_ready", []), config.first_ip):
                raise OSError("expired transport lease cannot be reopened")
            if guest and not initial and any(not lease_live(leases.get("guest_ready", []), address) for address in addresses):
                raise OSError("expired running gateway lease cannot be reopened")
            # Deletion requires the old elements to still exist when nft
            # commits. A scheduler pause between this read and the transaction
            # cannot turn an expired lease into a fresh authorization.
            required = [f"delete element inet {TABLE} transport_ready {{ {config.first_ip} }}"]
            if guest and not initial and addresses:
                required.append(f"delete element inet {TABLE} guest_ready {{ " + ", ".join(addresses) + " }")
            commands = required + commands
        command(["nft", "-f", "-"], input_text="\n".join(commands) + "\n")


def recovery_state(status, attempts=0, *, reason=None, error_type=None):
    value = {"schema": 1, "status": status, "time": time.time(), "attempts": attempts,
             "retrying": status == "recovering" or (status == "failed" and reason in ("retry_exhausted", "runtime_failure"))}
    if reason is not None:
        value["reason"] = reason
    if error_type is not None:
        value["error_type"] = error_type
    try:
        write_state("recovery.json", value)
    except OSError:
        print("gateway recovery status could not be persisted", file=sys.stderr, flush=True)


def recovery_stopped(attempts):
    """An in-flight retry status must not outlive a terminal CAS rejection."""
    with state_lock():
        try:
            value = json.loads((STATE / "recovery.json").read_text())
        except (OSError, ValueError):
            value = {}
        if (isinstance(value, dict) and type(value.get("schema")) is int and value["schema"] == 1
                and value.get("status") in ("blocked", "failed") and value.get("retrying") is False
                and type(value.get("attempts")) is int and value["attempts"] >= 0
                and type(value.get("time")) in (int, float) and math.isfinite(value["time"])):
            return
        # Never reuse arbitrary reason/error metadata from a state file.
        recovery_state("blocked", attempts, reason="recovery_superseded")


def require_recovery(token):
    """Call only under state_lock; a terminal block never owns a retry token."""
    path = STATE / "blocked.json"
    if not path.is_file() or json.loads(path.read_text()).get("recovery_token") != token:
        raise RecoveryBlocked("gateway recovery was superseded")
    if not recovery_authorized():
        raise RecoveryBlocked("kernel recovery authorization was revoked")


def recovery_authorized():
    # The kernel guard is revoked in the same transaction as terminal closure.
    # A full/read-only state filesystem therefore cannot preserve authority in
    # a stale recovery token. Reinstalling policy also requires this guard.
    for item in read_leases().get("recovery_allowed", []):
        value = item.get("elem") if isinstance(item, dict) else item
        value = value.get("val") if isinstance(value, dict) else value
        if (type(value) is int and value == 1) or (type(value) is str and value == "0x00000001"):
            return True
    return False


def block(reason="verification failed"):
    # One nft transaction closes new packets AND established transport/reply flows.
    with state_lock():
        command(["nft", "-f", "-"], input_text=f"flush set inet {TABLE} guest_ready\nflush set inet {TABLE} transport_ready\nflush set inet {TABLE} recovery_allowed\n")
        # Closing the kernel gate must not depend on available disk space.
        # Noninitial renewal rejects the empty sets even if the latch file
        # cannot be persisted.
        try:
            (STATE / "ready.json").unlink(missing_ok=True)
        except OSError:
            print("gateway gate closed; readiness file could not be removed", file=sys.stderr, flush=True)
        try:
            write_state("blocked.json", {"reason": reason, "time": time.time()})
        except OSError:
            print("gateway gate closed; blocked state could not be persisted", file=sys.stderr, flush=True)
        recovery_state("blocked" if reason in ("operator test or shutdown", "gateway stopped") else "failed",
                       reason=reason)


def close_for_recovery(reason="transport or lease failed"):
    """Close first, then issue a token which cannot undo a later terminal block."""
    with state_lock():
        path = STATE / "blocked.json"
        previous = json.loads(path.read_text()) if path.is_file() else {}
        if path.exists() and not previous.get("recovery_token"):
            raise RecoveryBlocked("gateway is terminally blocked")
        if not recovery_authorized():
            raise RecoveryBlocked("kernel recovery authorization was revoked")
        command(["nft", "-f", "-"], input_text=f"flush set inet {TABLE} guest_ready\nflush set inet {TABLE} transport_ready\n")
        (STATE / "ready.json").unlink(missing_ok=True)
        token = previous.get("recovery_token") or secrets.token_hex(16)
        write_state("blocked.json", {"reason": reason, "time": time.time(), "recovery_token": token})
        return token


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError("probe deadline expired")
    return value


def registered_guests():
    path = STATE / "guests.json"
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise OSError("guest registry is unavailable or not private")
    text = path.read_text()
    if len(text) > 16384:
        raise ValueError("guest registry is oversized")
    value = json.loads(text)
    if not isinstance(value, dict) or set(value) != {"guests"}:
        raise ValueError("invalid guest registry")
    return packet_module().guest_records(value["guests"])


def discover_uplink(config):
    records = json.loads(command(["ip", "-j", "route", "get", config.first_ip]))
    if not isinstance(records, list) or len(records) != 1:
        raise OSError("fixed underlay route is ambiguous")
    uplink = records[0].get("dev")
    if (not isinstance(uplink, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,15}", uplink)
            or uplink in ("lo", packet_module().INTERFACE)):
        raise OSError("fixed underlay route has no physical interface")
    config.uplink = uplink


def update_guest_policy(guests, seconds, *, transport=None):
    """Publish registration and its bounded leases in one kernel transaction."""
    elements = packet_module().registration_elements(guests)
    statements = []
    for name, values in elements.items():
        statements.append(f"flush set inet {TABLE} {name}")
        if values:
            statements.append(f"add element inet {TABLE} {name} {{ " + ", ".join(values) + " }")
    statements.append(f"flush set inet {TABLE} guest_ready")
    if seconds > 0 and elements["guest_addresses"]:
        entries = [address + f" timeout {seconds}s" for address in elements["guest_addresses"]]
        statements.append(f"add element inet {TABLE} guest_ready {{ " + ", ".join(entries) + " }")
    if transport is not None:
        statements.insert(0, f"delete element inet {TABLE} transport_ready {{ {transport} }}")
        statements.extend([f"flush set inet {TABLE} transport_ready",
                           f"add element inet {TABLE} transport_ready {{ {transport} timeout {LEASE_SECONDS}s }}"])
    command(["nft", "-f", "-"], input_text="\n".join(statements) + "\n")


def change_guest(config, value, *, remove=False):
    record = packet_module().guest_record(value)
    changed = False
    try:
        with state_lock():
            previous = registered_guests()
            exact = record in previous
            if any((item["tap"] == record["tap"] or item["guest_cidr"] == record["guest_cidr"])
                   and item != record for item in previous):
                raise ValueError("guest registration collides with another VM")
            ready = json.loads((STATE / "ready.json").read_text()) if (STATE / "ready.json").is_file() else {}
            if record["tap"] == ready.get("uplink"):
                raise ValueError("guest TAP cannot use the physical uplink")
            if exact and not remove:
                packet_module().verify_guest(record)
                return {"registered": True, "guest": record}
            if not exact and remove:
                packet_module().delete_guest(record)
                return {"removed": True, "guest": record}
            guests = [item for item in previous if item != record] if remove else previous + [record]
            packet_module().guest_records(guests)
            leases = read_leases()
            transport = [item.get("elem", {}) for item in leases.get("transport_ready", []) if isinstance(item, dict)]
            expiry = [item["expires"] for item in transport if item.get("val") == config.first_ip
                      and type(item.get("expires")) in (int, float) and 0 < item["expires"] <= LEASE_SECONDS]
            active = (not (STATE / "blocked.json").exists() and bool(expiry)
                      and all(lease_live(leases.get("guest_ready", []), item["guest_cidr"].split("/")[0]) for item in previous))
            seconds = math.floor(min(expiry)) - 1 if active else 0
            if not remove:
                if not ready.get("uplink") or seconds <= CHECK_INTERVAL + RENEWAL_MARGIN + NFT_TIMEOUT:
                    raise OSError("shared route has no healthy registration lease")
                packet_module().create_guest(record)
                # TAP creation never grants traffic. Recheck the physical lease
                # before publishing; registration cannot reopen an expired gate.
                transport = read_leases().get("transport_ready", [])
                expiry = [item["elem"]["expires"] for item in transport
                          if item.get("elem", {}).get("val") == config.first_ip
                          and type(item.get("elem", {}).get("expires")) in (int, float)
                          and 0 < item["elem"]["expires"] <= LEASE_SECONDS]
                if not expiry:
                    packet_module().delete_guest(record)
                    raise OSError("shared transport lease expired during registration")
                seconds = math.floor(min(expiry)) - 1
                if seconds <= NFT_TIMEOUT + 1:
                    packet_module().delete_guest(record)
                    raise OSError("shared lease has no publication margin")
            changed = True
            update_guest_policy(guests, seconds)
            write_state("guests.json", {"guests": guests})
    except Exception:
        if changed:
            block("guest registration failed")
        raise
    if remove:
        packet_module().delete_guest(record)
    return {"removed" if remove else "registered": True, "guest": record}


def observed_exit(config, host="1.1.1.1", *, deadline=None):
    """Native verified HTTPS, bound to WireGuard with DNS and proxies bypassed."""
    deadline = time.monotonic() + PROBE_SECONDS if deadline is None else deadline
    budget = remaining(deadline)
    args = ["curl", "-q", "--silent", "--show-error", "--fail", "--ipv4", "--noproxy", "*",
            "--interface", str(config.packet_settings.client_address.ip),
            "--resolve", "one.one.one.one:443:" + host,
            "--max-time", str(budget), "--max-filesize", "65536",
            "--write-out", "\n%{http_code}", "https://one.one.one.one/cdn-cgi/trace"]
    try:
        result = subprocess.run(args, text=True, capture_output=True, timeout=budget + .1)
        if result.returncode or len(result.stdout) > 65540:
            raise OSError("native exit verification failed")
        body, status = result.stdout.rsplit("\n", 1)
        addresses = [line[3:].strip() for line in body.splitlines() if line.startswith("ip=")]
        if status != "200" or len(addresses) != 1:
            raise OSError("invalid native exit verification response")
        return str(ipaddress.IPv4Address(addresses[0]))
    except subprocess.TimeoutExpired:
        error = TimeoutError("native exit verification deadline expired")
        error.probe_stage = "native_curl"
        raise error from None
    except (OSError, ValueError) as error:
        error.probe_stage = "native_curl"
        raise


def verify_exit(config, *, deadline=None):
    # Service outages may use the second TLS address; a wrong IP
    # never gets another attempt or a lease renewal. The primary gets at most
    # 12 seconds; the second uses what remains of one overall budget.
    started = time.monotonic()
    deadline = started + VERIFY_SECONDS if deadline is None else deadline
    failure = None
    failures = []
    hosts = ("1.1.1.1", "1.0.0.1")
    for index, host in enumerate(hosts):
        try:
            remaining(deadline)
            endpoint_deadline = min(deadline, time.monotonic() + PROBE_SECONDS) if index == 0 else deadline
            observed = observed_exit(config, host, deadline=endpoint_deadline)
            remaining(deadline)
        except (OSError, ValueError) as exc:
            failure = exc
            failures.append({"endpoint": host, "stage": getattr(exc, "probe_stage", "deadline"),
                             "error_type": type(exc).__name__})
            continue
        if observed != config.exit_ip:
            raise ValueError("observed public exit does not match the pinned address")
        return observed
    error = OSError("public exit could not be verified")
    error.probe_failures = failures
    error.probe_budget_seconds = max(0, deadline - started)
    raise error from failure


def verify_health(config):
    """Finish verification while kernel leases still leave time for renewal."""
    started = time.monotonic()
    leases = read_leases()
    required = [("transport_ready", config.first_ip)] + [("guest_ready", record["guest_cidr"].split("/")[0]) for record in registered_guests()]
    seconds = []
    for name, address in required:
        values = [item.get("elem", {}) for item in leases.get(name, []) if isinstance(item, dict)]
        # The pinned nftables release reports JSON timeout/expiry in seconds.
        expiry = [value["expires"] for value in values
                  if value.get("val") == address and type(value.get("expires")) in (int, float)
                  and 0 < value["expires"] <= LEASE_SECONDS]
        if not expiry:
            raise OSError("gateway kernel lease expired")
        seconds.append(min(expiry))
    deadline = min(time.monotonic() + VERIFY_SECONDS, started + min(seconds) - RENEWAL_MARGIN)
    remaining(deadline)
    return verify_exit(config, deadline=deadline)


def lease_live(elements, expected):
    for item in elements:
        element = item.get("elem", {}) if isinstance(item, dict) else {}
        if element.get("val") == expected and isinstance(element.get("expires"), (int, float)) and element["expires"] > 0:
            return True
    return False


def read_leases():
    leases = json.loads(command(["nft", "-j", "list", "table", "inet", TABLE]))
    ready_sets = {}
    for entry in leases.get("nftables", []):
        value = entry.get("set", {})
        if value.get("name") in ("guest_ready", "transport_ready", "recovery_allowed"):
            ready_sets[value["name"]] = value.get("elem", [])
    return ready_sets


def check(config, *, local=False):
    if (STATE / "blocked.json").exists() or not (STATE / "ready.json").exists():
        raise OSError("gateway is not ready")
    ready_sets = read_leases()
    guests = registered_guests()
    if (not lease_live(ready_sets.get("transport_ready", []), config.first_ip)
            or any(not lease_live(ready_sets.get("guest_ready", []), record["guest_cidr"].split("/")[0]) for record in guests)):
        raise OSError("gateway kernel lease expired")
    ready = json.loads((STATE / "ready.json").read_text())
    os.kill(int(ready["mihomo_pid"]), 0)
    os.kill(int(ready["wireguard_pid"]), 0)
    os.kill(int(ready["stream_pid"]), 0)
    with socket.create_connection(("127.0.0.1", SOCKS_PORT), timeout=1):
        pass
    if not local:
        try:
            config.validate_profile()
            verify_exit(config)
        except ValueError:
            block()
            raise
        except (OSError, RuntimeError, subprocess.SubprocessError):
            close_for_recovery()
            raise
    return {"ready": True, "mode": "packet", "guests": guests, "expected_exit_ip": config.exit_ip,
            "first_hop": f"{config.first_ip}:{config.first_port}/udp", "lease_seconds": LEASE_SECONDS}


def publish_ready(config, token, children, attempts):
    """The verified route may reopen only its latest registered, owned TAPs."""
    with state_lock():
        require_recovery(token)
        guests = registered_guests()
        for record in guests:
            packet_module().verify_guest(record)
        if any(children[name].poll() is not None for name in ("proxy", "wireguard", "carrier")):
            raise OSError("network transport exited before publication")
        transport = read_leases().get("transport_ready", [])
        if not any(item.get("elem", {}).get("val") == config.first_ip
                   and type(item.get("elem", {}).get("expires")) in (int, float)
                   and NFT_TIMEOUT + 1 < item["elem"]["expires"] <= LEASE_SECONDS
                   for item in transport if isinstance(item, dict)):
            raise OSError("bootstrap lease expired before publication")
        # Registration can change during verification. Rebuild its sets and
        # guest leases from this locked read, preserving a concurrent detach.
        update_guest_policy(guests, LEASE_SECONDS, transport=config.first_ip)
        write_state("ready.json", {"mihomo_pid": children["proxy"].pid,
                    "wireguard_pid": children["wireguard"].pid, "stream_pid": children["carrier"].pid,
                    "uplink": config.uplink, "time": time.time(), "expected_exit_ip": config.exit_ip})
        recovery_state("healthy", attempts)
        (STATE / "blocked.json").unlink()


def stop_children(children):
    stopped = True
    for name in ("carrier", "proxy", "wireguard"):
        child = children.get(name)
        if child is not None:
            try:
                packet_module()._stop(child)
            except (OSError, subprocess.SubprocessError):
                stopped = False
    return stopped


def run_transport(config, token, stopping, children, attempts, started):
    config.validate_profile()
    discover_uplink(config)
    with state_lock():
        require_recovery(token)
        for record in registered_guests():
            packet_module().verify_guest(record)
        install_firewall(config)
    # Only the private tunnel and its exact policy rules are recreated. TAPs
    # remain open in the same namespace, including the guest SSH path.
    packet_module().reset_network(config.packet_settings)
    children["wireguard"] = packet_module().start_wireguard(config.packet_settings, stopping=stopping)
    packet_module().setup_network(config.packet_settings)
    write_state("firewall-ready.json", {"uplink": config.uplink, "time": time.time()})
    command([config.binary, "-t", "-f", str(config.proxy_path), "-d", str(STATE)])
    renew_lease(config, initial=True, recovery_token=token)
    children["proxy"] = subprocess.Popen([config.binary, "-f", str(config.proxy_path), "-d", str(STATE)],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    listener_deadline = time.monotonic() + 15
    while not stopping.is_set():
        try:
            with socket.create_connection(("127.0.0.1", SOCKS_PORT), timeout=.5):
                break
        except OSError:
            if children["proxy"].poll() is not None or time.monotonic() >= listener_deadline:
                raise OSError("proxy listener startup failed")
            stopping.wait(.1)
    if stopping.is_set():
        return
    renew_lease(config, recovery_token=token)
    children["carrier"] = packet_module().start_stream(config.packet_settings)
    startup_deadline = time.monotonic() + config.startup_seconds
    while not stopping.is_set():
        if children["proxy"].poll() is not None or children["wireguard"].poll() is not None:
            raise OSError("network transport exited")
        if time.monotonic() >= startup_deadline:
            raise OSError("proxy startup verification timed out")
        if attempts > 3 or time.monotonic() - started >= RECOVERY_ALERT_SECONDS:
            recovery_state("failed", attempts, reason="retry_exhausted")
        if children["carrier"].poll() is not None:
            children["carrier"].wait(timeout=3)
            renew_lease(config, recovery_token=token)
            if stopping.wait(.5):
                return
            print("retrying fixed framed route during startup", flush=True)
            children["carrier"] = packet_module().start_stream(config.packet_settings)
            continue
        try:
            verify_exit(config, deadline=min(startup_deadline, time.monotonic() + VERIFY_SECONDS))
            break
        except ValueError:
            raise
        except OSError:
            if time.monotonic() >= startup_deadline:
                raise OSError("proxy startup verification timed out")
            renew_lease(config, recovery_token=token)
            stopping.wait(1)
    if stopping.is_set():
        return
    publish_ready(config, token, children, attempts)
    children["ready_since"] = time.monotonic()
    print("gateway ready; IPv4 packets use WireGuard over the pinned chain", flush=True)
    while not stopping.wait(CHECK_INTERVAL):
        if (any(children[name].poll() is not None for name in ("proxy", "wireguard", "carrier"))
                or (STATE / "blocked.json").exists()):
            raise OSError("proxy transport stopped or gateway was blocked")
        verify_health(config)
        renew_lease(config, guest=True)
        write_state("last-health.json", {"time": time.time(), "expected_exit_ip": config.exit_ip})


def serve(config):
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    stopping = threading.Event()
    signal.signal(signal.SIGTERM, lambda signum, frame: stopping.set())
    signal.signal(signal.SIGINT, lambda signum, frame: stopping.set())
    attempts = 0
    started = time.monotonic()
    had_failure = False
    try:
        with state_lock():
            if not (STATE / "guests.json").exists():
                write_state("guests.json", {"guests": []})
            discover_uplink(config)
            install_firewall(config, initial=True)
        config.validate_profile()
        token = close_for_recovery("startup verification")
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        if not isinstance(exc, RecoveryBlocked):
            try:
                block("gateway startup failed")
            except (OSError, RuntimeError, subprocess.SubprocessError):
                pass
        recovery_state("blocked" if isinstance(exc, RecoveryBlocked) else "failed", reason="startup_failed",
                       error_type=type(exc).__name__)
        while not stopping.wait(1):
            pass
        return
    while not stopping.is_set():
        children = {}
        attempts += 1
        exhausted = attempts > 3 or time.monotonic() - started >= RECOVERY_ALERT_SECONDS
        recovery_state("failed" if exhausted else "recovering", attempts,
                       reason="retry_exhausted" if exhausted else "same_route_retry")
        terminal = False
        try:
            run_transport(config, token, stopping, children, attempts, started)
        except RecoveryBlocked:
            recovery_stopped(attempts)
            terminal = True
        except ValueError as exc:
            try:
                block("fixed route validation failed")
            except (OSError, RuntimeError, subprocess.SubprocessError):
                pass
            recovery_state("failed", attempts, reason="fixed_route_validation_failed", error_type=type(exc).__name__)
            terminal = True
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            now = time.monotonic()
            if children.get("ready_since") is not None and (not had_failure or now - children["ready_since"] >= RECOVERY_STABLE_SECONDS):
                attempts = 0
                started = now
            had_failure = True
            try:
                token = close_for_recovery()
            except RecoveryBlocked:
                recovery_stopped(attempts)
                terminal = True
            except (OSError, RuntimeError, subprocess.SubprocessError):
                # Never bootstrap if the gate could not be confirmed closed.
                recovery_state("failed", attempts, reason="gate_close_failed")
                terminal = True
            if not terminal:
                failures = getattr(exc, "probe_failures", None)
                if failures is not None:
                    try:
                        write_state("health-failure.json", {"time": time.time(), "attempts": failures,
                            "budget_seconds": round(exc.probe_budget_seconds, 3), "maximum_budget_seconds": VERIFY_SECONDS})
                    except OSError:
                        pass
                exhausted = attempts >= 3 or now - started >= RECOVERY_ALERT_SECONDS
                recovery_state("failed" if exhausted else "recovering", attempts,
                               reason="retry_exhausted" if exhausted else "runtime_failure", error_type=type(exc).__name__)
        finally:
            # Shutdown closes before stopping children. Runtime failures have
            # already closed; a terminal operator/security block owns its state.
            try:
                if stopping.is_set():
                    try:
                        block("gateway stopped")
                    except (OSError, RuntimeError, subprocess.SubprocessError):
                        recovery_state("failed", attempts, reason="gate_close_failed")
            finally:
                if not stop_children(children):
                    recovery_state("failed", attempts, reason="transport_cleanup_failed")
                    terminal = True
        if terminal:
            # Preserve the namespace and management path for operator repair.
            while not stopping.wait(1):
                pass
            return
        if stopping.is_set():
            return
        delay = RECOVERY_DELAYS[max(0, attempts - 1)] if attempts < 3 and attempts > 0 else (5 if attempts == 0 else SLOW_RECOVERY_SECONDS)
        if stopping.wait(delay):
            return


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("serve", "check", "audit", "block", "validate-profile", "add-guest", "remove-guest"))
    parser.add_argument("--local", action="store_true")
    args = parser.parse_args()
    config = Config()
    if args.action in ("add-guest", "remove-guest"):
        text = sys.stdin.read(1025)
        if len(text) > 1024:
            raise ValueError("guest registration is oversized")
        print(json.dumps(change_guest(config, json.loads(text), remove=args.action == "remove-guest")))
    elif args.action == "serve":
        serve(config)
    elif args.action == "check":
        print(json.dumps(check(config, local=args.local), sort_keys=True))
    elif args.action == "audit":
        print(command(["nft", "list", "table", "inet", TABLE]), end="")
    elif args.action == "block":
        block("operator test or shutdown")
        print("gateway blocked; management SSH remains available")
    else:
        config.validate_profile()
        print("fixed proxy profile is valid")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        # All RuntimeError messages are constructed here; arbitrary Mihomo
        # stderr and private profile contents are never included.
        detail = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
        print(f"gateway operation failed ({detail}); networking remains closed", file=sys.stderr)
        sys.exit(1)
