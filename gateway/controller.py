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


def install_firewall(config):
    exists = subprocess.run(["nft", "list", "table", "inet", TABLE], capture_output=True).returncode == 0
    prefix = f"delete table inet {TABLE}\n" if exists else ""
    policy = packet_module().firewall(config, config.packet_settings, registered_guests())
    command(["nft", "-f", "-"], input_text=prefix + policy)


def renew_lease(config, *, guest=False, initial=False):
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
        if (STATE / "blocked.json").exists():
            raise OSError("gateway is latched closed")
        if not initial or guest:
            leases = read_leases()
            if not lease_live(leases.get("transport_ready", []), config.first_ip):
                raise OSError("expired transport lease cannot be reopened")
            if guest and not initial and any(not lease_live(leases.get("guest_ready", []), address) for address in addresses):
                raise OSError("expired running gateway lease cannot be reopened")
        command(["nft", "-f", "-"], input_text="\n".join(commands) + "\n")


def block(reason="verification failed"):
    # One nft transaction closes new packets AND established transport/reply flows.
    with state_lock():
        command(["nft", "-f", "-"], input_text=f"flush set inet {TABLE} guest_ready\nflush set inet {TABLE} transport_ready\n")
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


def update_guest_policy(guests, seconds):
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
        if value.get("name") in ("guest_ready", "transport_ready"):
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
        config.validate_profile()
        try:
            verify_exit(config)
        except Exception:
            block()
            raise
    return {"ready": True, "mode": "packet", "guests": guests, "expected_exit_ip": config.exit_ip,
            "first_hop": f"{config.first_ip}:{config.first_port}/udp", "lease_seconds": LEASE_SECONDS}


def serve(config):
    config.validate_profile()
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name in ("ready.json", "blocked.json", "firewall-ready.json", "health-failure.json"):
        (STATE / name).unlink(missing_ok=True)
    write_state("guests.json", {"guests": []})
    discover_uplink(config)
    # No guest NIC can be attached before the atomic default-deny installation.
    install_firewall(config)
    stopping = threading.Event()
    process = None
    wireguard = None
    carrier = None
    failure = None

    def stop(signum, frame):
        stopping.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        wireguard = packet_module().start_wireguard(config.packet_settings)
        packet_module().setup_network(config.packet_settings)
        write_state("firewall-ready.json", {"uplink": config.uplink, "time": time.time()})
        command([config.binary, "-t", "-f", str(config.proxy_path), "-d", str(STATE)])
        renew_lease(config, initial=True)
        process = subprocess.Popen([config.binary, "-f", str(config.proxy_path), "-d", str(STATE)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # The proxy starts first. Connecting the keyless carrier requires
        # its SOCKS listener, but guest forwarding remains closed.
        listener_deadline = time.monotonic() + 15
        while True:
            try:
                with socket.create_connection(("127.0.0.1", SOCKS_PORT), timeout=.5):
                    break
            except OSError:
                if process.poll() is not None or time.monotonic() >= listener_deadline or stopping.is_set():
                    raise OSError("proxy listener startup failed")
                stopping.wait(.1)
        # Listener startup and exit verification have separate bounds.
        # Refresh the still-live transport gate before the longer probe;
        # no guest lease exists and an expired gate remains closed.
        renew_lease(config)
        carrier = packet_module().start_stream(config.packet_settings)
        startup_deadline = time.monotonic() + config.startup_seconds
        while not stopping.is_set():
            if process.poll() is not None or wireguard.poll() is not None:
                raise OSError("network transport exited")
            if time.monotonic() >= startup_deadline:
                raise OSError("proxy startup verification timed out")
            if carrier.poll() is not None:
                # SOCKS may acknowledge before the chained HY2 dial finishes.
                # A cold dial can fail while the proxy is still establishing
                # its sessions. Retry only this same fixed carrier during
                # startup: no guest lease has been granted yet.
                carrier.wait(timeout=3)
                renew_lease(config)
                if stopping.wait(.5):
                    return
                print("retrying fixed framed route during startup", flush=True)
                carrier = packet_module().start_stream(config.packet_settings)
                continue
            try:
                verify_exit(config)
                break
            except ValueError:
                raise
            except OSError:
                if time.monotonic() >= startup_deadline:
                    raise OSError("proxy startup verification timed out")
                renew_lease(config)
                stopping.wait(1)
        if stopping.is_set():
            return
        renew_lease(config, guest=True, initial=True)
        with state_lock():
            if (STATE / "blocked.json").exists():
                raise OSError("gateway is latched closed")
            ready = {"mihomo_pid": process.pid, "wireguard_pid": wireguard.pid,
                     "stream_pid": carrier.pid, "uplink": config.uplink,
                     "time": time.time(), "expected_exit_ip": config.exit_ip}
            write_state("ready.json", ready)
        print("gateway ready; IPv4 packets use WireGuard over the pinned chain", flush=True)
        while not stopping.wait(CHECK_INTERVAL):
            if (process.poll() is not None or wireguard.poll() is not None or carrier.poll() is not None
                    or (STATE / "blocked.json").exists()):
                raise OSError("proxy transport stopped or gateway was blocked")
            verify_health(config)
            renew_lease(config, guest=True)
            write_state("last-health.json", {"time": time.time(), "expected_exit_ip": config.exit_ip})
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        failure = type(exc).__name__
        attempts = getattr(exc, "probe_failures", None)
        if attempts is not None:
            # Only endpoint names and stages constructed here are recorded;
            # exception messages and private configuration are never retained.
            try:
                write_state("health-failure.json", {"time": time.time(), "attempts": attempts,
                    "budget_seconds": round(exc.probe_budget_seconds, 3),
                    "maximum_budget_seconds": VERIFY_SECONDS})
            except OSError:
                pass
    finally:
        try:
            block("gateway stopped or verification failed")
        finally:
            for child in (carrier, process, wireguard):
                if child is not None and child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait()
    if failure is not None:
        print(f"gateway latched closed; guest SSH remains available ({failure})", file=sys.stderr, flush=True)
        # Keep the namespace and host management path alive. No transport,
        # lease renewal or automatic recovery occurs in this state.
        while not stopping.wait(1):
            pass


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
