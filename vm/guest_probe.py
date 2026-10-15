#!/usr/bin/env python3
"""Run bounded native-guest checks and emit credential-free JSON."""
import argparse
import datetime
import errno
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import struct
import subprocess
import time
import urllib.request


PROXY_KEYS = {"http_proxy", "https_proxy", "all_proxy", "no_proxy", "ftp_proxy"}


def command(argv, timeout=30):
    try:
        result = subprocess.run(argv, text=True, capture_output=True, timeout=timeout)
        return result.returncode, result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return 124, ""


def result(name, passed, detail=None):
    return {"name": name, "status": "pass" if passed else "fail", "detail": detail or {}}


def stun_request():
    transaction = secrets.token_bytes(12)
    return struct.pack("!HHI", 0x0001, 0, 0x2112A442) + transaction, transaction


def stun_address(data, transaction):
    if len(data) < 20:
        raise ValueError("short STUN response")
    kind, length, magic = struct.unpack_from("!HHI", data)
    if kind != 0x0101 or magic != 0x2112A442 or data[8:20] != transaction or length > len(data) - 20:
        raise ValueError("invalid STUN response")
    offset = 20
    while offset + 4 <= length + 20:
        tag, size = struct.unpack_from("!HH", data, offset)
        offset += 4
        if offset + size > length + 20:
            raise ValueError("STUN attribute exceeds declared message")
        value = data[offset:offset + size]
        if len(value) != size:
            raise ValueError("short STUN attribute")
        if tag in (0x0020, 0x0001) and len(value) >= 8 and value[1] == 1:
            address = struct.unpack_from("!I", value, 4)[0]
            if tag == 0x0020:
                address ^= 0x2112A442
            return str(ipaddress.IPv4Address(address))
        offset += (size + 3) & ~3
    raise ValueError("no IPv4 STUN mapping")


def dns_request(name="example.com"):
    identifier = secrets.randbelow(65536)
    question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", identifier, 0x0100, 1, 0, 0, 0) + question + struct.pack("!HH", 1, 1), identifier


def dns_valid(data, identifier):
    if len(data) < 12:
        return False
    response_id, flags, questions, answers, _, _ = struct.unpack_from("!HHHHHH", data)
    return response_id == identifier and bool(flags & 0x8000) and flags & 0x000F == 0 and questions == 1 and answers > 0


def recv_exact(connection, length):
    data = bytearray()
    while len(data) < length:
        chunk = connection.recv(length - len(data))
        if not chunk:
            raise OSError("connection closed")
        data.extend(chunk)
    return bytes(data)


def dns_probe(server, tcp=False):
    request, identifier = dns_request()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as connection:
        connection.settimeout(15)
        connection.connect((server, 53))
        if tcp:
            connection.sendall(struct.pack("!H", len(request)) + request)
            length = struct.unpack("!H", recv_exact(connection, 2))[0]
            response = recv_exact(connection, length)
        else:
            connection.send(request)
            response = connection.recv(4096)
    return dns_valid(response, identifier)


def public_exit(url):
    # Ignore proxy environment variables: this tests the guest's ordinary
    # network path, not an application-specific proxy handler.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=30) as response:
        content = response.read(512).decode("ascii").strip()
    return str(ipaddress.IPv4Address(content))


def socket_rejected(address, port):
    try:
        with socket.create_connection((address, port), timeout=3):
            return False
    except OSError as error:
        if error.errno == errno.ECONNREFUSED:
            return True
        raise


def icmp_checks(gateway='10.77.0.1'):
    """Require actual echo replies and first-hop TTL expiry on a packet route."""
    target = "1.1.1.1"
    checks = []
    environment = dict(os.environ, LC_ALL="C")
    for name, ttl, count in (("icmp_policy", None, 2), ("icmp_ttl_one_expires", 1, 1)):
        arguments = ["ping", "-n", "-c", str(count), "-W", "3", "-w", "10"]
        if ttl is not None:
            arguments.extend(["-t", str(ttl)])
        arguments.append(target)
        try:
            completed = subprocess.run(arguments, text=True, capture_output=True,
                                       env=environment, timeout=15)
            output = completed.stdout
            statistics = re.search(r"(\d+) packets transmitted, (\d+) received", output)
            transmitted, received = (map(int, statistics.groups()) if statistics else (None, None))
            if ttl is None:
                passed = completed.returncode == 0 and transmitted == count and received == count
                detail = {"policy": "working", "target": target,
                          "transmitted": transmitted, "received": received}
            else:
                expires = bool(re.search(r"From " + re.escape(gateway) + r"\b[^\n]*Time to live exceeded", output))
                passed = completed.returncode == 1 and transmitted == 1 and received == 0 and expires
                detail = {"target": target, "ttl": 1, "expired_at_gateway": expires,
                          "gateway": gateway, "received_echo_replies": received}
        except (OSError, subprocess.TimeoutExpired):
            passed, detail = False, {"target": target, "reason": "ICMP probe failed"}
        checks.append(result(name, passed, detail))
    return checks


def timer_probe():
    """Exercise a real transient system timer, then remove its runtime state."""
    unit = "lemon-validation-" + secrets.token_hex(4)
    marker = "/run/" + unit + ".done"
    code, _ = command(["sudo", "-n", "systemd-run", "--unit=" + unit,
                       "--on-active=1s", "--collect", "/usr/bin/touch", marker])
    try:
        if code != 0:
            return False
        for _ in range(30):
            code, _ = command(["sudo", "-n", "test", "-f", marker])
            if code == 0:
                return True
            time.sleep(1)
        return False
    finally:
        command(["sudo", "-n", "systemctl", "stop", unit + ".timer", unit + ".service"])
        command(["sudo", "-n", "rm", "-f", marker])


def run(args):
    checks = []
    code, init_state = command(["cloud-init", "status", "--format", "json"])
    try:
        cloud_status = json.loads(init_state).get("status")
    except (ValueError, AttributeError):
        cloud_status = "unavailable"
    ready_valid = code == 0 and cloud_status == "done"
    checks.append(result("cloud_init_complete", ready_valid, {"state": cloud_status}))
    try:
        pid1 = Path("/proc/1/comm").read_text().strip()
    except OSError:
        pid1 = "unavailable"
    checks.append(result("systemd_pid1", pid1 == "systemd", {"pid1": pid1}))
    container_code, _ = command(["systemd-detect-virt", "--container"])
    vm_code, vm_type = command(["systemd-detect-virt", "--vm"])
    checks.append(result("independent_guest_kernel", container_code == 1 and vm_code == 0,
                         {"virtualization": vm_type, "kernel": os.uname().release}))
    code, boot_state = command(["systemctl", "is-system-running"])
    checks.append(result("systemd_boot_state", code == 0 and boot_state == "running", {"state": boot_state}))
    code, _ = command(["systemctl", "is-active", "systemd-journald"])
    checks.append(result("journald_active", code == 0))
    code, entry = command(["sudo", "-n", "journalctl", "--directory=/var/log/journal", "-n", "1", "--output=json", "--quiet"])
    try:
        stored_entry = json.loads(entry)
    except ValueError:
        stored_entry = None
    checks.append(result("journal_persistent_storage", code == 0 and isinstance(stored_entry, dict)))
    code, _ = command(["systemctl", "is-enabled", "ssh"])
    checks.append(result("ssh_enabled_at_boot", code == 0))
    if args.reboot_evidence:
        code, boots = command(["sudo", "-n", "journalctl", "--list-boots", "--quiet", "--no-pager"])
        boot_count = len([line for line in boots.splitlines() if re.match(r"\s*-?\d+\s+[a-f0-9]{32}\s", line)])
        checks.append(result("journal_survived_reboot", code == 0 and boot_count >= 2, {"recorded_boots": boot_count}))
    proxy_keys = sorted(key for key, value in os.environ.items() if key.lower() in PROXY_KEYS and value)
    checks.append(result("no_guest_proxy_environment", not proxy_keys, {"configured_keys": proxy_keys}))
    proxy_ports = []
    for port in (1080, 7890):
        if not socket_rejected("127.0.0.1", port):
            proxy_ports.append(port)
    checks.append(result("no_guest_proxy_listener", not proxy_ports, {"listening_ports": proxy_ports}))
    code, timezone = command(["timedatectl", "show", "--property=Timezone", "--value"])
    checks.append(result("guest_timezone", code == 0 and timezone == args.timezone, {"timezone": timezone}))
    code, locale = command(["locale", "-a"])
    language = os.environ.get("LANG", "")
    checks.append(result("guest_english_locale", bool(re.match(r"en_US[.\-]", language, re.I)) and "en_us" in locale.lower(),
                         {"language": language}))
    claude = shutil.which("claude")
    if not claude and (Path.home() / ".local/bin/claude").is_file():
        claude = str(Path.home() / ".local/bin/claude")
    code, version_output = command([claude, "--version"] if claude else ["/nonexistent"])
    version = re.search(r"\b\d+\.\d+\.\d+\b", version_output)
    checks.append(result("native_claude", code == 0 and bool(version), {"version": version.group() if version else None}))
    code, uid = command(["sudo", "-n", "id", "-u"])
    checks.append(result("guest_root_access", code == 0 and uid == "0"))
    if args.root_checks:
        if ready_valid and container_code == 1 and vm_code == 0:
            namespace = "lemon-validation-" + secrets.token_hex(4)
            code, _ = command(["sudo", "-n", "ip", "netns", "add", namespace])
            try:
                checks.append(result("guest_root_network_namespace", code == 0))
            finally:
                command(["sudo", "-n", "ip", "netns", "del", namespace])
            checks.append(result("systemd_timer_execution", timer_probe()))
        else:
            checks.append(result("guest_root_network_namespace", False, {"reason": "unverified_guest"}))
            checks.append(result("systemd_timer_execution", False, {"reason": "unverified_guest"}))
    if args.docker:
        code, _ = command(["sudo", "-n", "systemctl", "is-active", "docker"])
        checks.append(result("docker_daemon", code == 0))
        code, engine_version = command(["sudo", "-n", "docker", "info", "--format", "{{.ServerVersion}}"], 60)
        engine_valid = bool(re.fullmatch(r"[0-9]+(?:\.[0-9]+)+(?:[+~\-][a-zA-Z0-9.+~\-]+)?", engine_version))
        checks.append(result("docker_engine", code == 0 and engine_valid,
                             {"version": engine_version if engine_valid else None}))
        if args.docker_image:
            code, _ = command(["sudo", "-n", "docker", "run", "--rm", "--network", "bridge", args.docker_image,
                               "sh", "-c", "wget -qO- https://api.ipify.org"], 600)
            # The command output is checked separately rather than discarded.
            checks.append(result("docker_bridge_exit", code == 0 and _ == args.expected_exit_ip,
                                 {"observed_exit_ip": _ if re.fullmatch(r"\d+(?:\.\d+){3}", _) else None}))
            code, digests = command(["sudo", "-n", "docker", "image", "inspect", args.docker_image,
                                     "--format", "{{json .RepoDigests}}"])
            digest_values = sorted(set(re.findall(r"sha256:[a-f0-9]{64}", digests)))
            checks.append(result("docker_image_digest_recorded", code == 0 and bool(digest_values),
                                 {"digests": digest_values}))
    if args.network:
        for name, url in (("https_exit_ipify", "https://api.ipify.org"), ("https_exit_ifconfig", "https://ifconfig.me/ip")):
            try:
                observed = public_exit(url)
                checks.append(result(name, observed == args.expected_exit_ip, {"observed_exit_ip": observed}))
            except (OSError, ValueError, UnicodeError):
                checks.append(result(name, False, {"reason": "request_failed"}))
        code, addresses = command(["getent", "ahostsv4", "example.com"])
        checks.append(result("system_dns", code == 0 and bool(addresses)))
        for name, tcp in (("udp_dns", False), ("tcp_dns", True)):
            try:
                passed = dns_probe(args.dns_server, tcp)
            except OSError:
                passed = False
            checks.append(result(name, passed, {"server": args.dns_server}))
        try:
            request, transaction = stun_request()
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
                connection.settimeout(15)
                connection.connect((args.stun_host, args.stun_port))
                connection.send(request)
                observed = stun_address(connection.recv(2048), transaction)
            checks.append(result("udp_stun_exit", observed == args.expected_exit_ip, {"observed_exit_ip": observed}))
        except (OSError, ValueError):
            checks.append(result("udp_stun_exit", False, {"reason": "request_failed"}))
        checks.extend(icmp_checks(args.gateway))
        code, _ = command(["curl", "-6", "--noproxy", "*", "--connect-timeout", "5", "--max-time", "10", "https://api64.ipify.org"], 15)
        checks.append(result("ipv6_external_blocked", code != 0 and code != 124, {"policy": "blocked"}))
    return {"schema": 1, "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "passed": all(check["status"] == "pass" for check in checks), "checks": checks,
            "limitations": ["IPv6 is blocked; private-destination policy requires host-side counter evidence",
                            "VM detection and service-provider account acceptance are not hidden by routing"]}


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--expected-exit-ip", required=True)
    value.add_argument("--gateway", default="10.77.0.1")
    value.add_argument("--timezone", required=True)
    value.add_argument("--network", action="store_true")
    value.add_argument("--root-checks", action="store_true")
    value.add_argument("--reboot-evidence", action="store_true", help="Require journal entries from at least two real guest boots")
    value.add_argument("--docker", action="store_true")
    value.add_argument("--docker-image", help="Explicit Linux image for a real Docker bridge egress test")
    value.add_argument("--dns-server", default="1.1.1.1")
    value.add_argument("--stun-host", default="stun.l.google.com")
    value.add_argument("--stun-port", type=int, default=19302)
    return value


if __name__ == "__main__":
    arguments = parser().parse_args()
    ipaddress.IPv4Address(arguments.expected_exit_ip)
    ipaddress.IPv4Address(arguments.gateway)
    report = run(arguments)
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 1)
