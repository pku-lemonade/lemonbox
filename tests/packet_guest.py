#!/usr/bin/env python3
"""Measure the guest's native packet path using bounded real network probes."""
import argparse
import datetime
import errno
import http.client
import ipaddress
import json
import os
import re
import secrets
import signal
import socket
import ssl
import struct
import subprocess
import time


TARGET = "1.1.1.1"
TLS_HOST = "cloudflare-dns.com"
TCP_INFO_RTT_OFFSET = 68
DEADLINE = None


def remaining(cap=15, deadline=None):
    available = min(DEADLINE, deadline or DEADLINE) - time.monotonic()
    if available <= 0:
        raise TimeoutError("packet probe budget expired")
    return min(cap, available)


def check(name, passed, detail):
    return {"name": name, "status": "pass" if passed else "fail", "detail": detail}


def failure(error):
    detail = {"error_type": type(error).__name__}
    if isinstance(error, OSError) and error.errno is not None:
        detail["errno"] = error.errno
    if hasattr(error, "code") and isinstance(error.code, int):
        detail["http_status"] = error.code
    return detail


def tcp_trace(expected):
    results = []
    started = time.monotonic()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
        raw.settimeout(remaining(12))
        raw.connect((TARGET, 443))
        connected = time.monotonic()
        info = raw.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104)
        rtt_us = struct.unpack_from("=I", info, TCP_INFO_RTT_OFFSET)[0]
        connect_ms = (connected - started) * 1000
        results.append(check("remote_tcp_acknowledgment_rtt", rtt_us > 0,
                             {"target": TARGET, "rtt_us": rtt_us, "rtt_ms": rtt_us / 1000,
                              "connect_ms": round(connect_ms, 3), "measurement_only": True,
                              "method": "Linux TCP_INFO tcpi_rtt at byte offset 68 after connect"}))
        raw.settimeout(remaining(15))
        with ssl.create_default_context().wrap_socket(raw, server_hostname=TLS_HOST) as tls:
            tls.sendall(("GET /cdn-cgi/trace HTTP/1.1\r\nHost: " + TLS_HOST +
                         "\r\nConnection: close\r\nAccept: text/plain\r\n\r\n").encode("ascii"))
            response = http.client.HTTPResponse(tls)
            response.begin()
            body = response.read(65537)
            trace = dict(line.split("=", 1) for line in body.decode("ascii").splitlines() if "=" in line)
            observed = str(ipaddress.IPv4Address(trace.get("ip", "")))
            results.append(check("native_tls_trace_exit", response.status == 200 and len(body) <= 65536 and observed == expected,
                                 {"target": TARGET, "tls_hostname": TLS_HOST,
                                  "certificate_verified": True, "http_status": response.status,
                                  "observed_exit_ip": observed, "expected_exit_ip": expected,
                                  "tls_version": tls.version(), "elapsed_ms": round((time.monotonic() - started) * 1000, 3)}))
    return results


def ttl_one(gateway='10.77.0.1'):
    started = time.monotonic()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
        connection.settimeout(remaining(8))
        try:
            connection.connect((TARGET, 443))
        except OSError as error:
            evidence = subprocess.run(["ping", "-n", "-c", "1", "-t", "1", "-W", "2", TARGET],
                                      text=True, capture_output=True, timeout=5,
                                      env=dict(os.environ, LC_ALL="C"))
            expired = evidence.returncode == 1 and bool(re.search(
                r"From " + re.escape(gateway) + r"\b[^\n]*Time to live exceeded", evidence.stdout))
            return check("ttl_one_cannot_connect_remote_tcp", expired,
                         {"target": TARGET, "ttl": 1, "remote_connection_completed": False, "ttl_expiry_observed": expired,
                          "elapsed_ms": round((time.monotonic() - started) * 1000, 3), **failure(error)})
    return check("ttl_one_cannot_connect_remote_tcp", False,
                 {"target": TARGET, "ttl": 1, "remote_connection_completed": True})


def ping(payload, *, timeout=10):
    completed = subprocess.run(["ping", "-n", "-c", "2", "-i", "0.3", "-W", "3", "-w", "8",
                                "-M", "do", "-s", str(payload), TARGET],
                               text=True, capture_output=True, timeout=remaining(timeout),
                               env=os.environ | {"LC_ALL": "C"})
    return completed.returncode, completed.stdout + completed.stderr


def mtu_checks(mtu):
    payload = mtu - 28
    cached_mtu = None
    oversized_rejected = False
    rejection = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.setsockopt(socket.IPPROTO_IP, getattr(socket, "IP_MTU_DISCOVER", 10), 2)
        connection.settimeout(remaining(3))
        connection.connect((TARGET, 53))
        cached_mtu = connection.getsockopt(socket.IPPROTO_IP, getattr(socket, "IP_MTU", 14))
        try:
            connection.send(bytes(mtu - 27))
        except OSError as error:
            oversized_rejected = error.errno == errno.EMSGSIZE
            rejection = failure(error)
    if mtu == 1500:
        measured = cached_mtu == mtu and oversized_rejected
        results = [check("native_packet_path_mtu", measured,
                         {"target": TARGET, "kernel_ip_mtu": cached_mtu, "expected_path_mtu": mtu,
                          "df_oversized_ipv4_packet_bytes": mtu + 1,
                          "oversized_socket_rejected_with_emsgsize": oversized_rejected, **rejection})]
    else:
        code, output = ping(1472)
        escaped = re.escape(str(mtu))
        announced = bool(re.search(r"mtu\s*[= :]\s*" + escaped + r"\b", output, re.I))
        fragmentation = "Frag needed" in output or "message too long" in output.lower()
        details = {"target": TARGET, "payload_bytes": 1472, "ipv4_packet_bytes": 1500,
                   "expected_path_mtu": mtu, "kernel_ip_mtu": cached_mtu, "mtu_announced": announced,
                   "fragmentation_needed_or_cached_pmtu_error": fragmentation,
                   "ping_exit_code": code, "output": output[-1500:]}
        results = [check("native_packet_path_mtu", code != 0 and (announced or cached_mtu == mtu) and fragmentation, details)]
    code, output = ping(payload)
    statistics = re.search(r"(\d+) packets transmitted, (\d+) received", output)
    transmitted, received = map(int, statistics.groups()) if statistics else (None, None)
    results.append(check("tunnel_mtu_sized_icmp_echo", code == 0 and received is not None and received > 0,
                         {"target": TARGET, "payload_bytes": payload, "ipv4_packet_bytes": mtu,
                          "transmitted": transmitted, "received": received,
                          "ping_exit_code": code, "output": output[-1500:]}))
    return results


def padded_stun_packet(size=1472):
    if not 24 <= size <= 4096 or size % 4:
        raise ValueError("STUN request size must be an aligned datagram from24 through4096")
    transaction = secrets.token_bytes(12)
    attributes = struct.pack("!HH", 0xffff, size - 24) + bytes(size - 24)
    return struct.pack("!HHI", 1, len(attributes), 0x2112A442) + transaction + attributes, transaction


def stun_address(response, transaction):
    if len(response) < 20:
        raise ValueError("short STUN response")
    kind, length, magic = struct.unpack_from("!HHI", response)
    if (kind != 0x0101 or magic != 0x2112A442 or response[8:20] != transaction
            or length > len(response) - 20 or length % 4):
        raise ValueError("invalid STUN response")
    offset = 20
    while offset + 4 <= length + 20:
        tag, size = struct.unpack_from("!HH", response, offset)
        offset += 4
        if offset + size > length + 20:
            raise ValueError("invalid STUN attribute boundary")
        value = response[offset:offset + size]
        if tag == 0x0020 and len(value) >= 8 and value[1] == 1:
            address = struct.unpack_from("!I", value, 4)[0] ^ 0x2112A442
            return str(ipaddress.IPv4Address(address))
        offset += (size + 3) & ~3
    raise ValueError("STUN response has no IPv4 XOR-MAPPED-ADDRESS")


def large_stun(expected, mtu):
    size = (mtu - 28) // 4 * 4
    query, transaction = padded_stun_packet(size)
    target = socket.getaddrinfo("stun.l.google.com", 19302, socket.AF_INET, socket.SOCK_DGRAM)[0][4]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.setsockopt(socket.IPPROTO_IP, getattr(socket, "IP_MTU_DISCOVER", 10), 2)
        connection.settimeout(remaining(12))
        connection.connect(target)
        cached_mtu = connection.getsockopt(socket.IPPROTO_IP, getattr(socket, "IP_MTU", 14))
        connection.send(query)
        response = connection.recv(4097)
    observed = stun_address(response, transaction)
    return check("mtu_sized_df_stun_udp_exit", len(response) <= 4096 and observed == expected and cached_mtu == mtu,
                 {"target": target[0], "port": target[1], "udp_payload_bytes": len(query),
                  "ipv4_packet_bytes": len(query) + 28, "fragmentation_permitted": False,
                  "kernel_ip_mtu": cached_mtu, "response_bytes": len(response),
                  "transaction_id_matches": response[8:20] == transaction,
                  "observed_exit_ip": observed, "expected_exit_ip": expected,
                  "padding_attribute": "comprehension-optional0xffff"})


def run(args):
    global DEADLINE
    started = time.monotonic()
    DEADLINE = started + 60
    checks = []
    def budget_expired(signum, frame):
        raise TimeoutError("total packet probe budget expired")
    previous = signal.signal(signal.SIGALRM, budget_expired)
    signal.alarm(60)
    try:
        for names, operation in (
                (("remote_tcp_acknowledgment_rtt", "native_tls_trace_exit"), lambda: tcp_trace(args.expected_exit_ip)),
                (("ttl_one_cannot_connect_remote_tcp",), lambda: ttl_one(args.gateway)),
                (("native_packet_path_mtu", "tunnel_mtu_sized_icmp_echo"), lambda: mtu_checks(args.mtu)),
                (("mtu_sized_df_stun_udp_exit",), lambda: large_stun(args.expected_exit_ip, args.mtu))):
            try:
                remaining()
                values = operation()
                checks.extend(values if isinstance(values, list) else [values])
            except (OSError, ValueError, http.client.HTTPException, subprocess.SubprocessError) as error:
                checks.extend(check(name, False, failure(error)) for name in names)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    return {"schema": 1, "kind": "native_packet_path",
            "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "passed": len(checks) == 6 and all(item["status"] == "pass" for item in checks),
            "expected_exit_ip": args.expected_exit_ip, "expected_tunnel_mtu": args.mtu,
            "elapsed_seconds": round(time.monotonic() - started, 3), "maximum_guest_seconds": 60,
            "method": "guest-native sockets, verified TLS, Linux TCP_INFO, kernel IP_MTU, DF ping and padded STUN; no proxy client",
            "checks": checks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-exit-ip", required=True)
    parser.add_argument("--mtu", type=int, default=1500)
    parser.add_argument("--gateway", default="10.77.0.1")
    args = parser.parse_args()
    args.expected_exit_ip = str(ipaddress.IPv4Address(args.expected_exit_ip))
    if not 576 <= args.mtu <= 1500:
        parser.error("packet MTU probe requires an MTU from 576 through1500")
    report = run(args)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
