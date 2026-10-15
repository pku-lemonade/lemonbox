#!/usr/bin/env python3
"""Offer valid raw guest frames without changing any interface or firewall."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import socket
import struct
import subprocess


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4_packet(source, destination, protocol=17, source_port=42000, destination_port=53):
    source = ipaddress.IPv4Address(source).packed
    destination = ipaddress.IPv4Address(destination).packed
    if protocol == 1:
        payload = struct.pack("!BBHHH", 8, 0, 0, 0x7701, 1) + b"lemon-root-probe"
        payload = payload[:2] + struct.pack("!H", checksum(payload)) + payload[4:]
    elif protocol == 17:
        body = b"lemon-root-probe"
        payload = struct.pack("!HHHH", source_port, destination_port, 8 + len(body), 0) + body
        pseudo = source + destination + struct.pack("!BBH", 0, protocol, len(payload))
        payload = payload[:6] + struct.pack("!H", checksum(pseudo + payload) or 0xFFFF) + payload[8:]
    else:
        payload = b"lemon-root-probe"
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0x7701, 0, 64, protocol, 0, source, destination)
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def ipv6_packet():
    source = ipaddress.IPv6Address("2001:db8::2").packed
    destination = ipaddress.IPv6Address("2606:4700:4700::1111").packed
    body = b"lemon-root-probe"
    udp = struct.pack("!HHHH", 42000, 53, 8 + len(body), 0) + body
    pseudo = source + destination + struct.pack("!I3xB", len(udp), 17)
    udp = udp[:6] + struct.pack("!H", checksum(pseudo + udp) or 0xFFFF) + udp[8:]
    return struct.pack("!IHBB16s16s", 6 << 28, len(udp), 17, 64, source, destination) + udp


def json_command(argv):
    result = subprocess.run(argv, text=True, capture_output=True, timeout=15, check=True)
    return json.loads(result.stdout)


def run(allow_provisioning=False):
    if os.geteuid() != 0:
        raise RuntimeError("a root guest session is required")
    if not allow_provisioning and json_command(["cloud-init", "status", "--format", "json"]).get("status") != "done":
        raise RuntimeError("native cloud-init has not completed")
    vm = subprocess.run(["systemd-detect-virt", "--vm"], capture_output=True, timeout=15)
    container = subprocess.run(["systemd-detect-virt", "--container"], capture_output=True, timeout=15)
    if vm.returncode != 0 or container.returncode != 1:
        raise RuntimeError("not an independent guest kernel")
    routes = json_command(["ip", "-j", "route", "show", "default"])
    routes = [route for route in routes if route.get("gateway")]
    if len(routes) != 1:
        raise RuntimeError("unexpected guest default route")
    interface = routes[0]["dev"]
    gateway = routes[0]["gateway"]
    addresses = json_command(["ip", "-j", "address", "show", "dev", interface])[0]["addr_info"]
    guest_ip = next(item["local"] for item in addresses if item["family"] == "inet")
    spoofed_ip = str(ipaddress.IPv4Address(guest_ip) + 1)
    adjacent_guest = str(ipaddress.IPv4Address(int(ipaddress.IPv4Address(guest_ip)) ^ 4))
    neighbors = json_command(["ip", "-j", "neigh", "show", "to", gateway, "dev", interface])
    neighbors = [entry for entry in neighbors if entry.get("lladdr")]
    if len(neighbors) != 1:
        raise RuntimeError("management gateway neighbor is unavailable")
    target_mac = bytes.fromhex(neighbors[0]["lladdr"].replace(":", ""))
    source_mac = bytes.fromhex((Path("/sys/class/net") / interface / "address").read_text().strip().replace(":", ""))
    frames = [
        ("spoofed_source", 0x0800, ipv4_packet(spoofed_ip, "1.1.1.1")),
        ("spoofed_source", 0x0800, ipv4_packet(adjacent_guest, "1.1.1.1")),
        ("spoofed_source", 0x0800, ipv4_packet("198.51.100.10", gateway, source_port=8443)),
        ("non_ipv4", 0x86DD, ipv6_packet()),
        ("unsupported_protocol", 0x0800, ipv4_packet(guest_ip, "1.1.1.1",
                                                    protocol=253)),
    ]
    frames.append(("spoofed_source", 0x0800, ipv4_packet(spoofed_ip, "1.1.1.1", protocol=1)))
    for destination in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "224.0.0.1", adjacent_guest):
        frames.append(("private_destination", 0x0800, ipv4_packet(guest_ip, destination, destination_port=80)))
        frames.append(("private_destination", 0x0800, ipv4_packet(guest_ip, destination, protocol=1)))
    offered = {}
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)) as connection:
        connection.bind((interface, 0))
        for category, ethertype, packet in frames:
            frame = (target_mac + source_mac + struct.pack("!H", ethertype) + packet).ljust(60, b"\0")
            # Repeat each frame to make its evidence distinct from one incidental
            # packet, while keeping the probe bounded and insignificant in load.
            for _ in range(3):
                if connection.send(frame) != len(frame):
                    raise RuntimeError("incomplete raw frame write")
                offered[category] = offered.get(category, 0) + 1
    return {"schema": 1, "offered_frames": offered,
            "method": "guest-root AF_PACKET with valid IP/UDP/ICMP checksums; no configuration changes"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-provisioning", action="store_true",
                        help="Operator allows raw-frame checks before native cloud-init finishes")
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.allow_provisioning), sort_keys=True))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        print(json.dumps({"schema": 1, "error": "guest raw-frame probe failed"}))
        raise SystemExit(1)
