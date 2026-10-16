"""Route complete IPv4 packets through WireGuard outside the guest.

wireguard-go supplies only the WireGuard TUN device and encryption. Linux
forwards the guest's original TCP/UDP/ICMP packets; no TCP stack terminates them
here. A framed TCP stream carries encrypted datagrams through the pinned SOCKS
route to the exit server's loopback WireGuard listener.
"""

import base64
import binascii
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import tempfile
import time

from vm.route_contract import (
    BLOCKED_IPV4, GATEWAY_NFT_TABLE, GUEST_IP, GUEST_POOL, MAX_GUESTS,
    LEASE_SECONDS, MANAGEMENT_MARK, ROUTE_MARK, ROUTE_TABLE, SOCKS_PORT,
    WG_CLIENT_ADDRESS, WG_ENDPOINT_PORT, WG_INTERFACE, WG_MTU,
    WG_SERVER_IP, WG_STREAM_PORT,
)


STATE = Path("/run/lemon")
WIREGUARD_STATE = Path("/run/wireguard")
INTERFACE = WG_INTERFACE
TABLE = GATEWAY_NFT_TABLE


def _key(value):
    """Reject malformed keys without including their contents in exceptions."""
    if not isinstance(value, str) or len(value) != 44:
        raise ValueError("invalid WireGuard key")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("invalid WireGuard key") from None
    if (len(decoded) != 32 or not any(decoded)
            or base64.b64encode(decoded).decode("ascii") != value):
        raise ValueError("invalid WireGuard key")
    return value


class PacketSettings:
    """Validated private packet-tunnel configuration; repr never exposes keys."""

    __slots__ = ("client_private_key", "server_public_key", "client_address",
                 "server_address", "endpoint_port", "mtu",
                 "transport", "stream_port")

    @classmethod
    def from_mapping(cls, data):
        fields = set(cls.__slots__)
        if not isinstance(data, dict) or set(data) != fields:
            raise ValueError("invalid WireGuard configuration fields")
        settings = cls()
        settings.transport = data["transport"]
        settings.stream_port = data["stream_port"]
        if settings.transport != "stream":
            raise ValueError("invalid WireGuard carrier")
        if type(settings.stream_port) is not int or settings.stream_port != WG_STREAM_PORT:
            raise ValueError("invalid stream port")
        settings.client_private_key = _key(data["client_private_key"])
        settings.server_public_key = _key(data["server_public_key"])
        if not isinstance(data["client_address"], str) or not isinstance(data["server_address"], str):
            raise ValueError("invalid WireGuard tunnel addresses")
        try:
            settings.client_address = ipaddress.IPv4Interface(data["client_address"])
            settings.server_address = ipaddress.IPv4Address(data["server_address"])
        except (ValueError, TypeError):
            raise ValueError("invalid WireGuard tunnel addresses") from None
        settings.endpoint_port = data["endpoint_port"]
        if type(settings.endpoint_port) is not int or settings.endpoint_port != WG_ENDPOINT_PORT:
            raise ValueError("invalid WireGuard port")
        if (str(settings.client_address) != WG_CLIENT_ADDRESS
                or str(settings.server_address) != WG_SERVER_IP):
            raise ValueError("WireGuard addresses differ from the route contract")
        if type(data["mtu"]) is not int or data["mtu"] != WG_MTU:
            raise ValueError("invalid WireGuard MTU")
        settings.mtu = data["mtu"]
        return settings

    @classmethod
    def from_file(cls, path):
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                raise ValueError("WireGuard configuration must be a private regular file")
            try:
                content = handle.read(4097)
            except UnicodeError:
                raise ValueError("invalid WireGuard configuration JSON") from None
        if len(content) > 4096:
            raise ValueError("WireGuard configuration is oversized")

        def unique_pairs(pairs):
            result = {}
            for name, value in pairs:
                if name in result:
                    raise ValueError("duplicate WireGuard configuration field")
                result[name] = value
            return result

        try:
            data = json.loads(content, object_pairs_hook=unique_pairs)
        except (UnicodeError, json.JSONDecodeError):
            raise ValueError("invalid WireGuard configuration JSON") from None
        return cls.from_mapping(data)


def command(args):
    result = subprocess.run(args, text=True, capture_output=True, check=False, timeout=10)
    if result.returncode:
        # wg errors and the configuration file can contain private keys.
        # Only ip diagnostics are suitable for an operator-facing error.
        if args[0] == "ip":
            raise RuntimeError(f"ip failed: {result.stderr.strip()[:500]}")
        raise RuntimeError(f"{Path(args[0]).name} failed")
    return result.stdout


def guest_record(value):
    """Canonical, bounded guest allocation accepted only from the host controller."""
    if not isinstance(value, dict) or set(value) != {"tap", "guest_cidr", "gateway_cidr"}:
        raise ValueError("invalid guest registration fields")
    tap = value["tap"]
    if not isinstance(tap, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,15}", tap) or tap in ("lo", INTERFACE):
        raise ValueError("invalid guest TAP")
    try:
        guest = ipaddress.IPv4Interface(value["guest_cidr"])
        gateway = ipaddress.IPv4Interface(value["gateway_cidr"])
    except (ValueError, TypeError):
        raise ValueError("invalid guest addresses") from None
    if (guest.network.prefixlen != 30 or guest.network != gateway.network
            or not guest.network.subnet_of(ipaddress.IPv4Network(GUEST_POOL))
            or int(guest.ip) != int(guest.network.network_address) + 2
            or int(gateway.ip) != int(guest.network.network_address) + 1):
        raise ValueError("guest registration must use a distinct canonical pool /30")
    return {"tap": tap, "guest_cidr": str(guest), "gateway_cidr": str(gateway)}


def guest_records(values):
    if not isinstance(values, list) or len(values) > MAX_GUESTS:
        raise ValueError("invalid guest registry")
    records = [guest_record(value) for value in values]
    if (len({value["tap"] for value in records}) != len(records)
            or len({value["guest_cidr"] for value in records}) != len(records)):
        raise ValueError("guest registration collision")
    return records


def registration_elements(guests):
    records = guest_records(guests)
    return {
        "guest_interfaces": [json.dumps(value["tap"]) for value in records],
        "guest_sources": [json.dumps(value["tap"]) + " . " + value["guest_cidr"].split("/")[0] for value in records],
        "guest_addresses": [value["guest_cidr"].split("/")[0] for value in records],
        "guest_gateways": [value["gateway_cidr"].split("/")[0] for value in records],
    }


def firewall(config, settings, guests):
    """Lease-gated forwarding with no physical-interface forwarding fallback."""
    client = settings.client_address.ip
    max_mss = settings.mtu - 40  # IPv4 header20 +minimum TCP header20.
    blocked = ", ".join(BLOCKED_IPV4)
    elements = registration_elements(guests)
    if not isinstance(config.uplink, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,15}", config.uplink):
        raise ValueError("gateway physical uplink is required")
    registered = "\n".join(
        f'  set {name} {{ type {"ifname . ipv4_addr" if name == "guest_sources" else "ifname" if name == "guest_interfaces" else "ipv4_addr"}; '
        + ("elements = { " + ", ".join(values) + " }; " if values else "") + "}"
        for name, values in elements.items())
    return f"""table inet {TABLE} {{
{registered}
  set transport_ready {{ type ipv4_addr; flags timeout; timeout {LEASE_SECONDS}s; }}
  set guest_ready {{ type ipv4_addr; flags timeout; timeout {LEASE_SECONDS}s; }}
  set recovery_allowed {{ type mark; elements = {{ 1 }}; }}
  chain guest_ingress {{
    type filter hook prerouting priority mangle; policy accept;
    iifname @guest_interfaces meta nfproto != ipv4 counter drop
    iifname @guest_interfaces iifname . ip saddr != @guest_sources counter drop
    iifname @guest_interfaces ip daddr @guest_gateways tcp sport 22 ct mark {MANAGEMENT_MARK} ct state established,related accept
    iifname @guest_interfaces ip daddr {{ {blocked} }} counter drop
    iifname . ip saddr @guest_sources ip saddr @guest_ready meta l4proto {{ tcp, udp, icmp }} meta mark set {ROUTE_MARK} ct mark set {ROUTE_MARK} counter accept
    iifname @guest_interfaces counter drop
  }}
  chain input {{
    type filter hook input priority filter; policy drop;
    iifname \"lo\" accept
    iifname . ip saddr @guest_sources ip daddr @guest_gateways tcp sport 22 ct mark {MANAGEMENT_MARK} ct state established,related accept
    iifname \"{INTERFACE}\" ip daddr {client} meta l4proto {{ tcp, udp, icmp }} ct state established,related accept
    iifname \"{config.uplink}\" ip saddr @transport_ready ip saddr {config.first_ip} udp sport {config.first_port} ct state established,related accept
    counter drop
  }}
  chain forward {{
    type filter hook forward priority filter; policy drop;
    ct state invalid counter drop
    iifname . ip saddr @guest_sources oifname \"{INTERFACE}\" ip saddr @guest_ready tcp flags & syn == syn tcp option maxseg size > {max_mss} tcp option maxseg size set {max_mss} counter
    iifname \"{INTERFACE}\" oifname . ip daddr @guest_sources ip daddr @guest_ready tcp flags & syn == syn tcp option maxseg size > {max_mss} tcp option maxseg size set {max_mss} counter
    iifname . ip saddr @guest_sources oifname \"{INTERFACE}\" ip saddr @guest_ready ct mark {ROUTE_MARK} meta l4proto {{ tcp, udp, icmp }} counter accept
    iifname \"{INTERFACE}\" oifname . ip daddr @guest_sources ip daddr @guest_ready ct mark {ROUTE_MARK} ct state established,related meta l4proto {{ tcp, udp, icmp }} counter accept
    counter drop
  }}
  chain output {{
    type filter hook output priority filter; policy drop;
    oifname \"lo\" accept
    oifname . ip daddr @guest_sources tcp dport 22 ct mark set {MANAGEMENT_MARK} accept
    oifname . ip daddr @guest_sources ip daddr @guest_ready meta l4proto icmp ct state related counter accept
    oifname \"{INTERFACE}\" ip saddr {client} meta l4proto {{ tcp, udp, icmp }} counter accept
    oifname \"{config.uplink}\" ip daddr @transport_ready ip daddr {config.first_ip} udp dport {config.first_port} counter accept
    counter drop
  }}
  chain guest_nat {{
    type nat hook postrouting priority srcnat; policy accept;
    oifname \"{INTERFACE}\" ip saddr @guest_addresses ct mark {ROUTE_MARK} snat ip to {GUEST_IP}
  }}
}}
"""


def _stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def start_wireguard(settings, *, stopping=None):
    """Create the TUN device and peer; keep the private key out of argv/logs."""
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    WIREGUARD_STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    process = subprocess.Popen(["wireguard-go", "-f", INTERFACE], stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    temporary = None
    try:
        deadline = time.monotonic() + 10
        control_socket = WIREGUARD_STATE / (INTERFACE + ".sock")
        while not control_socket.exists():
            if stopping is not None and stopping.is_set():
                raise OSError("WireGuard startup stopped")
            if process.poll() is not None:
                raise OSError("WireGuard process exited during startup")
            if time.monotonic() >= deadline:
                raise OSError("WireGuard control socket startup timed out")
            if stopping is None:
                time.sleep(0.05)
            else:
                stopping.wait(0.05)
        with tempfile.NamedTemporaryFile(mode="w", prefix="wireguard-", suffix=".conf",
                                         dir=STATE, delete=False, encoding="ascii") as handle:
            temporary = Path(handle.name)
            handle.write(f"[Interface]\nPrivateKey = {settings.client_private_key}\n"
                         f"[Peer]\nPublicKey = {settings.server_public_key}\n"
                         "AllowedIPs = 0.0.0.0/0\n"
                         f"Endpoint = 127.0.0.1:{settings.endpoint_port}\n"
                         "PersistentKeepalive = 25\n")
        command(["wg", "setconf", INTERFACE, str(temporary)])
        temporary.unlink()
        temporary = None
        return process
    except BaseException:
        _stop(process)
        raise
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def start_stream(settings):
    """Start the keyless carrier through the fixed local SOCKS listener."""
    args = ["python3", str(Path(__file__).with_name("stream.py")), "client",
            "--listen-port", str(settings.endpoint_port), "--socks-port", str(SOCKS_PORT),
            "--remote-port", str(settings.stream_port)]
    # The carrier emits only fixed lifecycle messages and exception types.
    # Keep those useful diagnostics visible; datagrams and keys are never logged.
    return subprocess.Popen(args, stdin=subprocess.DEVNULL)


def setup_network(settings):
    """Forward marked guest packets and source-bound health checks via wg0."""
    command(["ip", "link", "set", "lo", "up"])
    command(["ip", "addr", "add", str(settings.client_address), "dev", INTERFACE])
    command(["ip", "link", "set", INTERFACE, "mtu", str(settings.mtu), "up"])
    command(["ip", "rule", "add", "priority", "177", "fwmark", str(ROUTE_MARK), "lookup", str(ROUTE_TABLE)])
    command(["ip", "rule", "add", "priority", "178", "from", str(settings.client_address.ip), "lookup", str(ROUTE_TABLE)])
    command(["ip", "route", "add", "default", "dev", INTERFACE, "table", str(ROUTE_TABLE)])
    for name in ("all", "default", INTERFACE):
        for setting in ("rp_filter", "src_valid_mark"):
            path = Path("/proc/sys/net/ipv4/conf") / name / setting
            if path.read_text().strip() != "0":
                raise OSError(f"{setting} must be configured as0 by the container launcher")
    if Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() != "1":
        raise OSError("ip_forward must be configured as1 by the container launcher")


def reset_network(settings):
    """After reaping the tunnel, remove only its device and exact route rules."""
    links = json.loads(command(["ip", "-j", "link", "show"]))
    if any(link.get("ifname") == INTERFACE for link in links):
        command(["ip", "link", "del", "dev", INTERFACE])
    (WIREGUARD_STATE / (INTERFACE + ".sock")).unlink(missing_ok=True)
    for selector in (("177", "fwmark", str(ROUTE_MARK)),
                     ("178", "from", str(settings.client_address.ip))):
        # An absent rule is expected on first startup. All selectors are the
        # immutable private route; guest TAPs and the underlay default stay put.
        result = subprocess.run(["ip", "rule", "del", "priority", *selector, "lookup", str(ROUTE_TABLE)],
                                text=True, capture_output=True, timeout=10)
        if result.returncode not in (0, 2):
            raise RuntimeError("private tunnel rule reset failed")


def create_guest(record):
    record = guest_record(record)
    tap = record["tap"]
    command(["ip", "tuntap", "add", "dev", tap, "mode", "tap", "user", str(os.getuid())])
    try:
        command(["ip", "addr", "add", record["gateway_cidr"], "dev", tap])
        command(["ip", "link", "set", tap, "up"])
        for setting in ("rp_filter", "src_valid_mark"):
            if (Path("/proc/sys/net/ipv4/conf") / tap / setting).read_text().strip() != "0":
                raise OSError("guest TAP kernel policy must match the gateway")
    except BaseException:
        command(["ip", "link", "del", "dev", tap])
        raise


def delete_guest(record):
    record = guest_record(record)
    if not verify_guest(record, absent_ok=True):
        return False
    command(["ip", "link", "del", "dev", record["tap"]])
    return True


def verify_guest(record, *, absent_ok=False):
    record = guest_record(record)
    links = json.loads(command(["ip", "-d", "-j", "link", "show"]))
    matches = [value for value in links if value.get("ifname") == record["tap"]]
    if not matches and absent_ok:
        return False
    if len(matches) != 1:
        raise OSError("registered guest TAP is missing")
    info = matches[0].get("linkinfo", {})
    data = info.get("info_data", {})
    owner = data.get("user")
    expected = (os.getuid(), str(os.getuid()), pwd.getpwuid(os.getuid()).pw_name)
    if info.get("info_kind") != "tun" or data.get("type") != "tap" or type(owner) not in (int, str) or owner not in expected:
        raise OSError("guest interface is not the owned TAP")
    addresses = json.loads(command(["ip", "-j", "addr", "show", "dev", record["tap"]]))
    actual = [value["local"] + "/" + str(value["prefixlen"]) for row in addresses
              for value in row.get("addr_info", []) if value.get("family") == "inet"]
    if actual != [record["gateway_cidr"]]:
        raise OSError("guest TAP address differs from its allocation")
    return True
