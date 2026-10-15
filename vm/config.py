"""Separate VM settings from the single private route shared by every VM."""
from copy import deepcopy
import base64
import binascii
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import tempfile
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .sharing import validate_shares
from .route_contract import SOCKS_PORT, packet_settings


VM_DEFAULTS = {
    "username": "debian", "hostname": "lemonbox", "timezone": "America/Los_Angeles",
    "cpus": 2, "memory_mib": 4096, "disk_gib": 24,
    "desktop": True, "docker": True,
}

def _object(value, allowed, field, required=()):
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    if set(value) - set(allowed):
        raise ValueError(f"{field} contains an unknown setting")
    if set(required) - set(value):
        raise ValueError(f"{field} is missing a required setting")
    return value


def _integer(value, low, high, field):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{field} must be an integer from {low} to {high}")
    return value


def _boolean(value, field):
    if type(value) is not bool:
        raise ValueError(f"{field} must be true or false")
    return value


def _text(value, field, maximum=255):
    if (not isinstance(value, str) or not value or len(value) > maximum
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError(f"{field} must be nonempty text without control characters")
    return value


def _ipv4(value, field):
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a numeric IPv4 address")
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError:
        raise ValueError(f"{field} must be a numeric IPv4 address") from None


def _hostname(value, field, maximum=253):
    value = _text(value, field, maximum)
    if not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
               for label in value.split(".")):
        raise ValueError(f"{field} must be a valid hostname")
    return value


def _node(value, field, allow_placeholder):
    keys = {"server", "port", "password", "sni", "skip_cert_verify"}
    _object(value, keys, field, required=keys)
    result = deepcopy(value)
    result["server"] = _ipv4(value["server"], field + ".server")
    result["port"] = _integer(value["port"], 1, 65535, field + ".port")
    result["password"] = _text(value["password"], field + ".password", 4096)
    if not allow_placeholder and "REPLACE_" in result["password"]:
        raise ValueError(f"Set the private {field}.password before setup")
    _hostname(value["sni"], field + ".sni")
    result["skip_cert_verify"] = _boolean(value["skip_cert_verify"], field + ".skip_cert_verify")
    return result


def _wireguard_key(value, field, allow_placeholder):
    if allow_placeholder and isinstance(value, str) and value.startswith("REPLACE_"):
        return value
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a base64 WireGuard key")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError(f"{field} must be a base64 WireGuard key") from None
    if (len(decoded) != 32 or not any(decoded)
            or base64.b64encode(decoded).decode("ascii") != value):
        raise ValueError(f"{field} must be a base64 WireGuard key")
    return value


def _wireguard(value, allow_placeholder):
    fields = {"client_private_key", "server_public_key"}
    _object(value, fields, "wireguard", required=fields)
    return {field: _wireguard_key(value[field], "wireguard." + field, allow_placeholder)
            for field in fields}


def _unique_json(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Configuration contains a duplicate setting")
        result[key] = value
    return result


def _read_json(path, require_private=True):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("Configuration must be a regular file")
    if require_private and (path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077):
        raise ValueError("Configuration must be owned by you with mode 0600")
    try:
        return json.loads(path.read_text(), object_pairs_hook=_unique_json)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ValueError("Configuration must contain valid UTF-8 JSON") from None


def write_private_json(path, data):
    write_private_text(path, json.dumps(data, indent=2) + "\n")


def write_private_text(path, text):
    """Atomically write a private file; never follow an existing destination symlink."""
    path = Path(path)
    if path.is_symlink():
        raise ValueError("Private configuration paths must not be symlinks")
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + "-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as target:
            target.write(text)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


class Config:
    """Per-VM settings contain no route credentials or transport artifacts."""

    @classmethod
    def load(cls, path, *, require_private=True, require_sources=True):
        return cls.from_dict(_read_json(path, require_private), require_sources=require_sources)

    @classmethod
    def from_dict(cls, data, *, require_sources=True):
        _object(data, {"version", "vm", "desktop", "shares"}, "config", required={"version"})
        if type(data["version"]) is not int or data["version"] != 1:
            raise ValueError("Unsupported configuration version; expected 1")
        vm = dict(VM_DEFAULTS)
        vm.update(_object(data.get("vm", {}), VM_DEFAULTS, "vm"))
        if (not isinstance(vm["username"], str) or vm["username"] == "root"
                or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", vm["username"])):
            raise ValueError("vm.username must be a normal Linux account name")
        _hostname(vm["hostname"], "vm.hostname", 63)
        _text(vm["timezone"], "vm.timezone", 128)
        try:
            ZoneInfo(vm["timezone"])
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError("vm.timezone must be an installed IANA time zone") from None
        _integer(vm["cpus"], 1, 64, "vm.cpus")
        _integer(vm["memory_mib"], 2048, 131072, "vm.memory_mib")
        _integer(vm["disk_gib"], 8, 512, "vm.disk_gib")
        _boolean(vm["desktop"], "vm.desktop")
        _boolean(vm["docker"], "vm.docker")

        desktop = {"port": 5901}
        desktop.update(_object(data.get("desktop", {}), desktop, "desktop"))
        _integer(desktop["port"], 1024, 65535, "desktop.port")

        shares = data.get("shares", [])
        if not isinstance(shares, list):
            raise ValueError("shares must be a list")
        normalized = validate_shares(shares, username=vm["username"], require_sources=require_sources)
        result = cls()
        result.vm, result.desktop, result.shares = vm, desktop, normalized
        result._require_sources = require_sources
        return result

    def as_dict(self):
        return deepcopy({"version": 1, "vm": self.vm, "desktop": self.desktop, "shares": self.shares})

    def write(self, path):
        # Recheck fields edited after loading before saving the VM settings.
        validated = Config.from_dict(self.as_dict(), require_sources=self._require_sources)
        write_private_json(path, validated.as_dict())


class RouteConfig:
    """The one validated fixed route; repr never includes credential contents."""

    @classmethod
    def load(cls, path, *, allow_placeholder=False, require_private=True):
        return cls.from_dict(_read_json(path, require_private), allow_placeholder=allow_placeholder)

    @classmethod
    def from_dict(cls, data, *, allow_placeholder=False):
        _object(data, {"version", "network", "wireguard"}, "route", required={"version", "network", "wireguard"})
        if type(data['version']) is not int or data['version'] != 1:
            raise ValueError('Unsupported route configuration version; expected 1')
        network = _object(data['network'], {'first_hop', 'exit_hop', 'expected_exit_ip'}, 'network',
                          required={'first_hop', 'exit_hop', 'expected_exit_ip'})
        result = cls()
        result.network = {
            'first_hop': _node(network['first_hop'], 'network.first_hop', allow_placeholder),
            'exit_hop': _node(network['exit_hop'], 'network.exit_hop', allow_placeholder),
            'expected_exit_ip': _ipv4(network['expected_exit_ip'], 'network.expected_exit_ip'),
        }
        result.wireguard = _wireguard(data['wireguard'], allow_placeholder)
        return result

    def as_dict(self):
        return deepcopy({'version': 1, 'network': self.network, 'wireguard': self.wireguard})

    def write(self, path):
        validated = RouteConfig.from_dict(self.as_dict())
        write_private_json(path, validated.as_dict())

    def mihomo_profile(self):
        nodes = []
        for name, key in (("usproxy", "first_hop"), ("VIRCS", "exit_hop")):
            value = self.network[key]
            node = {"name": name, "type": "hysteria2", "server": value["server"],
                    "port": value["port"], "password": value["password"], "sni": value["sni"],
                    "skip-cert-verify": value["skip_cert_verify"], "udp": True}
            if name == "VIRCS":
                node["dialer-proxy"] = "usproxy"
            nodes.append(node)
        profile = {"log-level": "warning", "mode": "rule", "ipv6": False, "allow-lan": False,
                "bind-address": "127.0.0.1", "socks-port": SOCKS_PORT, "dns": {"enable": False},
                "proxies": nodes, "rules": ["MATCH,VIRCS"]}
        return profile

    def render_proxy(self, path):
        write_private_json(path, self.mihomo_profile())

    def wireguard_profile(self):
        return packet_settings() | deepcopy(self.wireguard)

    def render_wireguard(self, path):
        write_private_json(path, self.wireguard_profile())

    def gateway_env(self):
        result = {"LEMON_FIRST_HOP_IP": self.network["first_hop"]["server"],
                "LEMON_FIRST_HOP_PORT": str(self.network["first_hop"]["port"]),
                "LEMON_FINAL_HOP_IP": self.network["exit_hop"]["server"],
                "LEMON_FINAL_HOP_PORT": str(self.network["exit_hop"]["port"]),
                "LEMON_EXPECTED_EXIT_IP": self.network["expected_exit_ip"]}
        result.update(LEMON_WIREGUARD_CONFIG="/etc/lemon/private/wireguard.json")
        return result

    def network_digest(self):
        """Fingerprint both transport credentials and the public exit pin."""
        values = {"network": self.network, "wireguard": self.wireguard}
        canonical = json.dumps(values, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(canonical).hexdigest()
