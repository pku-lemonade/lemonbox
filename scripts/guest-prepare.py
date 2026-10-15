#!/usr/bin/env python3
"""Create a private Debian VM overlay, SSH identities and NoCloud seed ISO."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from vm.config import write_private_json, write_private_text
from vm.route_contract import GUEST_DNS, GUEST_POOL


def ensure_key(path, comment):
    public = path.with_name(path.name + ".pub")
    if path.is_symlink() or public.is_symlink():
        raise ValueError("SSH identity paths must not be symlinks")
    if path.exists() != public.exists():
        raise ValueError("An incomplete SSH identity exists; restore it or choose a new state directory")
    if not path.exists():
        with tempfile.TemporaryDirectory(prefix=".identity-", dir=path.parent) as directory:
            private = Path(directory) / "key"
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment,
                            "-f", str(private)], check=True)
            try:
                os.replace(private, path)
                os.replace(private.with_suffix(".pub"), public)
            except BaseException:
                path.unlink(missing_ok=True)
                public.unlink(missing_ok=True)
                raise
    path.chmod(0o600)
    public.chmod(0o600)
    return public.read_text().strip()


def cloud_config(profile, access_key, host_private, host_public):
    user = profile["username"]
    files = [
        # Native provisioning enables the locale listed here.
        {"path": "/etc/locale.gen", "permissions": "0644", "content": "en_US.UTF-8 UTF-8\n"},
        {"path": "/etc/apt/apt.conf.d/90-no-recommends", "permissions": "0644",
         "content": "APT::Install-Recommends \"false\";\n"},
        {"path": "/etc/systemd/resolved.conf.d/20-unicast-dns.conf", "permissions": "0644",
         "content": "[Resolve]\nLLMNR=no\nMulticastDNS=no\n"},
        {"path": "/etc/cloud/cloud.cfg.d/90-static-network.cfg", "permissions": "0644",
         "content": "network:\n  config: disabled\n"},
        {"path": "/usr/local/lib/lemon/provision.sh", "permissions": "0755", "content": (ROOT / "guest/provision.sh").read_text()},
        {"path": "/usr/local/lib/lemon/desktop.sh", "permissions": "0755", "content": (ROOT / "guest/desktop.sh").read_text()},
        {"path": "/etc/systemd/journald.conf.d/20-persistent.conf", "content": "[Journal]\nStorage=persistent\n"},
        {"path": "/etc/ssh/sshd_config.d/60-lemon.conf", "content": "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\n"},
    ]
    if profile["desktop"]:
        files.append({"path": "/usr/local/lib/lemon/firefox-privacy.js", "permissions": "0644",
                      "content": (ROOT / "guest/firefox-privacy.js").read_text()})
    return {"hostname": profile["hostname"], "manage_etc_hosts": True, "preserve_hostname": False,
            "timezone": profile["timezone"], "disable_root": True, "ssh_pwauth": False,
            "users": [{"name": user, "uid": 1000, "groups": ["sudo"], "shell": "/bin/bash", "lock_passwd": True,
                       "sudo": "ALL=(ALL) NOPASSWD:ALL", "ssh_authorized_keys": [access_key]}],
            "ssh_genkeytypes": ["ed25519"], "ssh_keys": {"ed25519_private": host_private, "ed25519_public": host_public},
            "package_update": False, "package_upgrade": False, "write_files": files,
            "runcmd": [["bash", "/usr/local/lib/lemon/provision.sh", user,
                        str(profile["desktop"]).lower(), str(profile["docker"]).lower()]],
            "final_message": "Native Debian provisioning finished; inspect cloud-init status"}


def prepare(args):
    state = args.state_dir.resolve()
    if state == ROOT or ROOT in state.parents:
        raise ValueError("VM state and SSH identities must live outside the source repository")
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", args.username):
        raise ValueError("Choose a normal Linux account name")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]{0,62}", args.hostname):
        raise ValueError("Choose a valid hostname")
    if not 8 <= args.disk_gib <= 512:
        raise ValueError("Guest disk size must be between 8 and 512 GiB")
    address = ipaddress.IPv4Interface(args.guest_address)
    gateway = ipaddress.IPv4Address(args.gateway)
    pool = ipaddress.IPv4Network(GUEST_POOL)
    slot = (int(address.network.network_address) - int(pool.network_address)) // 4
    expected_mac = '52:54:00:77:00:' + format(int(address.ip) & 255, '02x')
    if (address.network.prefixlen != 30 or not address.network.subnet_of(pool)
            or address.ip != address.network.network_address + 2
            or gateway != address.network.network_address + 1
            or args.tap != 'vm' + str(slot) or args.ssh_port != 2222 + slot
            or args.mac != expected_mac):
        raise ValueError('Guest network identity must match its allocated private /30 subnet')
    base = args.base_image.resolve()
    if not base.is_file():
        raise ValueError("Download the verified base image before preparing the guest")
    profile = {"username": args.username, "hostname": args.hostname, "timezone": args.timezone,
               "guest_address": str(address), "guest_ip": str(address.ip), "gateway": str(gateway), "dns": GUEST_DNS,
               "mac": args.mac, "tap": args.tap, "ssh_port": args.ssh_port,
               "desktop": args.desktop, "docker": args.docker, "disk_gib": args.disk_gib}
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    state.chmod(0o700)
    manifest = state / "guest.json"
    disk = state / "disk.qcow2"
    seed = state / "seed.iso"
    for path in (manifest, disk, seed, state / "instance-id", state / "user-data", state / "meta-data", state / "network-config"):
        if path.is_symlink():
            raise ValueError("Guest preparation paths must not be symbolic links")
    if manifest.exists():
        previous = json.loads(manifest.read_text())
        if previous["profile"] != profile:
            raise ValueError("An existing VM uses another profile; use a new state directory to reprovision")
        if disk.is_file() and seed.is_file():
            return previous
    for tool in ("qemu-img", "cloud-localds", "ssh-keygen"):
        if not shutil.which(tool):
            raise ValueError(f"Required guest preparation tool missing: {tool}")
    keys = state / "ssh"
    if keys.is_symlink():
        raise ValueError("Guest SSH state must not be a symbolic link")
    keys.mkdir(exist_ok=True, mode=0o700)
    keys.chmod(0o700)
    access = ensure_key(keys / "id_ed25519", "lemonbox-access")
    host = ensure_key(keys / "host_ed25519", "lemonbox-guest-host")
    cloud = cloud_config(profile, access, (keys / "host_ed25519").read_text(), host)
    instance_id = (state / "instance-id").read_text().strip() if (state / "instance-id").exists() else "lemon-" + str(uuid.uuid4())
    write_private_text(state / "instance-id", instance_id + "\n")
    write_private_text(state / "user-data", "#cloud-config\n" + json.dumps(cloud, indent=2) + "\n")
    write_private_text(state / "meta-data", json.dumps({"instance-id": instance_id, "local-hostname": args.hostname}) + "\n")
    network = {"version": 2, "ethernets": {"eth0": {"match": {"macaddress": profile["mac"]}, "set-name": "eth0",
                "dhcp4": False, "dhcp6": False, "addresses": [profile['guest_address']],
                "routes": [{"to": "0.0.0.0/0", "via": profile['gateway']}], "nameservers": {"addresses": [GUEST_DNS]}}}}
    write_private_text(state / "network-config", json.dumps(network, indent=2) + "\n")
    if not disk.exists():
        temporary_disk = state / (".disk-" + str(uuid.uuid4()) + ".qcow2")
        try:
            subprocess.run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", "base.qcow2",
                            temporary_disk.name, f"{args.disk_gib}G"], cwd=state, check=True, stdout=subprocess.DEVNULL)
            temporary_disk.chmod(0o600)
            temporary_disk.replace(disk)
        finally:
            temporary_disk.unlink(missing_ok=True)
    new_seed = state / (".seed-" + str(uuid.uuid4()) + ".iso")
    try:
        subprocess.run(["cloud-localds", "--filesystem=iso", "--network-config", str(state / "network-config"),
                        str(new_seed), str(state / "user-data"), str(state / "meta-data")], check=True)
        new_seed.chmod(0o600)
        new_seed.replace(seed)
    finally:
        new_seed.unlink(missing_ok=True)
    result = {"profile": profile, "instance_id": instance_id, "disk": str(disk), "seed": str(seed),
              "access_key": str(keys / "id_ed25519"), "guest_host_public_key": host}
    write_private_json(manifest, result)
    for path in (disk, seed, manifest, state / "instance-id", state / "user-data", state / "meta-data", state / "network-config"):
        path.chmod(0o600)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--base-image", type=Path, required=True)
    parser.add_argument("--username", default="debian")
    parser.add_argument("--hostname", default="lemonbox")
    parser.add_argument("--timezone", default="America/Los_Angeles")
    parser.add_argument("--disk-gib", type=int, default=24)
    parser.add_argument("--guest-address", default="10.77.0.2/30")
    parser.add_argument("--gateway", default="10.77.0.1")
    parser.add_argument("--mac", default="52:54:00:77:00:02")
    parser.add_argument("--tap", default="vm0")
    parser.add_argument("--ssh-port", type=int, default=2222)
    parser.add_argument("--desktop", action="store_true")
    parser.add_argument("--docker", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        result = prepare(args)
        print(json.dumps(result, indent=2))
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"Guest preparation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
