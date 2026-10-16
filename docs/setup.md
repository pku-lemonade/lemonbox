# Prepare the host once

This is an operator task. The everyday interface is `lemonbox`; it does not install host software, download runtime assets, build containers or configure your VPS. A future agent can follow this document using native tools.

## Host requirements

Use Linux x86_64, Python 3.11+, OpenSSH, rootless Podman with `slirp4netns`, POSIX ACL tools (`setfacl` and `getfacl`, from the `acl` package), and working KVM. Install these through your host's package manager. Your login must be able to read and write `/dev/kvm`; after joining the `kvm` group, log out and back in. Check:

```sh
python3 --version
podman info
test -r /dev/kvm && test -w /dev/kvm
```

Enable hardware virtualization in firmware if necessary. Lemonbox does not switch to software emulation or invoke sudo to refresh your groups.

Route health checks and automatic recovery run inside the shared gateway container, which publishes recovery state and alerts. `lemonbox status` and other local Lemonbox commands read and display that state when invoked. [Troubleshooting](troubleshooting.md#internet-is-closed) explains recovery progress and failure alerts.

## Prepare the shared assets

The following URLs and checksums match [release.json](../release.json). When updating the release, use its new values. Download over verified HTTPS and verify the archive before unpacking it.

```sh
install -d -m 700 "$HOME/.local/share/lemonbox/gateway"
curl --fail --location --proto '=https' --tlsv1.2 https://github.com/MetaCubeX/mihomo/releases/download/v1.19.25/mihomo-linux-amd64-compatible-v1.19.25.gz -o /tmp/lemonbox-mihomo.gz
printf '%s  %s\n' 8d14bf2edbf2911db004abaed12754d63041eaf87e565af6f1e589883cd93ec8 /tmp/lemonbox-mihomo.gz | sha256sum --check
```

Continue only after the checksum passes:

```sh
gzip -dc /tmp/lemonbox-mihomo.gz > "$HOME/.local/share/lemonbox/gateway/mihomo"
chmod 700 "$HOME/.local/share/lemonbox/gateway/mihomo"
rm /tmp/lemonbox-mihomo.gz
curl --fail --location --proto '=https' --tlsv1.2 https://cloud.debian.org/images/cloud/trixie/20261001-2618/debian-13-generic-amd64-20261001-2618.qcow2 -o "$HOME/.local/share/lemonbox/gateway/base.qcow2"
printf '%s  %s\n' 6f0f93335bdef4ccf523c4317cc663ea52ca23b862667785f3d6d186ab4674a937385ccff0c55996b4b2e4c19e440cdf211e2a75ffa2f6548037ab43950c841d "$HOME/.local/share/lemonbox/gateway/base.qcow2" | sha512sum --check
```

Continue only after the image checksum passes:

```sh
chmod 400 "$HOME/.local/share/lemonbox/gateway/base.qcow2"
podman build --http-proxy=false -t localhost/lemonbox:latest -f gateway/Dockerfile .
sudo python3 scripts/install-launcher.py
lemonbox
```

Run the build from this checkout. The container image contains QEMU and networking tools; Mihomo is mounted read-only into the external gateway, never copied into the image or installed in a guest. Each VM gets its own writable disk overlay. The base image is shared using hard links, so VM state and gateway state must be on the same filesystem.

The installer creates `/usr/local/bin/lemonbox`, a symlink to this checkout, for all host users. Ensure `/usr/local/bin` is on each user's `PATH`. Updates to the checkout take effect immediately. Other users need read/execute access; the checkout and its parent directories must be writable only by their owner or trusted administrators. A collaborator-writable checkout lets that person change code the VM owner runs.

Each user's state remains private. To share a VM on this host, the owner grants the person's host username through `lemonbox access`; that person runs `lemonbox join` under their own account. They need Python 3.11+ and OpenSSH, without Podman, KVM, sudo or shared Unix group membership.

## Supply the route

Prepare the exit VPS independently using [the manual reference](vps.md). Lemonbox needs the two Hysteria endpoints and passwords, expected public exit, client WireGuard private key and matching server public key. There is no administrator SSH key setting.

The guided setup asks for these once. They live in the owner's private `~/.local/share/lemonbox/gateway/config.json`. [route.example.json](../route.example.json) uses documentation-only IP addresses, example TLS names and placeholder credentials; replace them with your own route settings. VM templates contain only VM settings. Ordinary VM creation reuses the route.

An operator should check the local tools and asset checksums before handing the prepared host to its user. Start the default VM, run `lemonbox diagnose`, then exercise Claude, shell and desktop if enabled. Keep private reports outside the checkout.

## Runtime updates

Update `release.json` together with the corresponding pins in `gateway/Dockerfile`, `guest/provision.sh`, `vm/runtime.py` and this runbook. The manifest documents the pins; it does not rewrite source. Fetch and verify changed host assets, and rebuild with the same Podman command. Stop all VMs with `lemonbox stop --all`, then run `lemonbox update` to apply the already built image. Start the VMs you want to use. Settings and lifecycle commands always validate their inputs; there is no separate configuration-check command.

## Retire an old shared Podman socket

Lemonbox shares guest SSH access, not the owner's Podman API. If this host previously used the old `lemon` shared-container setup, run these as that Podman owner:

```sh
systemctl --user disable --now lemon-podman-proxy.socket
systemctl --user stop lemon-podman-proxy.service
rm ~/.config/systemd/user/lemon-podman-proxy.socket ~/.config/systemd/user/lemon-podman-proxy.service
systemctl --user daemon-reload
```

Remove the old socket directory's `claude` access/default ACLs and any group write permission on the owner's executable checkout and its parents. Keep unrelated shared workspaces unchanged. These are operator cleanup steps, not actions performed by `lemonbox access`. Leave native `podman.socket` running; removing the proxy does not stop containers.
