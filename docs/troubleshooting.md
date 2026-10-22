# Troubleshooting

Start with `lemonbox status` and `lemonbox diagnose`. Diagnostics return a failure status for required checks; `lemonbox diagnose --host` checks only host prerequisites.

## Host prerequisites

Follow [Host preparation](setup.md) for tools and manually prepared assets. After joining the `kvm` group, log out and in. `/dev/kvm` and `/dev/net/tun` must be accessible, and rootless Podman needs your distribution's subordinate UID/GID setup. Lemonbox does not install tools or refresh login groups.

## Internet is closed

A shared gateway failure closes Internet access for all attached VMs. Their running shells remain available. The gateway automatically restarts the same fixed transport after a timeout, expired lease, missing route or exited transport process. TAPs, VM disks and running VM processes are preserved. Guest traffic opens only after a native HTTPS check verifies the configured public exit.

Run `lemonbox status` to view the gateway's reported recovery progress and alerts. The gateway continuously verifies the route and publishes its state. Repeated failures raise an alert while recovery continues more slowly inside the gateway container. An unexpected public exit, invalid profile or explicit operator block requires inspection and stays closed. Other local Lemonbox commands also display reported gateway alerts when invoked; alerts clear after the gateway reports recovery.

Missing or stale gateway reports appear as status unavailable. Use `lemonbox logs` to inspect gateway logs, or run `lemonbox diagnose` for an explicit network check.

If the reported cause requires a route/configuration repair or gateway replacement, fix it first, then perform manual recovery:

```bash
lemonbox stop --all
lemonbox settings
```

Choose **Recover the shared gateway**, then start your VMs. Manual replacement stops guest sessions; ordinary automatic tunnel recovery does not. If the chain or external services remain unavailable, traffic stays closed. Restore external services through your own administration method; [Manual VPS reference](vps.md).

## Invalid settings or failed restart

Use `lemonbox settings --path` (or `settings --route --path`) to locate the configuration. Fix malformed JSON in your editor, then apply it. VM settings use `lemonbox settings --apply`. Shared route changes require all VMs stopped before `lemonbox settings --route --apply`.

There is no saved old runtime or configuration rollback. Saved edits remain after an error. A failed new launch leaves the VM stopped; a failure before shutdown can leave the existing VM running. Fix the reported cause and run `lemonbox start`. A conflict during guided editing means another writer changed the configuration; reopen settings to review the current values.

## First boot or provisioning failure

```bash
lemonbox logs --guest
lemonbox shell
```

Inside the guest, use `cloud-init status --long` and `sudo journalctl -u cloud-final --no-pager`.

Desktop and Docker first boot downloads roughly 650 MB of guest software. Healthy provisioning can wait up to an hour; required route or provisioning failures are reported promptly. Another terminal can stop the VM or open its shell once SSH is available. Stop/restart cancels the readiness wait. An unrelated failed systemd unit does not block an otherwise ready Claude session.

`lemonbox logs` shows shared gateway logs. Manual runtime build errors belong to the command used in [Host preparation](setup.md).

## Desktop or shared folders

`lemonbox desktop --no-open` prints the VNC address. Keep its terminal open; TigerVNC uses `127.0.0.1::5901`. Use `--port 5902` when another VM already uses that local port. The desktop must have been installed at creation. Inside the guest, inspect `sudo systemctl status lemon-desktop.service`.

On a remote host, `lemonbox desktop --tailnet` prints the host's Tailscale IPv4 address for direct VNC access. Both computers must be connected to the tailnet, and tailnet access rules must allow the chosen TCP port. Check `tailscale status` on the host if address discovery fails. Userspace networking is unsupported. The listener closes when the desktop command exits; a VM without the desktop must be replaced with one created with **Install desktop** enabled.

If your VNC viewer asks for a password, run `lemonbox desktop --show-password` on the host with the same `--profile` selection. Use this VNC password, rather than a host or guest login password. macOS Screen Sharing requires password authentication; restart the host's desktop command after updating Lemonbox to apply it to an existing VM.

`lemonbox files list` shows host folders mounted directly under the guest home. The source must still exist and be accessible. Changing shares restarts only the selected VM. Read-only shares remain read-only to guest root.

## Joined SSH access

Run `lemonbox status` on the client. Confirm the address and allocated port with the owner, who can check `lemonbox access list`. The owner must authorize your matching public key. Encrypted keys can prompt in a normal session; the noninteractive status check needs your SSH agent.

Relays listen on host loopback. Another computer needs an existing forward or the [manual Tailscale recipe](usage.md#access-and-joining). An unexpected VM host-key change stops SSH. Verify the identity with the owner before trusting a new connection. Join never uploads your private key or disables host-key verification.
