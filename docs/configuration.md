# Configuration

Use `lemonbox` for setup and `lemonbox settings` for changes. Shared route credentials are configured once, separately from VM settings.

| Choice | When it changes |
| --- | --- |
| Username, hostname, timezone, disk, installed desktop/Docker | VM creation |
| CPU count, RAM, local VNC port | Creation or later VM settings |
| Shared host folders and permissions | `lemonbox files` |
| Hysteria first hop/exit, required public IPv4, existing WireGuard keys | Shared route settings, with all VMs stopped |

Fresh defaults use your host username, hostname `lemonbox`, `America/Los_Angeles`, 2 CPUs, 4 GiB RAM and a 24 GiB disk. A saved VM template may supply different defaults. KVM acceleration is required; ensure your login has access to `/dev/kvm`. Creation settings remain attached to the VM disk.

## Shared gateway

```text
VM private packets → shared host gateway → WireGuard in a framed TCP stream
                   → exit Hysteria through first-hop Hysteria → VPS → Internet
```

The external WireGuard peer and packet-forwarding services must already match the supplied keys. Lemonbox performs no VPS administration. [Manual reference](vps.md).

Each VM receives a separate private `/30` network and SSH relay port. The default profile uses guest `10.77.0.2`, gateway `10.77.0.1` and relay `2222`; the next allocated profile uses `10.77.0.6`, gateway `10.77.0.5` and relay `2223`. Allocation remains attached to its profile. All guests use the same fixed public exit.

Creation also adds a writable `workspace` share from `<lemonbox-checkout>/workspaces/<profile>` to `/home/<guest-username>/workspace`. Its location is based on the checkout, not the owner's home directory. Every person authorized for that VM shares the guest account and can use the folder. Existing workspace shares are preserved, and ordinary settings changes do not re-add a workspace that was removed.

POSIX ACLs on the default host workspace give approved local users direct read/write access. The workspace root controls access; ordinary files and directories below it inherit shared permissions, including files created on the host by another approved user. Ordinary shared files use `0666`; shared subdirectories and executables use `0777`. The root denies access to its owning group and others, with named ACL entries for approved local users. Local grant and removal commands update the root ACL. The parent `workspaces` directory grants traversal without listing other VMs. The first permission setup normalizes existing workspace contents to these shared modes. See [Host files](usage.md#host-files) for the full permission rules. Custom host shares keep their existing host permissions.

VMs with the default workspace use SSH PAM session rules to give the shared guest account a `000` umask. Normal new files are writable by collaborators; explicitly private file modes and a user-selected umask still apply. The native QEMU sharing mode does not expose host ACLs to the guest, so host ACL inheritance alone cannot set guest file creation permissions. See the [QEMU ACL handlers](https://github.com/qemu/qemu/blob/v10.0.0/hw/9pfs/9p-posix-acl.c).

The shared gateway enforces the route and public exit. Kernel-expiring permissions close traffic when health checks or transport stop. Guests contain no transport clients, proxy variables or route credentials. The gateway continuously verifies the route and repairs transient failures on the same tunnel, verifying the public exit before guest traffic reopens. It publishes recovery state and alerts for `lemonbox status` and other local Lemonbox commands to display. Missing or stale reports appear as status unavailable. Unexpected exits, invalid configuration and operator blocks stay closed for inspection.

## Private state

State lives outside the checkout under `~/.local/share/lemonbox/`:

```text
gateway/                 Shared credentials, rendered transport files and manual assets
    config.json          The only editable route configuration
    mihomo               Manually supplied private executable
    base.qcow2           Manually supplied Debian base image
<vm-name>/
    config.json          VM settings and explicit host shares
    guest.json           Native identity and network allocation
    disk.qcow2           Persistent VM disk
    seed.iso             Initial cloud-init settings
    ssh/                 Owner access key and pinned native guest host key
    access.json          Localhost SSH relay settings
    local-users.json     Approved host usernames and their numeric user IDs
templates/               VM settings, with no route credentials or host shares
connections/             Optional SSH-only collaborator connections
```

Directories are private (`0700`), configurations `0600`. Do not publish the state directory. Generated transport files are derived from the shared `gateway/config.json`; edit that source through settings.

Every operation validates its configuration. Interactive edits capture a revision before prompting and reject conflicting writes. Applying VM changes saves the new settings and restarts that VM if needed. A failed new launch leaves it stopped; an error before shutdown can leave the existing VM running. Fix the reported cause and retry.

## Templates and manual editing

```bash
lemonbox settings --save-template current
lemonbox settings --path
lemonbox settings --route --path
```

The menu offers saved templates when creating another VM. They contain account/resources and desktop settings; each VM gets a new disk, SSH identities and default workspace. Additional shares must be selected explicitly.

Advanced users can edit the displayed JSON path using their editor. Configuration is validated when used. Apply VM edits with `lemonbox settings --apply`; apply route edits after `lemonbox stop --all` with `lemonbox settings --route --apply`. Supported shapes are in [config.example.json](../config.example.json) and [route.example.json](../route.example.json).

`lemonbox update` applies the manually rebuilt local runtime image and requires all VMs stopped. It does not download or select newer dependency versions. See [Host preparation](setup.md) for the pinned build.

## Collaborator state

For someone on this Linux host, `lemonbox access` grants their existing host username. The private `local-users.json` binds that name to its numeric user ID. During join, a local Unix socket checks the connecting process's OS identity before registering its SSH key. Account deletion and recreation under a different ID requires a new approval. No keys or connection details need copying between people.

Local join generates a dedicated private key under that user's saved connection and reuses it on subsequent joins. `lemonbox join --public-key KEY_OR_FILE` also registers an extra public key without replacing the dedicated key; repeat the option for more devices.

This grants guest SSH access; it does not change host groups or grant access to the owner's Podman socket. Public keys live in the guest's native `~/.ssh/authorized_keys`; the owner key remains protected. Removing a local grant also removes all its registered guest keys. `access.json` stores whether sharing is enabled and its localhost port.

For another computer, use **Remote access** to exchange the VM's connection details and approve the other person's public key. The relay listens on host loopback; an existing SSH forward or Tailscale can make it reachable. The owner's private SSH key and route credentials remain private in both flows.

Joined clients save a reachable address, guest username, exact public host key and local private-key path under `connections/shared/`, then `shared-2/` and so on. Join chooses these directory names automatically and reuses an existing connection when the details match. The menu shows `username@address:port`; users need not choose or remember a connection name. The private key stays on its owner's computer.

The menu remembers either a local VM or a joined connection. For automation, `--profile NAME` selects a local VM, `--connection NAME` selects a saved joined connection, and `join --name NAME` supplies an explicit connection name.
