# Architecture

## One shared route

Rootless Podman runs one `lemonbox-gateway` container. Each VM runs an unprivileged QEMU process in a separate container sharing that gateway's network namespace. Its private TAP, `/30` network, disk, account and SSH identity belong to that VM.

```text
Debian VM → its private TAP → source validation and canonical guest SNAT
          → WireGuard → framed TCP → first Hysteria node → final Hysteria VPS
          → server WireGuard → exact-source public SNAT → Internet
```

The host's only physical route traffic goes to the fixed first Hysteria endpoint. The final endpoint is dialed through it. Mihomo is a manually supplied, read-only host binary mounted into the gateway. Guests contain neither proxy software nor route keys, settings or environment variables.

The stream carries encrypted WireGuard datagrams; it does not terminate guest TCP connections. IPv4 TCP, UDP and ICMP share this packet path. IPv6, guest-initiated host/LAN/metadata and inter-VM connections are denied. Host-initiated SSH to each VM is a narrow management exception.

The allocator assigns distinct guest addresses from `10.77.0.0/24`. The default guest is `10.77.0.2`, the next is `10.77.0.6`. Before NAT, the firewall validates each source against its TAP. Outgoing guests are translated to canonical `10.77.0.2` inside WireGuard, allowing all profiles to reuse the installed VPS peer. Connection tracking sends replies to the originating VM. Gateway health probes use `10.78.0.2` independently of attached guests.

Expiring nftables gates limit both transport and guest forwarding. Bounded health checks verify the expected public exit through the packet route with native curl and verified TLS. Missing processes/routes, a wrong exit or expired gates close the route and latch it closed. Registration cannot renew or reopen a failed route. Recovery is explicit: stop all VMs, recover the shared gateway in Settings, then start the desired VMs. Stopping one VM detaches only its TAP.

The administrator separately maintains the VPS peer, forwarding, explicit public-source NAT and after-NAT source/interface guard. The guard is the enforcement boundary; periodic HTTPS checks provide additional evidence. See [the VPS reference](../vps.md). Lemonbox performs no remote administration.

## State and configuration

Private state lives outside the checkout under `~/.local/share/lemonbox/`:

| Directory | Contents |
| --- | --- |
| `gateway/` | One route configuration, generated proxy/WireGuard inputs, supplied Mihomo/base image, immutable applied image ID and VM address registry |
| `<profile>/` | VM settings, disk overlay, cloud-init seed, guest metadata, SSH keys and local access state |
| `templates/` | VM settings only |
| `connections/` | Joined-client invitations and local SSH settings |

`gateway/config.json` is the only editable route configuration. `proxy.json` and `wireguard.json` are derived inputs. `gateway/applied.json` contains only the immutable image ID and route digest; there are no generations or rollback snapshots. VM settings never include transport credentials.

Profile and gateway locks serialize lifecycle changes. VM startup holds the shared gateway lock from applied-image lookup through QEMU creation, so an idle-only route update cannot replace its network namespace midway. Editors compare the revision captured before prompting to reject stale writes. VM settings save atomically; applying running-VM settings restarts that VM. Saved settings remain available for correction after an error. A failed new launch leaves the VM stopped; a failure before shutdown can leave the existing VM running. Shared route/image changes require every VM stopped and validate derived inputs before allowing a launch.

QEMU has no Linux capabilities. The gateway owns the network capabilities. Container labels establish project/state ownership; immutable image IDs prevent a changed convenience tag from silently replacing a running runtime. Backend failure is distinguished from confirmed container absence.

## Preparation and release

[Host preparation](../setup.md) documents native download/checksum/build commands. Application code does not download host binaries or images, build containers, elevate permissions, migrate old state or administer the VPS.

`release.json` documents the Debian cloud image, initial native Claude binary, runtime base, package snapshot, Mihomo archive and QEMU machine type. Corresponding explicit pins in the Dockerfile, guest provisioning, runtime and setup runbook must be reviewed together; the manifest does not generate them. Once provisioned, the guest uses ordinary signed Debian repositories and can update normally. Guest provisioning installs native Claude and optional desktop/Docker, then removes its one-time provisioning script.

This is an observable KVM/QEMU VM, with ordinary private networking. [Detection limits](redteam.md) describes what root and service providers can infer.
