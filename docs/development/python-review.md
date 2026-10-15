# Python review: keep the job small

Every production Python file was reviewed individually. The rule was to keep code that implements a requested feature or protects a concrete routing, identity or data boundary; remove unused choices, duplicate helpers, historical formats and automation better expressed as native commands in a runbook.

## Deleted outright

- `bootstrap.py` and `scripts/guest-fetch-image.py`: automatic host binary/image downloading and its state/checksum machinery. Use [host preparation](../setup.md).
- `release.py` and `scripts/release-check.py`: custom credential/provenance scanner and cross-artifact release framework. Keep the public release pins, native checksum commands and ordinary Git/CI.
- `tunnel.py` and `scripts/vircs-wireguard.py`: VPS SSH, installer, peer replacement, rollback and remote recovery. Use [the manual VPS reference](../vps.md).
- Per-VM transport copies, generation directories, applied pointers, rollback snapshots, automatic Podman builds, sudo/group refresh and software-emulation fallback.
- Tests for those deleted paths, obsolete runtime-generation fixtures, browser/research experiments and stale archived setup documents.
- `tests/validate_reload.py`: a policy-normalizing/hash/report harness testing native nft transaction behavior. Use native inspection commands when needed.

Mihomo was previously downloaded on the host for the external gateway. It was not installed in the guest. The downloader has now been deleted; the verified host binary is supplied manually and mounted read-only into the one shared gateway. The guest installs native Claude, with optional ordinary desktop and Docker packages.

## Remaining files

| File | Its job | Kept because |
| --- | --- | --- |
| `vm/__init__.py` | Package marker | Imports need it |
| `config.py` | Current VM/route schemas and private atomic files | Invalid routes, key mismatches and partial credential writes must fail clearly |
| `state.py` | Cross-process locks and revision comparison | Two terminals must not overwrite settings or race lifecycle changes |
| `runtime.py` | VM disk preparation and KVM/QEMU lifecycle | Disk identity, allocation matching and owned-container checks protect actual user state; the existing gateway lock keeps startup atomic |
| `gateway_runtime.py` | One shared gateway and address allocator | Profiles need unique addresses; route changes must stop all VMs first |
| `route_contract.py` | Fixed internal packet protocol values | Host, guest and remote transport must agree |
| `cli.py` | Menu and short command dispatch | Owner and joined-client flows, settings and native argument forwarding are requested features |
| `onboarding.py` | Guided setup and VM-only templates | Hidden secrets, cancellation and validated inputs make setup usable |
| `workflows.py` | Native SSH/Claude, readiness and VNC | Repair access must survive route failures; child tunnels must stop cleanly |
| `connections.py` | SSH-only joined client | Invitations need an exact host-key pin and locally retained private key |
| `access.py` | Guest authorized keys and owned SSH relay | Revocation must preserve unrelated keys; stopping a relay must never signal an unrelated process |
| `local_access.py` | Host username grants and local key registration | Kernel-checked user IDs authenticate both ends without sharing Podman control or private keys |
| `sharing.py` | Explicit host-folder export and native guest mounts | Read-only enforcement and mount removal must preserve host/guest files and private credentials |
| `diagnostics.py` | User-facing route evidence | A real control listener and firewall counters distinguish blocking from an unavailable service |
| `guest_probe.py` | Native guest/network measurements | Exact exit, OS/Claude/Docker and TCP/UDP/DNS/STUN/ICMP behavior need end-to-end evidence |
| `gateway/controller.py` | Lease monitor and TAP registration | Route failure must close both kernel gates; attaching a VM cannot reopen a failed route |
| `gateway/packet.py` | WireGuard routes, source validation and nftables policy | Guest sudo must not bypass the fixed route or reach host/LAN/other VMs |
| `gateway/stream.py` | Framed carrier for WireGuard datagrams | Partial frames, bidirectional traffic and backpressure are real network behavior |
| `scripts/guest-prepare.py` | One-time disk, SSH identity and NoCloud seed | Native QEMU/cloud-init needs these artifacts; existing identities must survive seed regeneration |
| `scripts/install-launcher.py` | One-time global symlink to the checkout | The simple `lemonbox` command should work outside the repository without copying source |
| `guest/readiness.py` | Transient native service readiness probe | Ordinary Python can be checked directly without embedding source inside a string |
| `guest/authorized_keys.py` | Transient named SSH key edits | Locking and atomic updates preserve owner and unrelated keys |
| `guest/shares.py` | Transient native guest mount management | Explicit JSON requests keep data separate from executable source |

## Smaller cuts inside retained files

Removed the test-only probe import wrapper, duplicate seed-file writer and share-restart helper, unused mapped-xattr choice, test-only profile selector, unread workflow flags, optional process-tracking branch, intermediate share-binding wrapper and recursive unrelated-file permission audit. Removed dead ICMP mode flags, custom DNS/TLS/HTTP health machinery, unused SOCKS authentication plumbing and codec wrappers. Removed unused protocol aliases/server administration constants, test-only WireGuard binary overrides, unused startup arguments, an unused server connection-limit option and redundant generic address checks preceding exact fixed-contract checks. The gateway needs only NET_ADMIN; the unused low-port binding capability was removed. Native curl now performs bounded, verified-TLS exit probes.

The launcher checks only the required source/assets and searchable parent directories. Shares use one supported native security model. Access forwarding always tracks and reaps its actual child processes. ICMP is part of the supported packet route, not a configurable test mode.

## Tests

Tests remain for meaningful behavior: actual socket framing/backpressure, concurrent writers/allocations, stale saves, exact argv/stdin/exit transport, SSH pins, ownership, read-only mounts, source spoofing, expiring leases and explicit failure closure. Static help/default tables, mocked pass-throughs, repeated schemas/literal assertions and test-of-test parser variants were removed. Live validation is selected by the changed behavior; mocks do not establish a working guest or fixed public exit. See [validation](validation.md) and [cleanup results](cleanup-results.md).

The menu and relay modules remain the largest host files because they implement the requested multi-VM, joining and user workflows. Splitting them into generic frameworks or removing identity/data protections would add churn or reduce functionality; no such abstraction was introduced.
