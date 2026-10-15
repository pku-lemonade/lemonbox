# Cleanup results

The approved cleanup is implemented around one shared packet gateway and a short `lemonbox` interface. [The original review](full-review-2026-10-14.md) is historical; [the Python review](python-review.md) explains every remaining production module.

Deployment addresses and usernames below have been replaced with documentation examples for publication.

## What changed

- Deleted automatic host downloads/builds, VPS SSH/provisioning/rollback, custom release/provenance scanning, software-emulation fallback and sudo/group refresh.
- Deleted per-VM transport copies, generations, old runtime snapshots, unused modes/helpers and their tests. Removed stale archived setup documents.
- Kept one private route configuration. Derived transport files and the manually supplied Mihomo binary live only in the external gateway. VM settings and saved templates contain no route credentials.
- Multiple VMs now share one gateway with distinct private networks, disks, SSH identities and relay ports. Stopping one VM keeps the gateway and other VMs connected. Pre-NAT source validation and canonical guest SNAT reuse the installed server peer without remote changes.
- Setup, settings, files, desktop, access and joining use guided flows. Host preparation and VPS maintenance use concise native-command runbooks for operators or agents.
- Kept concrete protections for fixed routing, SSH identity, file ownership, read-only exports, concurrent edits and clean child-process shutdown. Configuration is validated when used; no separate check command is needed.

## Verification

Both running VMs reported native Claude `2.1.296`, `/home/debian`, hostname `lemonbox`, no proxy environment and public exit `203.0.113.20`. They use different private addresses (`10.77.0.2` and `10.77.0.6`) and different machine/SSH identities. The default machine-ID hash matches its pre-cleanup record. Stopping the test VM left the same gateway running and the default VM connected.

On the final shared-gateway build, both VMs passed 27 native/public diagnostic checks and 7 packet-path measurements each. Guest-root raw checks offered 54 frames per VM across spoofed sources, private/inter-VM destinations, IPv6 and unsupported protocols; all four external drop-counter categories passed. A bounded physical-uplink capture observed 3,049 IPv4 packets, all to the fixed first endpoint `198.51.100.10:8443/UDP`.

All seven local shared failures passed 91 checks: explicit block, actual kernel lease expiry, WireGuard/proxy/carrier exits, route removal and a temporary wrong expected exit. Existing and new TCP/UDP flows closed in both VMs, management SSH survived, and public stop-all/start-both recovery restored the exact exit. During the expiry case, gates were truly empty after 25.140 seconds, within the 35-second observation bound.

A real concurrency regression also covers a route change racing QEMU creation. The existing gateway lock now spans startup, so an idle-only update cannot replace the namespace midway. Private detailed reports live under each profile's `validation/` directory, outside the source checkout.

The final exact-source image repeated both sets of diagnostics, packet measurements and raw guards. The seven-case matrix was run before the final cuts to unused imports/constants, optional startup knobs and redundant validation; those deltas are recorded privately and did not alter forwarding, lease or framing algorithms. The exact final image also passed 13 shared block checks and four recovery checks. Both VMs returned to the pinned exit after public stop-all/start-both recovery, with gateway capabilities reduced to NET_ADMIN only.

The current shared SSH/VNC workflows passed 32 checks: both allocated relay ports and distinct host keys, isolated joined clients using Python/OpenSSH only, native Claude, shell/stdin/exit forwarding, rejected host-key changes, revoked keys, VNC handshake and tunnel cleanup. Temporary keys/relays were removed and original access/desktop state restored.

The final source and clean Git-index checkout passed 306 offline tests, compilation, Bash syntax, CLI help, documentation links and ignore checks. Actual route passwords/private keys were absent from staged files. Dependency pins were compared with the Dockerfile, provisioning, runtime and setup instructions using a one-time operator review.

## Test pruning and timing

The earlier 306-test run is historical release evidence. A later test review removed 75 duplicated/static/mock-only VM cases, retaining 231 tests. The combined suite passes in 2.977 seconds; the previous 306-test run took about 3.4 seconds. Test/helper code shrank by 802 lines, including removal of the duplicate native guest wrapper and packet speed benchmark.

The older Docker checkout removed eight low-value cases and consolidated repeated fixture runs: 105 tests in 24.982 seconds became 97 in 13.494 seconds. Its main overhead was local mock servers' 500 ms shutdown polling and repeated Python site/path imports in a fake Podman command. Test fixture polling now uses 10 ms and that stub skips site initialization; production timeouts stay unchanged.

The seven-case live reports span 648 seconds, including recovery. Those multi-minute operations caused most of the apparent testing delay, especially when repeated between edits. [Validation](validation.md) now selects live work by the change and reserves a complete enforcement matrix for one frozen release. Test/documentation edits use offline checks; this pruning changed no production files or running VMs.

## Separate cold-install evidence

Before the shared-gateway refactor, a fresh minimal VM completed the current native Claude/Docker factory installation and passed 14 post-reboot checks. An earlier fresh desktop VM exercised real VNC, command/stdin/exit forwarding, writable/read-only shares and SSH access/join/revocation. These results support the guest factory and user workflows; they are not described as a new cold shared-gateway install. Only the default and one reusable test disk remain; the default is left running and the reusable test VM stopped.

## Limits

This is an observable KVM/QEMU machine. Guest root can identify virtualization, NoCloud and optional virtio/9p devices. Fixed exit enforcement depends on the trusted host and owned VPS policy; deliberate nested tunnels through allowed public destinations remain possible. Sampled packets/IP checks complement the kernel enforcement rather than proving every future packet. See [detection limits](redteam.md).
