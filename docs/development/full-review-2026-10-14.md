# Lemonbox full code review — 2026-10-14

> Historical review. The user subsequently approved the full fresh-only refactor. See [cleanup results](cleanup-results.md) for the resulting implementation and verification. The proposal and decision text below describe the state at review time.

Deployment addresses and personal paths have been replaced with documentation examples for publication.

## Assessment

This is a working, tested deployment with useful network enforcement, but it is not yet a consistently designed, reproducible product. The largest problems are in state management, provisioning/recovery, the user interface, and the relationship between tests and release claims.

I should have done this repository-wide review before describing the earlier cleanup as complete. That completion message established that the deployed VM worked. It did not establish that all obsolete surfaces were gone or that the current source had passed a complete installation from empty state.

The appropriate response is a bounded refactor around a clear product contract, rather than deleting every defensive check or rewriting everything indiscriminately. Your preference is recorded: fresh setups, no compatibility obligations, and a simple user-facing CLI with guided choices instead of long argument lists.

No implementation, VM, gateway or VPS configuration was changed during this review. Only this report was added. Cleanup and refactoring await your decision.

Original source locations below refer to the reviewed snapshot; some of those files have since been removed. Current behavior and verification are in [cleanup results](cleanup-results.md).

## Scope and verification

- Reviewed the Lemonbox checkout. An unrelated container project was not modified or audited as part of this report.
- Covered host CLI/configuration/runtime/sharing, gateway/controller/framing, VPS provisioning, guest preparation, test runners and documentation.
- Three independent review tracks covered architecture, networking, and tests/documentation. Findings below combine source inspection with isolated temporary fixtures and mocked failure cases.
- Reran the offline suite: **363 tests passed**. The isolated reproductions did not modify the active profile.
- Read-only status showed the VM running, route healthy, configuration valid, expected exit `203.0.113.20`.
- Previous live packet/fault/exit/VNC/share results were inspected as existing evidence; destructive live tests were not rerun for this review.
- The source has **no Git commits** and is entirely untracked. For identification, the pre-report inventory contains 71 files with aggregate SHA256 `8dc727cbc4612611d6f791785bf559bc9b9f006d9761fa4f49b7a4da96ac1b81`. This hashes the sorted relative-path/file-SHA256 inventory serialized as compact JSON, excluding Git and Python cache files.
- Approximate scope: 5,003 implementation lines across 18 Python/shell/JavaScript files, 7,924 test/diagnostic lines across 31 files, and 2,265 documentation lines across 14 files. Size alone does not establish unnecessary code.

### Severity and confidence

**P2** means a consequential correctness, recovery, availability or release-validation problem. **P3** means maintainability, misleading configuration or documentation debt. No direct proxy escape or critical security exploit was demonstrated by this review. “High confidence” means the source path was identified and, where practical, the failure was reproduced in an isolated fixture. It does not mean a production outage was deliberately induced.

## Findings at a glance

| ID | Priority | Finding | Main consequence |
| --- | --- | --- | --- |
| R1 | P2 | No mutation lock or stale-edit detection | Concurrent valid changes overwrite each other |
| R2 | P2 | Apply operations commit parts of state before success | Desired settings, generated files, seal and running VM can disagree |
| R3 | P2 | Repair/reclaim requires the tunnel to be healthy already | A displaced or broken profile can reach a CLI recovery dead end |
| R4 | P2 | Peer-only rollback stops an unchanged stream service | Restored files and peer do not restore the previous live connection |
| R5 | P2 | Probe timing can exhaust the lease before renewal | A slow but correct route can latch closed |
| R6 | P2 | All Podman inspect failures are treated as absence | Stop can claim success without stopping anything |
| R7 | P2 | Global systemd health gates ordinary shell access | An unrelated failed unit can prevent its own repair |
| R8 | P2 | Runtime refresh/release contract is incomplete | Cached installations do not refresh; fresh builds drift |
| R9 | P2 | Some network diagnostics have false-positive success criteria | Failed services/timeouts can look like proven enforcement |
| R10 | P2 | Full clean-install behavior has not been established | Existing deployment success is stronger than fresh-install evidence |
| R11 | P2/P3 | CLI and diagnostics are unevenly organized | Long setup syntax, hidden repair verbs and wrong diagnostic defaults |
| R12 | P3 | Exposed settings and duplicated contracts drift | A configurable field can have no effect |
| R13 | P3 | Unused wrappers and historical tooling remain | Extra surfaces and contradictory instructions increase review cost |
| R14 | P2 release readiness | No reviewed Git baseline, CI or artifact-linked release | Evidence is difficult to reproduce or associate with a release |

## Detailed findings

### R1 — Valid concurrent changes can be lost

**High confidence; reproduced.** Atomic replacement of one JSON file is not a transaction across readers. Two callers can read the same configuration, change different fields and then overwrite each other.

Reproduction: snapshot A saves CPU count 4; stale snapshot B saves VNC port 5902. The final config has CPU count 2 and port 5902, with no conflict reported. The same pattern affects sharing and a settings editor left open while another command runs.

Evidence: private writer (`vm/config.py:167`, reviewed snapshot), launch settings (`vm/cli.py:184`, reviewed snapshot), share writes (`vm/cli.py:300`, reviewed snapshot), editor commit (`vm/onboarding.py:223`, reviewed snapshot).

**Change:** lock profile mutations and detect an editor’s stale starting revision before saving. Hold lifecycle locks during operations, but do not hold a lock for the entire time a user is answering prompts. A small profile-state transaction API would make this consistent.

**Required test:** two real processes change independent fields; both changes survive or the stale writer receives a clear conflict. Also exercise overlapping restart/setup.

### R2 — A failed apply can leave a partially committed profile

**High confidence; reproduced.** Individual config writes validate and replace atomically, but the complete operation does not.

- `setup --config` saves the imported config before download/install/build succeeds.
- `seal()` overwrites generated transport files before validating them and writes the manifest directly.
- Resource flags and shares are saved before the requested launch/restart succeeds.

Isolated failures left a new first-hop port saved after installer failure, a new generated proxy with the old manifest after validation failure, and changed CPU sizing after failed launch.

Evidence: setup import (`vm/cli.py:275`, reviewed snapshot), seal (`vm/runtime.py:252`, reviewed snapshot), launch override (`vm/cli.py:184`, reviewed snapshot), share apply (`vm/cli.py:326`, reviewed snapshot).

This remains fail-closed, but normal commands can subsequently refuse a previously usable installation. Persisting desired settings after a failed launch can be a valid product choice; the current design does not clearly distinguish desired state from successfully applied state.

**Change:** stage and validate a complete generated bundle, then commit an applied generation. Use one apply mechanism for setup, settings, shares and tunnel changes. Clearly report pending/unapplied settings. Keep short-lived transaction recovery data; it is operational safety, not old-version compatibility.

**Required test:** failures at download, validation, sealing, shutdown and startup boundaries leave a usable previous applied generation or an explicit recoverable state.

### R3 — A failed/displaced profile cannot reliably repair or reclaim its route

**High confidence; reproduced rejection path.** Public tunnel setup refuses to run unless the current gateway is healthy. A different profile taking over the VPS peer makes the previous profile unhealthy. Restarting that previous profile cannot restore a peer the VPS no longer accepts.

Evidence: healthy-gateway requirement (`vm/tunnel.py:233`, reviewed snapshot), failure latch and transport termination (`gateway/controller.py:627`, reviewed snapshot), existing recovery workaround (`docs/troubleshooting.md:65`, reviewed snapshot).

The source explicitly stops Mihomo and the carrier when latching closed. **Guest management SSH survives; VPS SSH through that production proxy does not.** The current documentation requires a separate trusted path such as Tailscale. That is a real additional prerequisite, not a complete public-CLI repair flow.

**Change:** provide a temporary management gateway through the same pinned Hysteria chain, independent of guest WireGuard health. It should provision/repair the VPS without granting guest Internet access or permitting alternative egress.

**Required test:** create profile A, let B take over the managed peer, then reclaim A through the public tool. B closes, A recovers, and both retain mandatory routing.

### R4 — Peer-only rollback disconnects a transport that did not change

**High confidence; reproduced command sequence.** Any failure during the managed server update stops the stream service, even if only the client peer changed and stream code/unit were unchanged. Restoring the old peer and restarting the service cannot restore its old TCP connection; the local controller deliberately latches after carrier exit.

Evidence: unconditional rollback stop (`scripts/vircs-wireguard.py:484`, reviewed snapshot), carrier failure latch (`gateway/controller.py:627`, reviewed snapshot).

The peer-rotation failure fixture restores files and the old peer, but still issues `systemctl stop lemon-wireguard-stream.service`. Existing rollback assertions therefore establish configuration restoration, not uninterrupted restoration of the previous route.

**Change:** stop/restart only components changed by the transaction. Preserve an unchanged stream during peer-only rollback. Preserve the local failure latch.

**Required test:** retain a real framed connection during an injected peer-only failure and check that it stays open while files/live peer are restored.

### R5 — Health-check deadlines do not leave a guaranteed renewal margin

**High confidence; isolated clock reproduction.** The lease lasts 30 seconds, checks wait 5 seconds, and two endpoints can each use a separate 12-second budget. Renewal then performs nft work. A reproduced schedule of 5 + 12 + 11.95 + 1.1 seconds verifies the correct exit but reaches renewal after expiry.

Evidence: time constants (`gateway/controller.py:32`, reviewed snapshot), verification loop (`gateway/controller.py:481`, reviewed snapshot), expired-lease refusal (`gateway/controller.py:228`, reviewed snapshot).

This is a false outage, **not a leak**. Refusing to reopen an expired running lease is correct.

**Change:** give the complete verification round a single deadline bounded by the remaining lease and a renewal margin. Keep kernel expiry and immediate wrong-IP closure.

**Required test:** primary timeout, slow successful secondary, and delayed nft/scheduling must fit the declared total budget or close deterministically.

### R6 — Backend errors can become a false “Stopped” result

**High confidence; reproduced.** Every nonzero `podman inspect` return becomes “container absent.” A simulated Podman database failure causes `down()` to issue no stop and still print that the VM stopped.

Evidence: inspect handling (`vm/runtime.py:97`, reviewed snapshot), shutdown (`vm/runtime.py:441`, reviewed snapshot).

This also compromises status and startup error reporting. It is particularly misleading before a user assumes a disk is safely stopped.

**Change:** distinguish confirmed absence from a backend/permission/storage error. A small Podman adapter should return explicit states and propagate actual failures.

**Required test:** absent container is normal; database/permission failures are explicit errors and never produce a successful shutdown claim.

### R7 — An unrelated failed service blocks shell and Claude

**High confidence; reproduced readiness result.** Ordinary commands require the entire guest’s systemd state to be `running`. A guest with cloud-init done, SSH/Docker active and Claude working, but one unrelated failed unit, reports not ready. Every shell/Claude invocation then waits and fails.

Evidence: readiness script (`vm/workflows.py:37`, reviewed snapshot), readiness requirements (`vm/workflows.py:126`, reviewed snapshot), access through readiness (`vm/cli.py:244`, reviewed snapshot).

**Change:** distinguish initial provisioning readiness, required services, route health and optional diagnostics. Provide shell access to repair a degraded guest.

**Required test:** an unrelated failing unit does not block repair shell access; genuinely failed provisioning and required services still receive accurate errors.

### R8 — Builds drift, while unchanged source prevents supported refresh

**High confidence.** There are two separate issues:

1. Runtime build caching looks only at four source files. With the same source fingerprint, it executes only image inspection and never refreshes Debian security/base packages.
2. On a fresh host, the Debian base tag/packages, cloud image’s `latest` URL and Claude installer resolve at installation time. The tested QEMU version is a deployment snapshot, not a reproducible future release.

Evidence: build cache (`vm/runtime.py:303`, reviewed snapshot), floating runtime base/packages (`gateway/Dockerfile:1`, reviewed snapshot), cloud image (`scripts/guest-fetch-image.py:14`, reviewed snapshot), Claude installer (`guest/provision.sh:14`, reviewed snapshot).

There is also a global `localhost/lemonbox:latest` dependency: private validation (`vm/runtime.py:239`, reviewed snapshot) requires the global tag to equal each profile’s seal. Rebuilding for one profile can invalidate another profile’s pinned image even if its immutable image still exists. This is a source-level consequence, not a live multi-profile reproduction.

**Change:** establish a tested release artifact, record/pin resolved versions and provide deliberate refresh semantics. Resolve runtime operations through the profile’s immutable image pin; use a global tag only as a convenience or default.

**Required test:** unchanged-source refresh updates a stale image; ordinary setup stays cached; updating one profile does not invalidate another; a release manifest explains exact produced versions.

### R9 — Some network checks overstate what failures prove

**High confidence; reproduced isolated diagnostic outcomes.**

- `socket_rejected()` treats any `OSError` as successful blocking. A closed service, missing route or outage also passes.
- TTL-one TCP considers any `OSError`, including a generic timeout or refusal, a successful result.
- Packet validation requires RTT ≥10 ms. That describes this host’s measured path; a valid nearby packet-forwarding setup can have lower latency.

Evidence: generic rejection (`tests/guest_probe.py:110`, reviewed snapshot), TTL-one result (`tests/packet_guest.py:81`, reviewed snapshot), RTT threshold (`tests/packet_guest.py:60`, reviewed snapshot).

These weaknesses do **not** demonstrate a production firewall bypass. The separate raw-packet counter, outage and post-NAT capture tests provide stronger evidence.

**Change:** use listening positive controls and enforcement counters, identify TTL expiry distinctly, and record RTT rather than treating a geography-dependent threshold as a universal invariant.

**Required test:** refused service, generic timeout and genuine policy/TTL rejection produce distinct results.

### R10 — Current evidence does not establish complete installation from empty state

**High confidence.** The recent fresh-workflow test rotated a WireGuard client on the existing VM. It did not initialize a completely empty profile and verify the current download/build/disk/seed/cloud-init lifecycle. Setup tests mock core steps; guest-preparation tests mainly inspect generated cloud-config dictionaries.

Evidence: actual fresh-peer scope (`docs/development/results.md:37`, reviewed snapshot), mocked setup (`tests/test_public_cli.py:302`, reviewed snapshot), cloud-config tests (`tests/test_validation.py:153`, reviewed snapshot), preparation implementation (`scripts/guest-prepare.py:68`, reviewed snapshot).

**Change:** make a disposable empty-state installation a release check. Add interrupted download/preparation retry coverage. Label existing live evidence according to its actual scope.

**Required test:** initialize empty state, resolve/download/build, generate unique disk/seed/keys, finish cloud-init, run Claude, reboot and verify user/resources/network. Clean up the disposable machine and its managed peer intentionally.

### R11 — The CLI is still too much of an operator interface

**High confidence.** Guided settings are useful, but normal setup still involves multiple commands and repeated profile/template/key/user options. First contact without a command is an argparse error. The advertised everyday surface contains sixteen actions, while repair messages also refer to hidden developer commands.

Diagnostics are uneven: `doctor` reports missing prerequisites but always exits zero; public `check` skips strict validation when VM construction retained a `config_error`, then can use probe defaults such as this deployment’s IP and blocked ICMP. Runtime code also depends on the shipped `tests/` tree.

Evidence: parser (`vm/cli.py:53`, reviewed snapshot), doctor (`vm/cli.py:422`, reviewed snapshot), check dispatch (`vm/cli.py:521`, reviewed snapshot), probe invocation (`vm/runtime.py:482`, reviewed snapshot).

**Change:** a short interactive front door and guided setup/profile selection. Put supported diagnostics in application code; keep tests as tests. Make hard prerequisite failures actionable, and validate the selected profile before diagnostics.

**Required test:** no-argument first run and returning-user menu, invalid profile diagnostics, unavailable host prerequisites, forwarded Claude arguments and stdin.

### R12 — The route contract is copied and one setting is decorative

**High confidence; reproduced.** `wireguard.remote_port` is accepted and documented, but changing it produces identical framed-client arguments. The framed client uses `stream_port`; the VPS uses a separately fixed internal UDP port.

Evidence: packet settings (`gateway/packet.py:49`, reviewed snapshot), carrier arguments (`gateway/packet.py:229`, reviewed snapshot), configuration table (`docs/configuration.md:132`, reviewed snapshot).

Addresses, ports, MTU, marks, route table IDs and expectations are repeated between host schema, gateway validators/renderers, remote script and response checks. Some duplication is necessary at separate trust boundaries; hand-copying defaults is not.

**Change:** remove the unused user-facing port or genuinely implement it end to end. For this fixed-route product, removing unnecessary knobs is preferable. Share one supported contract and derive artifacts while retaining independent validation at trust boundaries.

**Required test:** each exposed setting affects a supported runtime input or is rejected; the same contract reaches host, gateway and VPS checks.

### R13 — There are small real leftovers and larger research leftovers

**High confidence for repository callers.**

Confirmed candidates:
- runtime compatibility forwarding entry point (`vm/runtime.py:497`, reviewed snapshot): no repository caller.
- duplicate runtime status (`vm/runtime.py:471`, reviewed snapshot): public status uses the CLI implementation.
- Workflow.start (`vm/workflows.py:94`, reviewed snapshot): no production caller.
- packet_transport/stream_mode properties (`vm/config.py:249`, reviewed snapshot): no production callers.
- Creation-field lists and subprocess/private-file helpers repeat across modules; some have different security semantics and should not be merged blindly.
- CLI orchestration reaches into private SSH methods.
- Old commands remain in errors, such as `lemonbox console`, although that command was removed.
- experimental MTU comparator (`tests/validate_transport_mtu.py:1`, reviewed snapshot) needs separately prepared alternate HY2/echo ports outside the production route.
- Browser-scanner helpers cannot select the temporary driver/environment the docs recommend; validate_browser (`tests/validate_browser.py:137`, reviewed snapshot) runs remote system Python and discovers installed guest dependencies.
- Engineering instructions still mix current guidance, old test totals, old examples and chronological experiments. The network page (`docs/development/network.md:149`, reviewed snapshot) explicitly says to retain transparent mode “for compatibility”; that statement conflicts with the intended fresh-only product scope.

The remaining **transparent guest routing itself is active bootstrap functionality**, not unreachable old-version support. Removing it without changing setup would break current provisioning. The old raw WireGuard UDP format and server-v1 migration paths are gone; strings such as `iptables-legacy-save` refer to real existing host-firewall inspection and are not equivalent compatibility leftovers.

**Change:** delete uncalled wrappers; archive optional research tooling and chronological records; keep concise current architecture and test instructions. Correct actual examples, including the native validation command (`docs/development/validation.md:41`, reviewed snapshot) that omits Los Angeles timezone while its helper defaults to New York.

### R14 — Release identity and routine verification are missing

**High confidence.** The repo has no committed baseline or CI. Existing live reports are host-private and chiefly identify deployment snapshots. They are useful evidence, but not a reproducible release contract.

**Change:** after the chosen cleanup is reviewed, create a source baseline and automated offline checks, plus an artifact manifest connecting source revision, resolved dependencies and the precise live-test scope. A heavyweight packaging framework is not inherently necessary.

**Required test:** a clean checkout can run the documented offline command; a release identifies its source, image and dependency versions; empty-state release verification is reproducible.

## What should survive cleanup

The following code has a concrete purpose for your requirements:

| Keep | Reason |
| --- | --- |
| Fixed two-hop route and no alternative egress | Prevents accidental public-IP switching |
| Default-deny guest/physical forwarding and source validation | Contains guest-root and malformed traffic |
| Kernel-expiring leases and explicit failure latch | Enforces closure if the monitor/transport dies |
| Exact remote post-NAT source/interface guard | Enforces the assigned exit on forwarded packets |
| Framing and full-size TCP/UDP/ICMP/MTU behavior | Preserves the guest’s packet stack |
| SSH host-key pinning and transport keys outside the guest | Protects provisioning and keeps guest credentials separate |
| Runtime ownership/mount checks and immutable image pins | Prevents operating on the wrong runtime or adopting unapproved artifacts |
| Atomic private files and transaction recovery | Protects valid settings and interrupted operations |
| Real framing/socket tests, raw counter/capture controls and fault tests | Verify consequences rather than source spelling |

Generated `proxy.json` and `wireguard.json` are not additional user configurations. They are derived, least-privilege inputs for the external gateway. Saved templates are deliberate private snapshots. Disk/base/seed files are VM state. These can be organized more clearly without pretending all duplicates are removable.

## Proposed simpler CLI

The ordinary user should not have to repeatedly type profile, template, SSH key and username arguments.

A possible everyday interface:

```text
lemonbox             Open the menu; guide first setup if needed
lemonbox claude      Open Claude in the selected VM
lemonbox shell       Open a shell, including a repair shell
lemonbox desktop     Open the desktop connection
lemonbox files       Add/remove/view shared folders
lemonbox settings    Guided VM/network settings
lemonbox status      Report readiness and actionable problems
```

The menu selects the working VM. First setup asks for a template, account/resources, fixed route, VPS key/user/trust and optional folders, then performs the supported setup sequence. Remember the selected profile explicitly. Keep CLI flags for automation and forwarded Claude options, but do not require them in the normal guide.

Use the existing guided-config implementation as a starting point. Do not add a UI framework, plugin system or generic command-dispatch framework merely to provide a small menu.

## Approved cleanup

The user chose the complete fresh-only cleanup: fix every finding, provide one guided CLI, provision the VPS before first guest Internet access, retain only the full packet route, and remove superseded code and research tooling. Mandatory proxy enforcement remains required. Old-format migration support is outside the scope.

### Execution order

1. Freeze a source snapshot and define the supported user contract, including the simple CLI and one managed peer per exit.
2. Fix profile locking, staged application and accurate backend errors.
3. Make route repair independent of guest packet health; separate repair shell access from guest-wide health.
4. Correct health deadlines and preserve untouched transports during rollback.
5. Implement the fresh setup flow and remove the superseded paths.
6. Consolidate contracts/diagnostics, trim uncalled wrappers and archive research history.
7. Establish release artifacts/update policy and run empty-state installation plus targeted live enforcement tests.
8. Rewrite the concise user docs around the final flow, and produce a before/after review.

### Acceptance tests

- Competing/stale settings operations cannot silently lose changes.
- Interrupted apply produces a consistent previous or explicitly pending generation.
- Backend errors cannot be reported as absent/stopped runtimes.
- A degraded guest remains accessible for repair.
- Profile A → profile B → profile A takeover works through the public tool and the same pinned route.
- Peer-only rollback preserves an unchanged framed connection.
- Probe deadlines fit the kernel lease with a clear margin.
- Network “blocked”/TTL results distinguish actual enforcement from unrelated failure.
- A complete empty-state installation runs Claude, reboots, opens VNC and supports writable/read-only files.
- Fixed exit, raw-packet denial, full-size packet behavior, outage closure and restart recovery remain verified.
- Refresh updates the selected runtime deliberately without breaking other profiles.
- User-facing setup succeeds with guided choices and short commands; automation remains available.
- Source/docs contain no real route passwords or private keys; temporary diagnostics stay outside the production guest.

## Decision

Full cleanup is approved. This document preserves the original findings; [cleanup results](cleanup-results.md) describes their resolution and verification.
