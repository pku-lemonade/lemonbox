# Validation

## Normal development

Run the offline suite once after a coherent batch of changes. It uses Python 3.11+ and the standard library and takes about three seconds:

```sh
python3 -m unittest discover -s tests -p 'test_*.py' -q
```

For a focused edit, run the affected test module while working, then the whole suite once before committing. CI also compiles Python and checks the guest shell scripts; these are inexpensive syntax checks.

```sh
python3 -m compileall -q vm gateway scripts guest
bash -n guest/provision.sh guest/desktop.sh
```

`guest/readiness.py`, `guest/authorized_keys.py` and `guest/shares.py` are loaded directly from the checkout and run transiently over SSH. Readiness uses `python3 -c`; key and share management send source to `python3 -`. All three take a JSON request argument. They are not installed in the guest, and readiness leaves stdin available for the user's command.

## Choose live checks by the change

| Change | Useful additional check |
| --- | --- |
| Docs, test cleanup or wording | Offline checks |
| CLI, SSH, files or desktop behavior | One affected action on an existing VM |
| QEMU, image or namespace wiring | Build once after edits are complete; start the existing test VM and check the changed behavior |
| Guest provisioning, cloud image or package pins | One fresh first boot, reusing the test profile |
| Packet policy, carrier or failure handling | Relevant packet/root/fault checks on existing VMs |
| Enforcement release | Complete shared fault matrix once, after source and image are frozen |

Use the default and one reusable test VM. Do not create extra test profiles or change the VPS for ordinary validation. Keep the default identity/data intact. Reports stay in private host state; validation programs run transiently over SSH. Retain normal system logs.

`lemonbox diagnose` is the supported native guest/route check. It verifies the exact exit and uses a real control listener plus firewall counters for private blocking. A timeout or refused service alone is not evidence of enforcement.

The optional operator tools in `tests/` are:

- `validate_packet.py`: six TCP/verified TLS/TTL/MTU/ICMP/UDP checks, with a 60-second guest budget and 80-second SSH limit. It does not download a speed-test payload.
- `validate_adversarial.py`: guest-root spoofed, private/inter-VM, IPv6 and unsupported frames, verified against external drop counters.
- `validate_faults.py`: one chosen local failure, existing/new TCP/UDP denial, actual empty lease gates and management SSH survival. The 35-second gate observation limit covers the real 30-second kernel lease.
- `validate_recovery.py`: temporary stream/proxy/WireGuard loss, route removal or a 35-second controller pause. It verifies guest-gate closure, SSH survival, recovery on the same exit and an unchanged guest boot ID. The pause has an independent resume watchdog.

Use `validate_recovery.py` for automatically repairable faults. `validate_faults.py --fault block` still verifies an explicit operator block; its long denial-sampling protocol is not appropriate for transient faults that can now recover while being sampled. A persistent failure must produce a gateway alert that `lemonbox status` and other local commands display from published state. Test alert display and clearing with published-state fixtures offline, including missing and stale metadata reporting status unavailable, or use one bounded existing-gateway incident and then restore it.

Inspect each tool's help; pass the selected VM's pinned SSH configuration and allocated gateway address. Packet measurements require `--expected-exit-ip`; fault checks require `--first-hop-ip`. Read these values from your private route configuration; the tools have no deployment-specific defaults. There is no separate native guest wrapper: use `lemonbox diagnose`.

For an enforcement release, run both VMs with distinct addresses/identities and the same expected exit. Verify stopping one preserves the other; exercise the six local faults plus wrong-exit closure and explicit recovery. Check both guests, kernel gates and first-hop counters. Recover with `lemonbox stop --all`, then start the required VMs. Stop the reusable test VM afterward.

Cold installation, routine offline tests and full failure testing establish different things. Record exact source/image and scope; do not repeat a cold installation or complete fault matrix for unrelated edits.

## Where the time went

Before trimming, 306 VM tests took about 3.4 seconds. The older Docker suite took about 25 seconds, largely from local mock-server shutdown polling and repeated mock interpreter startup. Its fixtures now poll every 10 ms and skip unnecessary Python site startup.

The earlier seven-case live fault reports span 648 seconds, including recovery between cases; SSH/VNC workflows took 38 seconds. Repeated boots, image builds and first-boot downloads added more time. Those tasks are now reserved for the changes above. The packet speed benchmark and duplicate native validation wrapper were removed.
