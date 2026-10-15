#!/usr/bin/env python3
"""Exercise external fail-closed behavior; this intentionally closes networking.

Management SSH remains available. Stop all VMs, recover the shared gateway in
lemonbox settings, then start the VMs again; the closed latch is not reset here.
"""
import argparse
import datetime
import json
from pathlib import Path
import selectors
import shlex
import subprocess
import sys
import time

from report import private_report


ROOT = Path(__file__).resolve().parents[1]

def operation(args, command, timeout=30):
    completed = subprocess.run(["podman", "exec", args.gateway, *command], text=True, capture_output=True, timeout=timeout)
    if completed.returncode:
        raise RuntimeError("gateway operation failed")
    return completed.stdout


def audit(args):
    rules = json.loads(operation(args, ["nft", "-j", "list", "table", "inet", "lemon_vm"]))
    first_hop = None
    drops = 0
    for entry in rules.get("nftables", []):
        rule = entry.get("rule", {})
        expressions = rule.get("expr", [])
        encoded = json.dumps(expressions)
        counters = [part["counter"]["packets"] for part in expressions if isinstance(part, dict) and "counter" in part]
        if rule.get("chain") == "output" and "transport_ready" in encoded and args.first_hop_ip in encoded:
            first_hop = sum(counters)
        if any(isinstance(part, dict) and "drop" in part for part in expressions):
            drops += sum(counters)
    if first_hop is None:
        raise RuntimeError("first-hop enforcement counter was not found")
    return {"first_hop_accepted_packets": first_hop, "dropped_packets": drops}


def response_line(process, timeout):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        if not selector.select(timeout):
            raise RuntimeError("guest validation timed out")
        line = process.stdout.readline()
        if not line:
            raise RuntimeError("guest validation connection closed")
        return json.loads(line)


def kill_transport(args):
    """Kill exactly the chosen recorded child; never fall back to another PID."""
    keys = {"wireguard-kill": "wireguard_pid", "proxy-kill": "mihomo_pid", "stream-kill": "stream_pid"}
    if args.fault not in keys:
        raise ValueError("unknown transport fault")
    ready = json.loads(operation(args, ["cat", "/run/lemon/ready.json"]))
    pid = ready.get(keys[args.fault])
    if type(pid) is not int or pid <= 1:
        raise RuntimeError("chosen transport child is absent from readiness")
    operation(args, ["kill", "-KILL", str(pid)])
    return {"child": keys[args.fault], "signal": "SIGKILL"}


def kernel_gates_closed(args):
    """Require both sets empty; whole-second expiry zero can still be live."""
    policy = json.loads(operation(args, ["nft", "-j", "list", "table", "inet", "lemon_vm"], timeout=5))
    live = {}
    for item in policy.get("nftables", []):
        value = item.get("set", {})
        name = value.get("name")
        if name not in ("guest_ready", "transport_ready"):
            continue
        if name in live:
            raise RuntimeError("ambiguous kernel route gates")
        elements = value.get("elem", [])
        if not isinstance(elements, list):
            raise RuntimeError("invalid kernel route gate")
        # The pinned nftables reports JSON expiry in whole seconds. An
        # expires=0 entry may still admit packets for its remaining fraction
        # of a second. Actually expired entries are omitted by the dump.
        live[name] = bool(elements)
    if set(live) != {"guest_ready", "transport_ready"}:
        raise RuntimeError("both kernel route gates must be present")
    return not any(live.values())


def wait_for_gate_closure(args, fault_started, *, timeout=35):
    """Record real closure before sampling offered traffic, with a hard bound."""
    deadline = fault_started + timeout
    while True:
        before = time.monotonic()
        if before >= deadline:
            raise RuntimeError("kernel route gates did not close within the fault deadline")
        closed = kernel_gates_closed(args)
        observed = time.monotonic()
        if observed > deadline:
            raise RuntimeError("kernel route gate inspection exceeded the fault deadline")
        if closed:
            return {"closure_latency_seconds": round(observed - fault_started, 3),
                    "closure_deadline_seconds": timeout,
                    "closure_verified_from": "both nft guest_ready and transport_ready sets empty"}
        time.sleep(min(.5, deadline - observed))


def run(args):
    source = (ROOT / "tests/fault_guest.py").read_text()
    remote = "python3 -c " + shlex.quote(source)
    ssh = ["ssh", "-F", args.ssh_config, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
           "-o", "ConnectTimeout=15", args.ssh_target, remote]
    stopped = False
    transport_fault = None
    process = subprocess.Popen(ssh, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        baseline = response_line(process, 45)
        if not baseline.get("ready"):
            raise RuntimeError("guest baseline is not functional")
        fault_started = time.monotonic()
        if args.fault == "block":
            operation(args, ["python3", "/opt/lemon/controller.py", "block"])
        elif args.fault == "lease-expiry":
            completed = subprocess.run(["podman", "kill", "--signal", "STOP", args.gateway], capture_output=True, timeout=15)
            if completed.returncode:
                raise RuntimeError("could not suspend the gateway monitor")
            stopped = True
        elif args.fault == "route-remove":
            operation(args, ["ip", "route", "del", "default", "dev", "wg0", "table", "177"])
        else:
            transport_fault = kill_transport(args)
        closure = wait_for_gate_closure(args, fault_started)
        before = audit(args)
        process.stdin.write("CHECK\n")
        process.stdin.flush()
        observed = response_line(process, 45)
        after = audit(args)
        code = process.wait(timeout=10)
        local = subprocess.run(["podman", "exec", args.gateway, "python3", "/opt/lemon/controller.py", "check", "--local"],
                               text=True, capture_output=True, timeout=15)
        checks = dict(observed.get("checks", {}))
        checks.update(first_hop_gate_closed=after["first_hop_accepted_packets"] == before["first_hop_accepted_packets"],
                      offered_traffic_dropped=after["dropped_packets"] > before["dropped_packets"],
                      readiness_closed=local.returncode != 0)
        report = {"schema": 1, "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "fault": args.fault, "passed": bool(observed.get("passed")) and code == 0 and all(checks.values()),
                "baseline": baseline, "checks": checks, "counters_before": before, "counters_after": after,
                "kernel_gate_closure": closure,
                "recovery": "lemonbox stop --all; recover the shared gateway in lemonbox settings, then start the VMs"}
        if transport_fault is not None:
            report["transport_fault"] = transport_fault
        return report
    finally:
        if stopped:
            subprocess.run(["podman", "kill", "--signal", "CONT", args.gateway], capture_output=True, timeout=15)
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway", default="lemonbox-gateway")
    parser.add_argument("--ssh-config", required=True)
    parser.add_argument("--ssh-target", default="lemonbox")
    parser.add_argument("--output", required=True)
    parser.add_argument("--fault", choices=("block", "lease-expiry", "wireguard-kill", "proxy-kill", "stream-kill", "route-remove"), default="block")
    parser.add_argument("--first-hop-ip", required=True)
    args = parser.parse_args()
    if args.ssh_target.startswith("-") or args.gateway.startswith("-"):
        parser.error("invalid local target")
    try:
        report = run(args)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        report = {"schema": 1, "passed": False, "fault": args.fault, "error": "external fault validation failed"}
    private_report(args.output, report)
    if "checks" in report:
        for name, passed in report["checks"].items():
            print(("PASS " if passed else "FAIL ") + name)
    else:
        print("FAIL external_fault_validation")
    print("Fault report: " + args.output)
    return 0 if report.get("passed") else 1


if __name__ == "__main__":
    sys.exit(main())
