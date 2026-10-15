#!/usr/bin/env python3
"""Verify guest-root raw packets hit external gateway drop rules."""
import argparse
import datetime
import json
from pathlib import Path
import shlex
import subprocess
import sys
import time

from report import private_report


def gateway_command(args, command):
    result = subprocess.run(["podman", "exec", args.gateway, *command], text=True,
                            capture_output=True, timeout=20, check=True)
    return result.stdout


def ingress_counters(args):
    table = json.loads(gateway_command(args, ["nft", "-j", "list", "table", "inet", "lemon_vm"]))
    result = {}
    for entry in table.get("nftables", []):
        rule = entry.get("rule", {})
        expressions = rule.get("expr", [])
        if rule.get("chain") != "guest_ingress" or not any("drop" in part for part in expressions):
            continue
        encoded = json.dumps(expressions)
        if '"nfproto"' in encoded:
            category = "non_ipv4"
        elif '"saddr"' in encoded:
            category = "spoofed_source"
        elif '"daddr"' in encoded:
            category = "private_destination"
        else:
            category = "unsupported_protocol"
        result[category] = result.get(category, 0) + sum(
            part["counter"]["packets"] for part in expressions if "counter" in part)
    if set(result) != {"non_ipv4", "spoofed_source", "private_destination", "unsupported_protocol"}:
        raise RuntimeError("ingress-drop counters were not found")
    return result


def run(args):
    gateway_command(args, ["python3", "/opt/lemon/controller.py", "check", "--local"])
    before = ingress_counters(args)
    source = Path(__file__).with_name("adversarial_guest.py").read_text()
    remote = "sudo -n python3 -c " + shlex.quote(source)
    if args.allow_provisioning:
        remote += " --allow-provisioning"
    command = ["ssh", "-F", args.ssh_config, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
               "-o", "ConnectTimeout=15", args.ssh_target, remote]
    probe = subprocess.run(command, text=True, capture_output=True, timeout=60, check=True)
    offered = json.loads(probe.stdout)
    if offered.get("schema") != 1 or not isinstance(offered.get("offered_frames"), dict):
        raise ValueError("invalid raw guest response")
    time.sleep(1)
    after = ingress_counters(args)
    gateway_command(args, ["python3", "/opt/lemon/controller.py", "check", "--local"])
    checks = {category: after[category] - before[category] >= count
              for category, count in offered["offered_frames"].items()}
    return {"schema": 1, "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "passed": len(checks) == 4 and all(checks.values()), "checks": checks,
            "offered_frames": offered["offered_frames"], "counters_before": before, "counters_after": after,
            "method": offered["method"], "scope": "external drop counters during this bounded raw-frame test"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway", default="lemonbox-gateway")
    parser.add_argument("--ssh-config", required=True)
    parser.add_argument("--ssh-target", default="lemonbox")
    parser.add_argument("--output", required=True)
    parser.add_argument("--allow-provisioning", action="store_true",
                        help="Run bounded raw-frame checks while installation continues")
    args = parser.parse_args()
    if args.ssh_target.startswith("-") or args.gateway.startswith("-"):
        parser.error("invalid configured target")
    try:
        report = run(args)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        report = {"schema": 1, "passed": False, "error": "external guest-root validation failed"}
    private_report(args.output, report)
    for name, passed in report.get("checks", {}).items():
        print(("PASS " if passed else "FAIL ") + name)
    print("Guest-root report: " + args.output)
    return 0 if report.get("passed") else 1


if __name__ == "__main__":
    sys.exit(main())
