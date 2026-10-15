#!/usr/bin/env python3
"""Run bounded native packet-path measurements over the pinned guest SSH link."""
import argparse
import ipaddress
import json
from pathlib import Path
import subprocess
import sys

from report import private_report


PROBE = Path(__file__).with_name("packet_guest.py")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ssh-config", required=True)
    parser.add_argument("--ssh-target", default="lemonbox")
    parser.add_argument("--output", required=True)
    parser.add_argument("--expected-exit-ip", required=True)
    parser.add_argument("--mtu", type=int, default=1500)
    parser.add_argument("--guest-gateway", default="10.77.0.1")
    args = parser.parse_args()
    if args.ssh_target.startswith("-") or not 576 <= args.mtu <= 1500:
        parser.error("invalid SSH target or tunnel MTU")
    try:
        expected = str(ipaddress.IPv4Address(args.expected_exit_ip))
    except ValueError:
        parser.error("expected exit must be a numeric IPv4 address")
    source = ("import sys\nsys.argv = " + repr(["packet_guest.py", "--expected-exit-ip", expected,
                                                 "--mtu", str(args.mtu), "--gateway", args.guest_gateway]) + "\n" + PROBE.read_text())
    command = ["ssh", "-F", args.ssh_config, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
               "-o", "ConnectTimeout=15", args.ssh_target, "python3 -"]
    completed = None
    try:
        completed = subprocess.run(command, input=source, text=True, capture_output=True, timeout=80)
        report = json.loads(completed.stdout)
        if (not isinstance(report, dict) or report.get("schema") != 1
                or report.get("kind") != "native_packet_path" or not isinstance(report.get("checks"), list)):
            raise ValueError("invalid guest packet measurement response")
    except (OSError, ValueError, subprocess.TimeoutExpired):
        report = {"schema": 1, "kind": "native_packet_path", "passed": False, "checks": [],
                  "error": "guest packet measurement transport failed"}
        completed = None
    private_report(args.output, report)
    for item in report["checks"]:
        print(item["status"].upper() + " " + item["name"])
    if completed is None:
        print("FAIL guest_packet_measurement_transport")
    print("Packet report: " + str(Path(args.output)))
    return 0 if report.get("passed") and completed is not None and completed.returncode == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
