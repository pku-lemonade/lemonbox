#!/usr/bin/env python3
"""Exercise bounded automatic recovery on an existing gateway and running VM.

This temporarily interrupts the selected gateway. No VM, profile, route pin or
remote server is created or reconfigured. The pinned guest SSH link must already
work. Unlike validate_faults.py, this probe expects the gateway to recover.
"""
import argparse
import datetime
import ipaddress
import json
from pathlib import Path
import re
import selectors
import shlex
import signal
import subprocess
import sys
import time
import uuid

from report import private_report


CHILDREN = {"stream-kill": "stream_pid", "proxy-kill": "mihomo_pid", "wireguard-kill": "wireguard_pid"}
RECOVERY_SECONDS = 180
CLOSURE_SECONDS = 40
PAUSE_SECONDS = 35

# A separate session survives interruption or SIGKILL of this validator. It owns
# STOP and the timed CONT, so killing the operator's terminal cannot strand PID 1.
# The parent also requests CONT in its finally block. Never print command output.
PAUSE_WATCHDOG = r'''
import json, signal, subprocess, sys, threading
resume = threading.Event()
signal.signal(signal.SIGTERM, lambda *_: resume.set())
signal.signal(signal.SIGINT, lambda *_: resume.set())
try:
    result = subprocess.run(["podman", "kill", "--signal", "STOP", sys.argv[1]],
                            capture_output=True, timeout=10)
    print(json.dumps({"stopped": result.returncode == 0}), flush=True)
    if result.returncode == 0:
        resume.wait(float(sys.argv[2]))
finally:
    for attempt in range(3):
        try:
            result = subprocess.run(["podman", "kill", "--signal", "CONT", sys.argv[1]],
                                    capture_output=True, timeout=5)
            if result.returncode == 0:
                break
        except (OSError, subprocess.TimeoutExpired):
            pass
'''


class ProbeFailure(RuntimeError):
    """Only fixed, credential-free error codes may enter the report."""


def remaining(deadline, cap=5):
    available = deadline - time.monotonic()
    if available <= 0:
        raise ProbeFailure("recovery_deadline_expired")
    return min(cap, available)


def operation(args, command, *, timeout=5, allow_failure=False):
    completed = subprocess.run(["podman", "exec", args.gateway, *command],
                               text=True, capture_output=True, timeout=timeout)
    if completed.returncode and not allow_failure:
        raise ProbeFailure("gateway_operation_failed")
    return completed


def read_ready(args, *, timeout=5):
    value = json.loads(operation(args, ["cat", "/run/lemon/ready.json"], timeout=timeout).stdout)
    if not isinstance(value, dict) or any(type(value.get(key)) is not int or value[key] <= 1
                                          for key in CHILDREN.values()):
        raise ProbeFailure("invalid_recorded_children")
    return {key: value[key] for key in CHILDREN.values()}


def recovery_status(args, *, timeout=5):
    value = json.loads(operation(args, ["cat", "/run/lemon/recovery.json"], timeout=timeout).stdout)
    if not isinstance(value, dict) or value.get("schema") != 1 or value.get("status") not in (
            "healthy", "recovering", "failed", "blocked"):
        raise ProbeFailure("invalid_recovery_status")
    # Ignore free-form reasons and all other fields, including future additions.
    result = {"status": value["status"]}
    if type(value.get("attempts")) is int and value["attempts"] >= 0:
        result["attempts"] = value["attempts"]
    if "retrying" in value:
        if type(value["retrying"]) is not bool:
            raise ProbeFailure("invalid_recovery_status")
        result["retrying"] = value["retrying"]
    return result


def local_health(args, *, timeout=5):
    completed = operation(args, ["python3", "/opt/lemon/controller.py", "check", "--local"],
                          timeout=timeout, allow_failure=True)
    if completed.returncode:
        return False
    value = json.loads(completed.stdout)
    return (isinstance(value, dict) and value.get("ready") is True
            and value.get("expected_exit_ip") == args.expected_exit_ip)


def gate_state(args, *, timeout=5):
    value = json.loads(operation(args, ["nft", "-j", "list", "table", "inet", "lemon_vm"],
                                 timeout=timeout).stdout)
    gates = {}
    for entry in value.get("nftables", []):
        item = entry.get("set", {})
        name = item.get("name")
        if name in ("guest_ready", "transport_ready"):
            if name in gates or not isinstance(item.get("elem", []), list):
                raise ProbeFailure("invalid_kernel_gates")
            # expires=0 is rounded and can still admit packets. Only an empty
            # set proves that guest packets cannot pass the kernel gate.
            gates[name] = bool(item.get("elem", []))
    if set(gates) != {"guest_ready", "transport_ready"}:
        raise ProbeFailure("missing_kernel_gates")
    return gates


def ssh(args, remote, *, timeout=20):
    command = ["ssh", "-F", args.ssh_config, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
               "-o", "ConnectTimeout=5", "-o", "ConnectionAttempts=1", "-o", "ServerAliveInterval=2",
               "-o", "ServerAliveCountMax=2", "-o", "ClearAllForwardings=yes", "-o", "ControlPath=none",
               "-T", args.ssh_target, shlex.join(remote)]
    completed = subprocess.run(command, text=True, capture_output=True, timeout=timeout,
                               stdin=subprocess.DEVNULL)
    if completed.returncode:
        raise ProbeFailure("pinned_guest_ssh_failed")
    return completed.stdout.strip()


def guest_boot_id(args, *, timeout=12):
    value = ssh(args, ["cat", "/proc/sys/kernel/random/boot_id"], timeout=timeout)
    try:
        return str(uuid.UUID(value))
    except ValueError:
        raise ProbeFailure("invalid_guest_boot_id") from None


def guest_exit(args):
    # -q ignores .curlrc; unset proxy variables and explicitly disable curl's
    # proxy support. Only the expected IP is retained, never a response body.
    remote = ["env"]
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY", "NO_PROXY",
                 "http_proxy", "https_proxy", "all_proxy", "ftp_proxy", "no_proxy"):
        remote.extend(["-u", name])
    remote.extend(["curl", "-q", "-4", "--noproxy", "*", "--proxy", "", "--fail", "--silent",
                   "--show-error", "--connect-timeout", "5", "--max-time", "12", "--proto", "=https",
                   "https://api.ipify.org"])
    try:
        observed = str(ipaddress.IPv4Address(ssh(args, remote)))
    except ValueError:
        raise ProbeFailure("invalid_native_https_exit") from None
    if observed != args.expected_exit_ip:
        raise ProbeFailure("native_https_exit_mismatch")
    return observed


def start_pause(args):
    watchdog = subprocess.Popen([sys.executable, "-c", PAUSE_WATCHDOG, args.gateway, str(PAUSE_SECONDS)],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, start_new_session=True)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(watchdog.stdout, selectors.EVENT_READ)
            if not selector.select(15):
                raise ProbeFailure("gateway_pause_timed_out")
            if json.loads(watchdog.stdout.readline()).get("stopped") is not True:
                raise ProbeFailure("gateway_pause_failed")
        return watchdog
    except BaseException:
        finish_pause(args, watchdog)
        raise


def finish_pause(args, watchdog):
    if watchdog.poll() is None:
        try:
            watchdog.terminate()  # Handler wakes its finally/CONT immediately.
        except ProcessLookupError:
            pass
    try:
        watchdog.wait(timeout=20)
    except subprocess.TimeoutExpired:
        # Leave the detached watchdog alive so its independent timer can fire.
        pass
    finally:
        watchdog.stdout.close()
    completed = subprocess.run(["podman", "kill", "--signal", "CONT", args.gateway],
                               capture_output=True, timeout=10)
    return completed.returncode == 0


def induce_fault(args, baseline):
    if args.fault in CHILDREN:
        key = CHILDREN[args.fault]
        ready = read_ready(args)
        if ready != baseline:
            raise ProbeFailure("children_changed_before_fault")
        operation(args, ["kill", "-KILL", str(ready[key])])
        return {"child": key, "signal": "SIGKILL"}
    if args.fault == "route-remove":
        operation(args, ["ip", "route", "del", "default", "dev", "wg0", "table", "177"])
        return {"route": "default dev wg0 table 177", "operation": "remove"}
    raise ProbeFailure("unknown_fault")


def wait_for_guest_closure(args, started):
    deadline = started + CLOSURE_SECONDS
    while True:
        gates = gate_state(args, timeout=remaining(deadline))
        observed = time.monotonic()
        if observed > deadline:
            raise ProbeFailure("guest_gate_closure_timed_out")
        if not gates["guest_ready"]:
            boot = guest_boot_id(args, timeout=remaining(deadline, 12))
            return boot, {"latency_seconds": round(observed - started, 3),
                          "deadline_seconds": CLOSURE_SECONDS,
                          "verified_from": "nft guest_ready set empty",
                          "transport_gate_open_at_observation": gates["transport_ready"]}
        time.sleep(min(.1, remaining(deadline)))


def wait_for_recovery(args, baseline, started, states):
    deadline = started + RECOVERY_SECONDS
    while True:
        state = recovery_status(args, timeout=remaining(deadline))
        if not states or state != {key: value for key, value in states[-1].items() if key != "elapsed_seconds"}:
            states.append(state | {"elapsed_seconds": round(time.monotonic() - started, 3)})
        if state["status"] == "blocked" or (state["status"] == "failed" and state.get("retrying") is not True):
            raise ProbeFailure("gateway_recovery_" + state["status"])
        if state["status"] == "healthy" and local_health(args, timeout=remaining(deadline)):
            ready = read_ready(args, timeout=remaining(deadline))
            key = CHILDREN.get(args.fault)
            if key is None or ready[key] != baseline[key]:
                elapsed = time.monotonic() - started
                if elapsed > RECOVERY_SECONDS:
                    raise ProbeFailure("recovery_deadline_expired")
                return ready, round(elapsed, 3)
        time.sleep(min(.5, remaining(deadline)))


def run(args):
    report = {"schema": 1, "kind": "automatic_recovery", "fault": args.fault, "passed": False,
              "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "recovery_deadline_seconds": RECOVERY_SECONDS, "checks": {}, "recovery_states": []}
    checks = report["checks"]
    watchdog = None
    try:
        if not local_health(args) or recovery_status(args)["status"] != "healthy":
            raise ProbeFailure("gateway_baseline_unhealthy")
        baseline = read_ready(args)
        report["children_before"] = baseline
        boot = guest_boot_id(args)
        report["guest_boot_id_before"] = boot
        report["expected_exit_ip"] = guest_exit(args)
        checks["baseline_healthy"] = True
        started = time.monotonic()
        if args.fault == "lease-expiry":
            watchdog = start_pause(args)
            report["injected_fault"] = {"signal": "SIGSTOP", "target": "gateway parent",
                                        "automatic_sigcont_seconds": PAUSE_SECONDS}
        else:
            report["injected_fault"] = induce_fault(args, baseline)
        closed_boot, closure = wait_for_guest_closure(args, started)
        report["guest_gate_closure"] = closure
        checks["guest_gate_closed"] = True
        checks["pinned_ssh_reachable_during_closure"] = closed_boot == boot
        if closed_boot != boot:
            raise ProbeFailure("guest_rebooted_during_closure")
        ready, elapsed = wait_for_recovery(args, baseline, started, report["recovery_states"])
        report["children_after"] = ready
        report["recovered_after_seconds"] = elapsed
        checks["automatic_recovery_healthy"] = True
        if args.fault in CHILDREN:
            key = CHILDREN[args.fault]
            checks["chosen_child_replaced"] = ready[key] != baseline[key]
        after_boot = guest_boot_id(args)
        report["guest_boot_id_after"] = after_boot
        checks["guest_boot_preserved"] = after_boot == boot
        guest_exit(args)
        checks["native_https_exit_preserved"] = True
        report["passed"] = all(checks.values())
    except ProbeFailure as error:
        report["error"] = str(error)
    except KeyboardInterrupt:
        report["error"] = "validation_interrupted"
    except (OSError, ValueError, TypeError, AttributeError, subprocess.SubprocessError):
        report["error"] = "external_recovery_validation_failed"
    finally:
        if watchdog is not None:
            try:
                checks["gateway_parent_resumed"] = finish_pause(args, watchdog)
            except (OSError, subprocess.SubprocessError):
                checks["gateway_parent_resumed"] = False
            report["passed"] = report["passed"] and checks["gateway_parent_resumed"]
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway", default="lemonbox-gateway")
    parser.add_argument("--ssh-config", required=True)
    parser.add_argument("--ssh-target", default="lemonbox")
    parser.add_argument("--expected-exit-ip", required=True)
    parser.add_argument("--fault", choices=(*CHILDREN, "lease-expiry", "route-remove"), default="stream-kill")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", args.gateway) or not re.fullmatch(r"[^\s-][^\s]*", args.ssh_target):
        parser.error("invalid local target")
    try:
        args.expected_exit_ip = str(ipaddress.IPv4Address(args.expected_exit_ip))
        args.ssh_config = str(Path(args.ssh_config).resolve(strict=True))
    except (OSError, ValueError):
        parser.error("a pinned SSH configuration and numeric expected IPv4 exit are required")
    # SIGTERM follows the same report and resume cleanup path as Ctrl-C.
    def interrupted(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    report = run(args)
    private_report(args.output, report)
    for name, passed in report["checks"].items():
        print(("PASS " if passed else "FAIL ") + name)
    if not report["passed"]:
        print("FAIL " + report.get("error", "automatic_recovery_validation"))
    print("Recovery report: " + args.output)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
