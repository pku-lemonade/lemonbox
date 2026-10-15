"""Report native guest provisioning and service readiness over SSH."""
import json
import pathlib
import subprocess
import sys


def command(argv, timeout=15):
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return 124, ""


def main():
    require_docker = json.loads(sys.argv[1])["require_docker"]
    code, output = command(["cloud-init", "status", "--format", "json"])
    try:
        cloud = json.loads(output)
        if not isinstance(cloud, dict):
            cloud = {}
    except ValueError:
        cloud = {}
    cloud_status = cloud.get("status", "unavailable")
    cloud_failed = cloud_status == "error" or bool(cloud.get("errors"))
    ssh_code, _ = command(["systemctl", "is-active", "ssh"])
    claude = pathlib.Path.home() / ".local/bin/claude"
    claude_code, claude_version = command([str(claude), "--version"])
    docker_code = 0
    docker_client_code, docker_client_version = 0, ""
    if require_docker:
        docker_code, _ = command(["systemctl", "is-active", "docker"])
        docker_client_code, docker_client_version = command(["docker", "--version"])
    docker_client_ready = not require_docker or (docker_client_code == 0 and bool(docker_client_version))
    print(json.dumps({
        "cloud_status": cloud_status,
        "cloud_complete": code == 0 and cloud_status == "done" and not cloud_failed,
        "cloud_failed": cloud_failed or (cloud_status == "done" and code != 0),
        "ssh_ready": ssh_code == 0,
        "docker_daemon_ready": docker_code == 0,
        "docker_client_ready": docker_client_ready,
        "docker_ready": docker_code == 0 and docker_client_ready,
        "claude_ready": claude_code == 0 and bool(claude_version),
        "claude_version": claude_version if claude_code == 0 else "",
    }))


if __name__ == "__main__":
    main()
