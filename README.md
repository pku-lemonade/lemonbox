# Lemonbox

Persistent Debian VMs for Claude Code and collaborative development, with shared workspaces and a fixed network exit.

Each VM has a shell and optional desktop. Local VMs use one shared gateway; route credentials stay on the host.

## Start

Prepare the host tools, runtime image, Mihomo and Debian image once using [Host preparation](docs/setup.md). Lemonbox does not download host tools, build images or administer your VPS.

Install the launcher for all host users once from this checkout:

```bash
sudo python3 scripts/install-launcher.py
lemonbox
```

This creates `/usr/local/bin/lemonbox` as a link to this checkout; `/usr/local/bin` must be on each user's `PATH`. Future source edits need no reinstall. Other users need read/execute access to the checkout, but only its owner or trusted administrators should be able to change it or its parent directories. `./lemonbox` also works directly.

Choose **Create a VM**. The guide asks for your username, hostname, timezone, CPU, memory, disk and optional desktop/Docker. Saved VM templates can supply defaults. Configure the shared route once using your Hysteria chain and the keys matching your already prepared external WireGuard gateway. Passwords and private keys use hidden input.

The gateway verifies the fixed route before allowing guest Internet access. First boot with the desktop and Docker downloads roughly 650 MB of guest software; timing depends on your connection. Sign in to Claude using your own account.

```bash
lemonbox claude
lemonbox shell
lemonbox desktop
```

Commands start a stopped VM automatically. Your home is `/home/<username>`; files and Claude state survive stop, restart and host reboot. `lemonbox shell` opens in `~/workspace` when it exists; `--workdir` selects another directory. A running VM's shell stays accessible when Internet access or provisioning fails.

## Files and desktop

Each new VM gets `~/workspace`, backed by `workspaces/<vm-name>/` inside the Lemonbox checkout. Everyone with access to that VM shares its workspace, and files persist across restarts. Each VM has a separate host folder.

`lemonbox files` guides additional host folder selection, including read-only access. A shared folder appears at `~/name`. Adding or removing a share restarts only that VM; removing it keeps the host files.

`lemonbox desktop` starts the optional desktop and a localhost VNC tunnel. Keep its terminal open and use the displayed address. TigerVNC uses `127.0.0.1::5901`. Ctrl-C closes the tunnel; `lemonbox desktop --stop` stops the desktop.

Use `lemonbox desktop --show-password` with the same VM selection to display its VNC password. Password authentication supports macOS Screen Sharing and other VNC viewers.

On a remote host connected to Tailscale, use `lemonbox desktop --tailnet` and connect your VNC viewer to the displayed Tailscale address. Access lasts while the command runs. Anyone allowed by tailnet rules to reach that port can use the desktop with its VNC password. For two VMs, choose separate ports with `--port 5901` and `--port 5902`. See [Desktop](docs/usage.md#desktop).

## Multiple VMs

Select or create a VM in the menu. Each VM has its own disk, account, SSH identity, private IPv4 and relay port. They can run concurrently through the same gateway and public exit. `lemonbox stop` and `restart` affect only the selected VM; `lemonbox stop --all` also stops the shared gateway.

Use `lemonbox settings` for VM settings or the shared route. Shared route changes, manual gateway replacement and runtime updates require all VMs stopped. Automatic tunnel recovery preserves running VMs. Templates contain VM settings only; credentials are stored once in the shared gateway directory.

## Join a shared VM

On the same Linux host:

1. The owner runs `lemonbox access`, chooses **Add local user** and enters the person's host username.
2. That person runs `lemonbox join` under their own account and confirms the displayed owner. If several VMs are available, choose one.

Lemonbox checks the local account and registers that person's SSH key automatically. No connection details or keys need copying. Each person needs Python 3.11+, OpenSSH and the `lemonbox` command; collaborators need no Podman, KVM, sudo or `claude` group membership.

```bash
lemonbox join
lemonbox claude
lemonbox shell
```

Join saves the trusted connection; reconnecting needs no further approval. Each person keeps their own private key. Collaborators share the guest account, its sudo access, files and Claude state; they cannot manage the owner's Podman containers or VM settings through joined mode.

For someone on another computer, choose **Remote access** instead. That flow exchanges connection details and a public key; use an existing SSH forward or Tailscale to reach the VM. [Access and joining](docs/usage.md#access-and-joining) covers both methods and removing access.

`lemonbox shell` configures SSH automatically. For plain `ssh`, `scp` or an SSH editor, see [Native SSH configuration](docs/usage.md#native-ssh). Lemonbox generates private connection files with the VM host key pinned; it does not edit your `~/.ssh/config`.

## Routing and support

IPv4 TCP, UDP and ICMP use the shared fixed packet tunnel. IPv6, host and LAN destinations are blocked. A failed route closes Internet access for all attached VMs while the gateway repairs the same tunnel. It verifies the configured public exit before reopening traffic and preserves running VM sessions. It never selects another route.

The gateway continuously verifies the route, repairs transient failures and publishes recovery state and alerts. `lemonbox status` and other local Lemonbox commands display that reported state when invoked. Missing or stale reports appear as status unavailable. An unexpected exit, invalid configuration or explicit operator block stays closed for inspection. See [recovery and alerts](docs/troubleshooting.md#internet-is-closed).

This is an observable Linux VM. Virtualization and routing do not guarantee how a service classifies it.

```bash
lemonbox status
lemonbox diagnose
lemonbox --help-all
```

[Usage](docs/usage.md) · [Configuration](docs/configuration.md) · [Troubleshooting](docs/troubleshooting.md) · [Manual VPS reference](docs/vps.md)

Dependency pins are documented in [release.json](release.json). Update it together with the corresponding Dockerfile, guest provisioning and runtime values, then rebuild manually; `lemonbox update` applies the image you already built.
