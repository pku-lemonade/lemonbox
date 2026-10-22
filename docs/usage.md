# Using Lemonbox

Run `lemonbox` for the menu. It remembers your selected VM and offers setup when needed.

| Command | What it does |
| --- | --- |
| `lemonbox claude` | Open native Claude in your VM |
| `lemonbox shell` | Open your normal Linux shell, including repair access |
| `lemonbox desktop` | Start the desktop and open a local or tailnet VNC connection |
| `lemonbox files` | Add, remove or view shared host folders |
| `lemonbox settings` | Edit, validate and apply settings |
| `lemonbox status` | Show this VM and the gateway's reported health, recovery progress and alerts |
| `lemonbox access` | Connect someone to your VM, or remove their access |
| `lemonbox join` | Connect to someone else's VM with your own SSH key |

## Claude and shell

`lemonbox shell` starts in `/home/<username>/workspace` when that directory exists, including for joined users. Older VMs without a workspace open in the home directory. `lemonbox shell --workdir /absolute/path` overrides the default. Claude and `exec` start in `/home/<username>` unless given `--workdir`. Claude's account state and your files belong to the VM. Host environment variables and credentials are not forwarded.

```bash
lemonbox claude --resume
lemonbox claude --print 'Explain this project'
printf 'Summarize this text' | lemonbox claude --print
lemonbox shell
```

Native Claude options pass through. For an explicit directory:

```bash
lemonbox claude --workdir /home/debian/project -- --resume
```

For scripts, `exec` passes arguments and stdin to the guest and returns its exit code:

```bash
lemonbox exec -- git --version
lemonbox exec --workdir /home/debian/project -- git status
```

A running guest's shell and `exec` remain accessible when Internet access is closed, provisioning has failed or an unrelated service is degraded.

## Native SSH

`lemonbox shell` needs no manual SSH configuration. For native OpenSSH commands, use the generated configuration and its `lemonbox` host alias. On the owner's host, the default VM uses:

```bash
ssh -F ~/.local/share/lemonbox/default/ssh/host-config lemonbox
scp -F ~/.local/share/lemonbox/default/ssh/host-config ./file.txt lemonbox:~/
```

Replace `default` with the VM profile name; a custom state directory contains the same `ssh/host-config` path. This owner configuration connects through the local gateway using Podman.

After a collaborator runs `lemonbox join`, the first saved connection uses:

```bash
ssh -F ~/.local/share/lemonbox/connections/shared/ssh-config lemonbox
```

Join saves connections as `shared`, `shared-2`, and so on. Replace `shared` in the path for another saved connection. Each collaborator uses their own configuration and private key, including when they share the owner's host. [Access and joining](#access-and-joining) describes authorization and making the SSH port reachable.

The VM must already be running: native SSH does not start it. These files select the guest username, authentication key and pinned VM host key. They are generated; keep them private and make connection changes through Lemonbox.

For an editor that reads `~/.ssh/config`, add an `Include` line before existing `Host` entries, pointing to your generated file. For example, on the owner:

```sshconfig
Include ~/.local/share/lemonbox/default/ssh/host-config
```

Then connect to `lemonbox`. Include only the intended VM or joined connection: generated files all use that alias. Lemonbox does not add this entry for you.

## Host files

Each new VM automatically mounts `<lemonbox-checkout>/workspaces/<vm-name>/` at `~/workspace`. For example, a checkout at `/opt/lemonbox` gives the default VM `/opt/lemonbox/workspaces/default`. Everyone authorized for that VM uses the same guest account and can read and write its workspace. Each VM has a separate folder, mounted again on every boot. Workspace contents are excluded from Git and container builds.

Approved local host users can also read and write that VM's workspace directly on the host. The workspace root has a per-user access list; files and subdirectories inherit shared permissions beneath it. The shared VM account's new SSH sessions use a `000` umask for normal file creation. Adding or removing a local VM grant updates host workspace access too. Other host users cannot traverse the workspace root. Explicitly private file modes and user-selected umasks keep their restrictions.

The managed default workspace uses these permissions:

| Path | Permissions |
| --- | --- |
| `workspaces/<vm-name>/` root | Owner `rwx`, approved local users `rwx` through POSIX ACLs, owning group and others no access. Usually displayed as `0700` when owner-only or `0770+` with collaborator ACLs; the group mode bits represent the ACL mask. |
| Ordinary shared files below the root | `0666` (`rw-rw-rw-`) |
| Shared subdirectories and executable files below the root | `0777` (`rwxrwxrwx`) |

The root ACL is what keeps these broadly writable contents accessible only to approved users. Lemonbox manages it through `lemonbox access`; keep the workspace root restricted rather than running `chmod -R 777`. Inspect its full permissions with `getfacl /path/to/lemonbox/workspaces/VM_NAME`.

The first permission setup also makes existing ordinary files writable by collaborators and gives existing subdirectories and executables shared access. After that setup, explicitly private creation modes such as `0600`, later `chmod` changes and guest umask overrides can restrict individual files. Keep private credentials outside the shared workspace.

To copy your own project into the workspace without managing host ownership, upload through the VM's SSH account. After `lemonbox join`, a collaborator can run:

```bash
scp -r -F ~/.local/share/lemonbox/connections/shared/ssh-config \
  ./my-project lemonbox:workspace/
```

The VM must be running. Use the saved connection's directory in place of `shared` when needed. The project appears at `~/workspace/my-project` in the VM, with files created by the shared guest account. No host `chown` or `chmod` is needed for guest access. If you already included that SSH configuration in `~/.ssh/config` as described above, the command is simply `scp -r ./my-project lemonbox:workspace/`. Uploads can retain restrictive source modes, so use the direct host copy below when other host users also need to edit every copied file.

For direct copies by an approved local host user, use this command from the Lemonbox checkout, with rsync installed on the host:

```bash
rsync -rltp --chmod=a=rwX -- ~/my-project/ workspaces/default/my-project/
```

Replace `default` with the VM name. This copies the project's contents, including hidden files, sets shared files to `0666` and directories and executables to `0777`, and leaves the originals untouched. The `-p` option applies the adjusted modes to existing destination files too; see the [rsync permission options](https://rsync.samba.org/ftp/rsync/rsync.1.html#opt--chmod). Always target a project subdirectory so the command does not change the workspace root ACL.

Plain copies can retain restrictive source modes even when a destination default ACL exists. `cp -a`, `rsync -a` without permission adjustments, and moving existing files into the workspace can therefore leave files inaccessible to the VM or other host collaborators.

The default follows the checkout location when a VM is created. Templates get a fresh workspace for each new VM. Existing VMs keep their configured shares; add a workspace to one with `lemonbox files add /path/to/lemonbox/workspaces/VM_NAME --name workspace` after creating that host directory.

`lemonbox files` guides folder selection. Automation can use:

```bash
lemonbox files add ~/code/project
lemonbox files add ~/reference --read-only
lemonbox files list
lemonbox files remove project
```

The host folder's name becomes the guest folder name. Use `--name project` when a different name is needed. Shares mount directly under your home and survive reboot. Writable changes and deletions affect the host folder, including those made with guest sudo. Read-only shares remain read-only to guest root.

Adding or removing a share applies its settings and restarts the VM. Removal detaches the folder and keeps its host contents.

## Desktop

```bash
lemonbox desktop
lemonbox desktop --no-open
lemonbox desktop --show-password
lemonbox desktop --port 5902
lemonbox desktop --stop
```

The guide must have installed the optional desktop when creating this VM. Firefox, terminal, file manager and a Claude launcher are available. Use the guest browser for Claude's sign-in flow.

New desktop VMs include Noto Color Emoji. Add it to an existing VM with `lemonbox exec -- sudo apt-get install --yes --no-install-recommends fonts-noto-color-emoji`, then restart applications that were already open.

VNC is bound to host loopback through the pinned guest SSH connection. Keep the terminal open and connect a viewer to the displayed address. TigerVNC uses a double colon for the port: `127.0.0.1::5901`. Ctrl-C reaps the SSH tunnel; it leaves the VM and desktop running.

Each VM has its own generated VNC password. Run `lemonbox desktop --show-password` on the host with the same VM selection, then enter that password in your viewer. This also works with macOS Screen Sharing. The password survives restarts and is stored privately outside VM templates. Showing it does not start the VM or desktop. On the first desktop launch after this update, Lemonbox applies password authentication to an existing VM and restarts its desktop once; later launches preserve a running desktop when its configuration is unchanged.

For a remote host connected to Tailscale, expose the desktop directly to your tailnet:

```bash
lemonbox --profile second desktop --tailnet --port 5902
```

Run this on the server. Lemonbox discovers its Tailscale IPv4 address and binds the tunnel to that address. Connect a VNC viewer on your computer to the displayed address, for example `100.80.90.100:5902` (TigerVNC: `100.80.90.100::5902`). On macOS, use Finder's **Go → Connect to Server** with `vnc://100.80.90.100:5902`. Retrieve the password on the server with `lemonbox --profile second desktop --show-password`. It prints the address without opening a viewer on the server. Your computer must be connected to the tailnet, and its access rules must allow the server's TCP port. Anyone with that network access and the VNC password can use the shared desktop; Lemonbox SSH user grants do not restrict VNC access.

Keep the command running while using the desktop. Ctrl-C, terminal hangup or command termination closes its listener and connections. Each VM needs a different host port. This option requires the host's Tailscale network interface and IPv4 address; userspace networking is unsupported. Tailscale stays on the host, and no Serve configuration is created. Without `--tailnet`, the listener uses host loopback.

## Lifecycle

```bash
lemonbox stop
lemonbox start
lemonbox restart
lemonbox stop --all
lemonbox setup
```

Stop keeps the disk. Ordinary Claude/shell/desktop commands start it when needed. Restart stops guest jobs and uses the saved VM settings. Setup creates a new VM locally using the configured fixed Hysteria chain and pre-provisioned WireGuard peer. It performs no VPS administration.

Each profile has a separate disk, SSH identity, private IPv4 and allocated relay port. Multiple profiles run concurrently through one shared gateway. Stop/restart affects only the selected VM; `lemonbox stop --all` stops every VM and then the shared gateway.

## Settings

```bash
lemonbox settings
lemonbox settings --save-template current
lemonbox settings --path
lemonbox status --json
lemonbox --help-all
```

Templates contain VM settings only. The shared route credentials stay in one global configuration. Templates exclude guest identities and existing host shares; a new VM gets its own default workspace. Select or create another VM in the menu to reuse one. Shared route changes, manual gateway replacement and runtime updates require all VMs stopped. Automatic tunnel recovery keeps running VMs and verifies the fixed exit before restoring Internet access. `lemonbox status` displays the gateway's reported recovery progress and alerts; other local Lemonbox commands also display reported alerts when invoked. Missing or stale reports appear as status unavailable. For manual replacement, choose shared route recovery in `lemonbox settings` after `lemonbox stop --all`. For scripts, `--profile NAME` selects a VM explicitly; `--state-dir PATH` places its private state elsewhere.

## Access and joining

### Someone on this host

The owner runs `lemonbox access`, chooses **Add local user** and enters the person's existing host username, for example `alice`.

That person runs:

```bash
lemonbox join
```

If several VMs are available, choose one. On first join, check the displayed owner is the person you expect and confirm. Lemonbox verifies the local account and registers that person's SSH key automatically. There is no connection JSON or fingerprint comparison in this flow. Rejoining an already trusted connection keeps its owner approval. Each person runs under their own account and keeps their private key in their own home.

Local join generates a dedicated key at `~/.local/share/lemonbox/connections/shared/id_ed25519` (`shared-2`, etc. for later connections) and displays its path. Rejoining reuses the saved key. Each local join, including a repeat join, offers an optional additional public-key prompt. Press Enter to keep the current keys, or paste a public key or enter its `.pub` file path to authorize another device. It does not automatically reuse `~/.ssh/id_ed25519` or the keys used to log into the host.

To also connect from your laptop through the host, run this **on the host as the approved local user**, supplying your laptop's public key:

```bash
lemonbox join --public-key /path/to/laptop.pub
```

The option also accepts a quoted public-key line and can be repeated for more keys. It keeps the dedicated local key and adds the extra keys to the same user's grant. Rejoining preserves them; removing that user through `lemonbox access` removes all their registered keys. Private keys stay on their original computers.

After updating a host whose sharing relay is already running, the owner must stop and re-enable sharing once to load support for adding keys. This closes active relay connections; it keeps approvals and the VM running.

Your laptop can then use an existing host SSH alias as a jump host. For example, in the laptop's `~/.ssh/config`, where `owner-host` already connects to the Linux host:

```sshconfig
Host lemonbox
    HostName 127.0.0.1
    Port 2222
    User YOUR_VM_USERNAME
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
    ProxyJump owner-host
```

Use the VM's allocated port and the laptop private key matching the public key you added. `ProxyJump` carries the laptop's SSH connection to the host's loopback relay; the VM authenticates the laptop's key. Verify the VM fingerprint with its owner on the first connection.

Collaborators need Python 3.11+, OpenSSH and the `lemonbox` command. They need no Podman, KVM, sudo or `claude` group membership. The VM must be running and sharing enabled for joining or reconnecting.

Once joined:

```bash
lemonbox claude --resume
lemonbox shell
printf 'hello' | lemonbox exec -- cat
lemonbox status
```

Join remembers the VM. Joined mode offers Claude, shell, exec and connection status; the owner keeps VM, networking and Podman controls. Everyone shares the guest account, its sudo access, files and Claude state.

### Remove access

Use **People with access** to see local approvals and registered keys. Choose **Remove access** to revoke a person's approval and keys. This blocks new SSH sessions; an existing session stays open until it closes.

**Stop sharing** closes the shared SSH port and its active connections without shutting down the VM. It keeps approvals and keys for when sharing resumes.

### Someone on another computer

The owner chooses **Remote access** in `lemonbox access`. Follow the guide to copy the VM's connection details and fingerprint to the other person.

The other person runs `lemonbox join`, chooses the remote flow, pastes those details and checks the fingerprint with the owner. Join prints their public SSH key; the owner approves that key through **Remote access**. Private keys stay with their owners.

Remote clients need Python 3.11+ and OpenSSH on Linux or macOS, plus a reachable address. Lemonbox opens a loopback SSH relay and creates no public listener or host account. Use an existing SSH forward or Tailscale to reach it. The guide displays the VM port: normally `2222` for the default VM and `2223` for the next profile.

For SSH forwarding, someone with an existing account on the owner's host keeps this command running:

```bash
ssh -N -L 2222:127.0.0.1:2222 owner@owner-host
```

Join then uses `127.0.0.1:2222` on their computer. Substitute the displayed VM port on the right; choose another local port on the left if `2222` is busy.

For an existing Tailscale tailnet, the owner can forward the loopback relay:

```bash
tailscale serve --bg --tcp=2222 tcp://localhost:2222
```

Give the collaborator the owner's Tailscale address and port `2222`; tailnet policy must permit that TCP connection. Remove the forward with:

```bash
tailscale serve --bg --tcp=2222 off
```

Use the guide's port for another VM. Lemonbox does not change tailnet settings. [Tailscale Serve reference](https://tailscale.com/docs/reference/tailscale-cli/serve).

### Saved connections and automation

For local access, the owner can also use:

```bash
lemonbox access add alice
lemonbox access list
lemonbox access remove alice
```

The menu shows joined VMs as `username@address:port`. Saved connections use automatic internal names (`shared`, `shared-2`, …); normally users need not choose or remember them. For scripts, `--connection NAME` selects a joined connection and `--profile NAME` selects an owner VM. `join --name NAME` supplies an explicit saved name.

Joined status uses a noninteractive SSH check. Load an encrypted private key into your SSH agent if it needs a passphrase.
