"""QEMU and VM disks; all profiles use one external shared gateway."""
from copy import copy
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import sys
import time

from .config import Config, VM_DEFAULTS, write_private_json, write_private_text
from .gateway_runtime import SharedGateway
from .state import ProfileState, UNSPECIFIED

ROOT = Path(__file__).resolve().parents[1]
MACHINE_TYPE = 'pc-q35-10.0'
LABEL = 'io.lemonbox.project'
PROFILE_LABEL = 'io.lemonbox.profile'
STATE_LABEL = 'io.lemonbox.state'
SHARES_LABEL = 'io.lemonbox.shares'
RESOURCES_LABEL = 'io.lemonbox.resources'
RESERVED = {'gateway', 'connections', 'templates'}


def run(args, *, check=True, capture=False, timeout=None):
    result = subprocess.run(
        [str(x) for x in args], text=True, capture_output=capture, timeout=timeout
    )
    if check and result.returncode:
        detail = result.stderr.strip()[-1500:] if capture and result.stderr else ''
        raise RuntimeError(
            Path(str(args[0])).name + ' failed' + (': ' + detail if detail else '')
        )
    return result


class VM:
    def __init__(self, args):
        if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,31}', args.profile) or args.profile in RESERVED:
            raise ValueError(
                'Choose a short lowercase VM name other than gateway, connections or templates'
            )
        self.profile = args.profile
        self.state = Path(
            args.state_dir
            or os.environ.get('LEMONBOX_STATE_DIR')
            or Path.home() / '.local/share/lemonbox' / args.profile
        ).expanduser().resolve()
        if self.state == ROOT or ROOT in self.state.parents:
            raise ValueError('Private VM state must be outside the checkout')
        self.machine = 'lemonbox-' + self.profile + '-machine'
        self.shared_gateway = SharedGateway(self, state=getattr(args, 'gateway_state', None))
        shared = self.shared_gateway.state
        if self.state == shared or self.state in shared.parents or shared in self.state.parents:
            raise ValueError('VM state must be separate from shared gateway credentials')
        self.gateway = self.shared_gateway.name
        self.profile_state = ProfileState(self.state)
        self.config_path = self.state / 'config.json'
        self.args = copy(args)
        self.config, self.config_error = None, None
        if self.config_path.exists():
            try:
                self.config = Config.load(self.config_path, require_sources=False)
            except (ValueError, OSError) as error:
                self.config_error = str(error)
        self._resources()

    def _resources(self):
        settings = self.config.vm if self.config else VM_DEFAULTS
        self.args.cpus, self.args.memory = settings['cpus'], settings['memory_mib']

    @property
    def route_config(self):
        return self.shared_gateway.config

    @property
    def home(self):
        return '/home/' + json.loads((self.state / 'guest.json').read_text())['profile']['username']

    def save_config(self, candidate, *, expected_revision=UNSPECIFIED):
        self.profile_state.save_config(candidate, expected_revision=expected_revision)
        self.config = Config.load(self.config_path, require_sources=False)
        self.config_error = None
        self._resources()

    def validate_guest_settings(self, candidate=None):
        config = candidate or self.config
        if config and (self.state / 'guest.json').is_file():
            existing = json.loads((self.state / 'guest.json').read_text())['profile']
            changed = [
                key for key in ('username', 'hostname', 'timezone', 'disk_gib', 'desktop', 'docker')
                if existing[key] != config.vm[key]
            ]
            if changed:
                raise ValueError(
                    'Guest creation settings changed (' + ', '.join(changed) + '); create another VM'
                )

    def info(self, name):
        if name == self.gateway:
            return self.shared_gateway.info()
        if name != self.machine:
            raise ValueError('Unexpected VM container name')
        exists = run(['podman', 'container', 'exists', name], check=False, capture=True)
        if exists.returncode == 1:
            return None
        if exists.returncode:
            raise RuntimeError('Container backend could not determine whether ' + name + ' exists')
        try:
            records = json.loads(run(['podman', 'inspect', name], capture=True).stdout)
            if not isinstance(records, list) or len(records) != 1 or not isinstance(records[0], dict):
                raise ValueError
        except (ValueError, TypeError):
            raise RuntimeError('Container backend returned invalid inspection data') from None
        info = records[0]
        labels = info.get('Config', {}).get('Labels', {})
        if (
            labels.get(LABEL) != str(ROOT)
            or labels.get(PROFILE_LABEL) != self.profile
            or labels.get(STATE_LABEL) != str(self.state)
        ):
            raise ValueError('Container belongs to another project, profile or state: ' + name)
        return info

    def private(self):
        self.config = Config.load(self.config_path)
        self.config_error = None
        from .sharing import validate_shares

        self.config.shares = validate_shares(
            self.config.shares, state_dir=self.state,
            username=self.config.vm['username'], protected_paths=[self.shared_gateway.state]
        )
        self.validate_guest_settings()
        self._resources()
        self.runtime_image = self.shared_gateway.image()

    def apply_config(self, candidate=None, *, restart=True, expected_revision=UNSPECIFIED):
        with self.profile_state.lock():
            candidate = candidate or Config.load(self.config_path)
            self.validate_guest_settings(candidate)
            machine = self.info(self.machine)
            running = bool(machine and machine['State']['Status'] == 'running')
            self.save_config(candidate, expected_revision=expected_revision)
            if running:
                self.prepare_share_restart(candidate.shares)
                self.down()
                if restart:
                    self.up()

    def prepare_share_restart(self, shares):
        machine = self.info(self.machine)
        if not machine or machine['State']['Status'] != 'running':
            return
        recorded = json.loads(machine['Config']['Labels'].get(SHARES_LABEL, '[]'))
        if recorded:
            from .sharing import guest_prepare_restart_request
            from .workflows import Workflow

            request = guest_prepare_restart_request(shares, username=self.config.vm['username'])
            source = (ROOT / 'guest/shares.py').read_text()
            result = Workflow(self).run_script(source, args=[json.dumps(request)], sudo=True)
            if result.returncode:
                raise RuntimeError(
                    'Could not detach host folders safely; inspect mounts with lemonbox shell'
                )

    def ssh_config(self):
        metadata = json.loads((self.state / 'guest.json').read_text())
        keys = self.state / 'ssh'
        ip = metadata['profile']['guest_ip']
        known = keys / 'known_hosts'
        write_private_text(known, ip + ' ' + metadata['guest_host_public_key'] + '\n')
        proxy = shlex.join(['podman', 'exec', '-i', self.gateway, 'nc', ip, '22'])
        text = (
            'Host lemonbox\n' + f'  HostName {ip}\n  User {metadata["profile"]["username"]}\n'
            + '  IdentityFile ' + json.dumps(str(keys / 'id_ed25519'), ensure_ascii=False) + '\n'
            + '  UserKnownHostsFile ' + json.dumps(str(known), ensure_ascii=False) + '\n'
            + '  StrictHostKeyChecking yes\n  IdentitiesOnly yes\n  BatchMode yes\n'
            + '  ConnectTimeout 10\n  ServerAliveInterval 15\n  ServerAliveCountMax 3\n'
            + '  ProxyCommand ' + proxy + '\n'
        )
        path = keys / 'host-config'
        write_private_text(path, text)
        return path

    def prepare(self):
        self.private()
        base = self.shared_gateway.state / 'base.qcow2'
        if not base.is_file():
            raise ValueError('Prepare the verified Debian image first; see docs/setup.md')
        self.state.mkdir(mode=0o700, exist_ok=True)
        if not (self.state / 'base.qcow2').exists():
            os.link(base, self.state / 'base.qcow2')
        network = self.shared_gateway.allocation()
        options = []
        for key, flag in (
            ('username', '--username'), ('hostname', '--hostname'),
            ('timezone', '--timezone'), ('disk_gib', '--disk-gib')
        ):
            options += [flag, str(self.config.vm[key])]
        for key, flag in (
            ('guest_address', '--guest-address'), ('gateway', '--gateway'),
            ('mac', '--mac'), ('tap', '--tap'), ('ssh_port', '--ssh-port')
        ):
            options += [flag, str(network[key])]
        for key in ('desktop', 'docker'):
            if self.config.vm[key]:
                options.append('--' + key)
        run([
            'podman', 'run', '--rm', '--http-proxy=false', '--network', 'none',
            '--userns', 'keep-id', '--user', f'{os.getuid()}:{os.getgid()}',
            '-v', f'{ROOT}:/project:ro', '-v', f'{self.state}:/state:rw',
            '--entrypoint', 'python3', self.runtime_image, '/project/scripts/guest-prepare.py',
            '--state-dir', '/state', '--base-image', '/state/base.qcow2', *options
        ], capture=True)
        self.ssh_config()

    def health(self):
        return self.shared_gateway.health()

    def start_access(self):
        from .access import Relay

        Relay(self).start()

    def up(self):
        with self.shared_gateway.profile_state.lock():
            self.private()
            if not (self.state / 'guest.json').is_file():
                raise ValueError('Prepare the VM first with lemonbox setup')
            profile = json.loads((self.state / 'guest.json').read_text())['profile']
            allocation = self.shared_gateway.allocation()
            if any(
                profile[key] != allocation[key]
                for key in ('guest_address', 'guest_ip', 'gateway', 'mac', 'tap', 'ssh_port')
            ):
                raise ValueError('Guest network metadata differs from its assigned private network; run setup')
            machine = self.info(self.machine)
            shares = self.config.shares
            resources = {'cpus': self.args.cpus, 'memory_mib': self.args.memory, 'accel': 'kvm'}
            if machine and machine['State']['Status'] == 'running':
                labels = machine['Config']['Labels']
                if (
                    machine['Image'].removeprefix('sha256:') != self.runtime_image.removeprefix('sha256:')
                    or json.loads(labels[RESOURCES_LABEL]) != resources
                    or json.loads(labels[SHARES_LABEL]) != shares
                ):
                    raise ValueError('VM settings or runtime changed; run lemonbox restart')
                self.shared_gateway.ensure_running()
                self.ssh_config()
                self.start_access()
                return
            if machine:
                run(['podman', 'rm', machine['Id']], capture=True)
            if not os.access('/dev/kvm', os.R_OK | os.W_OK):
                raise ValueError('KVM access is unavailable; refresh your login after joining the kvm group')
            self.shared_gateway.attach()
            runtime = self.state / 'run'
            runtime.mkdir(mode=0o700, exist_ok=True)
            self._launch_qemu(profile, shares, runtime)
            self.ssh_config()
            self.start_access()
            write_private_json(
                self.state / 'runtime.json',
                dict(resources, image=self.runtime_image, gateway=self.gateway,
                     machine=self.machine, started_at=time.time())
            )
            print('VM started with kvm', file=sys.stderr)

    def _launch_qemu(self, profile, shares, runtime):
        from .sharing import podman_mount_args, qemu_args

        resources = {'cpus': self.args.cpus, 'memory_mib': self.args.memory, 'accel': 'kvm'}
        run([
            'podman', 'run', '-d', '--name', self.machine,
            '--label', LABEL + '=' + str(ROOT),
            '--label', PROFILE_LABEL + '=' + self.profile,
            '--label', STATE_LABEL + '=' + str(self.state),
            '--label', SHARES_LABEL + '=' + json.dumps(shares, separators=(',', ':')),
            '--http-proxy=false',
            '--label', RESOURCES_LABEL + '=' + json.dumps(resources, separators=(',', ':')),
            '--userns', 'keep-id:uid=1000,gid=1000', '--user', '1000:1000',
            '--network', 'container:' + self.gateway, '--no-hosts', '--cap-drop', 'ALL',
            '--device', '/dev/net/tun', '--device', '/dev/kvm', '--group-add', 'keep-groups',
            '--read-only', '--security-opt', 'no-new-privileges',
            '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=16m',
            '-v', f'{self.state}/disk.qcow2:/state/disk.qcow2:rw',
            '-v', f'{self.shared_gateway.state}/base.qcow2:/state/base.qcow2:ro',
            '-v', f'{self.state}/seed.iso:/state/seed.iso:ro',
            '-v', f'{runtime}:/run/lemonbox:rw', *podman_mount_args(shares),
            '--entrypoint', 'qemu-system-x86_64', self.runtime_image,
            '-name', profile['hostname'], '-machine', MACHINE_TYPE + ',accel=kvm,smm=off',
            '-cpu', 'host', '-smp', str(self.args.cpus), '-m', str(self.args.memory),
            '-nodefaults', '-display', 'none', '-serial', 'file:/run/lemonbox/console.log',
            '-qmp', 'unix:/run/lemonbox/qmp.sock,server=on,wait=off',
            '-drive', 'file=/state/disk.qcow2,format=qcow2,if=virtio,cache=none',
            '-drive', 'file=/state/seed.iso,format=raw,if=virtio,readonly=on',
            '-netdev', 'tap,id=guestnet,ifname=' + profile['tap'] + ',script=no,downscript=no',
            '-device', 'virtio-net-pci,netdev=guestnet,mac=' + profile['mac'],
            '-object', 'rng-random,filename=/dev/urandom,id=rng0',
            '-device', 'virtio-rng-pci,rng=rng0', *qemu_args(shares)
        ], capture=True)

    def down(self):
        from .access import Relay

        Relay(self).stop()
        machine = self.info(self.machine)
        if machine:
            if machine['State']['Status'] == 'running':
                try:
                    with socket.socket(socket.AF_UNIX) as client:
                        client.settimeout(3)
                        client.connect(str(self.state / 'run/qmp.sock'))
                        client.recv(16384)
                        client.sendall(b'{"execute":"qmp_capabilities"}\n')
                        client.recv(16384)
                        client.sendall(b'{"execute":"system_powerdown"}\n')
                        client.recv(16384)
                    deadline = time.monotonic() + 30
                    while time.monotonic() < deadline:
                        current = self.info(self.machine)
                        if not current or current['State']['Status'] != 'running':
                            break
                        time.sleep(.5)
                except OSError:
                    pass
                run(['podman', 'stop', '--time', '10', machine['Id']], capture=True)
            run(['podman', 'rm', machine['Id']], capture=True)
        self.shared_gateway.detach()
        print('VM stopped; its disk and the shared gateway remain.')

    def _registered_vms(self):
        for record in self.shared_gateway.records():
            args = copy(self.args)
            args.profile, args.state_dir = record['profile'], record['state']
            args.gateway_state = self.shared_gateway.state
            yield VM(args)

    def stop_all(self):
        for vm in self._registered_vms():
            with vm.profile_state.lock():
                vm.down()
        self.shared_gateway.stop()

    def validate(self):
        from .diagnostics import run as diagnose

        return diagnose(self)
