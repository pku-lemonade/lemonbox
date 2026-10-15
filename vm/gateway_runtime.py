"""One owner-managed packet gateway shared by all local VM profiles."""
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import time

from .config import RouteConfig, _read_json, write_private_json
from .route_contract import GUEST_POOL, MAX_GUESTS
from .state import ProfileState, UNSPECIFIED

ROOT = Path(__file__).resolve().parents[1]
NAME = 'lemonbox-gateway'
IMAGE = 'localhost/lemonbox:latest'
PROJECT_LABEL = 'io.lemonbox.project'
STATE_LABEL = 'io.lemonbox.state'
ROLE_LABEL = 'io.lemonbox.role'
ROUTE_LABEL = 'io.lemonbox.route-sha256'


def run(argv, *, check=True, input_text=None, timeout=30):
    result = subprocess.run([str(value) for value in argv], input=input_text, text=True,
                            capture_output=True, check=False, timeout=timeout)
    if check and result.returncode:
        # Proxy validation output can contain credentials; keep it private.
        raise RuntimeError(str(argv[0]) + ' could not complete the shared gateway operation')
    return result


def private_directory(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
        raise ValueError('Shared gateway directories must be private and owned by you')


def allocation_for(slot):
    subnet = ipaddress.IPv4Network((int(ipaddress.IPv4Network(GUEST_POOL).network_address) + 4 * slot, 30))
    gateway, guest = tuple(subnet.hosts())
    return {'slot': slot, 'tap': 'vm' + str(slot), 'guest_ip': str(guest),
            'guest_address': str(guest) + '/30', 'guest_cidr': str(guest) + '/30',
            'gateway': str(gateway), 'gateway_cidr': str(gateway) + '/30',
            'mac': '52:54:00:77:00:' + format(int(guest) & 255, '02x'), 'ssh_port': 2222 + slot}


class SharedGateway:
    def __init__(self, vm=None, state=None):
        self.vm = vm
        self.state = Path(state or Path.home() / '.local/share/lemonbox/gateway').expanduser().absolute()
        if self.state == ROOT or ROOT in self.state.parents:
            raise ValueError('Shared gateway state must be outside the source checkout')
        self.name = NAME
        self.config_path = self.state / 'config.json'
        self.profile_state = ProfileState(self.state)
        self.allocations_path = self.state / 'allocations.json'

    @property
    def config(self):
        return RouteConfig.load(self.config_path)

    def applied(self):
        path = self.state / 'applied.json'
        if not path.exists():
            return None
        value = _read_json(path)
        if (not isinstance(value, dict) or set(value) != {'runtime_image_id', 'network_sha256'}
                or not re.fullmatch(r'(?:sha256:)?[a-f0-9]{64}', str(value['runtime_image_id']))
                or not re.fullmatch(r'[a-f0-9]{64}', str(value['network_sha256']))):
            raise ValueError('Invalid applied shared route')
        return value

    def pending(self):
        applied = self.applied()
        return applied is None or applied['network_sha256'] != self.config.network_digest()

    def _registry(self):
        if not self.allocations_path.exists():
            return {'version': 1, 'profiles': {}}
        value = _read_json(self.allocations_path)
        if (not isinstance(value, dict) or set(value) != {'version', 'profiles'}
                or value['version'] != 1 or not isinstance(value['profiles'], dict)
                or len(value['profiles']) > MAX_GUESTS):
            raise ValueError('Invalid shared gateway address registry')
        slots, profiles = set(), set()
        for state, entry in value['profiles'].items():
            path = Path(state)
            if (not path.is_absolute() or path.resolve() != path
                    or path == self.state or path in self.state.parents or self.state in path.parents
                    or not isinstance(entry, dict) or set(entry) != {'profile', 'slot'}
                    or not isinstance(entry['profile'], str)
                    or not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,31}', entry['profile'])
                    or entry['profile'] in {'gateway', 'connections', 'templates'}
                    or type(entry['slot']) is not int or not 0 <= entry['slot'] < MAX_GUESTS
                    or entry['slot'] in slots or entry['profile'] in profiles
                    or (entry['slot'] == 0) != (entry['profile'] == 'default')):
                raise ValueError('Invalid shared gateway address allocation')
            slots.add(entry['slot'])
            profiles.add(entry['profile'])
        return value

    def records(self):
        """Snapshot allocations under the gateway lock, without locking any VM."""
        with self.profile_state.lock():
            registry = self._registry()
            return [dict(profile=entry['profile'], state=Path(state), **allocation_for(entry['slot']))
                    for state, entry in sorted(registry['profiles'].items(), key=lambda item: item[1]['slot'])]

    def allocation(self):
        if self.vm is None:
            raise ValueError('Select a VM before allocating its private network')
        state = Path(self.vm.state).absolute()
        profile = self.vm.profile
        if (state.resolve() != state or state == self.state or state in self.state.parents or self.state in state.parents
                or not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,31}', profile)
                or profile in {'gateway', 'connections', 'templates'}):
            raise ValueError('VM profile and state must be separate from the shared gateway')
        with self.profile_state.lock():
            registry = self._registry()
            entry = registry['profiles'].get(str(state))
            if entry and entry['profile'] != profile:
                raise ValueError('This VM state already belongs to another profile')
            if entry is None:
                if any(item['profile'] == profile for item in registry['profiles'].values()):
                    raise ValueError('This VM profile already has another state directory')
                slots = {item['slot'] for item in registry['profiles'].values()}
                slot = next((slot for slot in range(0 if profile == 'default' else 1, MAX_GUESTS)
                             if slot not in slots), None)
                if slot is None:
                    raise ValueError('The shared gateway has no free private VM networks')
                entry = {'profile': profile, 'slot': slot}
                registry['profiles'][str(state)] = entry
                write_private_json(self.allocations_path, registry)
            return allocation_for(entry['slot'])

    def info(self):
        exists = run(['podman', 'container', 'exists', self.name], check=False)
        if exists.returncode == 1:
            return None
        if exists.returncode:
            raise RuntimeError('Container backend cannot determine the shared gateway state')
        info = json.loads(run(['podman', 'inspect', self.name]).stdout)[0]
        labels = info.get('Config', {}).get('Labels', {})
        if (labels.get(PROJECT_LABEL) != str(ROOT) or labels.get(STATE_LABEL) != str(self.state)
                or labels.get(ROLE_LABEL) != 'gateway'):
            raise ValueError('The shared gateway container belongs to another owner or state')
        return info

    def _require_idle(self):
        result = run(['podman', 'ps', '--filter', 'label=' + PROJECT_LABEL + '=' + str(ROOT),
                      '--format', '{{.Names}}'])
        if any(re.fullmatch(r'lemonbox-[a-z0-9][a-z0-9_-]{0,31}-machine', name)
               for name in result.stdout.splitlines()):
            raise ValueError('Stop every VM before changing or stopping the shared gateway')

    def private(self):
        private_directory(self.state)
        candidate = self.config
        applied = self.applied()
        if not applied or applied['network_sha256'] != candidate.network_digest():
            raise ValueError('Shared route settings are pending; apply them before starting a VM')
        for name, expected in (('proxy.json', candidate.mihomo_profile()),
                               ('wireguard.json', candidate.wireguard_profile())):
            if _read_json(self.state / name) != expected:
                raise ValueError('Applied transport settings changed; apply the shared route again')
        binary = self.state / 'mihomo'
        if (binary.is_symlink() or not binary.is_file() or binary.stat().st_uid != os.getuid()
                or binary.stat().st_mode & 0o077 or not os.access(binary, os.X_OK)):
            raise ValueError('Place a trusted executable Mihomo at ' + str(binary) + ' with mode 0700')
        image = applied['runtime_image_id']
        actual = run(['podman', 'image', 'inspect', image, '--format', '{{.Id}}']).stdout.strip()
        if actual.removeprefix('sha256:') != image.removeprefix('sha256:'):
            raise ValueError('The applied shared gateway image is unavailable')
        return applied

    def image(self):
        return self.private()['runtime_image_id']

    def available_image(self):
        result = run(['podman', 'image', 'inspect', IMAGE, '--format', '{{.Id}}'], check=False)
        image = result.stdout.strip()
        if result.returncode or not re.fullmatch(r'(?:sha256:)?[a-f0-9]{64}', image):
            raise ValueError('Build the local runtime image first; see docs/setup.md')
        return image

    def apply_config(self, candidate=None, *, image=None, expected_revision=UNSPECIFIED):
        with self.profile_state.lock():
            if expected_revision is not UNSPECIFIED and expected_revision != self.profile_state.revision():
                raise ValueError('Shared route changed while you were editing. Reopen settings and try again.')
            candidate = RouteConfig.from_dict((candidate or self.config).as_dict())
            previous = self.applied()
            image = image or (previous or {}).get('runtime_image_id')
            if not isinstance(image, str) or not re.fullmatch(r'(?:sha256:)?[a-f0-9]{64}', image):
                raise ValueError('Build the shared runtime before applying the route')
            if previous and self.config.as_dict() == candidate.as_dict() and previous['runtime_image_id'] == image:
                try:
                    self.private()
                    return previous
                except (ValueError, OSError):
                    pass
            self._require_idle()
            self.profile_state.save_config(candidate, expected_revision=expected_revision)
            self.stop()
            candidate.render_proxy(self.state / 'proxy.json')
            candidate.render_wireguard(self.state / 'wireguard.json')
            env = [item for name, value in candidate.gateway_env().items() for item in ('-e', name + '=' + value)]
            run(['podman', 'run', '--rm', '--http-proxy=false', '--network', 'none', '--cap-drop', 'ALL',
                 '--read-only', '--security-opt', 'no-new-privileges', *env,
                 '-v', f'{self.state}/proxy.json:/etc/lemon/private/proxy.json:ro',
                 '-v', f'{self.state}/wireguard.json:/etc/lemon/private/wireguard.json:ro', image, 'validate-profile'])
            applied = {'runtime_image_id': image, 'network_sha256': candidate.network_digest()}
            write_private_json(self.state / 'applied.json', applied)
            self.private()
            return applied

    def health(self):
        return run(['podman', 'exec', self.name, 'python3', '/opt/lemon/controller.py', 'check', '--local'],
                   check=False, timeout=10).returncode == 0

    def ensure_running(self):
        with self.profile_state.lock():
            applied = self.private()
            selected = applied['runtime_image_id']
            info = self.info()
            if info and info.get('State', {}).get('Status') == 'running':
                if (info.get('Image', '').removeprefix('sha256:') != selected.removeprefix('sha256:')
                        or info.get('Config', {}).get('Labels', {}).get(ROUTE_LABEL) != applied['network_sha256']):
                    raise ValueError('The running shared gateway differs from its applied settings')
                if not self.health():
                    raise ValueError('The shared route is closed; run lemonbox stop --all, then Recover in lemonbox settings')
                return selected
            self._require_idle()
            if info:
                run(['podman', 'rm', info['Id']])
            env = [item for name, value in self.config.gateway_env().items() for item in ('-e', name + '=' + value)]
            run(['podman', 'run', '-d', '--name', self.name,
                 '--label', PROJECT_LABEL + '=' + str(ROOT), '--label', STATE_LABEL + '=' + str(self.state),
                 '--label', ROLE_LABEL + '=gateway', '--label', ROUTE_LABEL + '=' + applied['network_sha256'],
                 '--http-proxy=false', '--network', 'slirp4netns:enable_ipv6=false', '--no-hosts',
                 '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN',
                 '--device', '/dev/net/tun', '--read-only', '--security-opt', 'no-new-privileges',
                 '--sysctl', 'net.ipv4.ip_forward=1', '--sysctl', 'net.ipv4.conf.all.rp_filter=0',
                 '--sysctl', 'net.ipv4.conf.default.rp_filter=0', '--sysctl', 'net.ipv4.conf.all.src_valid_mark=0',
                 '--sysctl', 'net.ipv4.conf.default.src_valid_mark=0',
                 '--tmpfs', '/run/lemon:rw,noexec,nosuid,nodev,size=32m,mode=0700',
                 '--tmpfs', '/run/wireguard:rw,noexec,nosuid,nodev,size=1m,mode=0700',
                 '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=8m',
                 *[item for name in ('proxy.json', 'wireguard.json', 'mihomo')
                   for item in ('-v', f'{self.state}/{name}:/etc/lemon/private/{name}:ro')], *env, selected])
            deadline = time.monotonic() + 150
            while not self.health():
                info = self.info()
                if not info or info.get('State', {}).get('Status') != 'running' or time.monotonic() >= deadline:
                    raise RuntimeError('The shared fixed route did not become healthy; no VM was started')
                time.sleep(1)
            return selected

    def attach(self):
        with self.profile_state.lock():
            self.ensure_running()
            allocation = self.allocation()
            record = {name: allocation[name] for name in ('tap', 'guest_cidr', 'gateway_cidr')}
            run(['podman', 'exec', '-i', self.name, 'python3', '/opt/lemon/controller.py', 'add-guest'],
                input_text=json.dumps(record))
            return allocation

    def detach(self):
        with self.profile_state.lock():
            info = self.info()
            if info is None or info.get('State', {}).get('Status') != 'running':
                return False
            allocation = self.allocation()
            record = {name: allocation[name] for name in ('tap', 'guest_cidr', 'gateway_cidr')}
            run(['podman', 'exec', '-i', self.name, 'python3', '/opt/lemon/controller.py', 'remove-guest'],
                input_text=json.dumps(record))
            return True

    def stop(self):
        with self.profile_state.lock():
            self._require_idle()
            info = self.info()
            if info is None:
                return False
            if info.get('State', {}).get('Status') == 'running':
                run(['podman', 'stop', '--time', '10', info['Id']])
            run(['podman', 'rm', info['Id']])
            return True
