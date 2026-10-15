"""Guided settings and private reusable profiles, with validation before save."""
from copy import deepcopy
import getpass
import json
import os
from pathlib import Path
import re
import sys
import warnings

from .config import Config, RouteConfig
from .sharing import validate_shares


CREATION_FIELDS = ('username', 'hostname', 'timezone', 'disk_gib', 'desktop', 'docker')
ROOT = Path(__file__).resolve().parents[1]


def private_directory(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('Private configuration directories must not be symlinks')
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.stat().st_uid != os.getuid():
        raise ValueError('Private configuration directories must be owned by you')
    path.chmod(0o700)
    return path


def template_directory():
    return Path.home() / '.local/share/lemonbox/templates'


def template_path(name):
    if not isinstance(name, str) or not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,31}', name):
        raise ValueError('Template name must be short lowercase text, numbers, hyphens or underscores')
    directory = template_directory()
    if directory.is_symlink():
        raise ValueError('Private template directory must not be a symlink')
    return directory / (name + '.json')


def reusable(config):
    # Templates describe one VM. Route credentials belong only to the shared
    # gateway. New VMs get their own workspace rather than template host shares.
    data = config.as_dict()
    data['shares'] = []
    return Config.from_dict(data)


def save_template(path, name):
    candidate = reusable(Config.load(path))
    destination = template_path(name)
    private_directory(destination.parent)
    candidate.write(destination)
    return destination


def load_template(name):
    path = template_path(name)
    if not path.exists():
        raise ValueError('No saved template named ' + name + '; save one with lemonbox settings --save-template NAME')
    if path.parent.stat().st_mode & 0o077 or path.parent.stat().st_uid != os.getuid():
        raise ValueError('Private template directory must be owned by you with mode 0700')
    return reusable(Config.load(path))


def validate_candidate(data, state):
    config = Config.from_dict(data)
    config.shares = validate_shares(config.shares, state_dir=state, username=config.vm['username'])
    guest = Path(state) / 'guest.json'
    if guest.is_file():
        existing = json.loads(guest.read_text())['profile']
        changed = [field for field in CREATION_FIELDS if existing.get(field) != config.vm[field]]
        if changed:
            raise ValueError('Existing VM creation settings cannot be edited (' + ', '.join(changed) +
                             '); create another VM from the Lemonbox menu')
    return config


def _say(message):
    print(message, file=sys.stderr)


def _answer(prompt):
    # EOF is a cancellation, not acceptance of defaults.
    return input(prompt).strip()


def _confirm(prompt, default=False):
    while True:
        value = _answer(prompt + (' [Y/n]: ' if default else ' [y/N]: ')).lower()
        if not value:
            return default
        if value in ('y', 'yes'):
            return True
        if value in ('n', 'no'):
            return False
        _say('Enter yes or no.')


def _field(data, section, name, label, *, secret=False, validator=Config):
    target = data[section] if isinstance(section, str) else data[section[0]][section[1]]
    previous = target[name]
    complete = secret and 'REPLACE_' not in previous
    while True:
        if secret:
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter('error', getpass.GetPassWarning)
                    value = getpass.getpass(label + (' [Enter keeps saved password]: ' if complete else ': '))
            except getpass.GetPassWarning:
                raise ValueError('A terminal with hidden password input is required') from None
            if not value and complete:
                return
            if not value:
                _say('A password is required.')
                continue
        else:
            displayed = 'yes' if previous is True else 'no' if previous is False else str(previous)
            value = _answer(label + ' [' + displayed + ']: ')
            if not value:
                return
            if type(previous) is bool:
                if value.lower() not in ('yes', 'no', 'y', 'n', 'true', 'false'):
                    _say('Enter yes or no.')
                    continue
                value = value.lower() in ('yes', 'y', 'true')
            elif type(previous) is int:
                try:
                    value = int(value)
                except ValueError:
                    _say('Enter a whole number.')
                    continue
        target[name] = value
        try:
            options = {'require_sources': False} if validator is Config else {'allow_placeholder': True}
            validator.from_dict(data, **options)
            return
        except ValueError as error:
            target[name] = previous
            _say(str(error))


def _vm_fields(data, prepared):
    if prepared:
        _say('Account, hostname, timezone, disk and installed software are fixed for this VM.')
    else:
        for name, label in (
            ('username', 'Linux username'), ('hostname', 'Hostname'), ('timezone', 'Timezone (IANA name)'),
        ):
            _field(data, 'vm', name, label)
    for name, label in (
        ('cpus', 'Virtual CPUs'), ('memory_mib', 'RAM in MiB'),
    ):
        _field(data, 'vm', name, label)
    if not prepared:
        for name, label in (
            ('disk_gib', 'Disk in GiB'), ('desktop', 'Install desktop'), ('docker', 'Install Docker'),
        ):
            _field(data, 'vm', name, label)


def _network_fields(data):
    _say('The exit is dialed through the first hop. Passwords are hidden.')
    for hop, label in (('first_hop', 'First hop'), ('exit_hop', 'Exit hop')):
        _say(label + ' (Hysteria 2)')
        for name, description in (
            ('server', 'Server IPv4'), ('port', 'Port'), ('password', 'Password'),
            ('sni', 'TLS server name'), ('skip_cert_verify', 'Skip certificate verification'),
        ):
            _field(data, ('network', hop), name, description, secret=name == 'password', validator=RouteConfig)
    _field(data, 'network', 'expected_exit_ip', 'Required public exit IPv4', validator=RouteConfig)


def _summary(data):
    vm = data['vm']
    _say('\n' + vm['username'] + '@' + vm['hostname'] + ' · ' + vm['timezone'])
    _say(str(vm['cpus']) + ' CPUs · ' + str(vm['memory_mib']) + ' MiB RAM · ' +
         str(vm['disk_gib']) + ' GiB disk · KVM')
    _say('Desktop: ' + ('yes' if vm['desktop'] else 'no') + '; Docker: ' +
         ('yes' if vm['docker'] else 'no') + '; local VNC port: ' + str(data['desktop']['port']))


def _wireguard_fields(data):
    _say('Use the keys for your already configured external WireGuard gateway.')
    _field(data, 'wireguard', 'client_private_key', 'WireGuard client private key', secret=True, validator=RouteConfig)
    _field(data, 'wireguard', 'server_public_key', 'WireGuard server public key', validator=RouteConfig)


def guided(data, state, *, creating=False):
    data = deepcopy(data)
    prepared = (Path(state) / 'guest.json').is_file()
    if creating:
        _say('Set up your VM. Enter keeps the shown default; Ctrl-C cancels without saving.')
        _vm_fields(data, prepared)
        _field(data, 'desktop', 'port', 'Local VNC port')
    while True:
        _summary(data)
        _say('\n1  VM settings\n2  Local VNC port\n3  Save and apply\n0  Cancel')
        choice = _answer('Choose [3]: ') or '3'
        if choice == '0':
            return None
        if choice == '1':
            _vm_fields(data, prepared)
        elif choice == '2':
            _field(data, 'desktop', 'port', 'Local VNC port')
        elif choice == '3':
            try:
                return validate_candidate(data, state)
            except ValueError as error:
                _say(str(error) + '. Correct the setting or cancel.')
        else:
            _say('Choose 0, 1, 2 or 3.')


def guided_route(data, *, creating=False):
    """Edit the one shared route without creating per-VM credential copies."""
    data = deepcopy(data)
    if creating:
        _say('Configure the shared route once. These credentials stay outside every guest VM.')
        _network_fields(data)
        _wireguard_fields(data)
    while True:
        network = data['network']
        _say('\nShared route: ' + network['first_hop']['server'] + ' → ' +
             network['exit_hop']['server'] + '; required exit: ' + network['expected_exit_ip'])
        _say('1  Hysteria route\n2  Existing WireGuard keys\n3  Save and apply\n0  Cancel')
        choice = _answer('Choose [3]: ') or '3'
        if choice == '0':
            return None
        if choice == '1':
            _network_fields(data)
        elif choice == '2':
            _wireguard_fields(data)
        elif choice == '3':
            try:
                return RouteConfig.from_dict(data)
            except ValueError as error:
                _say(str(error) + '. Correct the setting or cancel.')
        else:
            _say('Choose 0, 1, 2 or 3.')


def initial_route(gateway, example):
    if gateway.config_path.exists():
        return RouteConfig.load(gateway.config_path)
    if not sys.stdin.isatty():
        raise ValueError('Configure the shared route once with lemonbox setup in a terminal')
    candidate = RouteConfig.load(example, allow_placeholder=True, require_private=False)
    return guided_route(candidate.as_dict(), creating=True)


def with_default_workspace(vm, config):
    """Give a new VM its own host-backed workspace under the Lemonbox checkout."""
    if any(share['name'] == 'workspace' for share in config.shares):
        return config
    if not isinstance(vm.profile, str) or not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,31}', vm.profile):
        raise ValueError('Invalid VM profile for its workspace')
    source = ROOT / 'workspaces' / vm.profile
    data = config.as_dict()
    data['shares'].append({'name': 'workspace', 'source': str(source), 'read_only': False})
    # Check boundaries and overlaps before creating directories through any symlinks.
    validate_shares(data['shares'], state_dir=vm.state, username=config.vm['username'], require_sources=False)
    source.mkdir(parents=True, exist_ok=True, mode=0o700)
    candidate = validate_candidate(data, vm.state)
    from .local_access import LocalAccess
    from .workspace_access import sync_workspace_access
    sync_workspace_access(vm, LocalAccess(vm).users(), source=source)
    _say('Workspace: ' + str(source) + ' → /home/' + config.vm['username'] + '/workspace')
    return candidate


def initial_config(vm, example):
    """Collect a valid candidate; the caller commits it after checking revision."""
    template = None
    if vm.config_path.exists():
        candidate = validate_candidate(Config.load(vm.config_path).as_dict(), vm.state)
        return candidate if (vm.state / 'guest.json').is_file() else with_default_workspace(vm, candidate)
    if sys.stdin.isatty():
        directory = template_directory()
        if directory.exists() and not directory.is_symlink():
            names = sorted(path.stem for path in directory.glob('*.json')
                           if re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,31}', path.stem))
            if names:
                default = 'current' if 'current' in names else names[0]
                _say('Saved templates: ' + ', '.join(names) + '. Enter "new" for fresh settings.')
                template = _answer('Template [' + default + ']: ') or default
                if template == 'new':
                    template = None
    candidate = (load_template(template) if template else
                 Config.load(example, require_private=False))
    if template is None:
        account = getpass.getuser()
        if re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', account):
            candidate.vm['username'] = account
    if sys.stdin.isatty():
        candidate = guided(candidate.as_dict(), vm.state, creating=True)
        return with_default_workspace(vm, candidate) if candidate is not None else None
    try:
        candidate = validate_candidate(candidate.as_dict(), vm.state)
        return with_default_workspace(vm, candidate)
    except ValueError as error:
        raise ValueError(str(error) + '; run lemonbox setup in a terminal or select a valid template') from None
