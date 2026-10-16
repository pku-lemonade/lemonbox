"""A guided front door and short everyday commands for the Linux VM."""
import argparse
from contextlib import redirect_stdout
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from .config import Config, RouteConfig, write_private_json
from .onboarding import (
    _answer, _confirm, guided, guided_route, initial_config, initial_route,
    private_directory, save_template, validate_candidate,
)
from .runtime import ROOT, VM
from .sharing import guest_mount_request
from .workflows import READY_TIMEOUT, Workflow
from .alerts import connection_alert, gateway_alert, route_alert


PUBLIC_COMMANDS = ('claude', 'shell', 'desktop', 'files', 'settings', 'status', 'access', 'join')
CLIENT_COMMANDS = ('claude', 'shell', 'status', 'join')
ADVANCED_COMMANDS = ('setup', 'start', 'stop', 'restart', 'exec', 'diagnose', 'update', 'logs')
FORWARDED_COMMANDS = {'claude', 'exec'}


def parser(*, advanced=False, client=False):
    result = argparse.ArgumentParser(
        prog='lemonbox', description='Claude in your Linux VM through one fixed route.',
        epilog='Run lemonbox without arguments for the menu. Use --help-all for advanced commands.',
        allow_abbrev=False,
    )
    result.add_argument('--help-all', action='store_true', help='Show all commands and advanced options')
    result.add_argument('--profile', help='Select a VM instead of the remembered choice' if advanced else argparse.SUPPRESS)
    result.add_argument('--state-dir', type=Path, help='Private VM state directory' if advanced and not client else argparse.SUPPRESS)
    result.add_argument('--connection', help='Select a saved SSH-only connection' if advanced else argparse.SUPPRESS)
    commands = result.add_subparsers(dest='action', metavar='COMMAND')

    def command(name, help_text):
        return commands.add_parser(name, allow_abbrev=False, add_help=name != 'claude', **(
            {'help': help_text} if name in (CLIENT_COMMANDS if client else PUBLIC_COMMANDS) or (advanced and (not client or name == 'exec')) else {}))

    for name, help_text in (
        ('claude', 'Open Claude; native Claude options pass through'),
        ('shell', 'Open a shell, including access to repair a degraded VM'),
        ('exec', 'Run a guest command with its stdin and exit status'),
    ):
        item = command(name, help_text)
        item.add_argument('--workdir', help='Absolute working directory inside the VM')
        if name != 'shell':
            item.add_argument('arguments', nargs=argparse.REMAINDER)
    desktop = command('desktop', 'Open the desktop over a localhost VNC connection')
    desktop.add_argument('--port', type=int, help='Override the saved local VNC port')
    desktop.add_argument('--no-open', action='store_true', help='Print the VNC address without opening a viewer')
    desktop.add_argument('--stop', action='store_true', help='Stop the guest desktop')
    files = command('files', 'Choose host folders to mount in your VM')
    shares = files.add_subparsers(dest='files_action')
    add = shares.add_parser('add', allow_abbrev=False, help='Add a folder and apply it')
    add.add_argument('source', type=Path)
    add.add_argument('--name', help='Guest folder name; defaults to the host folder name')
    add.add_argument('--read-only', action='store_true')
    remove = shares.add_parser('remove', allow_abbrev=False, help='Detach a folder; keep its host files')
    remove.add_argument('name')
    shares.add_parser('list', allow_abbrev=False, help='List shared folders')
    settings = command('settings', 'Edit and apply VM settings with guided prompts')
    settings.add_argument('--route', action='store_true', help='Edit the one shared gateway route')
    options = settings.add_mutually_exclusive_group()
    options.add_argument('--path', action='store_true', help='Print the settings file path')
    options.add_argument('--apply', action='store_true', help='Apply the saved settings')
    options.add_argument('--save-template', metavar='NAME', help='Save private reusable settings without guest keys/files')
    status_parser = command('status', 'Show this VM and the shared route')
    status_parser.add_argument('--json', action='store_true')
    command('setup', 'Create or resume this VM using the shared route')
    for name, help_text in (('start', 'Start and wait for native Claude'), ('restart', 'Restart using the saved VM settings')):
        item = command(name, help_text)
        item.add_argument('--timeout', type=int, default=READY_TIMEOUT)
    stop = command('stop', 'Stop this VM; keep the shared gateway and other VMs running')
    stop.add_argument('--all', action='store_true', help='Stop every local VM and the shared gateway')
    access_parser = command('access', 'Grant local users access to this VM')
    access_actions = access_parser.add_subparsers(dest='access_action')
    add_user = access_actions.add_parser('add', help='Allow a Linux user on this computer', allow_abbrev=False)
    add_user.add_argument('username')
    access_actions.add_parser('list', help='Show people with access', allow_abbrev=False)
    remove_user = access_actions.add_parser('remove', help='Remove a local user and their VM key', allow_abbrev=False)
    remove_user.add_argument('username')
    access_actions.add_parser('remote', help='Connect someone from another computer', allow_abbrev=False)
    access_actions.add_parser('stop', help='Close shared connections; keep approvals', allow_abbrev=False)
    join = command('join', 'Connect to a shared VM using only your local SSH key')
    join.add_argument('--name', help='Optional local label; chosen automatically when omitted')
    join.add_argument('--invitation', type=Path, help='Connection details JSON file from the owner')
    join.add_argument('--identity', type=Path, help='Your local private SSH key')
    join.add_argument('--public-key', action='append', default=[], metavar='KEY_OR_FILE',
                      help='Also authorize a public key when joining on this host (repeatable)')
    join.add_argument('--trust', action='store_true', help='Trust the VM fingerprint in the supplied connection details')
    diagnose = command('diagnose', 'Check host prerequisites, then the selected VM and route')
    diagnose.add_argument('--host', action='store_true', help='Only check host prerequisites')
    command('update', 'Apply a manually rebuilt runtime after stopping all VMs')
    logs = command('logs', 'Show gateway logs or the guest boot console')
    logs.add_argument('--guest', action='store_true')
    logs.add_argument('--follow', action='store_true')
    return result


def parse_arguments(argv):
    # Global options stop at the subcommand. Native Claude/exec payload may
    # contain identically named options and must not change the selected target.
    options = set()
    index = 0
    actions = {*PUBLIC_COMMANDS, *ADVANCED_COMMANDS}
    while index < len(argv) and argv[index] not in actions:
        value = argv[index]
        options.add(value.split('=', 1)[0])
        index += 2 if value in ('--profile', '--connection', '--state-dir') else 1
    explicit_profile = '--profile' in options
    explicit_connection = '--connection' in options
    target = selected_target() if not explicit_profile else {'kind': 'vm', 'profile': 'default'}
    client = explicit_connection or target['kind'] == 'connection'
    argument_parser = parser(advanced='--help-all' in argv, client=client)
    args, unknown = argument_parser.parse_known_args(argv)
    if hasattr(args, 'arguments') and args.arguments[:1] == ['--']:
        args.arguments = args.arguments[1:]
    if unknown:
        if args.action not in FORWARDED_COMMANDS:
            argument_parser.error('unrecognized arguments: ' + ' '.join(unknown))
        args.arguments = unknown + args.arguments
    if getattr(args, 'timeout', 1) <= 0:
        argument_parser.error('Readiness timeout must be positive')
    port = getattr(args, 'port', None)
    if port is not None and not 1 <= port <= 65535:
        argument_parser.error('Port must be between 1 and 65535')
    if args.action == 'settings' and args.route and args.save_template:
        argument_parser.error('Templates contain VM settings only')
    if args.profile and args.connection:
        argument_parser.error('Choose --profile or --connection')
    if args.profile:
        args.connection = None
    elif args.connection:
        args.profile = 'default'
    elif target['kind'] == 'connection':
        args.connection = target['name']
        args.profile = 'default'
    else:
        args.profile = target['profile']
    return args


def selection_path():
    return Path.home() / '.local/share/lemonbox/selection.json'


def selected_target():
    path = selection_path()
    if not path.exists():
        return {'kind': 'vm', 'profile': 'default'}
    if path.is_symlink() or path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
        raise ValueError('VM selection must be a private file owned by you')
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise ValueError('Invalid saved selection')
    field = {'vm': 'profile', 'connection': 'name'}.get(data.get('kind'))
    name = data.get(field) if field else None
    if set(data) != {'kind', field} or not isinstance(name, str) or not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,31}', name):
        raise ValueError('Invalid saved selection')
    return data


def save_selection(data):
    path = selection_path()
    private_directory(path.parent)
    write_private_json(path, data)


def select_profile(name):
    if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,31}', name) or name in ('gateway', 'connections', 'templates'):
        raise ValueError('Use a short VM name; gateway, connections and templates are reserved')
    save_selection({'kind': 'vm', 'profile': name})


def select_connection(name):
    from .connections import connection_directory
    connection_directory(name)
    save_selection({'kind': 'connection', 'name': name})


def reconcile(vm, workflow):
    from .local_access import LocalAccess
    from .workspace_access import sync_workspace_access
    sync_workspace_access(vm, LocalAccess(vm).users())
    shares = vm.config.shares if vm.config else []
    request = guest_mount_request(shares, username=workflow.username)
    source = (ROOT / 'guest/shares.py').read_text()
    result = workflow.run_script(source, args=[json.dumps(request)], sudo=True)
    if result.returncode:
        raise RuntimeError('Could not mount shared folders; inspect the mount service inside lemonbox shell')


def launch_locked(vm, workdir=None):
    """Launch under the lifecycle lock and record the instance being awaited."""
    vm.up()
    workflow = Workflow(vm, workdir=workdir)
    revision = vm.profile_state.revision()
    machine = vm.info(vm.machine)
    identity = machine.get('Id') if machine else None

    def check_current():
        with vm.profile_state.lock():
            current = vm.info(vm.machine)
            changed = (
                vm.profile_state.revision() != revision or
                not current or current['State']['Status'] != 'running' or
                (identity is not None and current.get('Id') != identity)
            )
            if changed:
                raise RuntimeError('VM stopped, restarted or settings changed while waiting; run the command again')
    return workflow, check_current


def finish_start(vm, launched, timeout=READY_TIMEOUT):
    """Wait without the lifecycle lock so stop and repair access stay available."""
    workflow, check_current = launched
    workflow.ready(timeout=timeout, check_current=check_current)
    with vm.profile_state.lock():
        check_current()
        reconcile(vm, workflow)
    return workflow


def ensure_running(vm, timeout=READY_TIMEOUT, workdir=None):
    with vm.profile_state.lock():
        launched = launch_locked(vm, workdir=workdir)
    return finish_start(vm, launched, timeout=timeout)


def repair_access(vm, workdir=None):
    # Running guests remain reachable even when cloud-init/services/egress fail.
    with vm.profile_state.lock():
        machine = vm.info(vm.machine)
        if not machine or machine['State']['Status'] != 'running':
            vm.up()
    workflow = Workflow(vm, workdir=workdir)
    workflow.accessible()
    return workflow


def restart(vm, timeout=READY_TIMEOUT):
    with vm.profile_state.lock():
        vm.private()
        vm.prepare_share_restart(vm.config.shares)
        with redirect_stdout(sys.stderr):
            vm.down()
        launched = launch_locked(vm)
    workflow = finish_start(vm, launched, timeout=timeout)
    print('Ready. Run lemonbox claude, shell or desktop.', file=sys.stderr)
    return workflow


def setup(vm, args):
    gateway = vm.shared_gateway
    revision = vm.profile_state.revision()
    route_revision = gateway.profile_state.revision()
    route = initial_route(gateway, ROOT / 'route.example.json')
    candidate = initial_config(vm, ROOT / 'config.example.json') if route else None
    if candidate is None:
        print('Cancelled. No settings were saved.', file=sys.stderr)
        return 130
    # Prompts stay outside locks; route credentials are stored once globally.
    with gateway.profile_state.lock():
        if gateway.profile_state.revision() != route_revision:
            raise ValueError('Shared route changed during setup; reopen the guide')
        applied = gateway.applied()
        current = RouteConfig.load(gateway.config_path) if gateway.config_path.exists() else None
        if applied is None or gateway.pending() or current.as_dict() != route.as_dict():
            image = applied['runtime_image_id'] if applied else gateway.available_image()
            gateway.apply_config(route, image=image, expected_revision=route_revision)
    with vm.profile_state.lock():
        vm.apply_config(candidate, restart=False, expected_revision=revision)
        vm.prepare()
        launched = launch_locked(vm)
    finish_start(vm, launched)
    print('Setup complete. Run lemonbox claude, shell or desktop.', file=sys.stderr)
    return 0


def settings_command(vm, args):
    if args.route:
        return route_settings(vm, args)
    if args.path:
        print(vm.config_path)
        return 0
    if not vm.config_path.exists():
        return setup(vm, args)
    if args.save_template:
        print('Private VM template saved: ' + str(save_template(vm.config_path, args.save_template)))
        return 0
    if not args.apply:
        if not sys.stdin.isatty():
            raise ValueError('Guided settings need a terminal; edit settings --path, then use settings --apply')
        print('1  This VM\n2  Shared route\n3  Recover the shared gateway (all VMs must be stopped)\n0  Back', file=sys.stderr)
        choice = _answer('Choose [1]: ') or '1'
        if choice == '0':
            return 0
        if choice == '2':
            return route_settings(vm, args)
        if choice == '3':
            vm.shared_gateway.stop()
            vm.shared_gateway.ensure_running()
            print('Shared gateway ready. Start the VMs you want to use.', file=sys.stderr)
            return 0
        if choice != '1':
            raise ValueError('Choose 0, 1, 2 or 3')
    with vm.profile_state.lock():
        revision = vm.profile_state.revision()
        baseline = Config.load(vm.config_path, require_sources=False)
    candidate = validate_candidate(baseline.as_dict(), vm.state) if args.apply else guided(baseline.as_dict(), vm.state)
    if candidate is None:
        print('Cancelled. Settings unchanged.', file=sys.stderr)
        return 0
    vm.apply_config(candidate, expected_revision=revision)
    ensure_running(vm)
    print('VM settings applied.', file=sys.stderr)
    return 0


def route_settings(vm, args):
    gateway = vm.shared_gateway
    if args.path:
        print(gateway.config_path)
        return 0
    with gateway.profile_state.lock():
        revision = gateway.profile_state.revision()
        baseline = RouteConfig.load(gateway.config_path)
    if not args.apply and not sys.stdin.isatty():
        raise ValueError('Shared route editing needs a terminal; edit settings --route --path, then apply')
    candidate = baseline if args.apply else guided_route(baseline.as_dict())
    if candidate is None:
        print('Cancelled. Shared route unchanged.', file=sys.stderr)
        return 0
    applied = gateway.applied()
    image = applied['runtime_image_id'] if applied else gateway.available_image()
    gateway.apply_config(candidate, image=image, expected_revision=revision)
    gateway.ensure_running()
    print('Shared route applied. Start the VMs you want to use.', file=sys.stderr)
    return 0


def files_command(vm, args):
    if not vm.config_path.exists():
        raise ValueError('Create your VM first with lemonbox setup')
    revision = vm.profile_state.revision()
    config = Config.load(vm.config_path, require_sources=False)
    action = args.files_action
    if action is None:
        if not sys.stdin.isatty():
            action = 'list'
        else:
            show_files(config)
            print('\n1  Add a host folder\n2  Remove a shared folder\n0  Back', file=sys.stderr)
            choice = _answer('Choose [0]: ') or '0'
            if choice == '0':
                return 0
            if choice == '1':
                source = _answer('Host folder: ')
                if not source:
                    return 0
                args.source = Path(source).expanduser()
                args.name = _answer('Name inside VM [' + args.source.name + ']: ') or args.source.name
                args.read_only = _confirm('Read-only?')
                action = 'add'
            elif choice == '2':
                args.name = _answer('Shared folder name: ')
                action = 'remove'
            else:
                raise ValueError('Choose 0, 1 or 2')
    if action == 'list':
        show_files(config)
        return 0
    data = config.as_dict()
    if action == 'add':
        source = args.source.expanduser().resolve()
        name = args.name or source.name
        if any(item['name'] == name for item in data['shares']):
            raise ValueError('A folder named ' + name + ' is already shared')
        data['shares'].append({'name': name, 'source': str(source), 'read_only': args.read_only})
    else:
        if not any(item['name'] == args.name for item in data['shares']):
            raise ValueError('No shared folder named ' + args.name)
        data['shares'] = [item for item in data['shares'] if item['name'] != args.name]
    candidate = validate_candidate(data, vm.state)
    print('Applying shared folders and restarting the VM. Running guest jobs will stop.', file=sys.stderr)
    vm.apply_config(candidate, expected_revision=revision)
    ensure_running(vm)
    show_files(candidate)
    return 0


def show_files(config):
    if not config.shares:
        print('No shared folders. Run lemonbox files to add one.')
    for item in config.shares:
        mode = 'read-only' if item['read_only'] else 'read/write'
        print(item['source'] + ' -> ' + item['target'] + ' (' + mode + ')')


def status(vm, json_output=False):
    entries, inspection_error = {}, None
    for role in ('gateway', 'machine'):
        try:
            entries[role] = vm.info(getattr(vm, role))
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            entries[role] = {'State': {'Status': 'unavailable'}}
            inspection_error = 'Container inspection is unavailable; check Podman and the shared gateway.'
    report = {
        'profile': vm.profile, 'state_dir': str(vm.state), 'configuration': str(vm.config_path),
        'configuration_valid': bool(vm.config) and not vm.config_error,
        'configuration_error': vm.config_error,
        **{role: item['State']['Status'] if item else 'stopped' for role, item in entries.items()},
        'routing_mode': 'wireguard', 'shared_gateway': vm.gateway,
        'inspection_error': inspection_error,
    }
    report['recovery'] = vm.shared_gateway.recovery_status() if report['gateway'] == 'running' else None
    recovery = report['recovery'] or {}
    report['gateway_healthy'] = recovery.get('status') == 'healthy'
    report['alert'] = route_alert(recovery=report['recovery'], gateway_status=report['gateway'],
                                 active=report['machine'] in ('running', 'unavailable'))
    if json_output:
        print(json.dumps(report, indent=2))
        return 0
    phase = recovery.get('status')
    route = 'healthy' if phase == 'healthy' else 'recovering' if phase == 'recovering' else (
        'closed' if phase in ('failed', 'blocked') else 'status unavailable')
    print(vm.profile + ': VM ' + report['machine'] + '; route ' + route)
    if inspection_error:
        print(inspection_error)
    if not report['configuration_valid']:
        print('Settings: ' + (vm.config_error or 'not configured; run lemonbox setup'))
    if vm.config:
        print('Home: /home/' + vm.config.vm['username'])
    try:
        route = vm.route_config
        print('Shared gateway: ' + vm.gateway + '; required public exit: ' + route.network['expected_exit_ip'])
    except (ValueError, OSError) as error:
        print('Shared route settings: ' + str(error))
    if report['machine'] == 'running' and phase in ('recovering', 'failed', 'blocked'):
        if recovery.get('retrying', recovery.get('status') == 'recovering'):
            print('Internet is closed while automatic recovery retries the fixed route '
                  '(attempt ' + str(recovery['attempts']) + '). Shell access remains available.')
        else:
            print('Internet is closed and needs attention. After fixing the cause, recover the shared gateway '
                  'in lemonbox settings; shell access remains available.')
    alert = report['alert']
    if alert and alert.get('status') == 'active':
        print('ALERT: ' + alert['reason'])
    return 0


def warn_gateway(vm):
    """Display the gateway's report while leaving repair commands available."""
    try:
        machine = vm.info(vm.machine)
        if not isinstance(machine, dict) or machine.get('State', {}).get('Status') != 'running':
            return
        alert = gateway_alert(vm.shared_gateway)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        alert = route_alert(gateway_status='unavailable', active=bool(vm.config))
    if alert:
        print('ALERT: ' + alert['reason'], file=sys.stderr)


def prerequisites(vm):
    required = ('podman', 'ssh', 'ssh-keygen', 'crun', 'slirp4netns')
    missing = [name for name in required if not shutil.which(name)]
    if not Path('/dev/net/tun').exists():
        missing.append('/dev/net/tun')
    if not os.access('/dev/kvm', os.R_OK | os.W_OK):
        missing.append('KVM access (join the kvm group and log in again)')
    if missing:
        print('Missing host prerequisites: ' + ', '.join(missing) + '. See docs/troubleshooting.md.', file=sys.stderr)
        return 1
    print('Host prerequisites: ready')
    return 0


def guest_command(vm, args):
    if args.action == 'desktop' and args.stop:
        machine = vm.info(vm.machine)
        if not machine or machine['State']['Status'] != 'running':
            print('Desktop is already stopped.', file=sys.stderr)
            return 0
        workflow = Workflow(vm)
        return workflow.vnc(args.port or (vm.config.desktop['port'] if vm.config else 5901), stop=True)
    if args.action in ('shell', 'exec'):
        workflow = repair_access(vm, workdir=args.workdir)
    else:
        workflow = ensure_running(vm, workdir=getattr(args, 'workdir', None))
    if args.action == 'shell':
        return workflow.shell()
    if args.action == 'exec':
        return workflow.execute(args.arguments)
    if args.action == 'claude':
        return workflow.claude(args.arguments)
    return workflow.vnc(args.port or vm.config.desktop['port'], open_viewer=not args.no_open)


def access_command(vm, args):
    from .access import Access, Relay
    from .local_access import LocalAccess
    manager = Access(vm)
    local = LocalAccess(vm)
    action = args.access_action
    interactive = action is None
    if action is None:
        if not sys.stdin.isatty():
            raise ValueError('The access guide needs a terminal; use access --help for automation')
        print('\nVM access\n', file=sys.stderr)
        print('1  Add local user\n2  People with access\n3  Remove access\n4  Remote access\n5  Stop sharing\n0  Back\n', file=sys.stderr)
        choice = _answer('Choose [0]: ') or '0'
        action = {'1': 'add', '2': 'list', '3': 'remove', '4': 'remote', '5': 'stop'}.get(choice)
        if choice == '0':
            return 0
        if action is None:
            raise ValueError('Choose a number from the access menu')
    if action == 'add':
        import pwd
        username = _answer('Linux username: ') if interactive else args.username
        try:
            username = pwd.getpwnam(username).pw_name
        except KeyError:
            raise ValueError('No Linux user named ' + username) from None
        if interactive:
            print('\nThey will share the VM account, sudo access, files and Claude login.', file=sys.stderr)
            if not _confirm('Grant access to ' + username + '?'):
                return 0
        repair_access(vm)
        local.grant(username)
        manager.enable()
        Relay(vm).start()
        print('\nAccess granted to ' + username + '.\n\nThey run:\n  lemonbox join')
    elif action == 'list':
        repair_access(vm)
        show_access_people(access_people(vm))
    elif action == 'remove':
        if interactive:
            repair_access(vm)
            entries = access_people(vm)
            show_access_people(entries, numbered=True)
            if not entries:
                return 0
            value = _answer('Person number (Enter to cancel): ')
            if not value:
                return 0
            if not value.isdecimal() or not 1 <= int(value) <= len(entries):
                raise ValueError('Choose a person from the numbered list')
            person = entries[int(value) - 1]
            if not _confirm('Remove access for ' + person['name'] + '? Existing SSH sessions stay open.'):
                return 0
        else:
            repair_access(vm)
            person = {'name': args.username, 'kind': 'local', 'id': args.username}
        if person['kind'] == 'local':
            local.revoke(person['id'])
        else:
            manager.revoke(person['id'])
        print('Access removed for ' + person['name'] + '. Existing SSH sessions stay open.')
    elif action == 'remote':
        return remote_access(vm, manager)
    elif action == 'stop':
        if interactive and not _confirm('Close shared SSH connections? Approvals will stay saved.'):
            return 0
        manager.disable()
        print('Sharing stopped. Approvals are saved.')
    return 0


def access_people(vm):
    from .access import Access
    from .local_access import LocalAccess, key_owner
    local = LocalAccess(vm).users()
    users = {(user['username'], user['uid']) for user in local}
    result = [{'name': user['username'], 'kind': 'local', 'id': user['username']} for user in local]
    for key in Access(vm).listkeys():
        owner = key_owner(key['name'])
        if owner in users:
            continue
        result.append({'name': owner[0] if owner else key['name'],
                       'kind': 'unregistered' if owner else 'remote', 'id': key['name']})
    return result


def show_access_people(entries, *, numbered=False):
    print('\nPeople with access\n')
    if not entries:
        print('No users added yet.')
    methods = {'local': 'local user', 'remote': 'remote key', 'unregistered': 'local key awaiting removal'}
    for index, entry in enumerate(entries, 1):
        print((str(index) + '  ' if numbered else '') + entry['name'] + ' (' + methods[entry['kind']] + ')')


def remote_access(vm, manager):
    from .access import Relay, parse_public_key
    if not sys.stdin.isatty():
        raise ValueError('Run lemonbox access remote in a terminal')
    repair_access(vm)
    manager.enable()
    Relay(vm).start()
    print('\nRemote access\n\n1. Send connection details\n')
    show_invitation(manager.invitation())
    print('\n2. Approve their public key\n')
    value = _answer('Public key or .pub file (Enter to finish later): ')
    if not value:
        print('Return to Remote access when they send their public key.')
        return 0
    text = value if value.startswith(('ssh-', 'ecdsa-', 'sk-')) else Path(value).expanduser().read_text()
    parsed = parse_public_key(text)
    name = _answer('Person or device label: ')
    print('They will share the VM account, sudo access, files and Claude login.', file=sys.stderr)
    if not _confirm('Allow ' + name + ' to connect with this key?'):
        return 0
    manager.add(name, parsed['key'])
    print('Added ' + name + '. They can now run lemonbox claude or lemonbox shell.')
    return 0


def show_invitation(invitation):
    from .access import parse_public_key
    print('They run lemonbox join and choose to connect to another computer. Send them:')
    print(json.dumps(invitation, separators=(',', ':')))
    print('\nVM fingerprint: ' + parse_public_key(invitation['host_key'])['fingerprint'])
    print('Ask them to compare this fingerprint, then send you their public key.')
    print('\nFor remote reachability, forward 127.0.0.1:' + str(invitation['port'])
          + ' here through your existing SSH or Tailscale setup.')


def join_command(args):
    from .access import parse_public_key, validate_invitation
    from .connections import Connection, connection_directory, next_connection_name, private_file
    terminal = sys.stdin.isatty()
    local_join = terminal and not (args.invitation or args.name or args.identity or args.trust)
    if args.public_key and not local_join:
        raise ValueError('--public-key requires joining a VM on this host in a terminal')
    if local_join:
        import pwd
        from .local_access import discover, register
        available = discover()
        if available:
            entry = available[0]
            if len(available) > 1:
                print('\nVMs available on this computer\n', file=sys.stderr)
                for number, candidate in enumerate(available, 1):
                    print(str(number) + '  ' + candidate['owner'] + ' / ' + candidate['hostname'], file=sys.stderr)
                choice = _answer('VM number [1] (0 to cancel): ') or '1'
                if choice == '0':
                    return 0
                if not choice.isdecimal() or not 1 <= int(choice) <= len(available):
                    raise ValueError('Choose a VM from the numbered list')
                entry = available[int(choice) - 1]
            connection = Connection.find(entry['invitation'])
            if connection is None:
                print('\n' + entry['hostname'] + ' · Owner: ' + entry['owner'], file=sys.stderr)
                if not _confirm('Join ' + entry['owner'] + "'s VM?"):
                    return 0
            name = connection.name if connection else next_connection_name()
            identity = connection.identity if connection else connection_directory(name) / 'id_ed25519'
            print('Local SSH key: ' + str(identity))
            values = list(args.public_key)
            if not values:
                value = _answer('Additional PUBLIC key or .pub file (Enter keeps current keys): ')
                if value:
                    values.append(value)
            public_keys = []
            for value in values:
                text = value if value.startswith(('ssh-', 'ecdsa-', 'sk-')) else Path(value).expanduser().read_text()
                public_keys.append(parse_public_key(text))
            if connection is None:
                private_directory(identity.parent.parent)
                private_directory(identity.parent)
                subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(identity),
                                '-C', 'lemonbox:' + name], check=True)
                connection = Connection.create(name, entry['invitation'], identity)
            public = subprocess.run(['ssh-keygen', '-y', '-f', str(identity)], stdout=subprocess.PIPE,
                                    text=True, check=True).stdout
            entry = register(entry, parse_public_key(public)['key'])
            for key in public_keys:
                entry = register(entry, key['key'], additional=True)
                print('Authorized additional public key: ' + key['fingerprint'])
            select_connection(connection.name)
            description = entry['hostname'] + ' (owner: ' + entry['owner'] + ')'
            if not connection.reachable():
                print('Access saved for ' + description + '.')
                print('VM SSH is unavailable. Ask the owner to check the VM, then run lemonbox join again.')
                return 1
            print('Joined ' + description + '.')
            print('\nRun:\n  lemonbox claude\n  lemonbox shell')
            return 0
        username = pwd.getpwuid(os.getuid()).pw_name
        print('No VM access is available for ' + username + '.', file=sys.stderr)
        print('Ask the owner to add ' + username + ' in lemonbox access.', file=sys.stderr)
        if args.public_key:
            raise ValueError('Additional keys need a local VM grant; ask the owner to add your Linux username')
        if not _confirm('Connect to a VM on another computer?'):
            return 0
    if not terminal and not (args.invitation and args.trust):
        raise ValueError('Run lemonbox join in a terminal, or supply --invitation and --trust (plus --identity for a new VM)')
    source = args.invitation.expanduser().read_text() if args.invitation else _answer('Paste the connection details from the owner, or their JSON file path: ')
    if not source.lstrip().startswith('{'):
        source = Path(source).expanduser().read_text()
    try:
        invitation = validate_invitation(json.loads(source))
    except json.JSONDecodeError:
        raise ValueError('The connection details must contain valid JSON') from None
    if terminal:
        host = _answer('Reachable SSH address [' + invitation['host'] + ']: ') or invitation['host']
        port = _answer('SSH port [' + str(invitation['port']) + ']: ')
        invitation = validate_invitation(dict(invitation, host=host, port=int(port) if port else invitation['port']))
    fingerprint = parse_public_key(invitation['host_key'])['fingerprint']
    print('VM fingerprint: ' + fingerprint, file=sys.stderr)
    if not args.trust:
        print('Compare this fingerprint with the one the owner sent.', file=sys.stderr)
        if not _confirm("Does this VM fingerprint match the owner's?"):
            return 130
    identity = private_file(args.identity.expanduser().absolute(), 'SSH identity') if args.identity else None
    connection = None
    if args.name:
        directory = connection_directory(args.name)
        if directory.exists() or directory.is_symlink():
            connection = Connection.load(args.name)
            if connection.invitation != invitation or (identity is not None and connection.identity != identity):
                raise ValueError('That label belongs to different connection details or a different SSH key; choose another --name')
    else:
        connection = Connection.find(invitation, identity)
    name = connection.name if connection else args.name or next_connection_name()
    directory = connection_directory(name)
    if connection:
        identity = connection.identity
    elif identity is None and not terminal:
        raise ValueError('Supply --identity for a new VM, or run lemonbox join in a terminal to choose or create a key')
    if identity is None:
        existing = Path.home() / '.ssh/id_ed25519'
        default = '1' if existing.is_file() else '2'
        print('1  Use an existing private SSH key\n2  Generate a new key for this connection', file=sys.stderr)
        choice = _answer('Choose [' + default + ']: ') or default
        if choice == '1':
            identity = Path(_answer('Private SSH key [' + str(existing) + ']: ') or str(existing)).expanduser()
        elif choice == '2':
            private_directory(directory.parent)
            private_directory(directory)
            identity = directory / 'id_ed25519'
            if identity.exists() or identity.is_symlink():
                raise ValueError('A key already exists at ' + str(identity) + '; use --identity to select it')
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(identity),
                            '-C', 'lemonbox:' + name], check=True)
        else:
            raise ValueError('Choose 1 or 2')
    identity = private_file(Path(identity).expanduser().absolute(), 'SSH identity')
    public = subprocess.run(['ssh-keygen', '-y', '-f', str(identity)], stdout=subprocess.PIPE,
                            text=True, check=True).stdout
    public = parse_public_key(public)
    if connection is None:
        connection = Connection.create(name, invitation, identity)
    select_connection(connection.name)
    print('Selected VM: ' + connection.address)
    print('Send this PUBLIC key to the VM owner:')
    print(public['key'])
    print('The owner runs lemonbox access, chooses Remote access, and adds this key.')
    print('Once the owner has added your key, run lemonbox claude or lemonbox shell.')
    return 0


def connection_menu(connection):
    if not sys.stdin.isatty():
        parser(client=True).print_help()
        return None
    print('\nLemonbox · ' + connection.address + '\n1  Claude\n2  Shell\n3  Status\n4  Join another VM\n0  Exit', file=sys.stderr)
    choice = _answer('Choose [1]: ') or '1'
    action = {'1': 'claude', '2': 'shell', '3': 'status', '4': 'join'}.get(choice)
    if choice == '0':
        return None
    if action is None:
        raise ValueError('Choose a number from the connection menu')
    return parse_arguments(['--connection', connection.name, action])


def dispatch_connection(args):
    from .connections import Connection, RemoteWorkflow
    if args.action == 'join':
        return join_command(args)
    if args.action not in CLIENT_COMMANDS and args.action != 'exec':
        raise ValueError('An SSH connection supports claude, shell, status and exec; VM controls require an explicit --profile')
    connection = Connection.load(args.connection)
    workflow = RemoteWorkflow(connection, workdir=getattr(args, 'workdir', None))
    alert = connection_alert(connection)
    if args.action != 'status' and alert:
        print('ALERT: ' + alert['reason'], file=sys.stderr)
    if args.action == 'claude':
        return workflow.claude(args.arguments)
    if args.action == 'shell':
        return workflow.shell()
    if args.action == 'exec':
        return workflow.execute(args.arguments)
    report = {'connection': connection.name, 'host': connection.invitation['host'],
              'port': connection.invitation['port'], 'username': connection.username,
              'host_key_fingerprint': connection.fingerprint, 'ssh_available': connection.reachable(),
              'alert': alert}
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(connection.address)
        print('SSH: ' + ('ready' if report['ssh_available'] else 'unavailable; check the address, key authorization and SSH agent'))
        print('Pinned host key: ' + report['host_key_fingerprint'])
        if alert:
            print('ALERT: ' + alert['reason'])
            print('Run lemonbox --profile default status for local gateway details.')
    return 0 if report['ssh_available'] else 1


def logs_command(vm, args):
    if args.guest:
        command = ['tail', '-n', '80', *(['-f'] if args.follow else []), str(vm.state / 'run/console.log')]
    else:
        vm.info(vm.gateway)
        command = ['podman', 'logs', '--tail', '80', *(['-f'] if args.follow else []), vm.gateway]
    return subprocess.run(command).returncode


def menu(vm, args):
    if not sys.stdin.isatty():
        parser().print_help()
        return None
    if not vm.config_path.exists():
        args.action = 'setup'
        return vm, args
    while True:
        print('\nLemonbox · ' + vm.profile + '\n1  Claude\n2  Shell\n3  Desktop\n4  Files\n5  Settings\n6  Status\n7  Select or create VM\n8  Stop this VM\n9  Share this VM\n10  Join another VM\n11  Stop all VMs and the shared gateway\n0  Exit', file=sys.stderr)
        choice = _answer('Choose [1]: ') or '1'
        actions = {'1': 'claude', '2': 'shell', '3': 'desktop', '4': 'files', '5': 'settings', '6': 'status', '8': 'stop', '9': 'access', '10': 'join'}
        if choice == '0':
            return None
        if choice == '11':
            selected = parse_arguments(['--profile', vm.profile, 'stop', '--all'])
            return vm, selected
        if choice == '7':
            directory = selection_path().parent
            names = sorted(path.name for path in directory.iterdir()
                           if path.name not in ('gateway', 'connections', 'templates') and path.is_dir() and (path / 'config.json').is_file()) if directory.exists() else []
            print('VMs: ' + (', '.join(names) or 'none'), file=sys.stderr)
            name = _answer('Select an existing name or enter a new name [' + vm.profile + ']: ') or vm.profile
            select_profile(name)
            args = parse_arguments(['--profile', name])
            vm = VM(args)
            if not vm.config_path.exists():
                args.action = 'setup'
                return vm, args
            continue
        if choice in actions:
            selected = parse_arguments(['--profile', vm.profile, '--state-dir', str(vm.state), actions[choice]])
            return vm, selected
        print('Choose a number from the menu.', file=sys.stderr)


def dispatch(vm, args):
    if args.action == 'join':
        return join_command(args)
    if args.action == 'access':
        return access_command(vm, args)
    if args.action == 'setup':
        return setup(vm, args)
    if args.action == 'settings':
        return settings_command(vm, args)
    if args.action == 'files':
        return files_command(vm, args)
    if args.action == 'start':
        ensure_running(vm, timeout=args.timeout)
        print('Ready. Run lemonbox claude, shell or desktop.', file=sys.stderr)
        return 0
    if args.action == 'restart':
        restart(vm, args.timeout)
        return 0
    if args.action == 'stop':
        if args.all:
            vm.stop_all()
        else:
            with vm.profile_state.lock():
                vm.down()
        return 0
    if args.action == 'status':
        return status(vm, args.json)
    if args.action in ('claude', 'shell', 'exec', 'desktop'):
        return guest_command(vm, args)
    if args.action == 'logs':
        return logs_command(vm, args)
    if args.action == 'diagnose':
        if prerequisites(vm):
            return 1
        if not args.host:
            Config.load(vm.config_path)
            return vm.validate()
        return 0
    if args.action == 'update':
        gateway = vm.shared_gateway
        gateway.apply_config(image=gateway.available_image())
        gateway.ensure_running()
        print('Manually rebuilt runtime applied. Start the VMs you want to use.', file=sys.stderr)
        return 0
    raise ValueError('Choose a command from lemonbox --help')


def main(argv=None):
    os.umask(0o077)
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        args = parse_arguments(argv)
        if args.help_all:
            parser(advanced=True, client=bool(args.connection)).print_help()
            return 0
        if args.action == 'join':
            return join_command(args)
        if args.connection:
            if args.action is None:
                from .connections import Connection
                args = connection_menu(Connection.load(args.connection))
                if args is None:
                    return 0
            return dispatch_connection(args)
        if args.action is None:
            location = args.state_dir or os.environ.get('LEMONBOX_STATE_DIR') or Path.home() / '.local/share/lemonbox' / args.profile
            if not (Path(location).expanduser() / 'config.json').is_file():
                if not sys.stdin.isatty():
                    parser().print_help()
                    return 0
                print('1  Join an existing VM using SSH\n2  Create a VM on this computer\n0  Exit', file=sys.stderr)
                choice = _answer('Choose [1]: ') or '1'
                if choice == '0':
                    return 0
                if choice == '1':
                    return join_command(parse_arguments(['join']))
                if choice != '2':
                    raise ValueError('Choose 0, 1 or 2')
                args.action = 'setup'
        vm = VM(args)
        if args.action is None:
            chosen = menu(vm, args)
            if chosen is None:
                return 0
            vm, args = chosen
        if args.action != 'status' and not (args.action == 'diagnose' and args.host):
            warn_gateway(vm)
        return dispatch(vm, args)
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
        print('lemonbox: ' + str(error), file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print('\nCancelled.', file=sys.stderr)
        return 130
