"""Supported diagnostics; reports and operator scripts stay on the host."""
import json
from pathlib import Path
import select
import subprocess

from .config import write_private_json
from .runtime import run as command
from .workflows import Workflow


def private_drop_count(vm):
    data = json.loads(command(['podman', 'exec', vm.gateway, 'nft', '-j', 'list',
                              'table', 'inet', 'lemon_vm'], capture=True, timeout=5).stdout)
    for item in data['nftables']:
        rule = item.get('rule', {})
        expressions = rule.get('expr', [])
        if (rule.get('chain') == 'guest_ingress' and any('drop' in expr for expr in expressions)
                and any(expr.get('match', {}).get('left', {}).get('payload', {}).get('field') == 'daddr'
                        for expr in expressions)):
            return next(expr['counter']['packets'] for expr in expressions if 'counter' in expr)
    raise ValueError('Private-destination enforcement counter is missing')


def controlled_private_check(vm):
    """A live listener and a drop counter distinguish denial from an outage."""
    script = ('import os,socket,sys,threading\n'
              'threading.Timer(45,lambda:os._exit(0)).start()\n'
              'def eof():\n sys.stdin.buffer.read();os._exit(0)\n'
              'threading.Thread(target=eof,daemon=True).start()\n'
              's=socket.socket();s.bind(("0.0.0.0",0));s.listen()\n'
              'print(s.getsockname()[1],flush=True)\n'
              'while True:\n c,_=s.accept();c.close()\n')
    listener = subprocess.Popen(['podman', 'exec', '-i', vm.gateway, 'python3', '-u', '-c', script],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True)
    try:
        if not select.select([listener.stdout], [], [], 10)[0]:
            raise RuntimeError('Diagnostic positive-control listener did not start')
        port = int(listener.stdout.readline())
        command(['podman', 'exec', vm.gateway, 'python3', '-c',
                 'import socket;socket.create_connection(("127.0.0.1",' + str(port) + '),2).close()'], capture=True, timeout=5)
        before = private_drop_count(vm)
        guest_gateway = json.loads((vm.state / 'guest.json').read_text())['profile']['gateway']
        probe = ('import socket,json\ntry:\n s=socket.create_connection((' + repr(guest_gateway) + ',' + str(port) + '),3);s.close();v=True\n'
                 'except OSError: v=False\nprint(json.dumps({"connected":v}))\n')
        response = Workflow(vm).run_script(probe, timeout=15)
        value = json.loads(response.stdout) if response.returncode == 0 else {}
        connected = value.get('connected') if isinstance(value, dict) else None
        if type(connected) is not bool:
            connected = None
        denied = connected is False
        after = private_drop_count(vm)
        return {'name': 'private_destination_enforced', 'status': 'pass' if denied and after > before else 'fail',
                'detail': {'listener_positive_control': True, 'guest_connected': connected,
                           'policy_drop_packets': after - before}}
    finally:
        # EOF reaches the remote watchdog; killing only `podman exec` could
        # leave its Python listener alive in the gateway. The timer bounds
        # remote lifetime even if the host or exec transport disappears.
        listener.stdin.close()
        try:
            listener.wait(timeout=5)
        except subprocess.TimeoutExpired:
            listener.terminate()
            try:
                listener.wait(timeout=5)
            except subprocess.TimeoutExpired:
                listener.kill()
                listener.wait()
        listener.stdout.close()


def run(vm):
    vm.private()
    workflow = Workflow(vm)
    workflow.accessible()
    gateway = json.loads((vm.state / 'guest.json').read_text())['profile']['gateway']
    options = ['--expected-exit-ip', vm.route_config.network['expected_exit_ip'], '--gateway', gateway,
               '--timezone', vm.config.vm['timezone'], '--network', '--root-checks']
    if vm.config.vm['docker']:
        options.append('--docker')
    source = 'import sys\nsys.argv = ' + repr(['guest_probe.py', *options]) + '\n' + Path(__file__).with_name('guest_probe.py').read_text()
    completed = workflow.run_script(source, timeout=300)
    try:
        report = json.loads(completed.stdout)
        if (completed.returncode not in (0, 1) or report.get('schema') != 1
                or not isinstance(report.get('checks'), list) or not report['checks']
                or any(not isinstance(item, dict) or item.get('status') not in ('pass', 'fail')
                       or not isinstance(item.get('name'), str) for item in report['checks'])):
            raise ValueError('Invalid guest diagnostic response')
        report['checks'].append(controlled_private_check(vm))
        report['passed'] = completed.returncode == 0 and all(item['status'] == 'pass' for item in report['checks'])
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError):
        report = {'schema': 1, 'passed': False, 'checks': [], 'error': 'Diagnostic transport or probe failed'}
    path = vm.state / 'validation' / 'diagnose.json'
    path.parent.mkdir(mode=0o700, exist_ok=True)
    write_private_json(path, report)
    for item in report['checks']:
        print(item['status'].upper() + ' ' + item['name'])
    print('Report: ' + str(path))
    return 0 if report['passed'] else 1
