"""Shared route ownership, stale edits, lifecycle isolation and address allocation."""
import base64
from copy import deepcopy
import json
import multiprocessing
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from vm.config import RouteConfig, write_private_json
from vm import gateway_runtime as gateway

ROOT = Path(__file__).resolve().parents[1]
IMAGE = 'sha256:' + 'a' * 64


def allocate_worker(directory, profile, output):
    vm = SimpleNamespace(state=Path(directory) / profile, profile=profile)
    output.put(gateway.SharedGateway(vm, Path(directory) / 'gateway').allocation())


class SharedGatewayTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='lemon-shared-gateway-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.vm = SimpleNamespace(state=self.directory / 'default', profile='default')
        self.manager = gateway.SharedGateway(self.vm, self.directory / 'gateway')
        self.route = json.loads((ROOT / 'route.example.json').read_text())
        self.route['network']['first_hop']['password'] = 'first-route-fixture'
        self.route['network']['exit_hop']['password'] = 'exit-route-fixture'
        self.route['wireguard'] = {'client_private_key': base64.b64encode(bytes(range(32))).decode(),
                                   'server_public_key': base64.b64encode(bytes(range(32, 64))).decode()}
        self.config = RouteConfig.from_dict(self.route)
        gateway.private_directory(self.manager.state)
        (self.manager.state / 'mihomo').write_text('#!/bin/sh\nexit 0\n')
        (self.manager.state / 'mihomo').chmod(0o700)
        self.calls = []
        self.running = []
        self.validation_failure = False

    def backend(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if argv[:2] == ['podman', 'ps']:
            return subprocess.CompletedProcess(argv, 0, '\n'.join(self.running), '')
        if argv[:3] == ['podman', 'container', 'exists']:
            return subprocess.CompletedProcess(argv, 1, '', '')
        if argv[:3] == ['podman', 'image', 'inspect']:
            return subprocess.CompletedProcess(argv, 0, IMAGE + '\n', '')
        if argv[-1] == 'validate-profile' and self.validation_failure:
            raise RuntimeError('validation failed')
        return subprocess.CompletedProcess(argv, 0, '', '')

    def apply(self):
        with patch.object(gateway, 'run', side_effect=self.backend):
            return self.manager.apply_config(self.config, image=IMAGE)

    def test_default_and_second_profile_keep_unique_stable_identity_and_no_route_copies(self):
        default = self.manager.allocation()
        self.assertEqual((default['guest_ip'], default['gateway'], default['ssh_port'], default['mac']),
                         ('10.77.0.2', '10.77.0.1', 2222, '52:54:00:77:00:02'))
        second = gateway.SharedGateway(SimpleNamespace(state=self.directory / 'second', profile='second'), self.manager.state)
        allocated = second.allocation()
        self.assertEqual((allocated['guest_address'], allocated['gateway'], allocated['tap'], allocated['ssh_port']),
                         ('10.77.0.6/30', '10.77.0.5', 'vm1', 2223))
        self.assertEqual(gateway.SharedGateway(second.vm, self.manager.state).allocation(), allocated)
        records = self.manager.records()
        self.assertEqual([record['profile'] for record in records], ['default', 'second'])
        self.assertNotIn('password', self.manager.allocations_path.read_text())
        self.assertFalse(self.vm.state.exists(), 'Address allocation must not copy transport state into a VM')

    def test_real_parallel_allocation_reserves_slot_zero_and_never_reuses_a_slot(self):
        context = multiprocessing.get_context('fork')
        output = context.Queue()
        workers = [context.Process(target=allocate_worker, args=(str(self.directory), 'worker' + str(i), output))
                   for i in range(6)]
        for process in workers:
            process.start()
        allocated = [output.get(timeout=10) for _ in workers]
        for process in workers:
            process.join(10)
            self.assertEqual(process.exitcode, 0)
        self.assertEqual({item['slot'] for item in allocated}, set(range(1, 7)))
        self.assertEqual(self.manager.allocation()['slot'], 0)
        self.assertEqual(self.manager.allocations_path.stat().st_mode & 0o777, 0o600)

    def test_conflicting_profile_or_tampered_registry_cannot_assign_another_vm_identity(self):
        self.manager.allocation()
        duplicate = gateway.SharedGateway(SimpleNamespace(state=self.directory / 'other', profile='default'), self.manager.state)
        with self.assertRaisesRegex(ValueError, 'another state'):
            duplicate.allocation()
        registry = json.loads(self.manager.allocations_path.read_text())
        registry['profiles'][str(self.directory / 'second')] = {'profile': 'second', 'slot': 0}
        write_private_json(self.manager.allocations_path, registry)
        with self.assertRaisesRegex(ValueError, 'allocation'):
            self.manager.records()

    def test_applied_route_has_one_private_pair_and_stale_edit_rejected_before_reuse(self):
        applied = self.apply()
        self.assertEqual(set(applied), {'runtime_image_id', 'network_sha256'})
        for name in ('config.json', 'proxy.json', 'wireguard.json', 'applied.json'):
            self.assertEqual((self.manager.state / name).stat().st_mode & 0o777, 0o600)
        self.calls.clear()
        with patch.object(gateway, 'run', side_effect=self.backend), self.assertRaisesRegex(ValueError, 'changed while'):
            self.manager.apply_config(self.config, image=IMAGE, expected_revision='outdated')
        self.assertEqual(self.calls, [])

    def test_route_changes_fail_before_mutation_while_any_vm_is_running(self):
        self.apply()
        original = (self.manager.state / 'config.json').read_bytes()
        candidate = deepcopy(self.route)
        candidate['network']['first_hop']['password'] = 'new-route-fixture'
        self.running = ['lemonbox-second-machine']
        with patch.object(gateway, 'run', side_effect=self.backend), self.assertRaisesRegex(ValueError, 'Stop every VM'):
            self.manager.apply_config(RouteConfig.from_dict(candidate), image=IMAGE)
        self.assertEqual((self.manager.state / 'config.json').read_bytes(), original)

    def test_validation_failure_leaves_desired_change_pending_and_prevents_boot(self):
        self.apply()
        original = (self.manager.state / 'applied.json').read_bytes()
        candidate = deepcopy(self.route)
        candidate['network']['expected_exit_ip'] = '203.0.113.90'
        self.validation_failure = True
        with patch.object(gateway, 'run', side_effect=self.backend), self.assertRaisesRegex(RuntimeError, 'validation failed'):
            self.manager.apply_config(RouteConfig.from_dict(candidate), image=IMAGE)
        self.assertEqual((self.manager.state / 'applied.json').read_bytes(), original)
        self.assertTrue(self.manager.pending())
        with patch.object(gateway, 'run', side_effect=self.backend), self.assertRaisesRegex(ValueError, 'pending'):
            self.manager.ensure_running()
        self.assertFalse(any('-d' in argv for argv, _ in self.calls))

    def test_unchanged_route_is_reused_while_another_vm_runs(self):
        applied = self.apply()
        self.calls.clear()
        self.running = ['lemonbox-second-machine']
        with patch.object(gateway, 'run', side_effect=self.backend):
            self.assertEqual(self.manager.apply_config(self.config, image=IMAGE), applied)
        self.assertFalse(any(argv[:2] in (['podman', 'run'], ['podman', 'stop']) for argv, _ in self.calls))

    def test_attach_detach_changes_only_selected_tap_and_keeps_shared_gateway_alive(self):
        with patch.object(self.manager, 'ensure_running', return_value=IMAGE), \
                patch.object(self.manager, 'info', return_value={'State': {'Status': 'running'}}), \
                patch.object(gateway, 'run', side_effect=self.backend):
            self.manager.attach()
            self.manager.detach()
        commands = [(argv[-1], json.loads(kwargs['input_text'])) for argv, kwargs in self.calls]
        self.assertEqual([command for command, _ in commands], ['add-guest', 'remove-guest'])
        self.assertEqual(commands[0][1], {'tap': 'vm0', 'guest_cidr': '10.77.0.2/30', 'gateway_cidr': '10.77.0.1/30'})
        self.assertEqual(commands[0][1], commands[1][1])

    def test_unowned_gateway_is_never_adopted(self):
        def inspect_backend(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, json.dumps([info]), '')
        info = {'Id': 'unrelated', 'Config': {'Labels': {}}, 'Mounts': []}
        with patch.object(gateway, 'run', side_effect=inspect_backend), self.assertRaisesRegex(ValueError, 'another owner'):
            self.manager.info()
        info['Config']['Labels'] = {gateway.PROJECT_LABEL: str(ROOT), gateway.STATE_LABEL: str(self.manager.state),
                                    gateway.ROLE_LABEL: 'gateway'}
        with patch.object(gateway, 'run', side_effect=inspect_backend):
            self.assertEqual(self.manager.info()['Id'], 'unrelated')

    def test_backend_error_is_not_treated_as_missing_gateway(self):
        with patch.object(gateway, 'run', return_value=subprocess.CompletedProcess([], 125, '', '')):
            with self.assertRaisesRegex(RuntimeError, 'backend'):
                self.manager.info()


if __name__ == '__main__':
    unittest.main()
