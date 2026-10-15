"""Interrupted image/seed creation must be retryable without partial artifacts."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


prepare = load("prepared_guest_seed", "guest-prepare.py")


class GuestPreparationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="lemon-preparation-test-")
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name)
        self.base = self.state / "base.qcow2"
        self.base.write_bytes(b"base-fixture")
        self.args = SimpleNamespace(state_dir=self.state, base_image=self.base, username="debian",
                                    hostname="lemonbox", timezone="America/Los_Angeles", disk_gib=24,
                                    desktop=True, docker=True, guest_address='10.77.0.2/30', gateway='10.77.0.1',
                                    mac='52:54:00:77:00:02', tap='vm0', ssh_port=2222)
        self.actual_run = subprocess.run
        self.fail_seed = False
        self.fail_disk = False
        self.calls = []

    def operation(self, arguments, **kwargs):
        arguments = [str(value) for value in arguments]
        self.calls.append(arguments)
        if arguments[0] == "ssh-keygen":
            return self.actual_run(arguments, **kwargs)
        if arguments[0] == "qemu-img":
            path = Path(kwargs["cwd"]) / arguments[-2]
            path.write_bytes(b"qcow-fixture")
            if self.fail_disk:
                raise subprocess.CalledProcessError(1, arguments)
        elif arguments[0] == "cloud-localds":
            Path(arguments[-3]).write_bytes(b"seed-fixture")
            if self.fail_seed:
                raise subprocess.CalledProcessError(1, arguments)
        else:
            self.fail("Unexpected preparation command")
        return subprocess.CompletedProcess(arguments, 0)

    def run_prepare(self):
        with patch.object(prepare.shutil, "which", side_effect=lambda name: "/fixture/" + name), \
                patch.object(prepare.subprocess, "run", side_effect=self.operation):
            return prepare.prepare(self.args)

    def test_failed_seed_retry_preserves_real_keys_instance_and_existing_disk(self):
        self.fail_seed = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_prepare()
        self.assertFalse((self.state / "guest.json").exists())
        self.assertFalse((self.state / "seed.iso").exists())
        self.assertFalse(list(self.state.glob(".seed-*")))
        keys = {path.name: path.read_bytes() for path in (self.state / "ssh").iterdir()}
        instance = (self.state / "instance-id").read_bytes()
        disk = (self.state / "disk.qcow2").read_bytes()
        self.fail_seed = False
        self.calls.clear()
        result = self.run_prepare()
        self.assertEqual({path.name: path.read_bytes() for path in (self.state / "ssh").iterdir()}, keys)
        self.assertEqual((self.state / "instance-id").read_bytes(), instance)
        self.assertEqual((self.state / "disk.qcow2").read_bytes(), disk)
        self.assertFalse(any(args[0] in ("ssh-keygen", "qemu-img") for args in self.calls))
        self.assertEqual(result["profile"]["username"], "debian")
        self.assertEqual(result["profile"]["timezone"], "America/Los_Angeles")
        for name in ("guest.json", "seed.iso", "disk.qcow2", "instance-id", "user-data", "meta-data", "network-config"):
            self.assertEqual((self.state / name).stat().st_mode & 0o777, 0o600)
        network = json.loads((self.state / "network-config").read_text())["ethernets"]["eth0"]
        self.assertEqual(network["addresses"], ["10.77.0.2/30"])
        self.assertEqual(network["routes"], [{"to": "0.0.0.0/0", "via": "10.77.0.1"}])

    def test_interrupted_disk_create_does_not_leave_a_partial_final_disk(self):
        self.fail_disk = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_prepare()
        self.assertFalse((self.state / "disk.qcow2").exists())
        self.assertFalse(list(self.state.glob(".disk-*")))
        self.fail_disk = False
        self.assertEqual(self.run_prepare()["disk"], str(self.state / "disk.qcow2"))

    def test_second_guest_has_unique_network_mac_and_native_ssh_identities(self):
        original = self.run_prepare()
        second = self.state / 'second'
        self.args.state_dir = second
        self.args.guest_address, self.args.gateway = '10.77.0.6/30', '10.77.0.5'
        self.args.mac, self.args.tap, self.args.ssh_port = '52:54:00:77:00:06', 'vm1', 2223
        result = self.run_prepare()
        profile = result['profile']
        self.assertEqual((profile['guest_ip'], profile['gateway'], profile['tap'], profile['ssh_port']),
                         ('10.77.0.6', '10.77.0.5', 'vm1', 2223))
        network = json.loads((second / 'network-config').read_text())['ethernets']['eth0']
        self.assertEqual(network['addresses'], ['10.77.0.6/30'])
        self.assertEqual(network['match']['macaddress'], '52:54:00:77:00:06')
        self.assertEqual(network['routes'][0]['via'], '10.77.0.5')
        self.assertNotEqual(result['instance_id'], original['instance_id'])
        self.assertNotEqual(result['guest_host_public_key'], original['guest_host_public_key'])
        self.assertNotEqual((second / 'ssh/id_ed25519.pub').read_bytes(),
                            (self.state / 'ssh/id_ed25519.pub').read_bytes())

    def test_unallocated_or_mismatched_guest_network_fails_before_creating_keys(self):
        for field, value in (('guest_address', '192.168.1.2/30'), ('guest_address', '10.77.0.2/24'),
                             ('gateway', '10.77.0.5'), ('tap', 'tap0'), ('ssh_port', 2223),
                             ('mac', '52:54:00:77:00:06')):
            with self.subTest(field=field):
                args = SimpleNamespace(**vars(self.args))
                setattr(args, field, value)
                with self.assertRaisesRegex(ValueError, 'allocated private'):
                    prepare.prepare(args)
        self.assertFalse((self.state / 'ssh').exists())

    def test_interrupted_identity_generation_is_cleanly_retryable(self):
        path = self.state / "access"
        def failed(arguments, **kwargs):
            Path(arguments[-1]).write_text("partial private identity")
            raise subprocess.CalledProcessError(1, arguments)
        with patch.object(prepare.subprocess, "run", side_effect=failed), self.assertRaises(subprocess.CalledProcessError):
            prepare.ensure_key(path, "access-test")
        self.assertFalse(path.exists())
        self.assertFalse(path.with_suffix(".pub").exists())
        self.assertFalse(list(self.state.glob(".identity-*")))
        public = prepare.ensure_key(path, "access-test")
        self.assertTrue(public.startswith("ssh-ed25519 "))

    def test_complete_preparation_reuses_instance_and_does_not_reseed_or_rekey(self):
        original = self.run_prepare()
        with patch.object(prepare.subprocess, "run") as operation:
            self.assertEqual(prepare.prepare(self.args), original)
        operation.assert_not_called()
        self.args.hostname = "other-host"
        with self.assertRaisesRegex(ValueError, "another profile"):
            self.run_prepare()

    def test_missing_seed_is_recreated_without_changing_existing_guest_disk_or_keys(self):
        original = self.run_prepare()
        disk = (self.state / 'disk.qcow2').read_bytes()
        key = (self.state / 'ssh/id_ed25519').read_bytes()
        (self.state / 'seed.iso').unlink()
        self.calls.clear()
        self.assertEqual(self.run_prepare(), original)
        self.assertEqual((self.state / 'disk.qcow2').read_bytes(), disk)
        self.assertEqual((self.state / 'ssh/id_ed25519').read_bytes(), key)
        self.assertEqual([command[0] for command in self.calls], ['cloud-localds'])

    def test_native_package_setup_replaces_rolling_sources_before_update_and_optional_installs(self):
        script = (ROOT / 'guest/provision.sh').read_text()
        beginning = script.index('apt_snapshot=')
        end = script.index('systemctl restart systemd-journald', beginning)
        restoration = script[script.rindex('sources=$(mktemp /etc/apt/sources.list.d/'):
                             script.index('\nrm -f /usr/local/lib/lemon/provision.sh')]
        directory = self.state / 'sources.list.d'
        directory.mkdir()
        executable = self.state / 'commands'
        executable.mkdir()
        trace = self.state / 'apt-trace.json'
        apt = executable / 'apt-get'
        apt.write_text('''#!/usr/bin/env python3
import json,os,pathlib,sys
target=pathlib.Path(os.environ['APT_TRACE'])
entries=json.loads(target.read_text()) if target.exists() else []
entries.append({'argv':sys.argv[1:], 'sources':pathlib.Path(os.environ['APT_SOURCE']).read_text(),
                'frontend':os.environ.get('DEBIAN_FRONTEND')})
target.write_text(json.dumps(entries))
''')
        apt.chmod(0o700)
        for command in ('locale-gen', 'update-locale'):
            target = executable / command
            target.write_text('#!/bin/sh\nexit 0\n')
            target.chmod(0o700)
        environment = os.environ | {'PATH': str(executable) + ':' + os.environ['PATH'],
                                     'APT_TRACE': str(trace), 'APT_SOURCE': str(directory / 'debian.sources')}
        for enabled in ('true', 'false'):
            (directory / 'debian.sources').write_text('URIs: https://deb.debian.org/debian\n')
            trace.unlink(missing_ok=True)
            section = ('desktop=' + enabled + '\ndocker=' + enabled + '\n'
                       + script[beginning:end] + '\n' + restoration)
            section = section.replace('/etc/apt/sources.list.d', str(directory))
            subprocess.run(['bash', '-euo', 'pipefail', '-c', section], env=environment, check=True)
            calls = json.loads(trace.read_text())
            self.assertEqual(calls[0]['argv'], ['update', '--error-on=any'])
            self.assertEqual(calls[1]['argv'][:3], ['install', '--yes', '--no-install-recommends'])
            self.assertEqual(calls[1]['frontend'], 'noninteractive')
            self.assertEqual(len(calls), 3)
            for call in calls[:2]:
                self.assertEqual(call['sources'].count('20261012T000000Z'), 2)
                self.assertIn('Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg', call['sources'])
                self.assertNotIn('deb.debian.org', call['sources'])
            self.assertIn('bind9-dnsutils', calls[1]['argv'])
            self.assertEqual('chromium' in calls[1]['argv'], enabled == 'true')
            self.assertEqual('docker.io' in calls[1]['argv'], enabled == 'true')
            self.assertEqual('docker-cli' in calls[1]['argv'], enabled == 'true')
            self.assertEqual(calls[2]['argv'], ['update', '--error-on=any'])
            restored = calls[2]['sources']
            self.assertIn('https://deb.debian.org/debian', restored)
            self.assertIn('https://security.debian.org/debian-security', restored)
            self.assertEqual(restored.count('Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg'), 2)
            self.assertNotIn('snapshot.debian.org', restored)
            self.assertNotIn('Check-Valid-Until: no', restored)
            self.assertEqual((directory / 'debian.sources').stat().st_mode & 0o777, 0o644)
            self.assertEqual(list(directory.iterdir()), [directory / 'debian.sources'])

    def test_installed_claude_is_verified_before_its_first_execution(self):
        script = (ROOT / 'guest/provision.sh').read_text()
        beginning = script.index('"$bootstrap" install 2.1.296') + len('"$bootstrap" install 2.1.296')
        end = script.index("\n  '\n", beginning)
        section = script[beginning:end]
        home = self.state / 'home'
        directory = home / '.local/bin'
        directory.mkdir(parents=True)
        marker = self.state / 'executed'
        native = directory / 'claude'
        native.write_text('#!/bin/sh\nprintf executed > "$APP_MARKER"\nprintf "2.1.296 (Claude Code)\\n"\n')
        native.chmod(0o700)
        environment = os.environ | {'HOME': str(home), 'APP_MARKER': str(marker)}
        rejected = subprocess.run(['bash', '-euo', 'pipefail', '-c', section], env=environment,
                                  capture_output=True, text=True, check=False)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertFalse(marker.exists(), 'Unverified installed bytes must never execute')
        expected = json.loads((ROOT / 'release.json').read_text())['claude_binary_sha256']
        verified = section.replace(expected, hashlib.sha256(native.read_bytes()).hexdigest())
        subprocess.run(['bash', '-euo', 'pipefail', '-c', verified], env=environment,
                       capture_output=True, text=True, check=True)
        self.assertEqual(marker.read_text(), 'executed')


if __name__ == "__main__":
    unittest.main()
