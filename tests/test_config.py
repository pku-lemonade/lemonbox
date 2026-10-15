"""Configuration contracts: preserve a fixed route and keep private files private."""
from copy import deepcopy
import base64
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from vm.config import Config, RouteConfig


ROOT = Path(__file__).resolve().parents[1]


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="lemon-config-test-")
        self.addCleanup(self.directory.cleanup)
        self.state = Path(self.directory.name)
        self.source = json.loads((ROOT / "config.example.json").read_text())
        self.route = json.loads((ROOT / "route.example.json").read_text())
        self.route["network"]["first_hop"]["password"] = "private-first-test-password"
        self.route["network"]["exit_hop"]["password"] = "private-exit-test-password"
        self.route["wireguard"] = {
            "client_private_key": base64.b64encode(bytes(range(32))).decode(),
            "server_public_key": base64.b64encode(bytes(range(32, 64))).decode(),
        }

    def write(self, name, value):
        path = self.state / name
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        return path

    def test_generated_profile_passes_gateway_validation_for_any_explicit_route(self):
        self.route['network']['first_hop'].update(server='203.0.113.10', port=7443)
        self.route['network']['exit_hop'].update(server='198.51.100.20', port=9443)
        self.route['network']['expected_exit_ip'] = '198.51.100.30'
        config = RouteConfig.from_dict(self.route)
        profile = self.state / 'generated.json'
        wireguard = self.state / 'wireguard.json'
        config.render_proxy(profile)
        config.render_wireguard(wireguard)
        spec = importlib.util.spec_from_file_location('lemon_gateway_config_test', ROOT / 'gateway/controller.py')
        gateway = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gateway)
        gateway.Config(config.gateway_env() | {'LEMON_PROXY_CONFIG': str(profile),
                                              'LEMON_WIREGUARD_CONFIG': str(wireguard)}).validate_profile()
        self.assertTrue(all(isinstance(value, str) for value in config.gateway_env().values()))
        self.assertNotIn('password', json.dumps(config.gateway_env()))
        self.assertNotIn(config.network['first_hop']['password'], repr(config))
        self.assertFalse({'LEMON_TAP_NAME', 'LEMON_GUEST_IP', 'LEMON_GATEWAY_CIDR'} & set(config.gateway_env()))

    def test_unknown_settings_never_silently_change_route_or_resource_intent(self):
        for section, key in ((None, "network"), (None, "wireguard"),
                             ("vm", "memory"), ("desktop", "listen")):
            with self.subTest(section=section):
                data = deepcopy(self.source)
                (data if section is None else data[section])[key] = "unexpected"
                with self.assertRaisesRegex(ValueError, "unknown setting"):
                    Config.from_dict(data)

    def test_bad_resource_types_and_bounds_fail(self):
        for key, value in (("cpus", True), ("cpus", 0), ("memory_mib", 1024),
                           ("disk_gib", 513), ("desktop", "true")):
            with self.subTest(setting=key):
                data = deepcopy(self.source)
                data["vm"][key] = value
                with self.assertRaises(ValueError):
                    Config.from_dict(data)

    def test_ips_ports_and_tls_fields_are_explicit_and_validated(self):
        for key, value in (("server", "proxy.example.com"), ("server", "::1"), ("port", 0),
                           ("port", True), ("skip_cert_verify", "false"), ("sni", "x\nsecret")):
            with self.subTest(setting=key):
                data = deepcopy(self.route)
                data["network"]["first_hop"][key] = value
                with self.assertRaises(ValueError):
                    RouteConfig.from_dict(data)

    def test_invalid_guest_identity_is_rejected(self):
        for key, value in (("username", "root;echo"), ("hostname", "bad..name"),
                           ("timezone", "Somewhere/Unknown")):
            with self.subTest(setting=key):
                data = deepcopy(self.source)
                data["vm"][key] = value
                with self.assertRaises(ValueError):
                    Config.from_dict(data)

    def test_config_file_rejects_symlinks_public_mode_and_duplicate_settings(self):
        path = self.write("config.json", self.source)
        path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "0600"):
            Config.load(path)
        path.chmod(0o600)
        link = self.state / "link.json"
        link.symlink_to(path)
        with self.assertRaisesRegex(ValueError, "regular file"):
            Config.load(link)
        path.write_text('{"version":1,"version":1}')
        with self.assertRaisesRegex(ValueError, "duplicate"):
            Config.load(path)

    def test_json_errors_never_echo_secret_lines(self):
        path = self.write("config.json", self.source)
        path.write_text('{"password":"private-first-test-password", BROKEN')
        with self.assertRaisesRegex(ValueError, "UTF-8 JSON") as failure:
            Config.load(path)
        self.assertNotIn("private-first-test-password", str(failure.exception))

    def test_writes_are_private_and_symlink_targets_remain_untouched(self):
        config = Config.from_dict(self.source)
        path = self.state / "config.json"
        config.write(path)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(Config.load(path).as_dict(), config.as_dict())
        existing = path.read_bytes()
        link = self.state / "link.json"
        link.symlink_to(path)
        with self.assertRaisesRegex(ValueError, "symlinks"):
            config.write(link)
        self.assertEqual(path.read_bytes(), existing)

    def test_cleanup_can_load_a_deleted_share_without_relaxing_normal_startup(self):
        deleted = self.state / "deleted"
        deleted.mkdir()
        self.source["shares"] = [{"name": "project", "source": str(deleted)}]
        path = self.write("config.json", self.source)
        deleted.rmdir()
        with self.assertRaisesRegex(ValueError, "does not exist"):
            Config.load(path)
        cleanup = Config.load(path, require_sources=False)
        self.assertEqual(cleanup.shares[0]["source"], str(deleted))
        cleanup.shares.clear()
        cleanup.write(path)
        self.assertEqual(Config.load(path).shares, [])

    def test_route_digest_binds_exit_pin_and_credentials_in_any_field_order(self):
        config = RouteConfig.from_dict(self.route)
        original = config.network_digest()
        resources = deepcopy(self.route)
        reordered = dict(reversed(list(config.network.items())))
        resources["network"] = reordered
        self.assertEqual(RouteConfig.from_dict(resources).network_digest(), original)
        for key in ("expected_exit_ip", "password"):
            modified = deepcopy(self.route)
            if key == "expected_exit_ip":
                modified["network"][key] = "203.0.113.7"
            else:
                modified["network"]["first_hop"][key] = "another-private-password"
            self.assertNotEqual(RouteConfig.from_dict(modified).network_digest(), original)

    def test_packet_keys_are_strict_and_internal_settings_cannot_be_overridden(self):
        failures = [("client_private_key", "not-a-key"), ("server_public_key", "AAAA"),
                    ("client_private_key", base64.b64encode(bytes(32)).decode()),
                    ("client_private_key", "REPLACE_PRIVATE_KEY"), ("enabled", False),
                    ("client_address", "10.77.0.2/30"), ("server_address", "10.79.0.1"),
                    ("endpoint_port", 15080), ("remote_port", 51820), ("mtu", 1500),
                    ("transport", "stream"), ("stream_port", 51822)]
        for field, value in failures:
            with self.subTest(setting=field):
                data = deepcopy(self.route)
                data["wireguard"][field] = value
                with self.assertRaises(ValueError) as failure:
                    RouteConfig.from_dict(data)
                self.assertNotIn(data["wireguard"]["server_public_key"], str(failure.exception))

    def test_packet_route_requires_both_keys_but_template_loading_allows_placeholders(self):
        for name in ("client_private_key", "server_public_key"):
            data = deepcopy(self.route)
            del data["wireguard"][name]
            with self.assertRaisesRegex(ValueError, "required"):
                RouteConfig.from_dict(data)
        data = deepcopy(self.route)
        data["wireguard"]["client_private_key"] = "REPLACE_WIREGUARD_PRIVATE_KEY"
        draft = RouteConfig.from_dict(data, allow_placeholder=True)
        self.assertEqual(draft.wireguard['client_private_key'], 'REPLACE_WIREGUARD_PRIVATE_KEY')
        with self.assertRaisesRegex(ValueError, 'WireGuard key'):
            draft.write(self.state / 'draft.json')

    def test_rendered_keys_are_private_and_key_changes_invalidate_applied_route(self):
        data = deepcopy(self.route)
        config = RouteConfig.from_dict(data)
        path = self.state / "wireguard.json"
        config.render_wireguard(path)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(path.read_text())["client_private_key"], config.wireguard["client_private_key"])
        original = config.network_digest()
        changed = deepcopy(data)
        changed["wireguard"]["client_private_key"] = base64.b64encode(bytes(range(64, 96))).decode()
        self.assertNotEqual(RouteConfig.from_dict(changed).network_digest(), original)

if __name__ == "__main__":
    unittest.main()
