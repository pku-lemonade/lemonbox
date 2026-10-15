"""Protocol/measurement regressions; no VM, external services or secrets needed."""
import importlib.util
from pathlib import Path
import struct
import unittest
from vm import guest_probe as probe


ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


adversarial = load("adversarial_guest", ROOT / "tests/adversarial_guest.py")


class ProtocolTests(unittest.TestCase):
    def assert_internet_checksum_valid(self, data):
        # Verify the wire checksum independently of the packet builder.
        padded = data + (b"\0" if len(data) % 2 else b"")
        total = sum(int.from_bytes(padded[index:index + 2], "big") for index in range(0, len(padded), 2))
        while total > 65535:
            total = (total & 65535) + (total >> 16)
        self.assertEqual(total, 65535)

    def test_root_adversarial_ipv4_udp_and_icmp_are_valid_wire_packets(self):
        udp = adversarial.ipv4_packet("10.77.0.3", "1.1.1.1")
        self.assertEqual(struct.unpack_from("!H", udp, 2)[0], len(udp))
        self.assertEqual(udp[9], 17)
        self.assert_internet_checksum_valid(udp[:20])
        pseudo = udp[12:20] + struct.pack("!BBH", 0, 17, len(udp) - 20)
        self.assert_internet_checksum_valid(pseudo + udp[20:])
        icmp = adversarial.ipv4_packet("10.77.0.2", "1.1.1.1", protocol=1)
        self.assertEqual(icmp[9], 1)
        self.assertEqual(icmp[20], 8)
        self.assert_internet_checksum_valid(icmp[:20])
        self.assert_internet_checksum_valid(icmp[20:])

    def test_root_adversarial_ipv6_udp_has_required_pseudo_header_checksum(self):
        packet = adversarial.ipv6_packet()
        self.assertEqual(packet[0] >> 4, 6)
        self.assertEqual(packet[6], 17)
        self.assertEqual(struct.unpack_from("!H", packet, 4)[0], len(packet) - 40)
        self.assertNotEqual(packet[46:48], b"\0\0")
        pseudo = packet[8:40] + struct.pack("!I3xB", len(packet) - 40, 17)
        self.assert_internet_checksum_valid(pseudo + packet[40:])

    def test_stun_decodes_real_xor_mapping_and_checks_transaction(self):
        request, transaction = probe.stun_request()
        self.assertEqual(len(request), 20)
        ip = int(probe.ipaddress.IPv4Address("203.0.113.23")) ^ 0x2112A442
        attribute = struct.pack("!HHBBHI", 0x0020, 8, 0, 1, 50000 ^ 0x2112, ip)
        response = struct.pack("!HHI", 0x0101, len(attribute), 0x2112A442) + transaction + attribute
        self.assertEqual(probe.stun_address(response, transaction), "203.0.113.23")
        with self.assertRaises(ValueError):
            probe.stun_address(response, b"wrong-id-123")

    def test_stun_rejects_truncation_and_out_of_bounds_attributes(self):
        _, transaction = probe.stun_request()
        for response in (b"short", struct.pack("!HHI", 0x0101, 64, 0x2112A442) + transaction,
                         struct.pack("!HHI", 0x0101, 4, 0x2112A442) + transaction + struct.pack("!HH", 0x20, 8) + b"x" * 8):
            with self.assertRaises(ValueError):
                probe.stun_address(response, transaction)

    def test_dns_validation_rejects_wrong_transaction_and_error_responses(self):
        request, identifier = probe.dns_request()
        self.assertGreater(len(request), 12)
        self.assertTrue(probe.dns_valid(struct.pack("!HHHHHH", identifier, 0x8180, 1, 1, 0, 0), identifier))
        self.assertFalse(probe.dns_valid(struct.pack("!HHHHHH", identifier ^ 1, 0x8180, 1, 1, 0, 0), identifier))
        self.assertFalse(probe.dns_valid(struct.pack("!HHHHHH", identifier, 0x8183, 1, 0, 0, 0), identifier))
        self.assertFalse(probe.dns_valid(request, identifier))


if __name__ == "__main__":
    unittest.main()
