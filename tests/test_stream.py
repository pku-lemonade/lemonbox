"""Framed opaque UDP preserves boundaries, rejects malformed frames and closes."""
import importlib.util
import select
from pathlib import Path
import socket
import struct
import threading
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("framed_transport_test", ROOT / "gateway/stream.py")
stream = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stream)


def read_frame(connection, *, deadline):
    """Decode test observations; production uses the incremental relay parser."""
    def read(count):
        value = bytearray()
        while len(value) < count:
            connection.settimeout(max(.001, deadline - time.monotonic()))
            data = connection.recv(count - len(value))
            if not data:
                raise EOFError("test peer closed")
            value.extend(data)
        return bytes(value)
    return read(struct.unpack("!H", read(2))[0])


class Fragments:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.timeouts = []
        self.sent = []
        self.closed = False

    def settimeout(self, value):
        self.timeouts.append(value)

    def recv(self, size):
        if not self.chunks:
            return b""
        data = self.chunks.pop(0)
        if len(data) > size:
            self.chunks.insert(0, data[size:])
        return data[:size]

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True

    def setsockopt(self, *args):
        pass


class SocketTests(unittest.TestCase):
    def test_socket_registry_shutdown_closes_all_descriptors_and_rejects_new_ones(self):
        stop = threading.Event()
        registry = stream.Sockets(stop)
        reader, writer = socket.socketpair()
        registry.add(reader)
        registry.add(writer)
        registry.close()
        self.assertTrue(stop.is_set())
        self.assertEqual((reader.fileno(), writer.fileno()), (-1, -1))
        later = socket.socket()
        with self.assertRaises(InterruptedError):
            registry.add(later)
        self.assertEqual(later.fileno(), -1)


class ProxyTests(unittest.TestCase):
    def test_socks_connect_targets_only_remote_ipv4_loopback_with_no_fallback(self):
        response = b"\x05\x00\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + b"\xcb\xbe"
        connection = Fragments([response])
        with mock.patch.object(stream.socket, "create_connection", return_value=connection) as opened:
            self.assertIs(stream.socks_connect(), connection)
        opened.assert_called_once_with(("127.0.0.1", 15080), timeout=15)
        self.assertEqual(connection.sent, [b"\x05\x01\x00", b"\x05\x01\x00\x01\x7f\x00\x00\x01\xca\x6e"])
        self.assertFalse(connection.closed)

    def test_proxy_rejection_closes_the_socket(self):
        connection = Fragments([b"\x05\x00\x05\x01\x00\x01"])
        with mock.patch.object(stream.socket, "create_connection", return_value=connection), \
                self.assertRaises(stream.ProtocolError):
            stream.socks_connect()
        self.assertTrue(connection.closed)


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.stop = threading.Event()
        self.registry = stream.Sockets(self.stop)
        self.threads = []
        self.errors = []
        self.echo = self.registry.add(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        self.echo.bind(("127.0.0.1", 0))
        self.echo.settimeout(.1)
        self.server_udp = self.registry.add(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        self.server_udp.connect(self.echo.getsockname())
        self.client_udp = self.registry.add(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        self.client_udp.bind(("127.0.0.1", 0))
        self.client_tcp, self.server_tcp = socket.socketpair()
        self.registry.add(self.client_tcp)
        self.registry.add(self.server_tcp)
        self.peer = self.registry.add(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        self.peer.bind(("127.0.0.1", 0))
        self.peer.settimeout(2)
        self.addCleanup(self.cleanup)

        def echo():
            while not self.stop.is_set():
                try:
                    data, address = self.echo.recvfrom(8192)
                    self.echo.sendto(data, address)
                except socket.timeout:
                    continue
                except OSError:
                    return

        self.thread(echo)
        self.thread(lambda: stream.relay(self.client_tcp, self.client_udp, client=True, stop=self.stop))
        self.thread(lambda: stream.relay(self.server_tcp, self.server_udp, stop=self.stop))

    def thread(self, function):
        def run():
            try:
                function()
            except (OSError, ValueError) as error:
                if not self.stop.is_set():
                    self.errors.append(type(error).__name__)
        worker = threading.Thread(target=run)
        self.threads.append(worker)
        worker.start()

    def cleanup(self):
        self.registry.close()
        for worker in self.threads:
            worker.join(timeout=2)
        self.assertTrue(all(not worker.is_alive() for worker in self.threads))

    def exchange(self, payload):
        self.peer.sendto(payload, self.client_udp.getsockname())
        self.assertEqual(self.peer.recv(8192), payload)

    def test_full_roundtrip_preserves_small_and_large_opaque_udp_boundaries(self):
        for length in (1, 1532, 4096):
            with self.subTest(length=length):
                self.exchange(bytes(index % 256 for index in range(length)))
        self.assertEqual(self.errors, [])

    def test_client_replies_only_to_first_udp_peer_and_ignores_another_sender(self):
        self.exchange(b"first peer")
        other = self.registry.add(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        other.bind(("127.0.0.1", 0))
        other.settimeout(.1)
        other.sendto(b"another peer", self.client_udp.getsockname())
        with self.assertRaises(socket.timeout):
            other.recv(8192)
        self.exchange(b"first peer still works")
        self.assertEqual(self.errors, [])


class RelayShutdownTests(unittest.TestCase):
    def test_udp_shutdown_wakeup_without_sender_exits_cleanly(self):
        for client in (True, False):
            with self.subTest(client=client):
                stop = threading.Event()
                connection, udp = mock.Mock(), mock.Mock()

                def shutdown(*args):
                    stop.set()
                    return (b'', None) if client else b''

                (udp.recvfrom if client else udp.recv).side_effect = shutdown
                with mock.patch.object(stream.select, 'select', return_value=([udp], [], [])):
                    stream.relay(connection, udp, client=client, stop=stop)
                connection.send.assert_not_called()


class DuplexRelayTests(unittest.TestCase):
    def setUp(self):
        self.stop = threading.Event()
        self.registry = stream.Sockets(self.stop)
        self.tcp, self.remote = socket.socketpair()
        self.registry.add(self.tcp)
        self.registry.add(self.remote)
        self.udp = self.registry.add(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        self.udp.bind(('127.0.0.1', 0))
        self.peer = self.registry.add(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        self.peer.bind(('127.0.0.1', 0))
        self.peer.settimeout(1)
        self.errors = []
        self.worker = None
        self.addCleanup(self.cleanup)

    def start(self, idle_seconds=30):
        def forward():
            try:
                stream.relay(self.tcp, self.udp, client=True, stop=self.stop, idle_seconds=idle_seconds)
            except (OSError, ValueError) as error:
                if not self.stop.is_set():
                    self.errors.append(type(error).__name__)
            finally:
                self.tcp.close()
        self.worker = threading.Thread(target=forward)
        self.worker.start()
        self.peer.sendto(b'initial peer', self.udp.getsockname())
        self.assertEqual(read_frame(self.remote, deadline=time.monotonic() + 1), b'initial peer')

    def cleanup(self):
        self.registry.close()
        if self.worker is not None:
            self.worker.join(timeout=2)
            self.assertFalse(self.worker.is_alive())

    def test_partial_incoming_frame_does_not_hold_outbound_datagrams(self):
        self.start()
        self.remote.sendall(b'\x00\x08par')
        for index in range(3):
            payload = b'outbound health ' + bytes([index])
            self.peer.sendto(payload, self.udp.getsockname())
            self.assertEqual(read_frame(self.remote, deadline=time.monotonic() + 1), payload)
        self.remote.sendall(b'tial!')
        self.assertEqual(self.peer.recv(8192), b'partial!')
        self.assertEqual(self.errors, [])

    def test_tcp_send_backpressure_does_not_hold_incoming_datagrams(self):
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2048)
        self.start()
        for _ in range(32):
            self.peer.sendto(b'x' * 4096, self.udp.getsockname())
        deadline = time.monotonic() + 1
        while select.select([], [self.tcp], [], 0)[1] and time.monotonic() < deadline:
            time.sleep(.005)
        self.assertFalse(select.select([], [self.tcp], [], 0)[1], 'TCP writer did not reach backpressure')
        self.remote.sendall(b'\x00\x07reverse')
        self.assertEqual(self.peer.recv(8192), b'reverse')
        self.assertEqual(self.errors, [])

    def test_continuous_outbound_activity_cannot_extend_a_partial_frame_deadline(self):
        self.start(idle_seconds=.15)
        self.remote.sendall(b'\x00\x40x')
        forwarded = 0
        for index in range(80):
            if not self.worker.is_alive():
                break
            self.peer.sendto(b'active ' + bytes([index]), self.udp.getsockname())
            try:
                read_frame(self.remote, deadline=time.monotonic() + 1)
                forwarded += 1
            except (OSError, ValueError, EOFError):
                break
            time.sleep(.005)
        self.worker.join(timeout=.5)
        self.assertFalse(self.worker.is_alive())
        self.assertGreater(forwarded, 2)
        self.assertEqual(self.errors, ['TimeoutError'])

    def test_oversized_prefix_is_rejected_without_accepting_its_payload(self):
        self.start()
        self.remote.sendall(struct.pack('!H', stream.MAX_DATAGRAM + 1))
        self.worker.join(timeout=1)
        self.assertFalse(self.worker.is_alive())
        self.assertEqual(self.errors, ['ProtocolError'])


if __name__ == "__main__":
    unittest.main()
