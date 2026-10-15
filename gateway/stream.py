#!/usr/bin/env python3
"""Carry opaque WireGuard UDP datagrams in an authenticated proxy TCP stream.

Every endpoint is IPv4 loopback. The client uses the gateway's fixed SOCKS
route; the server forwards only to the owned local WireGuard listener. No
WireGuard keys are required. Packet bytes are forwarded without inspection,
logging or storage.
"""
import argparse
import ipaddress
import select
import signal
import socket
import struct
import threading
import time

try:
    from route_contract import SOCKS_PORT, WG_ENDPOINT_PORT, WG_SERVER_PORT, WG_STREAM_PORT
except ModuleNotFoundError:
    from vm.route_contract import SOCKS_PORT, WG_ENDPOINT_PORT, WG_SERVER_PORT, WG_STREAM_PORT


LOOPBACK = "127.0.0.1"
MAX_DATAGRAM = 4096
IDLE_SECONDS = 30
SOCKS_TIMEOUT = 15
MAX_CONNECTIONS = 8


class ProtocolError(ValueError):
    """An incomplete or invalid framed datagram; messages contain no data."""


def port(value):
    if type(value) is not int or not 1024 <= value <= 65535:
        raise ValueError("Use an unprivileged listener port")
    return value


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Transport deadline expired")
    return remaining


def read_exact(connection, count, deadline, stop=None):
    result = bytearray()
    while len(result) < count:
        if stop is not None and stop.is_set():
            raise InterruptedError("Transport is stopping")
        connection.settimeout(min(.5, _remaining(deadline)))
        try:
            data = connection.recv(count - len(result))
        except socket.timeout:
            continue
        if not data:
            raise ProtocolError("Incomplete framed datagram")
        result.extend(data)
    return bytes(result)


def keepalive(connection):
    connection.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    for name, value in (("TCP_KEEPIDLE", 25), ("TCP_KEEPINTVL", 5), ("TCP_KEEPCNT", 3)):
        option = getattr(socket, name, None)
        if option is not None:
            connection.setsockopt(socket.IPPROTO_TCP, option, value)


def socks_connect(socks_port=SOCKS_PORT, remote_port=WG_STREAM_PORT, stop=None):
    """Connect only to the exit's loopback bridge through the pinned SOCKS route."""
    port(socks_port)
    port(remote_port)
    deadline = time.monotonic() + SOCKS_TIMEOUT
    connection = socket.create_connection((LOOPBACK, socks_port), timeout=SOCKS_TIMEOUT)
    try:
        connection.sendall(b"\x05\x01\x00")
        if read_exact(connection, 2, deadline, stop) != b"\x05\x00":
            raise ProtocolError("SOCKS authentication method rejected")
        connection.sendall(b"\x05\x01\x00\x01" + ipaddress.IPv4Address(LOOPBACK).packed
                           + struct.pack("!H", remote_port))
        version, status, reserved, kind = read_exact(connection, 4, deadline, stop)
        if (version, status, reserved) != (5, 0, 0):
            raise ProtocolError("Fixed proxy route rejected")
        length = {1: 4, 4: 16}.get(kind)
        if kind == 3:
            length = read_exact(connection, 1, deadline, stop)[0]
        if not length:
            raise ProtocolError("Invalid SOCKS destination response")
        read_exact(connection, length + 2, deadline, stop)
        keepalive(connection)
        return connection
    except BaseException:
        connection.close()
        raise


class Sockets:
    """Close blocked I/O promptly on shutdown, including worker connections."""

    def __init__(self, stop):
        self.stop = stop
        self.lock = threading.RLock()
        self.values = set()

    def add(self, connection):
        with self.lock:
            if self.stop.is_set():
                connection.close()
                raise InterruptedError("Transport is stopping")
            self.values.add(connection)
        return connection

    def remove(self, connection):
        with self.lock:
            self.values.discard(connection)
        connection.close()

    def close(self):
        self.stop.set()
        with self.lock:
            values = tuple(self.values)
            self.values.clear()
        for connection in values:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()


def relay(connection, udp, *, client=False, stop=None, idle_seconds=IDLE_SECONDS):
    """Forward bounded frames independently in both directions.

    Each direction holds at most one datagram. A partial incoming frame never
    blocks outgoing UDP, and a congested TCP send never blocks incoming data.
    Kernel socket queues provide backpressure; no unbounded Python queue exists.
    """
    stop = threading.Event() if stop is None else stop
    connection.setblocking(False)
    udp.setblocking(False)
    peer = None
    last_activity = time.monotonic()
    incoming = bytearray()
    expected = 2
    receive_deadline = None
    pending_udp = None
    outgoing = b""
    sent = 0
    send_deadline = None
    while not stop.is_set():
        deadlines = [last_activity + idle_seconds]
        if receive_deadline is not None:
            deadlines.append(receive_deadline)
        if send_deadline is not None:
            deadlines.append(send_deadline)
        deadline = min(deadlines)
        readers = ([connection] if pending_udp is None else []) + ([udp] if not outgoing else [])
        writers = ([connection] if outgoing else []) + ([udp] if pending_udp is not None else [])
        readable, writable, _ = select.select(readers, writers, (), min(.5, _remaining(deadline)))
        if stop.is_set():
            return
        if connection in writable:
            try:
                count = connection.send(memoryview(outgoing)[sent:])
            except BlockingIOError:
                count = None
            if count == 0:
                raise OSError("Framed TCP send closed")
            if count is not None:
                sent += count
                if sent == len(outgoing):
                    outgoing, sent, send_deadline = b"", 0, None
                    last_activity = time.monotonic()
        if udp in writable:
            try:
                count = udp.sendto(pending_udp, peer) if client else udp.send(pending_udp)
            except BlockingIOError:
                count = None
            if count is not None:
                if count != len(pending_udp):
                    raise OSError("Incomplete UDP write")
                pending_udp, receive_deadline = None, None
                last_activity = time.monotonic()
        if connection in readable:
            try:
                data = connection.recv(expected - len(incoming))
            except BlockingIOError:
                data = None
            if data == b"":
                if incoming:
                    raise ProtocolError("Incomplete framed datagram")
                return
            if data:
                if receive_deadline is None:
                    receive_deadline = time.monotonic() + idle_seconds
                incoming.extend(data)
                if len(incoming) == 2 and expected == 2:
                    length = struct.unpack("!H", incoming)[0]
                    if not 1 <= length <= MAX_DATAGRAM:
                        raise ProtocolError("Invalid framed datagram length")
                    expected += length
                elif len(incoming) == expected:
                    payload = bytes(incoming[2:])
                    incoming.clear()
                    expected = 2
                    if client and peer is None:
                        # An unsolicited reply cannot select the client's peer.
                        receive_deadline = None
                    else:
                        pending_udp = payload
        if udp in readable:
            try:
                if client:
                    payload, sender = udp.recvfrom(MAX_DATAGRAM + 1)
                else:
                    payload, sender = udp.recv(MAX_DATAGRAM + 1), None
            except BlockingIOError:
                continue
            if stop.is_set():
                return
            if client:
                if not isinstance(sender, tuple) or len(sender) != 2:
                    raise ProtocolError("Invalid local UDP peer")
                if sender[0] != LOOPBACK or (peer is not None and sender != peer):
                    continue
            if not 1 <= len(payload) <= MAX_DATAGRAM:
                raise ProtocolError("Invalid local UDP datagram length")
            if client and peer is None:
                peer = sender
            outgoing = struct.pack("!H", len(payload)) + payload
            sent = 0
            send_deadline = time.monotonic() + idle_seconds


def serve_client(listen_port=WG_ENDPOINT_PORT, socks_port=SOCKS_PORT, remote_port=WG_STREAM_PORT,
                 stop=None, sockets=None):
    stop = threading.Event() if stop is None else stop
    sockets = Sockets(stop) if sockets is None else sockets
    udp = sockets.add(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
    connection = None
    try:
        udp.bind((LOOPBACK, port(listen_port)))
        connection = sockets.add(socks_connect(socks_port, remote_port, stop))
        print("framed client ready", flush=True)
        relay(connection, udp, client=True, stop=stop)
    finally:
        if connection is not None:
            sockets.remove(connection)
        sockets.remove(udp)


def serve_server(listen_port=WG_STREAM_PORT, udp_port=WG_SERVER_PORT, *, stop=None, sockets=None):
    port(listen_port)
    port(udp_port)
    stop = threading.Event() if stop is None else stop
    sockets = Sockets(stop) if sockets is None else sockets
    listener = sockets.add(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    limiter = threading.BoundedSemaphore(MAX_CONNECTIONS)
    workers = set()
    workers_lock = threading.Lock()

    def worker(connection):
        udp = None
        try:
            keepalive(connection)
            udp = sockets.add(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            udp.connect((LOOPBACK, udp_port))
            relay(connection, udp, stop=stop)
        except (OSError, ValueError) as error:
            if not stop.is_set():
                print("framed connection stopped (" + type(error).__name__ + ")", flush=True)
        finally:
            if udp is not None:
                sockets.remove(udp)
            sockets.remove(connection)
            limiter.release()
            with workers_lock:
                workers.discard(threading.current_thread())

    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((LOOPBACK, listen_port))
        listener.listen(MAX_CONNECTIONS)
        listener.settimeout(.5)
        print("framed server ready", flush=True)
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            if not limiter.acquire(blocking=False):
                connection.close()
                continue
            sockets.add(connection)
            thread = threading.Thread(target=worker, args=(connection,), daemon=True)
            with workers_lock:
                workers.add(thread)
            thread.start()
    finally:
        sockets.close()
        with workers_lock:
            active = tuple(workers)
        for thread in active:
            thread.join(timeout=2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    client = commands.add_parser("client")
    client.add_argument("--listen-port", type=int, default=WG_ENDPOINT_PORT)
    client.add_argument("--socks-port", type=int, default=SOCKS_PORT)
    client.add_argument("--remote-port", type=int, default=WG_STREAM_PORT)
    server = commands.add_parser("server")
    server.add_argument("--listen-port", type=int, default=WG_STREAM_PORT)
    server.add_argument("--udp-port", type=int, default=WG_SERVER_PORT)
    args = parser.parse_args()
    stop = threading.Event()
    sockets = Sockets(stop)

    def shutdown(signum, frame):
        sockets.close()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    try:
        if args.mode == "client":
            serve_client(args.listen_port, args.socks_port, args.remote_port,
                         stop=stop, sockets=sockets)
        else:
            serve_server(args.listen_port, args.udp_port, stop=stop, sockets=sockets)
        return 0
    except (OSError, ValueError) as error:
        if not stop.is_set():
            print("framed transport stopped (" + type(error).__name__ + ")", flush=True)
            return 1
        return 0
    finally:
        sockets.close()


if __name__ == "__main__":
    raise SystemExit(main())
