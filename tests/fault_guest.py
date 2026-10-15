"""Hold TCP/UDP flows across an operator-controlled external gateway fault."""
import json
import socket
import ssl
import struct
import sys


def dns_query():
    return struct.pack("!HHHHHH", 4317, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\0" + struct.pack("!HH", 1, 1)


def blocked(action):
    try:
        response = action()
        return not response
    except (OSError, ssl.SSLError):
        return True


def main():
    tcp = udp = None
    try:
        tcp = ssl.create_default_context().wrap_socket(socket.create_connection(("1.1.1.1", 443), timeout=10),
                                                      server_hostname="cloudflare-dns.com")
        tcp.settimeout(3)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(5)
        udp.connect(("1.1.1.1", 53))
        udp.send(dns_query())
        baseline_dns = udp.recv(4096)
        if len(baseline_dns) < 12 or baseline_dns[:2] != struct.pack("!H", 4317):
            raise OSError("baseline DNS failed")
        print(json.dumps({"ready": True, "tcp_established": True, "udp_roundtrip": True}), flush=True)
        if sys.stdin.readline().strip() != "CHECK":
            return 1
        def existing_tcp():
            tcp.sendall(b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: cloudflare-dns.com\r\nConnection: close\r\n\r\n")
            return tcp.recv(4096)
        def existing_udp():
            udp.settimeout(3)
            udp.send(dns_query())
            return udp.recv(4096)
        def new_tcp():
            with socket.create_connection(("1.1.1.1", 443), timeout=3):
                return b"connected"
        def new_udp():
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
                connection.settimeout(3)
                connection.connect(("1.0.0.1", 53))
                connection.send(dns_query())
                return connection.recv(4096)
        checks = {"existing_tcp_blocked": blocked(existing_tcp), "existing_udp_blocked": blocked(existing_udp),
                  "new_tcp_blocked": blocked(new_tcp), "new_udp_blocked": blocked(new_udp)}
        print(json.dumps({"passed": all(checks.values()), "checks": checks}), flush=True)
        return 0 if all(checks.values()) else 1
    except (OSError, ssl.SSLError):
        print(json.dumps({"ready": False, "error": "guest baseline connection failed"}), flush=True)
        return 1
    finally:
        if tcp is not None:
            tcp.close()
        if udp is not None:
            udp.close()


if __name__ == "__main__":
    sys.exit(main())
