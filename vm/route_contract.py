"""The fixed private packet route used by the host, gateway and owned VPS.

These are internal protocol values, not user settings. Public destinations,
credentials and the selected exit belong to the shared private host route.
"""

SOCKS_PORT = 15080

GUEST_POOL = "10.77.0.0/24"
MAX_GUESTS = 64
GUEST_IP = "10.77.0.2"
GUEST_DNS = "1.1.1.1"

WG_INTERFACE = "wg0"
WG_CLIENT_ADDRESS = "10.78.0.2/30"
WG_SERVER_IP = "10.78.0.1"
WG_ENDPOINT_PORT = 51821
WG_SERVER_PORT = 51820
WG_STREAM_PORT = 51822
WG_MTU = 1500

ROUTE_MARK = 0x71
MANAGEMENT_MARK = 0x72
ROUTE_TABLE = 177
LEASE_SECONDS = 30
GATEWAY_NFT_TABLE = "lemon_vm"
BLOCKED_IPV4 = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4",
)


def packet_settings():
    """Return generated gateway settings; callers add only the two keys."""
    return {
        "client_address": WG_CLIENT_ADDRESS,
        "server_address": WG_SERVER_IP,
        "endpoint_port": WG_ENDPOINT_PORT,
        "transport": "stream",
        "stream_port": WG_STREAM_PORT,
        "mtu": WG_MTU,
    }
