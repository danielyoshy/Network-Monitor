"""Network interface inspection + traffic classification.

Adapted from Sniffnet's `networking` module (Rust): `MyDevice` keeps the
inspected adapter's addresses in sync so direction tagging stays correct when
the host's IP changes (VPN up/down, DHCP renew), and `get_traffic_direction` /
`get_traffic_type` / `is_local_connection` classify each packet against those
addresses. Ported here to Scapy's route tables.

Design notes carried over from Sniffnet:
  * Addresses are re-read periodically (`refresh()`), not just once at startup —
    Sniffnet calls `set_addresses()` every second in its capture loop.
  * Direction handles the awkward cases the naive "src in local set" misses:
    loopback-to-loopback (decided by port ordering), and an unspecified source
    (0.0.0.0 / ::) before the stack has been assigned an address.
  * `is_local_connection` uses the interface netmask to tell a LAN peer (same
    subnet or link-local) from an internet host.

Reads are lock-free: `refresh()` builds new immutable snapshots and swaps them
in with a single atomic attribute assignment, so the sniffer thread never sees
a half-updated table.
"""
import ipaddress
import socket

from scapy.all import conf

# Direction is represented as a bool `outgoing` (True) / incoming (False),
# matching Sniffnet's TrafficDirection { Outgoing, Incoming }.
UNICAST, MULTICAST, BROADCAST = "unicast", "multicast", "broadcast"

_V4_UNSPECIFIED = "0.0.0.0"
_V6_UNSPECIFIED = "::"
_V4_BROADCAST = "255.255.255.255"


class InterfaceInspector:
    """Snapshot of this host's interface addressing, refreshed on demand."""

    def __init__(self):
        # Immutable snapshots, replaced wholesale by refresh() (atomic swap).
        self._local_ips = frozenset({"127.0.0.1", "::1"})
        self._subnets = ()          # tuple[ip_network] of directly-connected nets
        self._broadcasts = frozenset()
        self.refresh()

    # -- inspection -----------------------------------------------------------

    def refresh(self):
        """Re-read the OS route tables and rebuild the addressing snapshot.

        Mirrors Sniffnet re-reading adapter addresses each second so a changed
        host IP (VPN, DHCP) doesn't silently flip every flow's direction.
        """
        local = {"127.0.0.1", "::1"}
        subnets = []
        broadcasts = set()

        try:
            conf.route.resync()
        except Exception:
            pass
        self._read_ipv4(local, subnets, broadcasts)
        self._read_ipv6(local, subnets)

        # Fallback: if the route table told us nothing, probe the primary
        # outbound address the way the old discover_local_ips() did.
        if len(local) <= 2:
            local |= _probe_local_ips()

        # Atomic swaps — readers see either the whole old or whole new snapshot.
        self._local_ips = frozenset(local)
        self._subnets = tuple({str(n): n for n in subnets}.values())  # dedup
        self._broadcasts = frozenset(broadcasts)

    @staticmethod
    def _is_real_subnet(network):
        """A subnet worth treating as LAN — not the multicast/loopback ranges
        that also appear as on-link routes in the OS table."""
        return not (network.is_multicast or network.is_loopback)

    def _read_ipv4(self, local, subnets, broadcasts):
        try:
            routes = list(conf.route.routes)
        except Exception:
            return
        for net, mask, gw, _iface, outip, _metric in routes:
            if outip and outip != _V4_UNSPECIFIED:
                local.add(outip)
            # A directly-connected subnet (not the default route, not a /32
            # host route) — gateway 0.0.0.0 means "on-link".
            if gw == _V4_UNSPECIFIED and 0 < mask < 0xFFFFFFFF:
                try:
                    prefix = bin(mask).count("1")
                    network = ipaddress.ip_network(
                        (net & mask, prefix), strict=False)
                    if self._is_real_subnet(network):
                        subnets.append(network)
                        broadcasts.add(str(network.broadcast_address))
                except ValueError:
                    continue

    def _read_ipv6(self, local, subnets):
        try:
            routes = list(conf.route6.routes)
        except Exception:
            return
        for entry in routes:
            try:
                net, plen, gw, _iface, addrs, _metric = entry
            except (ValueError, TypeError):
                continue
            for addr in addrs or ():
                if addr and addr != _V6_UNSPECIFIED:
                    local.add(addr)
            if plen == 128 and net not in (_V6_UNSPECIFIED, "::1"):
                local.add(net)
            if gw == _V6_UNSPECIFIED and 0 < plen < 128 and net != _V6_UNSPECIFIED:
                try:
                    network = ipaddress.ip_network((net, plen), strict=False)
                except ValueError:
                    continue
                if self._is_real_subnet(network):
                    subnets.append(network)

    # -- membership tests -----------------------------------------------------

    @property
    def local_ips(self):
        return self._local_ips

    def is_local_ip(self, ip):
        """True if `ip` is one of this host's own interface addresses."""
        return ip in self._local_ips

    def is_lan(self, ip):
        """True if `ip` is a LAN peer: link-local, or inside a connected subnet.

        Port of Sniffnet's `is_local_connection`.
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if addr.is_link_local:
            return True
        return any(addr in net for net in self._subnets)

    def is_broadcast(self, ip):
        return ip == _V4_BROADCAST or ip in self._broadcasts

    @staticmethod
    def is_multicast(ip):
        try:
            return ipaddress.ip_address(ip).is_multicast
        except ValueError:
            return False

    # -- classification (ported from manage_packets.rs) -----------------------

    def get_traffic_direction(self, src_ip, dst_ip, src_port, dst_port):
        """Return True if the packet is outgoing (host is the source).

        Direct port of Sniffnet's `get_traffic_direction`, including the
        loopback and unspecified-address special cases.
        """
        # Loopback-to-loopback: the higher (ephemeral) port is the client, so
        # it's the outgoing side.
        if (_is_loopback(src_ip) and _is_loopback(dst_ip)
                and src_port and dst_port):
            return src_port > dst_port

        if self.is_local_ip(src_ip):
            return True                              # source is us -> outgoing
        if src_ip not in (_V4_UNSPECIFIED, _V6_UNSPECIFIED):
            return False                             # remote source -> incoming
        # Source is 0.0.0.0/:: (no local IP yet); outgoing iff dest isn't local.
        return not self.is_local_ip(dst_ip)

    def get_traffic_type(self, dst_ip, outgoing):
        """Classify the remote endpoint as unicast / multicast / broadcast.

        Port of Sniffnet's `get_traffic_type` — only meaningful for outgoing
        traffic (an incoming packet reached us, so from our side it's unicast).
        """
        if not outgoing:
            return UNICAST
        if self.is_multicast(dst_ip):
            return MULTICAST
        if self.is_broadcast(dst_ip):
            return BROADCAST
        return UNICAST


def _is_loopback(ip):
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def _probe_local_ips():
    """Fallback local-IP discovery (no route table available)."""
    ips = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ips.add(info[4][0])
    except socket.gaierror:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # no packets actually sent
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    return ips
