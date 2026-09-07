"""5-tuple flow aggregation with 1-second rolling metrics.

The sniffer thread calls `add_packet()` for every captured frame (hot path,
must be cheap). An aggregator calls `tick()` once per second to roll up the
interval counters into throughput figures and produce a UI snapshot.

Flows are keyed *bidirectionally*: A->B and B->A collapse into one Flow so a
conversation (e.g. one HTTPS stream) is a single row. Direction is decided per
packet by comparing against the host's local IPs, which lets us split traffic
into upload (host is source) and download (host is destination).
"""
import ipaddress
import socket
import threading
import time

from backend import config
from backend.enrichment import enricher

# Transport protocol numbers we label; everything else shows its number/name.
# -1 is the sniffer's ARP sentinel (ARP has no L4 transport).
_PROTO_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6", -1: "ARP"}


def discover_local_ips():
    """Best-effort set of this host's own IP addresses.

    Used for direction tagging. Loopback is always included; the primary
    outbound address is discovered by opening a UDP socket (no packets sent).
    """
    ips = {"127.0.0.1", "::1"}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ips.add(info[4][0])
    except socket.gaierror:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # never actually transmits
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    return ips


class Flow:
    """One bidirectional conversation, identified by its canonical 5-tuple."""

    __slots__ = (
        "proto", "app_proto", "local_ip", "local_port", "remote_ip",
        "remote_port", "first_seen", "last_seen",
        "up_bytes", "down_bytes", "up_packets", "down_packets",
        "_iv_up", "_iv_down", "up_bps", "down_bps",
        "peak_up_bps", "peak_down_bps",
    )

    def __init__(self, proto, app_proto, local_ip, local_port, remote_ip, remote_port, now):
        self.proto = proto
        self.app_proto = app_proto
        self.local_ip = local_ip
        self.local_port = local_port
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.first_seen = now
        self.last_seen = now
        self.up_bytes = self.down_bytes = 0
        self.up_packets = self.down_packets = 0
        # Interval accumulators, drained and zeroed every tick.
        self._iv_up = self._iv_down = 0
        self.up_bps = self.down_bps = 0
        self.peak_up_bps = self.peak_down_bps = 0

    def record(self, length, outgoing, now):
        self.last_seen = now
        if outgoing:
            self.up_bytes += length
            self.up_packets += 1
            self._iv_up += length
        else:
            self.down_bytes += length
            self.down_packets += 1
            self._iv_down += length

    def roll(self, window):
        """Convert this interval's byte counts into a throughput rate."""
        self.up_bps = self._iv_up / window
        self.down_bps = self._iv_down / window
        self.peak_up_bps = max(self.peak_up_bps, self.up_bps)
        self.peak_down_bps = max(self.peak_down_bps, self.down_bps)
        self._iv_up = self._iv_down = 0


class FlowTable:
    """Thread-safe registry of active flows plus cumulative global counters."""

    def __init__(self):
        self._lock = threading.Lock()
        self._flows = {}  # canonical key -> Flow
        self.local_ips = discover_local_ips()
        # Cumulative, never reset (folded totals of expired flows + live ones).
        self._closed_up_bytes = 0
        self._closed_down_bytes = 0
        self._peak_up_bps = 0
        self._peak_down_bps = 0

    @staticmethod
    def _key(src_ip, src_port, dst_ip, dst_port, proto):
        """Direction-independent key: sort the two endpoints so both ways match."""
        a = (src_ip, src_port)
        b = (dst_ip, dst_port)
        return (a, b, proto) if a <= b else (b, a, proto)

    def add_packet(self, pkt):
        """Hot path. `pkt` is the dict produced by the sniffer's parser."""
        src_ip, dst_ip = pkt["src_ip"], pkt["dst_ip"]
        src_port, dst_port = pkt["src_port"], pkt["dst_port"]
        proto = pkt["proto"]
        length = pkt["length"]
        now = pkt["timestamp"]

        outgoing = src_ip in self.local_ips
        if outgoing or dst_ip in self.local_ips:
            # Normal case: one endpoint is us. Remote is the other side.
            if outgoing:
                local_ip, local_port = src_ip, src_port
                remote_ip, remote_port = dst_ip, dst_port
            else:
                local_ip, local_port = dst_ip, dst_port
                remote_ip, remote_port = src_ip, src_port
        else:
            # Neither endpoint is local (mirrored/forwarded traffic): treat the
            # source as remote and count it as inbound so it still shows up.
            local_ip, local_port = dst_ip, dst_port
            remote_ip, remote_port = src_ip, src_port

        key = self._key(src_ip, src_port, dst_ip, dst_port, proto)
        proto_name = _PROTO_NAMES.get(proto, str(proto))

        with self._lock:
            flow = self._flows.get(key)
            if flow is None:
                from backend.enrichment import app_protocol
                flow = Flow(
                    proto_name,
                    app_protocol(src_port, dst_port, proto_name),
                    local_ip, local_port, remote_ip, remote_port, now,
                )
                self._flows[key] = flow
            flow.record(length, outgoing, now)

    def tick(self, window):
        """Roll all flows, expire idle ones, and build a UI snapshot."""
        now = time.time()
        up_bps = down_bps = 0
        entries = []

        with self._lock:
            expired = []
            for key, flow in self._flows.items():
                flow.roll(window)
                up_bps += flow.up_bps
                down_bps += flow.down_bps

                if now - flow.last_seen > config.FLOW_IDLE_TIMEOUT:
                    self._closed_up_bytes += flow.up_bytes
                    self._closed_down_bytes += flow.down_bytes
                    expired.append(key)
                    continue

                meta = enricher.enrich(flow.remote_ip)
                entries.append({
                    "key": f"{flow.remote_ip}:{flow.remote_port}/{flow.proto}",
                    "proto": flow.proto,
                    "app_proto": flow.app_proto,
                    "local_ip": flow.local_ip,
                    "remote_ip": flow.remote_ip,
                    "remote_port": flow.remote_port,
                    "hostname": meta["hostname"],
                    "country": meta["country"],
                    "asn": meta["asn"],
                    "org": meta["org"],
                    "up_bytes": flow.up_bytes,
                    "down_bytes": flow.down_bytes,
                    "up_bps": round(flow.up_bps),
                    "down_bps": round(flow.down_bps),
                    "packets": flow.up_packets + flow.down_packets,
                    "last_seen": flow.last_seen,
                })

            for key in expired:
                del self._flows[key]

            active_flows = len(self._flows)
            live_up = sum(f.up_bytes for f in self._flows.values())
            live_down = sum(f.down_bytes for f in self._flows.values())

        self._peak_up_bps = max(self._peak_up_bps, up_bps)
        self._peak_down_bps = max(self._peak_down_bps, down_bps)

        # Busiest flows first, capped so a flood can't bloat the frame.
        entries.sort(key=lambda e: e["up_bps"] + e["down_bps"]
                     + (e["up_bytes"] + e["down_bytes"]) / 1e9, reverse=True)
        truncated = max(0, len(entries) - config.MAX_FLOWS_PER_TICK)
        entries = entries[:config.MAX_FLOWS_PER_TICK]

        # Protocol distribution across the visible flows.
        protocols = {}
        for e in entries:
            protocols[e["app_proto"]] = protocols.get(e["app_proto"], 0) + 1

        return {
            "timestamp": now,
            "global": {
                "upload_bps": round(up_bps),
                "download_bps": round(down_bps),
                "peak_upload_bps": round(self._peak_up_bps),
                "peak_download_bps": round(self._peak_down_bps),
                "active_flows": active_flows,
                "total_up_bytes": self._closed_up_bytes + live_up,
                "total_down_bytes": self._closed_down_bytes + live_down,
                "truncated_flows": truncated,
            },
            "protocols": protocols,
            "flows": entries,
        }


# Process-wide singleton shared by the sniffer and the API.
flow_table = FlowTable()
