"""5-tuple flow aggregation with 1-second rolling metrics.

The sniffer thread calls `add_packet()` for every captured frame (hot path,
must be cheap). An aggregator calls `tick()` once per second to roll up the
interval counters into throughput figures and produce a UI snapshot.

Flows are keyed *bidirectionally*: A->B and B->A collapse into one Flow so a
conversation (e.g. one HTTPS stream) is a single row. Direction, traffic type
(unicast/multicast/broadcast) and LAN-vs-internet scope are decided per packet
by the InterfaceInspector, which classifies each endpoint against the host's
live interface addressing (ported from Sniffnet's manage_packets logic).
"""
import threading
import time

from backend import config, labels
from backend.enrichment import enricher
from backend.interfaces import InterfaceInspector

# Transport protocol numbers we label; everything else shows its number/name.
# -1 is the sniffer's ARP sentinel (ARP has no L4 transport).
_PROTO_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6", -1: "ARP"}


class Flow:
    """One bidirectional conversation, identified by its canonical 5-tuple."""

    __slots__ = (
        "proto", "app_proto", "local_ip", "local_port", "remote_ip",
        "remote_port", "traffic_type", "is_lan", "first_seen", "last_seen",
        "up_bytes", "down_bytes", "up_packets", "down_packets",
        "_iv_up", "_iv_down", "up_bps", "down_bps",
        "peak_up_bps", "peak_down_bps",
    )

    def __init__(self, proto, app_proto, local_ip, local_port, remote_ip,
                 remote_port, traffic_type, is_lan, now):
        self.proto = proto
        self.app_proto = app_proto
        self.local_ip = local_ip
        self.local_port = local_port
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.traffic_type = traffic_type
        self.is_lan = is_lan
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
        # Live interface addressing; refreshed each tick (see refresh_interfaces).
        self.inspector = InterfaceInspector()
        # Cumulative, never reset (folded totals of expired flows + live ones).
        self._closed_up_bytes = 0
        self._closed_down_bytes = 0
        self._peak_up_bps = 0
        self._peak_down_bps = 0

    @property
    def local_ips(self):
        """This host's interface addresses (kept for callers/tests)."""
        return self.inspector.local_ips

    def refresh_interfaces(self):
        """Re-read interface addressing. Called once per tick, mirroring
        Sniffnet refreshing adapter addresses every second."""
        self.inspector.refresh()

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

        # Classify direction/type against live interface addressing (Sniffnet
        # manage_packets logic ported into InterfaceInspector).
        insp = self.inspector
        outgoing = insp.get_traffic_direction(src_ip, dst_ip, src_port, dst_port)
        if outgoing:
            local_ip, local_port = src_ip, src_port
            remote_ip, remote_port = dst_ip, dst_port
        else:
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
                    local_ip, local_port, remote_ip, remote_port,
                    insp.get_traffic_type(dst_ip, outgoing),
                    insp.is_lan(remote_ip),
                    now,
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
                    "traffic_type": flow.traffic_type,
                    "is_lan": flow.is_lan,
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

        hosts = self._group_by_host(entries)

        return {
            "timestamp": now,
            "global": {
                "upload_bps": round(up_bps),
                "download_bps": round(down_bps),
                "peak_upload_bps": round(self._peak_up_bps),
                "peak_download_bps": round(self._peak_down_bps),
                "active_flows": active_flows,
                "active_hosts": len(hosts),
                "total_up_bytes": self._closed_up_bytes + live_up,
                "total_down_bytes": self._closed_down_bytes + live_down,
                "truncated_flows": truncated,
            },
            "protocols": protocols,
            "hosts": hosts,
            "flows": entries,
        }

    def _group_by_host(self, entries):
        """Collapse per-flow entries into one row per remote host (IP).

        This is what makes the dashboard readable: instead of the same peer
        appearing once per port/protocol, each host is a single labelled row
        with its totals, the apps it's talking, and its individual connections
        nested for drill-down.
        """
        insp = self.inspector
        hosts = {}
        for e in entries:
            ip = e["remote_ip"]
            h = hosts.get(ip)
            if h is None:
                label = labels.describe(
                    ip,
                    is_self=insp.is_local_ip(ip),
                    is_gateway=insp.is_gateway(ip),
                    is_lan=e["is_lan"],
                    traffic_type=e["traffic_type"],
                    hostname=e["hostname"],
                    org=e["org"],
                )
                h = {
                    "ip": ip,
                    "name": label["name"],
                    "category": label["category"],
                    "hostname": e["hostname"],
                    "country": e["country"],
                    "asn": e["asn"],
                    "org": e["org"],
                    "is_lan": e["is_lan"],
                    "traffic_type": e["traffic_type"],
                    "up_bytes": 0, "down_bytes": 0,
                    "up_bps": 0, "down_bps": 0,
                    "packets": 0,
                    "apps": {},          # app_proto -> connection count
                    "connections": [],   # per-flow detail for the drawer
                }
                hosts[ip] = h
            h["up_bytes"] += e["up_bytes"]
            h["down_bytes"] += e["down_bytes"]
            h["up_bps"] += e["up_bps"]
            h["down_bps"] += e["down_bps"]
            h["packets"] += e["packets"]
            h["apps"][e["app_proto"]] = h["apps"].get(e["app_proto"], 0) + 1
            h["connections"].append({
                "app_proto": e["app_proto"],
                "proto": e["proto"],
                "remote_port": e["remote_port"],
                "local_ip": e["local_ip"],
                "up_bps": e["up_bps"], "down_bps": e["down_bps"],
                "up_bytes": e["up_bytes"], "down_bytes": e["down_bytes"],
                "packets": e["packets"],
            })
            # A late-arriving reverse-DNS name should upgrade a "Local device"
            # / bare-IP label without waiting for the flow to be re-created.
            if e["hostname"] and h["name"] in ("Local device", ip):
                h["name"] = e["hostname"]

        host_list = list(hosts.values())
        for h in host_list:
            h["apps"] = sorted(h["apps"], key=h["apps"].get, reverse=True)
            h["flow_count"] = len(h["connections"])
            ports = [c["remote_port"] for c in h["connections"]]
            h["role"] = labels.classify_role(
                h["ip"], h["category"], h["is_lan"], ports, h["hostname"],
            )
            # Primary user-facing Category + subtitle (the "Service/Host" name
            # is h["name"], already set above).
            h["service_category"], h["service_subtitle"] = labels.classify_service(
                h["ip"], h["category"], h["is_lan"], ports, h["hostname"],
            )
        host_list.sort(key=lambda h: h["up_bps"] + h["down_bps"]
                       + (h["up_bytes"] + h["down_bytes"]) / 1e9, reverse=True)
        return host_list


# Process-wide singleton shared by the sniffer and the API.
flow_table = FlowTable()
