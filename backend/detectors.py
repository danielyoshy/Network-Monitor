"""Live network-anomaly detection engine.

Four detectors, each a direct implementation of a technique from the
Anthropic-Cybersecurity-Skills playbooks, adapted to run in real time over the
capture path instead of over batch logs:

  * BeaconDetector   -> hunting-for-beaconing-with-frequency-analysis
                        (coefficient-of-variation on connection intervals; CV<0.20
                        indicates periodic C2 callbacks, MITRE T1071)
  * PortScanDetector -> detecting-port-scanning-with-fail2ban
                        (one source touching many distinct ports in a window, T1046)
  * DnsExfilDetector -> detecting-dns-exfiltration-with-dns-query-analysis
                        (Shannon entropy + subdomain length + uniqueness scoring, T1048)
  * ArpAnomalyDetector -> detecting-arp-poisoning-in-network-traffic
                        (IP->MAC change / flip-flop / flood, T1557.002)

`observe()` runs on the sniffer's hot path and only does cheap bookkeeping under
a lock. `evaluate()` runs once per aggregation tick, computes the statistical
verdicts, expires stale state, and returns the active alert list for the UI.
"""
import math
import statistics
import time
from collections import defaultdict, deque

from backend import config

# DNS qtype number -> name (only the ones the exfil heuristic cares about).
_QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR",
           15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits — verbatim from the DNS-exfil skill."""
    if not s:
        return 0.0
    freq = defaultdict(int)
    for ch in s:
        freq[ch] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _base_domain(qname: str) -> str:
    parts = qname.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else qname


def _subdomain(qname: str) -> str:
    parts = qname.rstrip(".").split(".")
    return ".".join(parts[:-2]) if len(parts) > 2 else ""


class DetectionEngine:
    """Thread-safe. One process-wide instance, shared by sniffer and API."""

    def __init__(self, inspector):
        # Shared InterfaceInspector — its is_local_ip() reflects live addressing.
        self.inspector = inspector
        import threading
        self._lock = threading.Lock()

        # Beaconing: remote_ip -> deque[connection timestamps]; last packet ts.
        self._beacon_conns = defaultdict(lambda: deque(maxlen=200))
        self._beacon_last = {}

        # Port scan: src_ip -> deque[(ts, dst_ip, dst_port)]
        self._scan = defaultdict(lambda: deque(maxlen=2000))

        # DNS exfil: base_domain -> rolling stats
        self._dns = defaultdict(lambda: {
            "queries": 0, "sub_len_sum": 0, "entropy_sum": 0.0,
            "unique_subs": set(), "txt": 0, "src_ips": set(), "last": 0.0,
        })

        # ARP: ip -> mac; ip -> deque[(mac, ts)]; mac -> deque[ts] (flood)
        self._arp_table = {}
        self._arp_hist = defaultdict(lambda: deque(maxlen=50))
        self._arp_rate = defaultdict(lambda: deque(maxlen=500))

        # Event-driven alerts (ARP) accumulate here; statistical alerts are
        # recomputed each tick. Keyed by (type, entity) for dedup.
        self._event_alerts = {}

    # ---- hot path -----------------------------------------------------------

    def observe(self, pkt):
        """Cheap per-packet bookkeeping. Called from the sniffer thread."""
        now = pkt["timestamp"]
        proto = pkt["proto"]
        src_ip, dst_ip = pkt["src_ip"], pkt["dst_ip"]

        with self._lock:
            # --- ARP (proto sentinel -1) ---
            if proto == -1:
                self._observe_arp(src_ip, pkt.get("src_mac", ""), now)
                return

            is_local = self.inspector.is_local_ip
            # --- Beaconing: outbound re-contacts to a remote host ---
            if is_local(src_ip) and not is_local(dst_ip):
                remote = dst_ip
                last = self._beacon_last.get(remote)
                if last is None or (now - last) >= config.BEACON_MIN_GAP:
                    self._beacon_conns[remote].append(now)
                self._beacon_last[remote] = now

            # --- Port scan: a source hitting many of our ports ---
            dst_port = pkt["dst_port"]
            if dst_port and is_local(dst_ip):
                self._scan[src_ip].append((now, dst_ip, dst_port))

            # --- DNS exfil: outbound DNS queries ---
            qname = pkt.get("dns_qname")
            if qname:
                self._observe_dns(src_ip, qname, pkt.get("dns_qtype", 0), now)

    def _observe_arp(self, ip, mac, now):
        if not mac or not ip or ip in ("0.0.0.0", ""):
            return
        mac = mac.lower()

        # Gateway impersonation (only if operator pinned the gateway).
        if config.GATEWAY_IP and ip == config.GATEWAY_IP and mac != config.GATEWAY_MAC:
            self._raise("arp-gateway", ip, "CRITICAL",
                        f"Gateway {ip} claimed by unexpected MAC {mac}",
                        [f"expected={config.GATEWAY_MAC}", f"seen={mac}"], now)

        # IP -> MAC change.
        known = self._arp_table.get(ip)
        if known and known != mac:
            self._raise("arp-change", ip, "HIGH",
                        f"IP {ip} moved from MAC {known} to {mac}",
                        [f"previous={known}", f"new={mac}"], now)
        self._arp_table[ip] = mac

        # Flip-flop: >2 distinct MACs for one IP within 60s.
        hist = self._arp_hist[ip]
        hist.append((mac, now))
        recent = [m for m, ts in hist if now - ts <= 60]
        if len(set(recent)) > 2:
            self._raise("arp-flipflop", ip, "CRITICAL",
                        f"IP {ip} flip-flopping across {len(set(recent))} MACs (active MITM)",
                        list(set(recent)), now)

        # Flood: many ARP frames from one MAC within the window.
        rate = self._arp_rate[mac]
        rate.append(now)
        recent_n = sum(1 for ts in rate if now - ts <= config.ARP_FLOOD_WINDOW)
        if recent_n > config.ARP_FLOOD_THRESHOLD:
            self._raise("arp-flood", mac, "MEDIUM",
                        f"ARP flood from {mac}: {recent_n} frames / {config.ARP_FLOOD_WINDOW:.0f}s",
                        [f"count={recent_n}"], now)

    def _observe_dns(self, src_ip, qname, qtype, now):
        base = _base_domain(qname)
        sub = _subdomain(qname)
        st = self._dns[base]
        st["queries"] += 1
        st["sub_len_sum"] += len(sub)
        st["entropy_sum"] += shannon_entropy(sub)
        st["unique_subs"].add(sub)
        st["src_ips"].add(src_ip)
        st["last"] = now
        if _QTYPES.get(qtype) in ("TXT", "NULL"):
            st["txt"] += 1

    def _raise(self, atype, entity, severity, message, indicators, now):
        """Record/refresh an event-driven alert (already holding the lock)."""
        key = (atype, entity)
        existing = self._event_alerts.get(key)
        if existing:
            existing["last_seen"] = now
            existing["count"] += 1
            existing["message"] = message
            existing["indicators"] = indicators
        else:
            self._event_alerts[key] = {
                "type": atype, "entity": entity, "severity": severity,
                "message": message, "indicators": indicators,
                "first_seen": now, "last_seen": now, "count": 1,
            }

    # ---- per-tick evaluation ------------------------------------------------

    def evaluate(self):
        """Compute statistical verdicts, expire stale state, return active alerts."""
        now = time.time()
        alerts = []

        with self._lock:
            alerts.extend(self._eval_beacons(now))
            alerts.extend(self._eval_scans(now))
            alerts.extend(self._eval_dns(now))

            # Merge event-driven alerts and drop ones past their TTL.
            for key, a in list(self._event_alerts.items()):
                if now - a["last_seen"] > config.ALERT_TTL:
                    del self._event_alerts[key]
                else:
                    alerts.append(dict(a))

        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        alerts.sort(key=lambda a: (sev_rank.get(a["severity"], 9),
                                   -a.get("score", 0)))
        return alerts

    def _eval_beacons(self, now):
        out = []
        for remote, conns in list(self._beacon_conns.items()):
            # Expire remotes that have gone quiet.
            if conns and now - conns[-1] > config.ALERT_TTL * 4:
                del self._beacon_conns[remote]
                self._beacon_last.pop(remote, None)
                continue
            if len(conns) < config.BEACON_MIN_CONNECTIONS:
                continue
            ts = list(conns)
            intervals = [b - a for a, b in zip(ts, ts[1:])]
            if len(intervals) < 2:
                continue
            mean = statistics.fmean(intervals)
            if not (config.BEACON_MIN_INTERVAL <= mean <= config.BEACON_MAX_INTERVAL):
                continue
            stdev = statistics.pstdev(intervals)
            cv = stdev / mean if mean else 999
            if cv < config.BEACON_MAX_CV:
                # Lower CV == more machine-like == higher score.
                score = min(100, int((1 - cv / config.BEACON_MAX_CV) * 60) + 40)
                out.append({
                    "type": "beacon", "entity": remote, "severity": "HIGH",
                    "message": f"Periodic callbacks to {remote} "
                               f"(~{mean:.1f}s interval, CV={cv:.2f})",
                    "indicators": [f"connections={len(ts)}", f"mean_interval={mean:.1f}s",
                                   f"cv={cv:.2f}"],
                    "score": score, "first_seen": ts[0], "last_seen": ts[-1], "count": len(ts),
                })
        return out

    def _eval_scans(self, now):
        out = []
        cutoff = now - config.SCAN_WINDOW
        for src, events in list(self._scan.items()):
            while events and events[0][0] < cutoff:
                events.popleft()
            if not events:
                del self._scan[src]
                continue
            ports = {p for _, _, p in events}
            hosts = {h for _, h, _ in events}
            if len(ports) >= config.SCAN_PORT_THRESHOLD or len(hosts) >= config.SCAN_HOST_THRESHOLD:
                score = min(100, 40 + len(ports) + 2 * len(hosts))
                kind = "horizontal (many hosts)" if len(hosts) >= config.SCAN_HOST_THRESHOLD \
                    else "vertical (many ports)"
                out.append({
                    "type": "portscan", "entity": src, "severity": "MEDIUM",
                    "message": f"Port scan from {src}: {len(ports)} ports across "
                               f"{len(hosts)} host(s) in {config.SCAN_WINDOW:.0f}s [{kind}]",
                    "indicators": [f"distinct_ports={len(ports)}", f"distinct_hosts={len(hosts)}"],
                    "score": score, "first_seen": events[0][0], "last_seen": events[-1][0],
                    "count": len(events),
                })
        return out

    def _eval_dns(self, now):
        out = []
        for base, st in list(self._dns.items()):
            if now - st["last"] > config.ALERT_TTL * 4:
                del self._dns[base]
                continue
            q = st["queries"]
            if q < config.DNS_MIN_QUERIES:
                continue
            avg_len = st["sub_len_sum"] / q
            avg_entropy = st["entropy_sum"] / q
            unique_ratio = len(st["unique_subs"]) / q
            txt_ratio = st["txt"] / q

            # Scoring lifted from the DNS-exfil skill.
            score, indicators = 0, []
            if avg_len > config.DNS_AVG_LEN_THRESHOLD:
                score += 25; indicators.append(f"avg_subdomain_len={avg_len:.1f}")
            if avg_entropy > config.DNS_ENTROPY_THRESHOLD:
                score += 25; indicators.append(f"avg_entropy={avg_entropy:.2f}")
            if unique_ratio > config.DNS_UNIQUE_RATIO_THRESHOLD:
                score += 20; indicators.append(f"unique_ratio={unique_ratio:.2f}")
            if txt_ratio > 0.3:
                score += 15; indicators.append(f"txt_ratio={txt_ratio:.2f}")
            if len(st["unique_subs"]) > 30:
                score += 15; indicators.append(f"unique_subdomains={len(st['unique_subs'])}")

            if score >= config.DNS_SCORE_THRESHOLD:
                out.append({
                    "type": "dns-exfil", "entity": base,
                    "severity": "CRITICAL" if score >= 80 else "HIGH",
                    "message": f"Possible DNS tunneling via {base} "
                               f"({q} queries, entropy {avg_entropy:.2f})",
                    "indicators": indicators, "score": min(score, 100),
                    "first_seen": st["last"], "last_seen": st["last"], "count": q,
                })
        return out


# Built lazily so it can share the FlowTable's live InterfaceInspector.
engine = None


def init_engine(inspector):
    global engine
    engine = DetectionEngine(inspector)
    return engine
