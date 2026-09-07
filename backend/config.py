"""Central configuration for the capture pipeline.

All tunables live here so the sniffer, enrichment layer, and API read from a
single source of truth. Environment variables override the defaults, which
keeps deployment-specific settings (interface, GeoIP paths) out of the code.
"""
import os

# --- Capture -----------------------------------------------------------------

# Network interface to capture on. None => Scapy's default interface.
INTERFACE = os.getenv("NM_INTERFACE") or None

# Berkeley Packet Filter applied at the kernel level, before packets ever reach
# user space. This is the cheapest place to drop traffic we do not care about.
# Default ignores loopback and multicast/mDNS noise; override with NM_BPF.
# Examples:
#   "tcp port 443"            -> only HTTPS
#   "not port 53"             -> everything except DNS
#   "host 1.2.3.4"            -> a single peer
BPF_FILTER = os.getenv("NM_BPF", "not host 127.0.0.1 and not port 5353")

# --- Aggregation -------------------------------------------------------------

# Rolling metrics window / broadcast cadence, in seconds.
EMIT_INTERVAL = float(os.getenv("NM_EMIT_INTERVAL", "1.0"))

# A flow with no packets for this many seconds is considered closed and dropped
# from the live table (its totals are already folded into the cumulative stats).
FLOW_IDLE_TIMEOUT = float(os.getenv("NM_FLOW_IDLE_TIMEOUT", "120"))

# Maximum number of flows sent to the UI per tick (busiest first). Prevents a
# scan/flood from ballooning each WebSocket frame.
MAX_FLOWS_PER_TICK = int(os.getenv("NM_MAX_FLOWS", "200"))

# --- Enrichment (MaxMind GeoLite2) -------------------------------------------

# Optional. Point these at GeoLite2-Country.mmdb / GeoLite2-ASN.mmdb to enable
# country + ASN resolution. If unset or missing, enrichment degrades silently.
GEOIP_COUNTRY_DB = os.getenv("NM_GEOIP_COUNTRY_DB", "")
GEOIP_ASN_DB = os.getenv("NM_GEOIP_ASN_DB", "")

# Reverse-DNS lookups run on a background thread pool; cap concurrency so a
# burst of new peers cannot spawn unbounded threads.
RDNS_WORKERS = int(os.getenv("NM_RDNS_WORKERS", "8"))
RDNS_TIMEOUT = float(os.getenv("NM_RDNS_TIMEOUT", "1.5"))

# --- Anomaly detection -------------------------------------------------------
# Thresholds for backend/detectors.py. Defaults mirror the values recommended
# in the Anthropic-Cybersecurity-Skills playbooks these detectors are based on.

# How long an alert stays "active" in the UI after its last trigger (seconds).
ALERT_TTL = float(os.getenv("NM_ALERT_TTL", "60"))

# C2 beaconing (coefficient-of-variation frequency analysis).
# A re-contact after this idle gap counts as a fresh "connection" event.
BEACON_MIN_GAP = float(os.getenv("NM_BEACON_MIN_GAP", "2.0"))
BEACON_MIN_CONNECTIONS = int(os.getenv("NM_BEACON_MIN_CONNECTIONS", "6"))
BEACON_MAX_CV = float(os.getenv("NM_BEACON_MAX_CV", "0.20"))     # <0.20 == periodic
BEACON_MIN_INTERVAL = float(os.getenv("NM_BEACON_MIN_INTERVAL", "1.0"))
BEACON_MAX_INTERVAL = float(os.getenv("NM_BEACON_MAX_INTERVAL", "3600"))

# Port scanning (distinct destination ports from one source in a window).
SCAN_WINDOW = float(os.getenv("NM_SCAN_WINDOW", "10"))
SCAN_PORT_THRESHOLD = int(os.getenv("NM_SCAN_PORT_THRESHOLD", "15"))
SCAN_HOST_THRESHOLD = int(os.getenv("NM_SCAN_HOST_THRESHOLD", "15"))

# DNS exfiltration (entropy / length / uniqueness scoring per base domain).
DNS_MIN_QUERIES = int(os.getenv("NM_DNS_MIN_QUERIES", "20"))
DNS_AVG_LEN_THRESHOLD = float(os.getenv("NM_DNS_AVG_LEN", "30"))
DNS_ENTROPY_THRESHOLD = float(os.getenv("NM_DNS_ENTROPY", "3.8"))
DNS_UNIQUE_RATIO_THRESHOLD = float(os.getenv("NM_DNS_UNIQUE_RATIO", "0.7"))
DNS_SCORE_THRESHOLD = int(os.getenv("NM_DNS_SCORE", "50"))

# ARP poisoning (IP-to-MAC change / flip-flop / flood).
ARP_FLOOD_WINDOW = float(os.getenv("NM_ARP_FLOOD_WINDOW", "10"))
ARP_FLOOD_THRESHOLD = int(os.getenv("NM_ARP_FLOOD_THRESHOLD", "50"))
# Optional: pin the gateway IP/MAC to catch gateway impersonation directly.
GATEWAY_IP = os.getenv("NM_GATEWAY_IP", "")
GATEWAY_MAC = os.getenv("NM_GATEWAY_MAC", "").lower()
