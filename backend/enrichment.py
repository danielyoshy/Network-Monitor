"""Asynchronous metadata enrichment for remote IP addresses.

Three independent lookups, each cached and non-blocking to the capture path:

  * GeoIP  -> country code + ASN / organisation (MaxMind GeoLite2, optional)
  * rDNS   -> human-readable hostname (background thread pool)
  * app    -> layer-7 service guessed from the transport port

The FlowTable never waits on any of these. It asks for whatever is cached
*right now*; the first miss schedules the work and later ticks pick up the
result once it lands. This mirrors Sniffnet's "resolve in the background, fill
in the UI when ready" behaviour.
"""
import ipaddress
import socket
import threading
from concurrent.futures import ThreadPoolExecutor

from backend import config

# --- Application-protocol map -------------------------------------------------
# Well-known transport ports -> service label. Not exhaustive; covers the
# services a desktop actually generates. Either endpoint's port can match.
_PORT_APP = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 123: "NTP", 143: "IMAP", 161: "SNMP", 179: "BGP",
    443: "HTTPS", 465: "SMTPS", 514: "Syslog", 587: "SMTP", 636: "LDAPS",
    853: "DoT", 993: "IMAPS", 995: "POP3S", 1194: "OpenVPN", 1723: "PPTP",
    3306: "MySQL", 3389: "RDP", 5060: "SIP", 5061: "SIP-TLS", 5222: "XMPP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB", 51820: "WireGuard",
}


def app_protocol(src_port, dst_port, transport):
    """Best-effort layer-7 label from the 5-tuple's ports."""
    # QUIC / HTTP-3 rides UDP/443, so the generic 443->HTTPS map would mislabel it.
    if transport == "UDP" and (dst_port == 443 or src_port == 443):
        return "QUIC"
    for port in (dst_port, src_port):
        if port in _PORT_APP:
            return _PORT_APP[port]
    return transport  # fall back to the transport name (TCP/UDP/...)


def is_global_ip(ip):
    """True only for routable public addresses worth enriching."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_unspecified or addr.is_reserved)


class Enricher:
    """Caches country/ASN/hostname per IP and resolves misses in the background."""

    def __init__(self):
        self._lock = threading.Lock()
        self._geo = {}          # ip -> {"country":..., "asn":..., "org":...}
        self._rdns = {}         # ip -> hostname (or "" once resolution failed)
        self._rdns_pending = set()
        self._pool = ThreadPoolExecutor(
            max_workers=config.RDNS_WORKERS, thread_name_prefix="rdns"
        )
        self._country_reader = None
        self._asn_reader = None
        self._load_geoip()

    # -- GeoIP (optional MaxMind GeoLite2) ------------------------------------

    def _load_geoip(self):
        if not (config.GEOIP_COUNTRY_DB or config.GEOIP_ASN_DB):
            return
        try:
            import geoip2.database  # noqa: WPS433 (optional dependency)
        except ImportError:
            print("[enrichment] geoip2 not installed; skipping GeoIP enrichment.")
            return
        import os
        if config.GEOIP_COUNTRY_DB and os.path.exists(config.GEOIP_COUNTRY_DB):
            self._country_reader = geoip2.database.Reader(config.GEOIP_COUNTRY_DB)
        if config.GEOIP_ASN_DB and os.path.exists(config.GEOIP_ASN_DB):
            self._asn_reader = geoip2.database.Reader(config.GEOIP_ASN_DB)
        if self._country_reader or self._asn_reader:
            print("[enrichment] GeoIP databases loaded.")

    def _geo_lookup(self, ip):
        record = {"country": "", "asn": "", "org": ""}
        if self._country_reader:
            try:
                record["country"] = self._country_reader.country(ip).country.iso_code or ""
            except Exception:
                pass
        if self._asn_reader:
            try:
                resp = self._asn_reader.asn(ip)
                if resp.autonomous_system_number:
                    record["asn"] = f"AS{resp.autonomous_system_number}"
                record["org"] = resp.autonomous_system_organization or ""
            except Exception:
                pass
        return record

    # -- Reverse DNS (background) ---------------------------------------------

    def _resolve_rdns(self, ip):
        try:
            socket.setdefaulttimeout(config.RDNS_TIMEOUT)
            host = socket.gethostbyaddr(ip)[0]
        except Exception:
            host = ""
        with self._lock:
            self._rdns[ip] = host
            self._rdns_pending.discard(ip)

    # -- Public API -----------------------------------------------------------

    def enrich(self, ip):
        """Return cached metadata for `ip`, scheduling any missing lookups.

        Always returns immediately. Never blocks the caller (the capture tick).
        """
        if not is_global_ip(ip):
            return {"country": "", "asn": "", "org": "", "hostname": ""}

        with self._lock:
            geo = self._geo.get(ip)
            if geo is None:
                geo = self._geo_lookup(ip)  # mmdb reads are fast, in-memory
                self._geo[ip] = geo

            hostname = self._rdns.get(ip)
            if hostname is None and ip not in self._rdns_pending:
                self._rdns_pending.add(ip)
                self._pool.submit(self._resolve_rdns, ip)

        return {
            "country": geo["country"],
            "asn": geo["asn"],
            "org": geo["org"],
            "hostname": hostname or "",
        }


# Process-wide singleton shared by the FlowTable.
enricher = Enricher()
