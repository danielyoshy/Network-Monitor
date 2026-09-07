"""Human-friendly naming for IP endpoints.

Turns raw addresses into readable labels so the dashboard reads like a list of
*people/services* instead of a wall of numbers:

    142.250.80.14    -> Google
    192.168.1.1      -> Router (Gateway)
    192.168.1.42     -> This device / a LAN hostname
    8.8.8.8          -> Google DNS
    239.255.255.250  -> SSDP (UPnP)

Everything here is a **best-effort hint** layered on top of, and never a
replacement for, the real data (reverse DNS + MaxMind ASN org from
`enrichment.py`). The raw IP is always still shown in the UI, so an occasional
imperfect guess on a shared CDN range is harmless. Resolution order, most
trustworthy first: this host / gateway / LAN, then reverse-DNS hostname and
ASN org (authoritative when present), then the curated provider ranges below.

Pure standard library (`ipaddress`); no new dependencies.
"""
import ipaddress

# --- Exact well-known addresses ---------------------------------------------

# Public DNS resolvers — exact and highly reliable.
_DNS_SERVERS = {
    "8.8.8.8": "Google DNS", "8.8.4.4": "Google DNS",
    "1.1.1.1": "Cloudflare DNS", "1.0.0.1": "Cloudflare DNS",
    "9.9.9.9": "Quad9 DNS", "149.112.112.112": "Quad9 DNS",
    "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
    "94.140.14.14": "AdGuard DNS", "94.140.15.15": "AdGuard DNS",
    "2001:4860:4860::8888": "Google DNS", "2001:4860:4860::8844": "Google DNS",
    "2606:4700:4700::1111": "Cloudflare DNS", "2606:4700:4700::1001": "Cloudflare DNS",
    "2620:fe::fe": "Quad9 DNS",
}

# Common multicast groups -> what the traffic actually is.
_MULTICAST_NAMES = {
    "224.0.0.1": "All hosts (IGMP)",
    "224.0.0.2": "All routers",
    "224.0.0.22": "IGMP",
    "224.0.0.251": "mDNS (Bonjour)",
    "224.0.0.252": "LLMNR",
    "239.255.255.250": "SSDP (UPnP)",
    "ff02::1": "All nodes (IPv6)",
    "ff02::2": "All routers (IPv6)",
    "ff02::fb": "mDNS (Bonjour)",
    "ff02::c": "SSDP (UPnP)",
    "ff02::1:3": "LLMNR",
}

# --- Curated provider ranges -------------------------------------------------
# Best-effort org attribution for the big consumer-traffic networks, used only
# when GeoIP/ASN data isn't available. Kept deliberately conservative.
_PROVIDER_RANGES = [
    # Google
    ("Google", ["8.8.4.0/24", "8.8.8.0/24", "8.34.208.0/20", "8.35.192.0/20",
                "64.233.160.0/19", "66.102.0.0/20", "66.249.64.0/19",
                "72.14.192.0/18", "74.125.0.0/16", "108.177.0.0/17",
                "142.250.0.0/15", "172.217.0.0/16", "172.253.0.0/16",
                "173.194.0.0/16", "209.85.128.0/17", "216.58.192.0/19",
                "216.239.32.0/19", "2607:f8b0::/32"]),
    # Cloudflare
    ("Cloudflare", ["104.16.0.0/13", "172.64.0.0/13", "162.158.0.0/15",
                    "173.245.48.0/20", "103.21.244.0/22", "141.101.64.0/18",
                    "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
                    "197.234.240.0/22", "198.41.128.0/17", "131.0.72.0/22",
                    "2606:4700::/32"]),
    # Apple (owns all of 17.0.0.0/8)
    ("Apple", ["17.0.0.0/8", "2620:149::/32"]),
    # Microsoft / Azure
    ("Microsoft", ["13.64.0.0/11", "13.104.0.0/14", "13.107.0.0/16",
                   "20.0.0.0/8", "40.74.0.0/15", "40.76.0.0/14",
                   "40.80.0.0/12", "52.96.0.0/12", "104.40.0.0/13",
                   "131.253.0.0/16", "2603::/24"]),
    # Amazon / AWS (a slice; ASN org covers the rest when GeoIP is present)
    ("Amazon AWS", ["3.0.0.0/9", "13.32.0.0/15", "13.224.0.0/14",
                    "18.64.0.0/10", "52.84.0.0/15", "52.0.0.0/11",
                    "54.144.0.0/12", "99.84.0.0/16", "205.251.192.0/19"]),
    # Meta / Facebook / Instagram / WhatsApp
    ("Meta", ["31.13.24.0/21", "31.13.64.0/18", "66.220.144.0/20",
              "69.63.176.0/20", "129.134.0.0/16", "157.240.0.0/16",
              "173.252.64.0/18", "179.60.192.0/22", "185.60.216.0/22",
              "2a03:2880::/32"]),
    # Akamai CDN
    ("Akamai", ["2.16.0.0/13", "23.32.0.0/11", "23.192.0.0/11",
                "95.100.0.0/15", "104.64.0.0/10", "184.24.0.0/13"]),
    # Fastly CDN
    ("Fastly", ["151.101.0.0/16", "199.232.0.0/16", "2a04:4e40::/32"]),
    # Netflix
    ("Netflix", ["23.246.0.0/18", "37.77.184.0/21", "45.57.0.0/17",
                 "64.120.128.0/17", "66.197.128.0/17", "108.175.32.0/20",
                 "185.2.220.0/22", "192.173.64.0/18", "198.38.96.0/19",
                 "198.45.48.0/20", "208.75.76.0/22"]),
    # Steam / Valve (game download + matchmaking + Steam Datagram Relay)
    ("Steam (Valve)", ["155.133.224.0/19", "162.254.192.0/21", "185.25.180.0/22",
                       "205.196.6.0/24", "208.64.200.0/22", "208.78.164.0/22",
                       "146.66.152.0/21", "153.254.86.0/24", "192.69.96.0/22"]),
]


def _compile(ranges):
    nets = []
    for name, cidrs in ranges:
        for cidr in cidrs:
            try:
                nets.append((ipaddress.ip_network(cidr), name))
            except ValueError:
                continue
    # Most-specific (longest prefix) first so a nested range wins.
    nets.sort(key=lambda n: n[0].prefixlen, reverse=True)
    return nets


_COMPILED = _compile(_PROVIDER_RANGES)
_provider_cache = {}


def provider_for(ip):
    """Return a curated provider name for `ip`, or "" if none is known."""
    if ip in _provider_cache:
        return _provider_cache[ip]
    name = ""
    if ip in _DNS_SERVERS:
        name = _DNS_SERVERS[ip]
    else:
        try:
            addr = ipaddress.ip_address(ip)
            for net, provider in _COMPILED:
                if addr in net:
                    name = provider
                    break
        except ValueError:
            pass
    _provider_cache[ip] = name
    return name


# --- Role classification: service/server vs personal computer ----------------
# A port is a "service port" if a listener there is offering a service (the
# server side of a conversation). Everything <1024 is well-known; these are the
# common registered/high service ports a desktop actually meets.
_SERVICE_PORTS_HIGH = {
    1194, 1723, 3306, 3389, 5000, 5060, 5061, 5222, 5432, 5900, 6379,
    8000, 8006, 8080, 8443, 8888, 9000, 9090, 27017, 32400, 51820,
}

# Gaming / matchmaking / game-server ports. Traffic to these is a *server*, not
# a peer, even though they sit in the high-port range.
_STEAM_PORT_RANGE = range(27000, 27037)          # Steam / Source: 27000-27036
_STEAM_PORTS = {3478, 4379, 4380, 27014, 27015, 27018, 27019, 27036}  # +SDR/relay
_GAME_PORTS = {
    1119, 3074, 3479, 3480, 3658, 3724, 6112, 6250, 6672,
    7777, 7778, 7779, 9308, 25565,  # Blizzard/Xbox/PSN/UE/Minecraft/etc.
}

# Reverse-DNS suffixes that unambiguously belong to server/CDN/game
# infrastructure. Matched with a dot boundary (so "evil-valve.net.attacker.com"
# does not match).
_INFRA_DOMAINS = (
    "valve.net", "steamserver.net", "steamcontent.com", "steampowered.com",
    "akamai.net", "akamaiedge.net", "akamaitechnologies.com",
    "amazonaws.com", "aws.com", "cloudfront.net",
    "cloudflare.com", "cloudflare.net",
    "1e100.net", "googleusercontent.com", "google.com", "googlevideo.com",
    "gvt1.com", "gvt2.com",
    "azure.com", "azureedge.net", "windows.net", "microsoft.com", "msedge.net",
    "facebook.com", "fbcdn.net", "instagram.com", "whatsapp.net",
    "netflix.com", "nflxvideo.net", "nflxso.net",
    "fastly.net", "fastlylb.net",
    "apple.com", "icloud.com", "aaplimg.com",
    "twitch.tv", "ttvnw.net",
    "riotgames.com", "riotcdn.net", "ea.com", "epicgames.com",
    "xboxlive.com", "playstation.net", "battle.net", "blizzard.com",
)


def _as_int(port):
    try:
        return int(port)
    except (TypeError, ValueError):
        return None


def _int_ports(ports):
    return [p for p in (_as_int(x) for x in ports) if p and p > 0]


def is_service_port(port):
    """True if `port` looks like a listening service (the server side)."""
    p = _as_int(port)
    if p is None or p <= 0:
        return False
    if p < 1024 or p in _SERVICE_PORTS_HIGH:
        return True
    if p in _STEAM_PORT_RANGE or p in _STEAM_PORTS or p in _GAME_PORTS:
        return True
    return False


def is_infra_hostname(hostname):
    """True if the reverse-DNS name belongs to known server/CDN/game infra."""
    hn = (hostname or "").strip().strip(".").lower()
    if not hn:
        return False
    return any(hn == d or hn.endswith("." + d) for d in _INFRA_DOMAINS)


def _is_local_ip(ip):
    """Strictly local/residential address space (RFC1918 / link-local / loopback)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_link_local or addr.is_loopback


def service_detail(remote_ports, hostname=""):
    """A specific service sub-label (e.g. "Steam Infrastructure",
    "Gaming Server"), or "" when the traffic isn't a recognisable game/service.
    """
    hn = (hostname or "").lower()
    ports = _int_ports(remote_ports)
    if (hn.endswith("valve.net") or hn.endswith("steamserver.net") or "steam" in hn
            or any(p in _STEAM_PORT_RANGE or p in _STEAM_PORTS for p in ports)):
        return "Steam Infrastructure"
    if any(p in _GAME_PORTS for p in ports):
        return "Gaming Server"
    return ""


def classify_role(ip, category, is_lan, remote_ports, hostname=""):
    """Classify a host as ``"service"`` (server / service / infrastructure) or
    ``"personal"`` (a personal computer / end-user device).

    Resolution order:
      1. Infrastructure categories (gateway/DNS/provider/multicast/broadcast).
      2. This host itself -> personal.
      3. Reverse-DNS match against known server/CDN/game domains -> service.
      4. Any recognised service/gaming port on the remote side -> service.
      5. **Fallback hierarchy:** ``personal`` is assigned ONLY when the peer is
         strictly local (a verified LAN subnet or RFC1918/link-local address).
         An outbound connection to an external IP is never "personal" by
         default — it defaults to ``service``.
    """
    if category in ("gateway", "dns", "provider", "multicast", "broadcast"):
        return "service"
    if category == "self":
        return "personal"
    if is_infra_hostname(hostname):
        return "service"
    if any(is_service_port(p) for p in remote_ports):
        return "service"
    # Peers are personal ONLY inside local/residential address space.
    if is_lan or _is_local_ip(ip):
        return "personal"
    return "service"


def describe(ip, *, is_self=False, is_gateway=False, is_lan=False,
             traffic_type="unicast", hostname="", org=""):
    """Produce a friendly display name and a category for an endpoint.

    Returns ``{"name": str, "category": str}``. Category is a stable slug the
    frontend maps to an icon/colour: one of
    ``self | gateway | lan | multicast | broadcast | dns | provider | internet``.
    """
    if is_self or ip in ("127.0.0.1", "::1"):
        return {"name": "This device", "category": "self"}

    if traffic_type == "broadcast" or ip == "255.255.255.255":
        return {"name": "Broadcast", "category": "broadcast"}

    if traffic_type == "multicast" or _is_multicast(ip):
        return {"name": _MULTICAST_NAMES.get(ip, "Multicast group"),
                "category": "multicast"}

    if is_gateway:
        return {"name": "Router (Gateway)", "category": "gateway"}

    if is_lan:
        # A resolved name is far more useful than "Local device"; keep it.
        return {"name": hostname or "Local device", "category": "lan"}

    # Authoritative data first (real reverse DNS / ASN org), then curated hints.
    provider = provider_for(ip)
    if ip in _DNS_SERVERS:
        return {"name": _DNS_SERVERS[ip], "category": "dns"}
    if hostname:
        return {"name": hostname, "category": "provider" if provider else "internet"}
    if provider:
        return {"name": provider, "category": "provider"}
    if org:
        return {"name": org, "category": "internet"}
    return {"name": ip, "category": "internet"}


def _is_multicast(ip):
    try:
        return ipaddress.ip_address(ip).is_multicast
    except ValueError:
        return False
