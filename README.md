# Network Traffic Monitor

A real-time, flow-based packet analyzer built with Python, Scapy, FastAPI,
WebSockets, and JavaScript. Inspired by Sniffnet's architecture: raw frames are
aggregated into **network flows**, enriched with geolocation/DNS metadata, and
streamed to a live dashboard.

## 🚀 Start the Website

**The dashboard runs at [http://localhost:8000](http://localhost:8000) once the server is running.**

Run these three steps from the **repository root** (the folder containing this README):

```bash
# 1. Install dependencies (first time only)
pip install -r requirements.txt

# 2. Start the server  ── run the terminal as Administrator / root (see note below)
uvicorn backend.main:app --reload

# 3. Open the dashboard in your browser
#    http://localhost:8000
```

> **⚠️ Administrator / root is required** for packet capture.
> - **Windows:** install [Npcap](https://npcap.com/) and run your terminal **as Administrator**.
> - **macOS / Linux:** start it with `sudo` (e.g. `sudo uvicorn backend.main:app --reload`).
>
> **Do not** open `frontend/index.html` directly from the file system — the page
> only works when served by the running server at `http://localhost:8000`.
>
> To stop the server, press `Ctrl+C` in the terminal.

## Architecture

```
   NIC ──BPF filter──> Scapy sniff() ──5-tuple──> FlowTable ──1s tick──> WebSocket ──> Dashboard
 (kernel drops noise)   (daemon thread)          (aggregation)   (broadcast)     (Chart.js UI)
```

- **Flow aggregation** — packets sharing a 5-tuple (src IP/port, dst IP/port,
  transport) collapse into one bidirectional flow. Direction is decided against
  the host's own IPs, splitting traffic into upload vs download.
- **Rolling metrics** — a 1-second timer converts per-flow byte counts into live
  throughput, tracks totals and peaks.
- **Metadata enrichment** — optional MaxMind GeoLite2 country/ASN lookups,
  port→application-protocol mapping (HTTPS/DNS/SSH/…), and background reverse DNS.
- **Readable host view** — traffic is grouped into one row **per host**, each
  given a friendly name and type instead of a bare number: `142.250.80.14` →
  "🌐 Google", your router → "📶 Router (Gateway)", a LAN device → "🖥️ Local
  device" (or its hostname), `8.8.8.8` → "🧭 Google DNS". Every host's
  individual connections are still one click away in the detail drawer, and the
  raw IP is always shown alongside the label.
- **Broadcast loop** — an asyncio aggregator snapshots the flow table each second
  and pushes it to all connected dashboards, decoupled from the capture thread.

## Anomaly detection

`backend/detectors.py` runs four live detectors over the capture path and raises
scored alerts shown in the dashboard's Anomaly Alerts panel. Each is a real-time
adaptation of a playbook from the
[Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills)
collection:

| Detector | Technique | Based on skill | MITRE |
|----------|-----------|----------------|-------|
| **C2 beaconing** | Coefficient-of-variation on connection intervals (CV < 0.20 == periodic) | `hunting-for-beaconing-with-frequency-analysis` | T1071 |
| **Port scan** | One source touching many distinct ports/hosts in a window | `detecting-port-scanning-with-fail2ban` | T1046 |
| **DNS exfiltration** | Shannon entropy + subdomain length + uniqueness scoring per base domain | `detecting-dns-exfiltration-with-dns-query-analysis` | T1048 |
| **ARP poisoning** | IP→MAC change / flip-flop / flood / gateway impersonation | `detecting-arp-poisoning-in-network-traffic` | T1557.002 |

All thresholds are tunable via `NM_*` environment variables (see `backend/config.py`).
Pin your gateway with `NM_GATEWAY_IP` / `NM_GATEWAY_MAC` to catch gateway spoofing directly.

## Dependencies

`pip install -r requirements.txt` (see [Start the Website](#-start-the-website) above).
`geoip2` is optional — without it (or without the GeoLite2 databases) country/ASN
columns simply stay blank.

## Configuration

All settings are environment variables (see `backend/config.py`):

| Variable | Default | Purpose |
|----------|---------|---------|
| `NM_BPF` | `not host 127.0.0.1 and not port 5353` | Kernel-level BPF capture filter |
| `NM_INTERFACE` | default iface | Interface to capture on |
| `NM_EMIT_INTERVAL` | `1.0` | Rolling-window / broadcast cadence (s) |
| `NM_FLOW_IDLE_TIMEOUT` | `120` | Idle seconds before a flow is closed |
| `NM_MAX_FLOWS` | `200` | Max flows sent to the UI per tick |
| `NM_GEOIP_COUNTRY_DB` | — | Path to `GeoLite2-Country.mmdb` |
| `NM_GEOIP_ASN_DB` | — | Path to `GeoLite2-ASN.mmdb` |

Example (PowerShell), capture only web traffic with GeoIP enabled:

```powershell
$env:NM_BPF="tcp port 443 or tcp port 80"
$env:NM_GEOIP_COUNTRY_DB="C:\geoip\GeoLite2-Country.mmdb"
$env:NM_GEOIP_ASN_DB="C:\geoip\GeoLite2-ASN.mmdb"
uvicorn backend.main:app --reload
```

## Pushing changes to Git

```bash
git add .
git commit -m "your commit message"
git push
```
