# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

Install dependencies:
```bash
pip install -r requirements.txt
```

Run the server (must run from the repository root, not from `backend/`, because the frontend is mounted with the relative path `frontend`):
```bash
uvicorn backend.main:app --reload
```

Then open the dashboard at **http://localhost:8000** — FastAPI serves the frontend as static files. Do NOT open `frontend/index.html` directly from the filesystem; `app.js` connects to `ws://127.0.0.1:8000/ws/packets`, so the page only works when served by the running server. (The README's `open index.html` instruction is misleading.)

**Packet capture requires Administrator/root privileges.** On Windows, run the terminal as Administrator and install Npcap; without elevation Scapy's `sniff()` will fail or capture nothing.

There is no test suite, linter, or build step configured.

## Architecture

Flow-based (Sniffnet-style) pipeline: raw frames are aggregated into 5-tuple flows, enriched, and broadcast to the dashboard once per second. The capture thread and the serving event loop are decoupled so a slow/disconnected client can never stall capture.

```
NIC ─BPF─> sniff() ─5-tuple─> FlowTable ─1s tick─> WebSocket broadcast ─> Chart.js UI
        (daemon thread)      (aggregation)        (asyncio loop)
```

- **`backend/config.py`** — Single source of truth for all tunables, each overridable via `NM_*` environment variables (BPF filter, interface, emit interval, idle timeout, GeoIP DB paths). Read this first before changing behavior.

- **`backend/sniffer.py`** — Scapy blocking `sniff()` loop with the BPF filter applied *in the kernel* (`filter=`), `store=False`. `_parse()` flattens each frame to a 5-tuple dict (handles IPv4, IPv6, ARP; transport via TCP/UDP); `_handle()` pushes it into the shared `flow_table`. Holds no state itself.

- **`backend/flows.py`** — The heart. `FlowTable` (thread-safe) keys flows **bidirectionally** — `_key()` sorts the two endpoints so A→B and B→A collapse into one `Flow`. `add_packet()` is the hot path (called per packet from the sniffer thread); `tick(window)` is called once per second by the aggregator to roll interval byte-counters into throughput, expire idle flows, enrich remote IPs, and build the UI snapshot. `_group_by_host()` then collapses the per-flow rows into **one entry per remote IP** (the `hosts` snapshot key) — friendly-labelled via `labels.describe()`, with each host's individual connections nested under `connections` for drill-down. The InterfaceInspector drives upload/download direction tagging.

- **`backend/enrichment.py`** — `Enricher` singleton, all lookups cached and **non-blocking to the capture path**: GeoIP country/ASN (optional MaxMind, degrades silently if absent), `app_protocol()` port→service map, and reverse DNS on a `ThreadPoolExecutor`. `enrich()` returns whatever is cached *now* and schedules misses; later ticks pick up results (e.g. `8.8.8.8` → `dns.google` appears a second or two after first sighting).

- **`backend/labels.py`** — Pure-stdlib **friendly naming** layer used by `FlowTable._group_by_host`. `describe()` turns a raw IP into `{name, category}` for the UI (e.g. `142.250.80.14` → "Google", the default gateway → "Router (Gateway)", a LAN peer → its hostname or "Local device", `239.255.255.250` → "SSDP (UPnP)"). Resolution order is *authoritative-first*: this host / gateway / LAN, then real reverse-DNS hostname and ASN org, and only then the **curated best-effort** `_PROVIDER_RANGES` / `_DNS_SERVERS` tables. Those tables are hints, not truth — the raw IP is always shown too, so an imperfect guess on a shared CDN range is harmless. `category` is a stable slug (`self|gateway|lan|multicast|broadcast|dns|provider|internet`) the frontend maps to an icon + coloured badge. `classify_role(ip, category, is_lan, remote_ports, hostname)` adds an orthogonal **role** — `"service"` (server/service/infrastructure) vs `"personal"` (a personal computer / end-user device). Resolution order: infrastructure category → self → **reverse-DNS infra-domain match** (`is_infra_hostname`, e.g. `*.valve.net`, `*.akamai.net`, `*.amazonaws.com`) → **service/gaming port** (`is_service_port`, incl. Steam 27000–27036 + game ports) → **fallback**. The fallback is the important invariant: `"personal"` is assigned **only** when the peer is strictly local (a verified LAN subnet or an RFC1918/link-local/loopback address) — an outbound connection to an *external* IP is never `"personal"` by default, it falls through to `"service"`. The frontend's host-table tabs filter on `role`. `classify_service(ip, category, is_lan, remote_ports, hostname)` is the finer, user-facing taxonomy: it returns `(service_category, subtitle)` where `service_category` is one of **Gaming Infrastructure** (domains `*.valve.net`/`*.steamdb.net`/`*.epicgames.com` or ports 27000–27050; subtitle "Steam / Valve SDR"), **CDN & Cloud Hosting** (Akamai/CloudFront/Fastly/`1e100.net`/Azure/AWS domains), **Secure Web Traffic (HTTPS)** (ports 80/443/8080/8443), **Network System Services** (53/123/67/68), **Local Endpoint / Loopback** (loopback/broadcast/multicast/self/LAN/RFC1918), or **Other Service**. Precedence is that listed order after the local guard. These become the host's `service_category` + `service_subtitle`; the specific "Service/Host" name stays in `name`.

- **`backend/detectors.py`** — Anomaly `DetectionEngine` singleton (built via `init_engine(local_ips)` at sniffer import). `observe(pkt)` runs on the hot path doing only cheap bookkeeping under a lock; `evaluate()` runs once per tick to compute statistical verdicts, expire stale state, and return scored alerts. Four detectors, each ported from an Anthropic-Cybersecurity-Skills playbook: **beacon** (coefficient-of-variation on connection intervals), **portscan** (distinct-port windowing), **dns-exfil** (Shannon entropy/length scoring — verbatim `shannon_entropy`), **arp** (IP→MAC change/flip-flop/flood, event-driven). Statistical alerts are recomputed each tick; ARP alerts are raised at observe-time and cached with a TTL.

- **`backend/main.py`** — FastAPI app. `lifespan` starts the sniffer daemon thread **and** an asyncio `_aggregation_loop` that calls `flow_table.tick()` every `EMIT_INTERVAL`, attaches `detectors.engine.evaluate()` as `snapshot["alerts"]`, and broadcasts via `ConnectionManager` (tracks all connected dashboards). `/ws/packets` just registers the client and awaits; **all data is server-pushed**, clients send nothing. Frontend mounted last at `/`.

- **`frontend/app.js`** — Opens the WebSocket and renders on each snapshot (the backend already did the 1-second aggregation, so there's no client-side accumulation clock anymore). Maintains time-series history for the throughput and concurrent-flows charts; `renderFlows()` filters by the search box; the drawer shows per-flow detail looked up by `key` in `latestSnapshot`.

### Key contracts and quirks

- **The snapshot JSON shape is the contract between backend and frontend.** Five parts — `global` (KPIs), `protocols` (donut), `hosts` (the per-IP table + drawer, the primary UI), `flows` (the flat per-flow list, retained for compatibility/tests), and `alerts` (anomaly panel). All but `alerts` are produced in `FlowTable.tick()`; `alerts` is attached in `main._aggregation_loop`. Consumed in `app.js` `render()`/`renderHosts()`/`renderAlerts()`/`openDrawer()`. `hosts` is the frontend's source of truth for the table and drawer; each host carries a `name` (specific "Service/Host" label), a `category` slug + `role` (`service`/`personal`, drives the filter tabs), and a `service_category` + `service_subtitle` (the primary user-facing Category) — all from `labels.py`, mapped by `app.js` to icons + coloured badges. Change a field in one place → update the other.
- **Detectors depend on parser fields.** `dns-exfil` needs `dns_qname`/`dns_qtype` and `arp` needs `src_mac`, both extracted in `sniffer._parse()`. If you drop those fields, those detectors silently go quiet.
- **Detection logic is grounded in the cloned skills repo**, not invented. When changing a detector, re-read the corresponding `SKILL.md` in `Anthropic-Cybersecurity-Skills/skills/` rather than guessing thresholds.
- **The old raw-packet `packet_queue` model is gone.** Backend no longer emits per-packet; it emits aggregated flow snapshots on a timer. There is no more fake latency chart or `Math.random()` metric.
- **Enrichment is eventually-consistent.** `hostname`/`country`/`asn` are blank on a flow's first tick and fill in on later ticks. Don't treat blank as "no data" permanently.
- The WebSocket URL uses `location.host`, so the frontend follows whatever host/port the server runs on — no hardcoded port to keep in sync.
- **GeoIP databases are not bundled** (MaxMind license). Country/ASN stay blank unless `NM_GEOIP_COUNTRY_DB` / `NM_GEOIP_ASN_DB` point at real `.mmdb` files.

## Testing without live capture

Live capture needs Administrator/Npcap, but the whole pipeline can be driven with synthetic packets — no root required:
- **Flows:** feed dicts to `flow_table.add_packet({...})`, call `flow_table.tick(1.0)`, inspect the snapshot (flow merging, direction tagging, app-protocol mapping).
- **Detectors:** `init_engine({localips})`, feed `engine.observe({...})` events (a beacon = repeated outbound packets to one IP spaced by `BEACON_MIN_GAP`; a scan = one src hitting many `dst_port`s; DNS exfil = `dns_qname` with long high-entropy subdomains; ARP = repeated `src_mac` changes for one `src_ip`), then `engine.evaluate()`. Note `evaluate()` uses real `time.time()`, so keep synthetic timestamps within the TTL windows (or monkeypatch `detectors.time.time`).
