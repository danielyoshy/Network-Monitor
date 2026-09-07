"""Packet capture: read frames off the wire, extract fields, feed the pipeline.

The BPF filter is handed straight to libpcap/npcap so unwanted traffic is
dropped in the kernel before it ever reaches this process. Everything that
survives is parsed into a compact dict (5-tuple + the layer-2 MAC and layer-7
DNS fields the detectors need) and pushed into two consumers:

  * flow_table  -> aggregates into flows / rolling metrics
  * detection engine -> statistical anomaly detection (beacon/scan/DNS/ARP)

This module holds no state of its own.
"""
from scapy.all import ARP, DNS, DNSQR, IP, IPv6, TCP, UDP, sniff

from backend import config, detectors
from backend.flows import flow_table

# Share the FlowTable's discovered local IPs so direction logic stays consistent.
detectors.init_engine(flow_table.local_ips)


def _parse(packet):
    """Flatten a Scapy packet into the dict the pipeline expects.

    Returns None for frames we don't track (no L3 IP/ARP layer).
    """
    if packet.haslayer(IP):
        l3 = packet[IP]
        src_ip, dst_ip, proto = l3.src, l3.dst, l3.proto
    elif packet.haslayer(IPv6):
        l3 = packet[IPv6]
        src_ip, dst_ip, proto = l3.src, l3.dst, l3.nh
    elif packet.haslayer(ARP):
        arp = packet[ARP]
        return {
            "timestamp": float(packet.time),
            "length": len(packet),
            "proto": -1,  # sentinel: ARP has no transport
            "src_ip": arp.psrc, "dst_ip": arp.pdst,
            "src_port": 0, "dst_port": 0,
            "src_mac": arp.hwsrc, "dst_mac": arp.hwdst,
        }
    else:
        return None

    src_port = dst_port = 0
    if packet.haslayer(TCP):
        src_port, dst_port = packet[TCP].sport, packet[TCP].dport
    elif packet.haslayer(UDP):
        src_port, dst_port = packet[UDP].sport, packet[UDP].dport

    parsed = {
        "timestamp": float(packet.time),
        "length": len(packet),
        "proto": proto,
        "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": src_port, "dst_port": dst_port,
    }

    # Layer-7: pull the DNS question for exfiltration analysis (queries only).
    if packet.haslayer(DNSQR) and packet.haslayer(DNS) and packet[DNS].qr == 0:
        try:
            parsed["dns_qname"] = packet[DNSQR].qname.decode("utf-8", "ignore")
            parsed["dns_qtype"] = int(packet[DNSQR].qtype)
        except Exception:
            pass

    return parsed


def _handle(packet):
    """Per-packet callback. Fans the parsed frame out to both consumers."""
    parsed = _parse(packet)
    if parsed is None:
        return
    flow_table.add_packet(parsed)
    detectors.engine.observe(parsed)


def start_sniffing():
    """Blocking capture loop. Runs on a daemon thread; needs admin/root.

    The BPF filter and interface come from config. `store=False` keeps Scapy
    from retaining packets in memory (we've already extracted what we need).
    """
    bpf = config.BPF_FILTER or None
    iface = config.INTERFACE
    print(f"[sniffer] capturing on {iface or 'default iface'} | BPF: {bpf or '(none)'}")
    sniff(prn=_handle, store=False, filter=bpf, iface=iface)
