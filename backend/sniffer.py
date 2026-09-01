import queue
from scapy.all import IP, TCP, UDP, ARP, sniff

# Thread-safe queue to pass packets from the sniffer to FastAPI
packet_queue = queue.Queue()

def handle_packet(packet):
    """Callback function executed for every captured packet."""
    data = {
        "length": len(packet),
        "protocol": "Other",
        "src": "N/A",
        "dst": "N/A"
    }

    if packet.haslayer(IP):
        data["src"] = packet[IP].src
        data["dst"] = packet[IP].dst
        if packet.haslayer(TCP):
            data["protocol"] = "TCP"
        elif packet.haslayer(UDP):
            data["protocol"] = "UDP"
    elif packet.haslayer(ARP):
        data["protocol"] = "ARP"
        data["src"] = packet[ARP].psrc
        data["dst"] = packet[ARP].pdst

    # Add packet metadata to queue
    packet_queue.put(data)

def start_sniffing():
    """Starts continuous packet capture on the default network interface."""
    # Note: Requires Administrator / root privileges
    sniff(prn=handle_packet, store=False)