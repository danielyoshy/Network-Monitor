# Network Traffic Monitor

A real-time packet analyzer built with Python, FastAPI, WebSockets, and JavaScript.

## Features
- Captures Layer 2–4 network traffic (Ethernet, IP, TCP, UDP, ARP) using Scapy and raw sockets.
- Multithreaded background sniffer streaming data asynchronously over WebSockets.
- Live dashboard displaying real-time packet logs.

## Setup & Execution
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
## Run the Program
uvicorn backend.main:app --reload
open index.html