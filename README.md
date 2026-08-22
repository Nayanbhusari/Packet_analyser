# NetScope Pro

A lightweight, browser-based packet analyzer. Live capture and PCAP inspection through a single-page web UI, backed by a small Flask + Scapy server — no Wireshark install, no bloated GUI framework.

Built for personal / local use: point it at a network interface, watch traffic flow in through decoded layers, protocol charts, a live topology view, and basic threat heuristics (port scans, SYN floods, ARP spoofing, ICMP floods).

## Features

- **Live capture** over WebSocket (Socket.IO) — packets appear in the table as they're sniffed, no polling
- **Layered packet detail view** — Ethernet → IP → TCP/UDP/ICMP → TLS, each collapsible, plus a synced hex dump
- **TLS SNI extraction** — pulls the hostname out of a TLS ClientHello without decrypting anything, so you can see *what site* a 443 connection is going to
- **PCAP import** — drag in an existing capture and it runs through the same decode/threat pipeline as live traffic
- **Basic threat detection** — rolling-window heuristics for port scans, SYN floods, ARP spoofing, and ICMP floods
- **Protocol charts, top-talkers list, and a live network topology graph** (Chart.js + canvas)
- **CSV export** of the current capture
- **Simulation mode** — if the backend isn't reachable, the UI falls back to a client-side traffic generator so the interface still works without root/admin privileges

## Tech stack

| Layer | Tool |
|---|---|
| Packet capture | [Scapy](https://scapy.net/) |
| Server / realtime transport | Flask + Flask-SocketIO |
| Frontend | Vanilla JS, single HTML file (no build step) |
| Styling | Tailwind (CDN) + custom CSS |
| Charts | Chart.js |
| Fonts | Space Grotesk (UI), JetBrains Mono (data) |

## Requirements

- Python 3.9+
- Root / Administrator privileges (raw packet capture requires elevated permissions on every OS)
- **Windows only:** [Npcap](https://npcap.com/#download) must be installed first — Scapy has no way to capture packets on Windows without it. During install, check **"Install Npcap in WinPcap API-compatible Mode"**.
- **macOS only:** Xcode Command Line Tools (`xcode-select --install`) if you don't already have them — needed to build Scapy's dependencies.
- **Linux:** works out of the box on most distros; no extra driver needed.

## Setup

```bash
git clone https://github.com/Nayanbhusari/Packet_analyser.git
cd Packet_analyser
pip install -r requirements.txt
```

## Running

**Windows** (after installing Npcap): open Command Prompt or PowerShell **as Administrator**, then:
```bash
python server.py
```

**macOS / Linux**: raw sockets need root, so run with `sudo`. Using a virtualenv, `sudo` won't see it by default — either point at the venv's Python explicitly, or install system-wide:
```bash
sudo python3 server.py
# or, if using a virtualenv:
sudo $(which python3) server.py
```

Then open **http://localhost:5000** in your browser.

1. Pick a network interface from the dropdown
2. Click **Start Capture**
3. Filter by protocol or search text, click any row for the full layer breakdown + hex dump
4. **Export CSV** to save the current table, or drag in a `.pcap`/`.pcapng` file to analyze offline

## ⚠️ Security note

This is built for **local, single-user use only** — there's no authentication on the capture controls or the PCAP upload endpoint. The server currently binds to `0.0.0.0`, meaning it's reachable from other devices on your network, not just `localhost`. If you plan to run this anywhere other than a trusted personal machine:

- Change `host="0.0.0.0"` to `host="127.0.0.1"` in `server.py` before running it
- Don't expose port 5000 to the internet or an untrusted network

## Project structure

```
netscope-pro/
├── server.py          # Flask + Scapy backend — capture, decode, PCAP parsing
├── index.html          # Entire frontend — UI, styling, and client logic
└── requirements.txt
```

## Limitations

- Decodes Ethernet, ARP, IPv4, ICMP, TCP, UDP, DNS, HTTP, and TLS ClientHello (SNI) — not the thousands of protocols Wireshark supports
- No IPv6 support yet
- Threat detection is heuristic, not a replacement for a real IDS
- No built-in authentication — see the security note above

## License

Personal project — add a license of your choice before publishing if you want others to reuse it.
