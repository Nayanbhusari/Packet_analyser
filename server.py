#!/usr/bin/env python3
"""
NetScope Pro — Backend Server
Real-time packet capture and PCAP analysis powered by Scapy + Flask-SocketIO.
"""

import os
import sys
import time
import base64
import tempfile
import threading
from flask import Flask, send_from_directory, request, jsonify
from flask_socketio import SocketIO, emit

try:
    from scapy.all import (
        get_if_list, get_if_addr, sniff, rdpcap,
        Ether, IP, TCP, UDP, ICMP, ARP, DNS, Raw
    )
except ImportError:
    print("=" * 58)
    print("  Scapy not installed. Run:  pip install scapy")
    print("=" * 58)
    sys.exit(1)

# ─── App ────────────────────────────────────────────────────────
app = Flask(__name__, static_folder=".")
app.config["SECRET_KEY"] = "netscope-pro-2024"
socketio = SocketIO(app, async_mode="threading")

capture_active = False


# ─── Helpers ────────────────────────────────────────────────────
def safe_addr(iface):
    try:
        a = get_if_addr(iface)
        return a if a and a != "0.0.0.0" else None
    except Exception:
        return None


def build_layers(pkt):
    """Decode packet into collapsible protocol-layer blocks."""
    layers = []

    # Ethernet
    if pkt.haslayer(Ether):
        e = pkt[Ether]
        tn = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6"}.get(e.type, "Unknown")
        layers.append({
            "name": "Ethernet II", "color": "#ff7832",
            "fields": [
                ["Destination MAC", e.dst],
                ["Source MAC", e.src],
                ["Type", f"0x{e.type:04X} ({tn})"],
            ],
        })

    # ARP
    if pkt.haslayer(ARP):
        a = pkt[ARP]
        op = {1: "Request (1)", 2: "Reply (2)"}.get(a.op, str(a.op))
        layers.append({
            "name": "Address Resolution Protocol", "color": "#ff7832",
            "fields": [
                ["Hardware Type", "Ethernet (1)"],
                ["Protocol Type", "IPv4 (0x0800)"],
                ["Operation", op],
                ["Sender MAC", a.hwsrc],
                ["Sender IP", a.psrc, True],
                ["Target MAC", a.hwdst],
                ["Target IP", a.pdst, True],
            ],
        })
        return layers

    # IPv4
    if pkt.haslayer(IP):
        ip = pkt[IP]
        pm = {6: "TCP (6)", 17: "UDP (17)", 1: "ICMP (1)"}
        ttl_n = " (Windows)" if ip.ttl <= 64 else " (Linux/Unix)"
        layers.append({
            "name": "Internet Protocol Version 4", "color": "#00aaff",
            "fields": [
                ["Version", "4"],
                ["Header Length", f"{ip.ihl * 4} bytes ({ip.ihl})"],
                ["Total Length", str(ip.len)],
                ["Differentiated Services", f"0x{ip.tos:02X}"],
                ["TTL", str(ip.ttl) + ttl_n],
                ["Protocol", pm.get(ip.proto, f"Unknown ({ip.proto})")],
                ["Header Checksum", f"0x{ip.chksum:04X}"],
                ["Source Address", ip.src, True],
                ["Destination Address", ip.dst, True],
            ],
        })

        # ICMP
        if pkt.haslayer(ICMP):
            ic = pkt[ICMP]
            tn2 = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable", 11: "Time Exceeded"}
            layers.append({
                "name": "Internet Control Message Protocol", "color": "#ffaa00",
                "fields": [
                    ["Type", f"{ic.type} ({tn2.get(ic.type, 'Unknown')})"],
                    ["Code", str(ic.code)],
                    ["Checksum", f"0x{ic.chksum:04X}"],
                    ["Identifier", f"0x{ic.id:04X}"],
                    ["Sequence Number", f"0x{ic.seq:04X}"],
                ],
            })
            return layers

        # TCP
        if pkt.haslayer(TCP):
            t = pkt[TCP]
            pn = {80: " (HTTP)", 443: " (HTTPS)", 22: " (SSH)", 21: " (FTP)",
                  25: " (SMTP)", 53: " (DNS)", 3389: " (RDP)", 8080: " (HTTP-Alt)"}
            dlen = len(pkt[Raw].load) if pkt.haslayer(Raw) else 0
            layers.append({
                "name": "Transmission Control Protocol", "color": "#00ff88",
                "fields": [
                    ["Source Port", f"{t.sport}{pn.get(t.sport, '')}"],
                    ["Destination Port", f"{t.dport}{pn.get(t.dport, '')}"],
                    ["Sequence Number", str(t.seq)],
                    ["Acknowledgment", str(t.ack) if t.flags.A else "(not set)"],
                    ["Header Length", f"{t.dataofs * 4} bytes"],
                    ["Flags", str(t.flags)],
                    ["Window Size", str(t.window)],
                    ["Checksum", f"0x{t.chksum:04X}"],
                    ["Urgent Pointer", str(t.urgptr)],
                    ["Payload Length", f"{dlen} bytes"],
                ],
            })
            return layers

        # UDP
        if pkt.haslayer(UDP):
            u = pkt[UDP]
            layers.append({
                "name": "User Datagram Protocol", "color": "#00aaff",
                "fields": [
                    ["Source Port", str(u.sport)],
                    ["Destination Port", str(u.dport)],
                    ["Length", str(u.len)],
                    ["Checksum", f"0x{u.chksum:04X}" if u.chksum else "0x0000"],
                ],
            })
            return layers

    return layers


def pkt_to_dict(pkt, pid, ts):
    """Convert one Scapy packet to a frontend-friendly dict."""
    d = dict(id=pid, time=round(ts, 6), src_ip="", dst_ip="",
             src_port=0, dst_port=0, protocol="Other",
             length=len(pkt), info="", flags="",
             src_mac="", dst_mac="", is_suspicious=False)

    if not pkt.haslayer(Ether):
        d["info"] = "Non-Ethernet frame"
        d["raw_b64"] = base64.b64encode(bytes(pkt)[:1024]).decode()
        d["raw_full_len"] = len(pkt)
        d["layers"] = []
        return d

    d["src_mac"] = pkt[Ether].src
    d["dst_mac"] = pkt[Ether].dst

    if pkt.haslayer(ARP):
        d["protocol"] = "ARP"
        d["src_ip"] = pkt[ARP].psrc
        d["dst_ip"] = pkt[ARP].pdst
        d["info"] = (f"Who has {d['dst_ip']}? Tell {d['src_ip']}"
                     if pkt[ARP].op == 1 else
                     f"{d['src_ip']} is at {d['src_mac']}")

    elif pkt.haslayer(IP):
        d["src_ip"] = pkt[IP].src
        d["dst_ip"] = pkt[IP].dst

        if pkt.haslayer(ICMP):
            d["protocol"] = "ICMP"
            tn = {0: "Echo reply", 8: "Echo request",
                  3: "Dest unreachable", 11: "Time exceeded"}
            d["info"] = tn.get(pkt[ICMP].type, f"ICMP Type {pkt[ICMP].type}")

        elif pkt.haslayer(TCP):
            d["src_port"] = pkt[TCP].sport
            d["dst_port"] = pkt[TCP].dport
            d["flags"] = str(pkt[TCP].flags)
            dl = len(pkt[Raw].load) if pkt.haslayer(Raw) else 0
            sp, dp = d["src_port"], d["dst_port"]

            if sp == 80 or dp == 80:
                d["protocol"] = "HTTP"
                if pkt.haslayer(Raw):
                    try:
                        line = pkt[Raw].load.decode("utf-8", errors="ignore").split("\r\n")[0][:120]
                        d["info"] = line or f"{sp} → {dp} [{d['flags']}]"
                    except Exception:
                        d["info"] = f"{sp} → {dp} [{d['flags']}] Len={dl}"
                else:
                    d["info"] = f"{sp} → {dp} [{d['flags']}]"
            elif sp == 443 or dp == 443:
                d["protocol"] = "HTTPS"
                d["info"] = f"{sp} → {dp} [{d['flags']}] Len={dl}"
            else:
                d["protocol"] = "TCP"
                d["info"] = (f"{sp} → {dp} [{d['flags']}] "
                             f"Seq={pkt[TCP].seq} Ack={pkt[TCP].ack} Len={dl}")

        elif pkt.haslayer(UDP):
            d["src_port"] = pkt[UDP].sport
            d["dst_port"] = pkt[UDP].dport
            sp, dp = d["src_port"], d["dst_port"]
            if sp == 53 or dp == 53:
                d["protocol"] = "DNS"
                if pkt.haslayer(DNS) and pkt[DNS].qd:
                    try:
                        qn = pkt[DNS].qd.qname.decode()
                        d["info"] = f"{'Response' if pkt[DNS].qr else 'Query'} {qn}"
                    except Exception:
                        d["info"] = f"{sp} → {dp} Len={pkt[UDP].len}"
                else:
                    d["info"] = f"{sp} → {dp} Len={pkt[UDP].len}"
            else:
                d["protocol"] = "UDP"
                d["info"] = f"{sp} → {dp} Len={pkt[UDP].len}"
    else:
        d["info"] = f"Unknown ethertype 0x{pkt[Ether].type:04X}"

    raw = bytes(pkt)
    d["raw_b64"] = base64.b64encode(raw[:1024]).decode()
    d["raw_full_len"] = len(raw)
    d["layers"] = build_layers(pkt)
    return d


# ─── Capture Thread ─────────────────────────────────────────────
def capture_loop(iface):
    global capture_active
    count = 0
    t0 = time.time()

    def handler(pkt):
        nonlocal count
        if not capture_active:
            return
        count += 1
        try:
            socketio.emit("packet", pkt_to_dict(pkt, count, time.time() - t0))
        except Exception:
            pass

    try:
        sniff(iface=iface, prn=handler,
              stop_filter=lambda _: not capture_active, store=False)
    except PermissionError:
        socketio.emit("capture_error", {
            "error": "Permission denied. Linux/macOS: run with sudo. Windows: run as Administrator + install Npcap."
        })
    except OSError as e:
        socketio.emit("capture_error", {
            "error": f"Cannot open \"{iface}\": {e}"
        })
    except Exception as e:
        socketio.emit("capture_error", {"error": f"Capture error: {e}"})
    finally:
        capture_active = False
        socketio.emit("capture_stopped", {"count": count})


# ─── HTTP Routes ────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(".", "index.html")


@app.route("/api/interfaces")
def api_interfaces():
    result = []
    for name in get_if_list():
        result.append({"name": name, "ip": safe_addr(name) or "N/A"})
    return jsonify(result)


@app.route("/api/pcap/upload", methods=["POST"])
def upload_pcap():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400

    try:
        fd, tmp = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        f.save(tmp)
        pkts = rdpcap(tmp)
        os.unlink(tmp)

        if not pkts:
            return jsonify({"error": "PCAP contains no packets"}), 400

        cap = 15000
        truncated = len(pkts) > cap
        pkts = pkts[:cap]
        base_t = float(pkts[0].time) if pkts[0].time else 0.0

        results = []
        for i, p in enumerate(pkts):
            try:
                ts = (float(p.time) - base_t) if p.time else i * 0.001
                results.append(pkt_to_dict(p, i + 1, ts))
            except Exception:
                continue

        return jsonify({"packets": results, "total": len(results),
                        "truncated": truncated})
    except Exception as e:
        return jsonify({"error": f"PCAP parse failed: {e}"}), 500


# ─── Socket.IO Events ──────────────────────────────────────────
@socketio.on("connect")
def _connect():
    emit("connected", {"message": "Backend ready"})


@socketio.on("start_capture")
def _start(data):
    global capture_active
    if capture_active:
        emit("capture_error", {"error": "Already capturing"})
        return
    iface = data.get("interface")
    if not iface:
        emit("capture_error", {"error": "No interface specified"})
        return
    capture_active = True
    threading.Thread(target=capture_loop, args=(iface,), daemon=True).start()
    emit("capture_started", {"interface": iface})


@socketio.on("stop_capture")
def _stop():
    global capture_active
    capture_active = False


# ─── Entry Point ────────────────────────────────────────────────
if __name__ == "__main__":
    print()
    print("  ╔═══════════════════════════════════════════╗")
    print("  ║      NetScope Pro  —  Backend Server      ║")
    print("  ╠═══════════════════════════════════════════╣")
    print("  ║  http://localhost:5000                    ║")
    print("  ║                                           ║")
    print("  ║  Packet capture needs elevated rights:    ║")
    print("  ║    Linux / macOS  →  sudo python server.py║")
    print("  ║    Windows        →  Run as Administrator  ║")
    print("  ╚═══════════════════════════════════════════╝")
    print()
    socketio.run(app, host="0.0.0.0", port=5000, debug=False)