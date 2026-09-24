#!/usr/bin/env python3
"""Packet monitor. Runs unprivileged once the interpreter holds CAP_NET_RAW:

    python3 -m venv --copies .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    sudo setcap cap_net_raw,cap_net_admin+eip .venv/bin/python3
    .venv/bin/python3 main.py

Writes each packet as one JSON line to captures/capture-<UTC>.jsonl for later analysis:
    pd.read_json("captures/capture-....jsonl", lines=True)
"""
import argparse
import ipaddress
import json
import logging
import os
import queue
import signal
import socket
import subprocess
import sys
import threading
import time
from collections import Counter, deque
from datetime import datetime, timezone

import requests
from flask import Flask, jsonify, render_template, request
from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, sniff
from werkzeug.serving import make_server

def default_capture_interface():
    """Use the interface carrying the host's default route unless overridden."""
    try:
        route = subprocess.run(
            ["ip", "route", "get", "1.1.1.1"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        ).stdout.split()
        if "dev" in route:
            return route[route.index("dev") + 1]
    except (FileNotFoundError, subprocess.TimeoutExpired, ValueError, IndexError):
        pass
    return "lo"


CAPTURE_INTERFACE = os.environ.get("CAPTURE_IFACE") or default_capture_interface()
HOST_IP = os.environ.get("HOST_IP", "192.168.1.190")
HOST_HOSTNAME = socket.gethostname()
FLASK_HOST = "0.0.0.0"
FLASK_PORT = int(os.environ.get("FLASK_PORT", "1234"))
PACKET_RING_SIZE = 5000
LOG_DIR = os.environ.get("LOG_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "captures"))
LOG_QUEUE_SIZE = 50000
LOG_FLUSH_SECONDS = 2

MEMORY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "memory.md")
OUI_PATHS = ("/usr/share/nmap/nmap-mac-prefixes", "/var/lib/ieee-data/oui.txt")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/chat")
OLLAMA_FALLBACK_URL = os.environ.get("OLLAMA_FALLBACK_URL", "").strip()
OLLAMA_PROXY_TOKEN = os.environ.get("OLLAMA_PROXY_TOKEN", "").strip()
MODEL_STANDARD = os.environ.get("OLLAMA_MODEL", "qwen3:14b")
MODEL_DEEP = os.environ.get("OLLAMA_MODEL_DEEP", "gpt-oss:20b")
OLLAMA_TIMEOUT = 300
CONV_IDLE_SECONDS = 120
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
RDAP_RATE_LIMIT = 1.0

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("netmon")

app = Flask(__name__)
stop_event = threading.Event()

packet_ring = deque(maxlen=PACKET_RING_SIZE)
ring_lock = threading.Lock()
_counter = 0

dns_names = {}
dns_lock = threading.Lock()

log_queue = queue.Queue(maxsize=LOG_QUEUE_SIZE)
log_dropped = 0

conversations = {}
conv_lock = threading.Lock()

analysis_cache = {}
enrich_cache = {}
ollama_lock = threading.Lock()
_rdap_last_call = 0.0

PROTOCOL_ROWS = []
PORT_INDEX = {}
PROTOCOL_REFERENCE = ""
OUI = {}

# Vendor substring -> what that kind of device usually is. Passive inference only.
VENDOR_HINTS = [
    ("raspberry", "Raspberry Pi (single-board computer, often a DNS/ad-blocker or home server)"),
    ("amazon", "Amazon device (Echo, Fire TV or Kindle)"),
    ("google", "Google device (Nest, Chromecast or Home)"),
    ("apple", "Apple device (Mac, iPhone, iPad or Apple TV)"),
    ("samsung", "Samsung device (smart TV, phone or appliance)"),
    ("bose", "Bose audio device (speaker or soundbar)"),
    ("sonos", "Sonos speaker"),
    ("roku", "Roku streaming device"),
    ("netgear", "Netgear network equipment (router, switch or AP)"),
    ("tp-link", "TP-Link network equipment"),
    ("ubiquiti", "Ubiquiti network equipment"),
    ("cisco", "Cisco network equipment"),
    ("mikrotik", "MikroTik router"),
    ("espressif", "ESP32/ESP8266 IoT microcontroller"),
    ("texas instruments", "TI wireless module (IoT/embedded)"),
    ("hewlett", "HP device (PC or printer)"),
    ("canon", "Canon printer or camera"),
    ("epson", "Epson printer"),
    ("brother", "Brother printer"),
    ("intel", "PC network adapter (Intel)"),
    ("realtek", "PC network adapter (Realtek)"),
    ("liteon", "PC or laptop network adapter"),
    ("luxshare", "Apple accessory or peripheral (Luxshare is an Apple contract manufacturer)"),
    ("murata", "Wi-Fi module (Murata, common in IoT and appliances)"),
    ("wistron", "Laptop or embedded device"),
    ("shenzhen", "Consumer IoT device (generic Shenzhen ODM)"),
    ("hon hai", "Foxconn-built device (PC, console or accessory)"),
    ("foxconn", "Foxconn-built device (PC, console or accessory)"),
    ("nintendo", "Nintendo console"),
    ("sony", "Sony device (PlayStation, TV or audio)"),
    ("microsoft", "Microsoft device (Xbox or Surface)"),
    ("ring", "Ring camera or doorbell"),
    ("wyze", "Wyze camera"),
    ("tuya", "Tuya smart-home device"),
    ("philips", "Philips device (Hue lighting or TV)"),
    ("ecobee", "ecobee smart thermostat"),
    ("honeywell", "Honeywell device (thermostat or alarm)"),
]


def detect_protocol(pkt):
    if pkt.haslayer(DNS):
        return "DNS"
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        if 443 in (tcp.sport, tcp.dport):
            return "HTTPS"
        if 80 in (tcp.sport, tcp.dport):
            return "HTTP"
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    return "OTHER"
    


def cache_dns_names(pkt):
    dns = pkt[DNS]
    if not pkt.haslayer(DNSQR):
        return
    qname = pkt[DNSQR].qname
    if isinstance(qname, bytes):
        qname = qname.decode(errors="replace")
    qname = qname.rstrip(".")
    if not qname:
        return
    for i in range(min(dns.ancount or 0, 10)):
        try:
            rdata = dns.an[i].rdata
        except (IndexError, AttributeError):
            break
        if isinstance(rdata, bytes):
            rdata = rdata.decode(errors="replace")
        rdata = str(rdata)
        try:
            ipaddress.ip_address(rdata)
        except ValueError:
            continue
        with dns_lock:
            dns_names[rdata] = qname


def resolve_hostname(ip):
    if ip == HOST_IP:
        return HOST_HOSTNAME
    with dns_lock:
        return dns_names.get(ip, "")


def process_packet(pkt):
    global _counter
    if not pkt.haslayer(IP):
        return

    ip_layer = pkt[IP]
    src_port = dst_port = None
    flags = ""

    if pkt.haslayer(TCP):
        src_port, dst_port = pkt[TCP].sport, pkt[TCP].dport
        flags = str(pkt[TCP].flags)
    elif pkt.haslayer(UDP):
        src_port, dst_port = pkt[UDP].sport, pkt[UDP].dport

    if pkt.haslayer(DNS) and pkt[DNS].qr == 1:
        cache_dns_names(pkt)

    src_mac = dst_mac = ""
    if pkt.haslayer(Ether):
        src_mac, dst_mac = pkt[Ether].src, pkt[Ether].dst

    with ring_lock:
        _counter += 1
        record = {
            "no": _counter,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_hostname": resolve_hostname(ip_layer.src),
            "src_mac": src_mac,
            "src_ip": ip_layer.src,
            "src_port": src_port,
            "dst_hostname": resolve_hostname(ip_layer.dst),
            "dst_mac": dst_mac,
            "dst_ip": ip_layer.dst,
            "dst_port": dst_port,
            "protocol": detect_protocol(pkt),
            "length": len(pkt),
            "flags": flags,
        }
        packet_ring.append(record)

    track_conversation(record)

    global log_dropped
    try:
        log_queue.put_nowait(record)
    except queue.Full:
        log_dropped += 1


def conv_key(a, b):
    return f"{a}|{b}" if a < b else f"{b}|{a}"


def track_conversation(rec):
    """Running per-pair totals. The 5000-packet ring only covers ~10s at full rate,
    so analysis needs aggregates that outlive rotation."""
    key = conv_key(rec["src_ip"], rec["dst_ip"])
    now = time.time()
    with conv_lock:
        c = conversations.get(key)
        if c is None:
            ip_a, ip_b = sorted((rec["src_ip"], rec["dst_ip"]))
            c = {
                "key": key, "ip_a": ip_a, "ip_b": ip_b,
                "host_a": "", "host_b": "",
                "mac_a": "", "mac_b": "",
                "initiator": rec["src_ip"],
                "first_seen": rec["timestamp"], "last_seen": rec["timestamp"],
                "total": 0, "bytes": 0,
                "a_to_b": 0, "b_to_a": 0,
                "protocols": Counter(), "dst_ports": Counter(), "flags": Counter(),
                "touched": now,
            }
            conversations[key] = c

        c["total"] += 1
        c["bytes"] += rec.get("length") or 0
        c["last_seen"] = rec["timestamp"]
        c["touched"] = now
        c["protocols"][rec["protocol"]] += 1
        if rec["src_ip"] == c["ip_a"]:
            c["a_to_b"] += 1
            src_key, dst_key = "a", "b"
        else:
            c["b_to_a"] += 1
            src_key, dst_key = "b", "a"
        if rec["src_hostname"]:
            c[f"host_{src_key}"] = rec["src_hostname"]
        if rec["dst_hostname"]:
            c[f"host_{dst_key}"] = rec["dst_hostname"]
        if rec["src_mac"]:
            c[f"mac_{src_key}"] = rec["src_mac"]
        if rec["dst_mac"]:
            c[f"mac_{dst_key}"] = rec["dst_mac"]
        if rec["dst_port"] is not None:
            c["dst_ports"][rec["dst_port"]] += 1
        if rec.get("flags"):
            c["flags"][rec["flags"]] += 1


def sweep_conversations():
    cutoff = time.time() - CONV_IDLE_SECONDS
    with conv_lock:
        for key in [k for k, c in conversations.items() if c["touched"] < cutoff]:
            del conversations[key]
            analysis_cache.pop(key, None)


def capture_loop():
    log.info("Capturing on %s", CAPTURE_INTERFACE)
    last_sweep = time.time()
    while not stop_event.is_set():
        try:
            # Short timeout so the loop re-checks stop_event even on an idle link.
            sniff(iface=CAPTURE_INTERFACE, prn=process_packet, store=0, filter="ip", timeout=1)
            if time.time() - last_sweep > 30:
                sweep_conversations()
                last_sweep = time.time()
        except PermissionError:
            log.error(
                "No raw socket permission. Grant it to this interpreter once:\n"
                "    sudo setcap cap_net_raw,cap_net_admin+eip %s",
                os.path.realpath(sys.executable),
            )
            return
        except ValueError as exc:
            log.error(
                "Capture interface %r is unavailable: %s. Set CAPTURE_IFACE or use "
                "--interface with a name from `ip -br link`.",
                CAPTURE_INTERFACE,
                exc,
            )
            return
        except Exception:
            log.exception("Capture failed")
            return


def log_writer(path):
    """Drains the packet queue to JSONL. Disk I/O stays off the capture thread."""
    written = 0
    with open(path, "a", buffering=1024 * 64) as fh:
        while True:
            try:
                record = log_queue.get(timeout=LOG_FLUSH_SECONDS)
            except queue.Empty:
                fh.flush()
                if stop_event.is_set():
                    break
                continue
            fh.write(json.dumps(record, separators=(",", ":")) + "\n")
            written += 1
            if written % 500 == 0:
                fh.flush()
        fh.flush()
    log.info("Wrote %d packets to %s", written, path)
    if log_dropped:
        log.warning("Dropped %d packets: log queue full", log_dropped)


def parse_memory(path):
    """memory.md is the single source of truth for port->service. Returns the row list
    plus an index. Ranges wider than MAX_RANGE (ICMP/IGMP list '0-255', which are
    protocol numbers rather than ports) are kept as rows but left out of the index."""
    MAX_RANGE = 64
    rows, index, transport = [], {}, ""

    try:
        lines = open(path, encoding="utf-8").read().splitlines()
    except OSError:
        log.warning("No protocol reference at %s; port labels unavailable", path)
        return [], {}, ""

    for line in lines:
        s = line.strip()
        if s.startswith("## "):
            transport = s[3:].strip()
            continue
        if not s.startswith("|") or s.startswith("|--") or "---" in s:
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if len(cells) != 4 or cells[0] == "Protocol":
            continue

        name, acronym, port_spec, desc = cells
        ports = []
        for part in port_spec.replace("/", ",").split(","):
            part = part.strip()
            if "-" in part:
                lo, hi = part.split("-", 1)
                if lo.strip().isdigit() and hi.strip().isdigit():
                    lo, hi = int(lo), int(hi)
                    if 0 <= hi - lo <= MAX_RANGE:
                        ports.extend(range(lo, hi + 1))
            elif part.isdigit():
                ports.append(int(part))

        row = {"protocol": name, "acronym": acronym, "port": port_spec,
               "transport": transport, "description": desc}
        rows.append(row)
        for p in ports:
            index.setdefault(p, []).append(row)

    reference = "\n".join(lines)
    log.info("Protocol reference: %d entries, %d ports indexed", len(rows), len(index))
    return rows, index, reference


def load_oui():
    """MAC prefix -> vendor. Purely passive device identification: the OUI is in every
    frame we already capture, so no scanning is involved.

    Merges all available sources because their coverage differs - nmap's file knows
    Raspberry Pi, the IEEE registry does not, and vice versa."""
    table = {}
    for path in OUI_PATHS:
        added = 0
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "(hex)" in line:                      # IEEE: "B0-8C-B3   (hex)\t\tVendor"
                        head, _, vendor = line.partition("(hex)")
                        prefix = head.strip().replace("-", "").upper()
                        vendor = vendor.strip()
                    else:                                     # nmap: "B08CB3  Vendor"
                        parts = line.split(None, 1)
                        if len(parts) != 2:
                            continue
                        prefix, vendor = parts[0].upper(), parts[1].strip()
                    if len(prefix) == 6 and vendor and prefix not in table:
                        try:
                            int(prefix, 16)
                        except ValueError:
                            continue
                        table[prefix] = vendor
                        added += 1
        except OSError:
            continue
        if added:
            log.info("OUI: +%d prefixes from %s", added, path)
    if not table:
        log.warning("No OUI database found; device vendor identification unavailable")
    return table


_arp_cache = {"at": 0.0, "map": {}}


def arp_neighbours():
    """The OS already keeps a neighbour table. Reading it costs nothing and covers
    devices that have not sent traffic we happened to capture."""
    if time.time() - _arp_cache["at"] < 10:
        return _arp_cache["map"]
    table = {}
    try:
        out = subprocess.run(["ip", "neigh", "show"], capture_output=True,
                             text=True, timeout=3).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 5 and "lladdr" in parts:
                table[parts[0]] = parts[parts.index("lladdr") + 1]
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError, IndexError):
        pass
    _arp_cache.update(at=time.time(), map=table)
    return table


def identify_device(ip, mac):
    if not mac:
        return None
    prefix = mac.replace(":", "").replace("-", "").upper()[:6]
    vendor = OUI.get(prefix, "")
    guess = ""
    low = vendor.lower()
    for needle, description in VENDOR_HINTS:
        if needle in low:
            guess = description
            break
    randomised = False
    try:
        randomised = bool(int(mac[:2], 16) & 0x02)
    except ValueError:
        pass
    return {
        "ip": ip, "mac": mac, "oui": prefix,
        "vendor": vendor, "guess": guess, "randomised": randomised,
    }


def port_label(port):
    hits = PORT_INDEX.get(port)
    if not hits:
        return str(port)
    names = sorted({h["acronym"] for h in hits})
    return f"{port} ({'/'.join(names)})"


def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True


def lookup_reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        pass
    try:
        r = subprocess.run(["dig", "-x", ip, "+short", "+time=3", "+tries=1"],
                           capture_output=True, text=True, timeout=5)
        return r.stdout.strip().rstrip(".")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def lookup_rdap(ip):
    global _rdap_last_call
    empty = {"rdap_org": "", "rdap_country": "", "rdap_netname": "", "rdap_range": ""}
    elapsed = time.time() - _rdap_last_call
    if elapsed < RDAP_RATE_LIMIT:
        time.sleep(RDAP_RATE_LIMIT - elapsed)

    for base in ("https://rdap.arin.net/registry/ip/",
                 "https://rdap.db.ripe.net/ip/",
                 "https://rdap.apnic.net/ip/"):
        try:
            _rdap_last_call = time.time()
            resp = requests.get(f"{base}{ip}", timeout=10)
            if resp.status_code != 200:
                continue
            data = resp.json()
            org = country = ""
            for entity in data.get("entities", []):
                vcard = entity.get("vcardArray", [None, []])
                if isinstance(vcard, list) and len(vcard) > 1:
                    for field in vcard[1]:
                        if field[0] == "fn":
                            org = field[3]
                        if field[0] == "adr" and isinstance(field[3], list) and field[3]:
                            country = field[3][-1]
            return {
                "rdap_org": org or data.get("name", ""),
                "rdap_country": country or data.get("country", ""),
                "rdap_netname": data.get("name", ""),
                "rdap_range": f'{data.get("startAddress", "")}-{data.get("endAddress", "")}',
            }
        except (requests.RequestException, json.JSONDecodeError, KeyError, IndexError):
            continue
    return empty


def lookup_shodan(ip):
    empty = {"shodan_ports": "", "shodan_vulns": "", "shodan_os": ""}
    if not SHODAN_API_KEY:
        return empty
    try:
        resp = requests.get(f"https://api.shodan.io/shodan/host/{ip}",
                            params={"key": SHODAN_API_KEY}, timeout=10)
        if resp.status_code != 200:
            return empty
        data = resp.json()
        vulns = data.get("vulns")
        return {
            "shodan_ports": json.dumps(data.get("ports", [])),
            "shodan_vulns": json.dumps(list(vulns.keys()) if isinstance(vulns, dict) else (vulns or [])),
            "shodan_os": data.get("os") or "",
        }
    except (requests.RequestException, json.JSONDecodeError):
        return empty


def enrich_ip(ip):
    cached = enrich_cache.get(ip)
    if cached:
        return cached
    result = {"reverse_dns": lookup_reverse_dns(ip)}
    if is_private_ip(ip):
        result.update({"rdap_org": "Private", "rdap_country": "LAN",
                       "rdap_netname": "Private", "rdap_range": "",
                       "shodan_ports": "", "shodan_vulns": "", "shodan_os": ""})
    else:
        result.update(lookup_rdap(ip))
        result.update(lookup_shodan(ip))
    result["last_updated"] = datetime.now(timezone.utc).isoformat()
    enrich_cache[ip] = result
    return result


SYSTEM_PROMPT = (
    "You are a network security analyst. You read one packet-capture conversation and "
    "report on it in a fixed format. You never use markdown, headings, bullets or emoji. "
    "You never describe or restate the input data. You never explain your reasoning."
)

OUTPUT_FORMAT = (
    "Reply with exactly these six lines and nothing else:\n"
    "Initiator: <host that started it, hostname if known else IP>\n"
    "Receiver: <the other host, hostname if known else IP>\n"
    "Protocols: <only those listed above>\n"
    "Purpose: <most plausible explanation, one or two sentences>\n"
    "Indicators: <anything suspicious, or: None observed>\n"
    "Risk: <Low or Medium or High or Critical>\n\n"
    "No other text. Under 120 words."
)


def describe_host(ip, hostname, mac=""):
    e = enrich_ip(ip)
    bits = [ip]
    name = hostname or e.get("reverse_dns")
    if name:
        bits.append(f'"{name}"')
    dev = identify_device(ip, mac)
    if dev and dev["vendor"]:
        bits.append(f"NIC vendor {dev['vendor']}")
        if dev["guess"]:
            bits.append(f"- probably a {dev['guess']}")
    org = e.get("rdap_org")
    if org and org != "Private":
        bits.append(f"owned by {org}")
    country = e.get("rdap_country")
    if country and country != "LAN":
        bits.append(f"[{country}]")
    return " ".join(bits)


def build_analysis_prompt(conv, sample, deep):
    """Compact prose, not a JSON dump. A raw blob invites the model to summarise the
    blob; prose plus a trailing format instruction keeps it on task. Only the protocol
    rows for ports actually seen are included, which also shrinks the prompt a lot."""
    ports = conv["dst_ports"].most_common(15)

    ref_lines, seen = [], set()
    for port, _ in ports:
        for row in PORT_INDEX.get(port, []):
            tag = (row["acronym"], row["port"])
            if tag not in seen:
                seen.add(tag)
                ref_lines.append(
                    f"  {row['port']}/{row['transport']} {row['acronym']} "
                    f"({row['protocol']}) - {row['description']}"
                )

    lines = [
        f"Host A: {describe_host(conv['ip_a'], conv['host_a'], conv.get('mac_a', ''))}",
        f"Host B: {describe_host(conv['ip_b'], conv['host_b'], conv.get('mac_b', ''))}",
        f"First packet seen from: {conv['initiator']}",
        f"Window: {conv['first_seen']} to {conv['last_seen']}",
        f"Volume: {conv['total']} packets, {conv['bytes']} bytes "
        f"({conv['a_to_b']} from A to B, {conv['b_to_a']} from B to A)",
        "Protocols: " + ", ".join(f"{k} x{v}" for k, v in conv["protocols"].most_common()),
        "Destination ports: " + (", ".join(f"{port_label(p)} x{n}" for p, n in ports) or "none"),
    ]
    if conv["flags"]:
        lines.append("TCP flags: " + ", ".join(f"{k} x{v}" for k, v in conv["flags"].most_common()))
    if ref_lines:
        lines.append("\nPort reference for the ports above:\n" + "\n".join(ref_lines))
    if deep and sample:
        lines.append("\nRecent packets:")
        for p in sample[-40:]:
            lines.append(
                f"  {p['timestamp'][11:23]} {p['src_ip']}:{p['src_port']} -> "
                f"{p['dst_ip']}:{p['dst_port']} {p['protocol']} {p.get('length', 0)}B "
                f"{p.get('flags', '')}".rstrip()
            )

    return "\n".join(lines) + "\n\n" + OUTPUT_FORMAT


def call_ollama(model, prompt, max_predict):
    """think=False matters: qwen3 and gpt-oss are reasoning models that spend the
    num_predict budget on a separate `thinking` field, leaving `content` empty."""
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "stream": False,
        "think": False,
        "options": {"num_predict": max_predict, "temperature": 0.3},
    }
    urls = [OLLAMA_URL]
    if OLLAMA_FALLBACK_URL and OLLAMA_FALLBACK_URL not in urls:
        urls.append(OLLAMA_FALLBACK_URL)
    errors = []

    for url in urls:
        headers = {"Authorization": f"Bearer {OLLAMA_PROXY_TOKEN}"} if OLLAMA_PROXY_TOKEN else {}
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=OLLAMA_TIMEOUT)
            if resp.status_code == 200:
                message = resp.json().get("message", {})
                content = (message.get("content") or "").strip()
                if not content:
                    content = (message.get("thinking") or "").strip()
                return (content, None) if content else (None, "Model returned an empty response")

            error = f"HTTP {resp.status_code}: {resp.text[:200]}"
            errors.append(f"{url}: {error}")
            if resp.status_code != 404:
                break
        except requests.RequestException as exc:
            log.warning("Ollama call failed for %s: %s", url, exc.__class__.__name__)
            errors.append(f"{url}: unreachable ({exc.__class__.__name__})")

    return None, "Ollama unavailable; tried: " + "; ".join(errors)


@app.route("/api/protocols")
def api_protocols():
    port = request.args.get("port", type=int)
    if port is not None:
        return jsonify({"port": port, "matches": PORT_INDEX.get(port, [])})
    return jsonify({"count": len(PROTOCOL_ROWS), "protocols": PROTOCOL_ROWS})


@app.route("/api/conversation")
def api_conversation():
    key = request.args.get("key", "")
    with conv_lock:
        conv = conversations.get(key)
        snapshot = dict(conv) if conv else None
    if snapshot is None:
        return jsonify({"error": "Conversation not found or already idled out"}), 404

    ports = [
        {"port": p, "count": n, "matches": PORT_INDEX.get(p, [])}
        for p, n in snapshot["dst_ports"].most_common(20)
    ]
    return jsonify({
        "key": snapshot["key"],
        "ip_a": snapshot["ip_a"], "ip_b": snapshot["ip_b"],
        "host_a": snapshot["host_a"], "host_b": snapshot["host_b"],
        "initiator": snapshot["initiator"],
        "first_seen": snapshot["first_seen"], "last_seen": snapshot["last_seen"],
        "total": snapshot["total"], "bytes": snapshot["bytes"],
        "a_to_b": snapshot["a_to_b"], "b_to_a": snapshot["b_to_a"],
        "protocols": dict(snapshot["protocols"].most_common()),
        "flags": dict(snapshot["flags"].most_common()),
        "ports": ports,
        "device_a": identify_device(snapshot["ip_a"], snapshot["mac_a"]),
        "device_b": identify_device(snapshot["ip_b"], snapshot["mac_b"]),
        "analysis": analysis_cache.get(key),
    })


@app.route("/api/device/<ip>")
def api_device(ip):
    """Everything known about one host without probing it: MAC vendor, inferred type,
    reverse DNS, RDAP, and which ports it has been seen using."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": "Invalid IP address"}), 400

    mac, ports, protocols, seen = "", Counter(), Counter(), None
    with conv_lock:
        for c in conversations.values():
            for side in ("a", "b"):
                if c[f"ip_{side}"] != ip:
                    continue
                mac = mac or c[f"mac_{side}"]
                protocols.update(c["protocols"])
                ports.update(c["dst_ports"])
                seen = max(seen or c["last_seen"], c["last_seen"])

    if not mac:
        mac = arp_neighbours().get(ip, "")

    return jsonify({
        "ip": ip,
        "private": is_private_ip(ip),
        "device": identify_device(ip, mac),
        "enrichment": enrich_ip(ip),
        "last_seen": seen,
        "protocols": dict(protocols.most_common()),
        "ports": [{"port": p, "count": n, "matches": PORT_INDEX.get(p, [])}
                  for p, n in ports.most_common(20)],
    })


@app.route("/api/enrichment/<ip>")
def api_enrichment(ip):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": "Invalid IP address"}), 400
    return jsonify(enrich_ip(ip))


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    body = request.get_json(silent=True) or {}
    key = body.get("key", "")
    tier = "deep" if body.get("tier") == "deep" else "standard"
    model = MODEL_DEEP if tier == "deep" else MODEL_STANDARD

    with conv_lock:
        conv = conversations.get(key)
        snapshot = dict(conv) if conv else None
    if snapshot is None:
        return jsonify({"error": "Conversation not found or already idled out"}), 404

    # An explicit click always re-runs: on a live conversation the packet count moves
    # constantly, so a count-keyed cache would never hit anyway. The stored result is
    # for restoring the last analysis when a group is re-expanded.
    limit = 60 if tier == "deep" else 20
    with ring_lock:
        sample = [p for p in packet_ring
                  if conv_key(p["src_ip"], p["dst_ip"]) == key][-limit:]

    prompt = build_analysis_prompt(snapshot, sample, tier == "deep")
    with ollama_lock:
        text, err = call_ollama(model, prompt, 2000 if tier == "deep" else 700)
    if err:
        return jsonify({"error": err}), 502

    result = {
        "analysis": text, "model": model, "tier": tier,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "packets_at_run": snapshot["total"],
    }
    analysis_cache[key] = result
    return jsonify(result)


RECON_OPTIONS = [
    {"group": "Scan type", "exclusive": True, "options": [
        {"flag": "-sn", "label": "Ping sweep", "desc": "Host discovery only, no port scan. Fastest way to see what is alive.", "root": False},
        {"flag": "-sT", "label": "TCP connect", "desc": "Full TCP handshake. Works without root, but noisier and slower.", "root": False},
        {"flag": "-sS", "label": "SYN scan", "desc": "Half-open scan. Faster and quieter than connect, needs root.", "root": True},
        {"flag": "-sU", "label": "UDP scan", "desc": "Finds DNS, DHCP, SNMP, mDNS and SSDP services. Slow; pair with a port list.", "root": True},
    ]},
    {"group": "Identification", "exclusive": False, "options": [
        {"flag": "-sV", "label": "Service versions", "desc": "Banner-grabs each open port to name the software and version.", "root": False},
        {"flag": "-O", "label": "OS detection", "desc": "Fingerprints the TCP/IP stack to guess the operating system.", "root": True},
        {"flag": "--osscan-guess", "label": "Aggressive OS guess", "desc": "Report closest matches even when confidence is low.", "root": True},
        {"flag": "-A", "label": "Aggressive", "desc": "Shorthand for -sV -O plus default scripts and traceroute.", "root": True},
    ]},
    {"group": "Port selection", "exclusive": True, "options": [
        {"flag": "-F", "label": "Fast (top 100)", "desc": "Top 100 ports. Good first pass.", "root": False},
        {"flag": "--top-ports 1000", "label": "Top 1000", "desc": "nmap's default set of most common ports.", "root": False},
        {"flag": "-p-", "label": "All 65535", "desc": "Every TCP port. Thorough but slow.", "root": False},
        {"flag": "-p 22,80,443,445,3389,8080", "label": "Common admin", "desc": "SSH, HTTP, HTTPS, SMB, RDP and HTTP-alt.", "root": False},
    ]},
    {"group": "Device fingerprinting scripts", "exclusive": False, "options": [
        {"flag": "--script smb-os-discovery", "label": "SMB OS", "desc": "Windows and Samba hosts reveal OS, hostname and domain over SMB.", "root": False},
        {"flag": "--script nbstat", "label": "NetBIOS", "desc": "NetBIOS name and MAC. Often names the machine outright.", "root": True},
        {"flag": "--script broadcast-dhcp-discover", "label": "DHCP", "desc": "Asks the DHCP server for lease details and network config.", "root": True},
        {"flag": "--script upnp-info", "label": "UPnP", "desc": "Smart TVs, consoles and media devices advertise make and model.", "root": False},
        {"flag": "--script dns-service-discovery", "label": "mDNS/Bonjour", "desc": "Printers, Chromecasts and speakers announce their type and name.", "root": False},
        {"flag": "--script snmp-info", "label": "SNMP", "desc": "Managed switches, printers and APs expose model and uptime.", "root": True},
        {"flag": "--script http-title", "label": "HTTP title", "desc": "Page title of any web UI, which usually names the device.", "root": False},
        {"flag": "--script ssl-cert", "label": "TLS cert", "desc": "Certificate subject and issuer often identify the appliance.", "root": False},
    ]},
    {"group": "Timing and output", "exclusive": False, "options": [
        {"flag": "-T4", "label": "Faster timing", "desc": "Speeds up scans on a responsive LAN.", "root": False},
        {"flag": "-Pn", "label": "Skip ping", "desc": "Treat the host as up. Use when it does not answer pings.", "root": False},
        {"flag": "-n", "label": "No DNS", "desc": "Skip reverse DNS, which makes scans noticeably faster.", "root": False},
        {"flag": "--reason", "label": "Show reason", "desc": "Explains why nmap called each port open or closed.", "root": False},
        {"flag": "-v", "label": "Verbose", "desc": "Progress and findings as they happen.", "root": False},
        {"flag": "-oN scan.txt", "label": "Save output", "desc": "Write results to scan.txt.", "root": False},
    ]},
]

RECON_PRESETS = [
    {"name": "What is this device?",
     "flags": ["-sV", "-O", "-T4", "--script upnp-info", "--script dns-service-discovery"],
     "desc": "Best single answer to 'what am I looking at' for one host on your LAN."},
    {"name": "Quick look",
     "flags": ["-F", "-T4", "-n"],
     "desc": "Top 100 ports, no DNS. A few seconds per host."},
    {"name": "Full TCP sweep",
     "flags": ["-p-", "-sV", "-T4", "--reason"],
     "desc": "Every port with version detection. Slow but thorough."},
    {"name": "Subnet discovery",
     "flags": ["-sn", "-T4"],
     "desc": "Who is alive on the network. Point this at a CIDR range, not one host."},
    {"name": "UDP services",
     "flags": ["-sU", "--top-ports 1000", "-T4"],
     "desc": "DNS, DHCP, SNMP, mDNS and SSDP. Needs root and takes a while."},
]


@app.route("/api/recon/options")
def api_recon_options():
    return jsonify({"groups": RECON_OPTIONS, "presets": RECON_PRESETS})


@app.route("/")
def dashboard():
    return render_template("dashboard.html", host_ip=HOST_IP, host_hostname=HOST_HOSTNAME)


@app.route("/api/packets")
def api_packets():
    since = request.args.get("since", 0, type=int)
    with ring_lock:
        rows = [p for p in packet_ring if p["no"] > since]
    return jsonify(rows[-500:])


def main():
    global CAPTURE_INTERFACE, PROTOCOL_ROWS, PORT_INDEX, PROTOCOL_REFERENCE, OUI

    parser = argparse.ArgumentParser(description="Packet Monitor")
    parser.add_argument("-i", "--interface", default=CAPTURE_INTERFACE)
    parser.add_argument("-p", "--port", type=int, default=FLASK_PORT)
    parser.add_argument("--log-dir", default=LOG_DIR, help="JSONL capture log directory")
    parser.add_argument("--no-log", action="store_true", help="Disable capture logging")
    args = parser.parse_args()

    CAPTURE_INTERFACE = args.interface
    PROTOCOL_ROWS, PORT_INDEX, PROTOCOL_REFERENCE = parse_memory(MEMORY_PATH)
    OUI = load_oui()

    log_path = None
    if not args.no_log:
        os.makedirs(args.log_dir, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        log_path = os.path.join(args.log_dir, f"capture-{stamp}.jsonl")

    log.info("Interface: %s", CAPTURE_INTERFACE)
    log.info("Host: %s (%s)", HOST_HOSTNAME, HOST_IP)
    log.info("Dashboard: http://localhost:%d", args.port)
    log.info("Capture log: %s", log_path or "disabled")
    log.info("Models: %s (standard), %s (deep)", MODEL_STANDARD, MODEL_DEEP)

    server = make_server(FLASK_HOST, args.port, app, threaded=True)
    capture_thread = threading.Thread(target=capture_loop, daemon=True, name="capture")
    writer_thread = None
    if log_path:
        writer_thread = threading.Thread(target=log_writer, args=(log_path,), daemon=True, name="logwriter")

    def handle_signal(signum, _frame):
        log.info("Signal %d received, shutting down", signum)
        stop_event.set()
        # shutdown() blocks until serve_forever returns, so it cannot run on this thread.
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    capture_thread.start()
    if writer_thread:
        writer_thread.start()
    try:
        server.serve_forever()
    finally:
        stop_event.set()
        server.server_close()
        capture_thread.join(timeout=3)
        if capture_thread.is_alive():
            log.warning("Capture thread did not stop in time")
        if writer_thread:
            # Generous timeout: the writer drains whatever is still queued before exiting.
            writer_thread.join(timeout=10)
            if writer_thread.is_alive():
                log.warning("Log writer did not finish flushing")
        log.info("Shutdown complete")


if __name__ == "__main__":
    main()
