#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Paradox Universal Environment Engine v3.0
Detects OS and unlocks only what actually runs here.
"""

from __future__ import annotations

import os
import sys
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from paradox.core import console, VERSION
from rich.prompt import Prompt
from rich.table import Table
from rich import box

BANNER = rf"""
[bold red]
  ███████╗███╗   ██╗██╗   ██╗
  ██╔════╝████╗  ██║██║   ██║
  █████╗  ██╔██╗ ██║██║   ██║
  ██╔══╝  ██║╚██╗██║╚██╗ ██╔╝
  ███████╗██║ ╚████║ ╚████╔╝ 
  ╚══════╝╚═╝  ╚═══╝  ╚═══╝  
[/bold red]
[bold yellow]  PARADOX ENV v{VERSION}  |  Linux · Termux · macOS · Windows · iSH[/bold yellow]
[dim]  auto-detect → unlock only what works here[/dim]
"""

ENV_LINUX, ENV_TERMUX, ENV_MACOS, ENV_WINDOWS, ENV_ISH, ENV_UNKNOWN = (
    "linux", "termux", "macos", "windows", "ish", "unknown"
)


@dataclass
class Caps:
    env: str
    is_root: bool = False
    scapy: bool = False
    nmap: bool = False
    aircrack: bool = False
    raw_socket: bool = False
    monitor: bool = False
    arch: str = ""
    distro: str = ""


def detect_env() -> str:
    if sys.platform == "win32":
        return ENV_WINDOWS
    if sys.platform == "darwin":
        return ENV_MACOS
    if (
        os.environ.get("TERMUX_VERSION")
        or os.environ.get("PREFIX", "").startswith("/data/data/com.termux")
        or Path("/data/data/com.termux").exists()
    ):
        return ENV_TERMUX
    if Path("/etc/iSH-version").exists():
        return ENV_ISH
    if sys.platform.startswith("linux"):
        return ENV_LINUX
    return ENV_UNKNOWN


def probe(env: str) -> Caps:
    c = Caps(env=env)
    c.is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    c.arch = platform.machine()
    try:
        import scapy  # noqa: F401
        c.scapy = True
    except ImportError:
        pass
    c.nmap = shutil.which("nmap") is not None
    c.aircrack = shutil.which("aireplay-ng") is not None or shutil.which("aircrack-ng") is not None
    c.raw_socket = c.is_root and env in (ENV_LINUX, ENV_TERMUX, ENV_MACOS)
    c.monitor = c.is_root and env in (ENV_LINUX, ENV_TERMUX)
    if env == ENV_LINUX:
        try:
            c.distro = Path("/etc/os-release").read_text().split("PRETTY_NAME=")[1].split("\n")[0].strip('"')
        except Exception:
            c.distro = "Linux"
    elif env == ENV_TERMUX:
        c.distro = "Android/Termux"
    elif env == ENV_MACOS:
        c.distro = f"macOS {platform.mac_ver()[0]}"
    elif env == ENV_WINDOWS:
        c.distro = f"Windows {platform.win32_ver()[0]}"
    else:
        c.distro = env
    return c


def print_caps(c: Caps) -> None:
    t = Table(
        title=f"[bold red]{c.env.upper()}  |  {c.distro}  |  {c.arch}[/bold red]",
        box=box.MINIMAL_DOUBLE_HEAD,
    )
    t.add_column("Capability", style="cyan", width=20)
    t.add_column("Status", width=10)
    t.add_column("Note", style="dim")

    def row(name: str, ok: bool, note: str = "") -> None:
        t.add_row(name, "[green]YES[/green]" if ok else "[red]NO[/red]", note)

    row("Root", c.is_root, "needed for raw sockets")
    row("Scapy", c.scapy, "packet craft")
    row("nmap", c.nmap, "port scan")
    row("aircrack-ng", c.aircrack, "deauth / crack")
    row("Raw socket", c.raw_socket, "ARP / MITM")
    row("Monitor mode", c.monitor, "802.11 deauth")
    console.print(t)


def main() -> None:
    console.print(BANNER)
    env = detect_env()
    caps = probe(env)
    console.print(
        f"[bold green]Detected: {caps.env.upper()}  |  {caps.distro}  |  "
        f"{'ROOT' if caps.is_root else 'no root'}[/bold green]\n"
    )
    print_caps(caps)

    if not caps.is_root and caps.env not in (ENV_WINDOWS, ENV_ISH):
        console.print("[yellow][!] Not root — most attacks will fail.[/yellow]")
        if caps.env == ENV_TERMUX:
            console.print("[dim]  su -c 'python3 paradox_env.py'[/dim]")
        else:
            console.print("[dim]  sudo python3 paradox_env.py[/dim]")

    console.print("\n[bold]Recommended next step:[/bold]")
    if caps.env in (ENV_LINUX, ENV_TERMUX):
        console.print("  [cyan]sudo python3 paradox_wifi.py[/cyan]   — WiFi client attacks")
        console.print("  [cyan]sudo python3 paradox_netscan.py[/cyan] — full netscan engine")
    elif caps.env == ENV_MACOS:
        console.print("  [cyan]sudo python3 paradox_netscan.py[/cyan]")
    else:
        console.print("  Limited on this platform. Use Linux/Termux for full suite.")

    console.print("\n[dim]env engine is detection + guidance. Attack logic lives in wifi/netscan.[/dim]")


if __name__ == "__main__":
    main()
