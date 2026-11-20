#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# paradox_env.py | Python 3.11+ | Linux · Termux · macOS · Windows · iSH
# Paradox Tech — Universal Environment Engine v1.0
#
# Auto-detects your shell/OS → unlocks every attack that actually runs there.
# If it only works on Linux → Linux module. macOS only → macOS module.
# Termux limited → falls back to what Android can do. Windows → PowerShell suite.
#
# Works standalone OR alongside paradox_netscan_v2_0_0.py + paradox_wifi.py

from __future__ import annotations

import os, sys, platform, subprocess, socket, struct, threading, time
import ctypes, ctypes.util, json, re, random, base64, shutil, tempfile
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

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
[bold red]⛧ PARADOX TECH[/bold red]  [bold white]ENV ENGINE[/bold white]  [dim]v1.0[/dim]
[dim]cross-platform · termux · linux · macos · windows[/dim]
"""

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — ENVIRONMENT DETECTION + CAPABILITY MATRIX
# ═══════════════════════════════════════════════════════════════════════════════

ENV_LINUX   = "linux"
ENV_TERMUX  = "termux"
ENV_MACOS   = "macos"
ENV_WINDOWS = "windows"
ENV_ISH     = "ish"
ENV_UNKNOWN = "unknown"

@dataclass
class EnvCapabilities:
    env:              str
    raw_socket:       bool   = False   # PF_PACKET / BPF raw socket
    monitor_mode:     bool   = False   # 802.11 monitor mode
    iptables:         bool   = False   # netfilter/iptables
    pf:               bool   = False   # macOS pf firewall
    kernel_module:    bool   = False   # LKM insmod
    ld_preload:       bool   = False   # LD_PRELOAD injection
    ptrace:           bool   = False   # ptrace process injection
    ebpf:             bool   = False   # eBPF/XDP
    npcap:            bool   = False   # Windows Npcap
    airport:          bool   = False   # macOS airport utility
    keychain:         bool   = False   # macOS Keychain
    winrm:            bool   = False   # Windows WinRM
    wmi:              bool   = False   # Windows WMI
    registry:         bool   = False   # Windows Registry
    termux_api:       bool   = False   # Termux:API (SMS/GPS/contacts)
    aircrack_ng:      bool   = False   # aircrack-ng suite
    hostapd:          bool   = False   # hostapd evil twin
    dnsmasq:          bool   = False   # dnsmasq
    nmap:             bool   = False   # nmap
    scapy:            bool   = False   # Scapy
    is_root:          bool   = False
    kernel_version:   str    = ""
    arch:             str    = ""
    distro:           str    = ""
    unavailable:      list   = field(default_factory=list)

def detect_environment() -> str:
    """Detect current shell/OS environment."""
    # Windows first (sys.platform is definitive)
    if sys.platform == "win32":
        return ENV_WINDOWS

    # macOS
    if sys.platform == "darwin":
        return ENV_MACOS

    # Android/Termux detection
    if (os.environ.get("TERMUX_VERSION") or
        os.environ.get("PREFIX", "").startswith("/data/data/com.termux") or
        Path("/data/data/com.termux").exists() or
        Path("/system/build.prop").exists()):
        return ENV_TERMUX

    # iSH (iOS Alpine emulation)
    if (Path("/etc/iSH-version").exists() or
        os.environ.get("ISH_VERSION") or
        (Path("/etc/os-release").exists() and
         "ish" in Path("/etc/os-release").read_text().lower())):
        return ENV_ISH

    # Linux (Kali, Parrot, Ubuntu, Arch, etc.)
    if sys.platform.startswith("linux"):
        return ENV_LINUX

    return ENV_UNKNOWN
