# Paradox NetScan

**See the network. Understand the system.**

Python network discovery, assessment and attack toolkit — v4.0.0, packaged and clean.

| Module | File | What it does |
|--------|------|----------------|
| Core | `paradox/core.py` | Host/NetworkInfo models, OUI lookup, ARP discovery, adaptive port scan, core attack primitives |
| Attacks | `paradox/attacks.py` | MITM + sniffer, DNS spoof, TCP RST injection, SYN/UDP floods, DHCP starvation, ICMP redirect, evil twin, ARP storm, passive discovery, knock detector |
| Entry | `paradox_netscan.py` | Interactive menu — discovery · assessment · attacks |

---

## Quick start

```bash
git clone https://github.com/Paradoxdreamer/paradox-netscan.git
cd paradox-netscan
pip install rich scapy requests
sudo python3 paradox_netscan.py
```

Root required for raw sockets, ARP, monitor mode and injection. Port scans and passive discovery work without it.

---

## Menu

**Discovery** — ARP scan, passive discovery (zero packets sent), ARP storm, host details, common + full port scans, security assessment with CVE lookup, network info.

**Attacks** — A1 ARP MITM + sniffer (HTTP / DNS / TLS SNI / cookies / credentials) · A2 DNS spoof with catch-all · A3/A4 ARP blackhole single + mass · A5 TCP RST injection with sequence prediction · A6 multi-threaded SYN flood with live pps tracking · A7 raw UDP flood · A8 DHCP starvation with spoofed MACs · A9 ICMP redirect · A10 Wi-Fi deauth (monitor mode) · A11 evil twin AP (hostapd + dnsmasq) · AK port knock detector.

**Other** — JSON report export.

---

## Dependencies

```bash
pip install rich scapy requests
```

Optional system tools (Linux): `nmap`, `aircrack-ng`, `hostapd`, `dnsmasq`, `iw`.

Works on Linux / Kali / Parrot. Android Termux works for TCP-side features only — raw sockets and monitor mode need root.

---

## Responsible use

Only use on networks and devices you own or have explicit permission to test. Traffic interception and disruption features are for controlled labs only.

---

**Paradox Tech · 2026**
