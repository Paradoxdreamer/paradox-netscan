# Paradox NetScan

**See the network. Understand the system.**

Python network research toolkit — discovery, host inspection, Wi‑Fi research, environment capability matrix.

| Module | File | What it does |
|--------|------|----------------|
| Env Engine | `paradox_env.py` | Detect OS/root/capabilities → interactive menu |
| NetScan | `paradox_netscan.py` | LAN discovery, ports, services, assessment |
| Wi‑Fi | `paradox_wifi.py` | Wireless visibility / assessment |

---

## Quick start (clone → run)

### Linux / Kali / Parrot

```bash
git clone https://github.com/Paradoxdreamer/paradox-netscan.git
cd paradox-netscan
pip install rich scapy requests
python3 paradox_env.py          # banner + capability menu
python3 paradox_netscan.py      # main netscan menu
python3 paradox_wifi.py         # wifi menu
```

### Termux (Android)

```bash
pkg update
pkg install -y git python clang libxml2 libxslt
pip install rich scapy requests

git clone https://github.com/Paradoxdreamer/paradox-netscan.git
cd paradox-netscan

# Restore full sources + fix MarkupError + compact banners:
bash setup_termux.sh
# or:
# curl -sL https://raw.githubusercontent.com/Paradoxdreamer/paradox-netscan/main/setup_termux.sh | bash

python paradox_env.py
python paradox_netscan.py
python paradox_wifi.py
```

**Root note (Termux):** Without root, ARP/Scapy raw sockets, monitor mode, and injection stay blocked. Env menu and limited TCP checks still work. Use a rooted device or a Linux box for full features.

---

## Commands cheat sheet

| Goal | Command |
|------|---------|
| Environment / capability menu | `python3 paradox_env.py` |
| Network assessment menu | `python3 paradox_netscan.py` |
| Wi‑Fi research menu | `python3 paradox_wifi.py` |
| Fix Rich MarkupError only | `bash fix_markup_now.sh` |
| Full Termux restore + fix | `bash setup_termux.sh` |

After launch you should see a **compact 2‑line banner** and an interactive menu (not a crash).

---

## Dependencies

```bash
pip install rich scapy requests
```

Optional system tools (Linux): `nmap`, `aircrack-ng`, `hostapd`, `dnsmasq`.

---

## Responsible use

Only use on networks and devices you own or have explicit permission to test. Traffic interception and disruption features are for controlled labs only.

---

**Paradox Tech · 2026**
