# Paradox Suite v3.0

Production-ready local-network offensive toolkit. Shared core, clean entry points, no broken imports.

## Layout

```
paradox/
  __init__.py
  core.py              # shared discovery, ARP, MITM, blackhole, deauth, port scan
paradox_wifi.py        # WiFi client attack menu (Termux / Linux)
paradox_netscan.py     # full discovery + MITM + reports
paradox_env.py         # environment detector
README.md
```

## Install

```bash
pip install rich scapy
# optional: aircrack-ng, nmap
```

## Run (root required)

```bash
# WiFi focused (kick / blackhole / MITM clients)
sudo python3 paradox_wifi.py

# Full netscan engine
sudo python3 paradox_netscan.py

# Detect what works on this machine
python3 paradox_env.py
```

Termux (rooted):

```bash
su -c 'python3 paradox_wifi.py'
```

## What works

| Action | Needs monitor mode? | Notes |
|--------|---------------------|-------|
| ARP discover | No | Just be connected |
| Port scan | No | |
| ARP black hole (single / mass) | No | Cuts internet instantly |
| ARP MITM | No | Forwards traffic through you |
| 802.11 deauth | Yes | USB adapter on Android |
| Credential sniff | No | Run after MITM |
| JSON / HTML report | No | |

## Design

- One shared `paradox.core` — no duplicated logic, no circular imports
- Each entry point is standalone
- Soft failures: missing scapy/monitor → clear message, rest keeps working
- Clean restore on Ctrl-C for ARP attacks

Authorized testing only. You own the network or have explicit permission.
