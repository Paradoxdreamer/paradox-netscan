# Paradox NetScan / WiFi Attack Suite

Offensive local-network toolkit (authorized testing only).

## Files
- `paradox_netscan.py` — v1 original
- `paradox_netscan_v2_0_0.py` — full apex engine (ARP/NDP, exploits, MITM, C2, post-ex)
- `paradox_wifi.py` — Termux/Android focused WiFi attack suite (mass kick, blackhole, MITM)
- `paradox_env.py` — universal environment engine (Linux / Termux / macOS / Windows / iSH)

## Quick start
```bash
# Linux / Kali
sudo python3 paradox_netscan_v2_0_0.py

# Termux (rooted)
su -c "python3 paradox_wifi.py"

# Environment detector + platform modules
sudo python3 paradox_env.py
```

## Requirements
```bash
pip install rich scapy requests
# optional: paramiko, aircrack-ng, hostapd, dnsmasq
```

## What it does
- Discover every client on the Wi-Fi
- Mass-kick everyone except you (ARP black-hole or 802.11 deauth)
- MITM, DNS spoof, credential sniff, SSL strip
- Redis / Docker / vsftpd / Telnet / FTP exploitation
- Rogue DHCP, IPv6 RA, NTLM relay, LLMNR responder
- Post-exploitation, persistence, lateral movement, C2 beacon
- Platform-aware modules (only unlocks what the OS can actually run)

Use only on networks you own or have explicit written permission to test.
