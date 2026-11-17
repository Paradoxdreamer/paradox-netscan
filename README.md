# Paradox NetScan v1.0

WiFi recon + host attack framework.

## Features
- Scan nearby WiFi networks (nmcli / iwlist)
- Connect to chosen AP
- ARP host discovery
- Quick + deep port scan
- Attack menu:
  - ARP poison (MITM)
  - 802.11 deauth
  - OS fingerprint
  - HTTP intercept / DNS spoof
  - SMB / Telnet / SSH / FTP / VNC / RDP probes
  - ICMP / SYN / UDP floods
  - Passive pcap capture
  - mDNS + NetBIOS enum

## Requirements
```bash
pip install scapy netifaces rich
# optional: paramiko for SSH brute
```

Must run as root.

```bash
sudo python paradox_netscan.py
```

Termux: `pkg install nmap python && pip install scapy netifaces rich` then `tsu` / root.

## Notes
For authorized testing only. You own the network or have explicit permission.
