<div align="center">

<img src="https://files.catbox.moe/sfxhhz.jpg" width="320" alt="Paradox NetScan"/>

# Paradox NetScan

**See the network. Understand the system.**  
*But beware — every host is someone's home.*

<br/>

<a href="https://github.com/Paradoxdreamer/paradox-netscan">
  <img src="https://img.shields.io/badge/status-shipped_anyway-0A2540?style=for-the-badge" alt="status"/>
</a>
<a href="#">
  <img src="https://img.shields.io/badge/python-%3E%3D3.11-339933?style=for-the-badge&logo=python&logoColor=white" alt="python"/>
</a>
<a href="#">
  <img src="https://img.shields.io/badge/root-required-red?style=for-the-badge" alt="root"/>
</a>
<a href="#">
  <img src="https://img.shields.io/badge/license-MIT-blue?style=for-the-badge" alt="mit"/>
</a>

<br/>

<sub>ARP discovery · port scan · MITM · DNS spoof · floods · evil twin · CVE assessment</sub>

</div>

---

<details open>
<summary><b>// This is </b></summary>
<br/>

A network toolkit that finds every device on the LAN, fingerprints what they run, and — if you ask nicely — takes the middle seat between them and their router.

Built as a **package**: `paradox/core.py` (discovery + scan engine) and `paradox/attacks.py` (the loud part), driven by one menu in `paradox_netscan.py`.

| thing | reality |
|:------|:--------|
| discovery | ARP · passive sniff · ARP storm · mDNS/DHCP |
| scan | adaptive threads (RTT-aware) · banner grab · fingerprint |
| assessment | 28 dangerous ports · CVE lookup · risk score 0-100 |
| MITM | HTTP / DNS / TLS SNI / cookies / plain-text creds |
| floods | SYN (raw, threaded) · UDP · deauth · DHCP starvation |
| menu | three sections · live Rich dashboards |
| deploy | pip install · sudo · hope + ethics |

</details>

---

<details open>
<summary><b>// terminal usage (pick your poison)</b></summary>
<br/>

### 🐧 Linux / Kali / Parrot — full power

```bash
sudo apt install -y python3-pip aircrack-ng hostapd dnsmasq
git clone https://github.com/Paradoxdreamer/paradox-netscan.git
cd paradox-netscan
pip install rich scapy requests
sudo python3 paradox_netscan.py
```

Everything works: raw sockets, monitor mode, ARP, injection. This is home turf.

### 🤖 Termux (Android) — half power, no root

```bash
pkg update && pkg install -y git python clang libxml2 libxslt
pip install rich scapy requests
git clone https://github.com/Paradoxdreamer/paradox-netscan.git
cd paradox-netscan
python paradox_netscan.py
```

Works: port scans, banner grab, HTTP/SSH checks, passive discovery.  
Dead without root: ARP MITM, deauth, floods, monitor mode. Rooted phone?  

```bash
su -c 'python paradox_netscan.py'
pkg install aircrack-ng   # + USB WiFi adapter via OTG for deauth
```

### 🍏 iSH (iOS) — potato power

```bash
apk update && apk add python3 py3-pip
pip install rich requests   # skip scapy — no raw sockets on iSH
git clone https://github.com/Paradoxdreamer/paradox-netscan.git
cd paradox-netscan
python3 paradox_netscan.py
```

iSH is an x86 emulator on iOS: no raw sockets, no ARP, no monitor mode. TCP scans and HTTP checks only. Slow. It tries its best.

### 😂 TempleOS — divine power

```bash
# not gonna happen, king
```

TempleOS is a 640×480 holy sandbox with no network stack. You cannot MITM what has no NIC. **Jack ran as root on everything, and so would you — but God does not route packets.** 640x480 resolution, 16 colors, zero open ports. The most secure OS ever shipped. 💀

</details>

---

<details>
<summary><b>// menu (the useful keys)</b></summary>
<br/>

```text
── DISCOVERY ──
1   ARP discovery        find all live hosts
2   passive discovery    silent, zero packets sent
3   ARP storm            flood subnet, fastest discovery
4   host details         full info on one host
5/6 port scan            common / all 65535
7   security assessment  vulns + CVEs + risk score
8   network info         iface · gateway · subnet

── ATTACKS ──
A1  ARP MITM + sniffer   HTTP/DNS/TLS-SNI/cookies/creds
A2  DNS spoof            redirect domains + catch-all
A3/A4 blackhole          kill one host / all of them
A5  TCP RST inject       kill flows with seq prediction
A6  SYN flood            threaded raw, live pps
A7  UDP flood            bandwidth exhaustion
A8  DHCP starvation      exhaust the pool, spoofed MACs
A9  ICMP redirect        reroute via type-5
A10 deauth               monitor mode required
A11 evil twin AP         hostapd + dnsmasq clone
AK  knock detector       passive sequence watch

── OTHER ──
E   export report        JSON
Q   quit
```

</details>

---

<details>
<summary><b>// stack</b></summary>
<br/>

```text
paradox_netscan.py     menu entry · banner · assessment tables
paradox/
  core.py              models · OUI · discovery · adaptive scan · primitives
  attacks.py           MITM sniffer · DNS spoof · RST · floods · evil twin …
```

- rich: tables, live dashboards, banners (it is 80% of the aesthetic)
- scapy: packet craft — ARP, DNS, 802.11
- requests: live NVD CVE lookup

</details>

---

<details>
<summary><b>// known vibes</b></summary>
<br/>

| works if… | might flake if… |
|:----------|:-----------------|
| running as root | you typed python3 without sudo |
| wifi iface supports monitor | phone chipset (it does not) |
| scapy installed | slim containers without pcap |
| target is yours | it is not — then close the tool |

</details>

---

<details>
<summary><b>// rules (read this)</b></summary>
<br/>

**Only run this on networks and devices you own or have explicit permission to test.**  
MITM, deauth and floods are lab tools. On someone else's LAN they are not a vibe, they are a charge sheet.

</details>

---

<div align="center">

<br/>

**Powered by: paradox overlord**

<sub>MIT · © Paradoxdreamer · Paradox Tech 2026</sub>

<br/>

```text
Built with curiosity.
Refined through failure.
Shipped anyway.
```

</div>
