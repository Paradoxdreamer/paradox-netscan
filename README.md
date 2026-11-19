# Paradox Suite v3.0

Local-network offensive toolkit. Shared core, clean entry points.

## Layout (target)

```
paradox-netscan/
├── README.md
├── paradox/
│   ├── __init__.py
│   └── core.py          # shared ARP/MITM/blackhole/deauth/scan
├── paradox_wifi.py      # WiFi client attacks (Termux/Linux)
├── paradox_netscan.py   # full recon + reports
└── paradox_env.py       # platform detector
```

## Install

```bash
pip install rich scapy
```

## Run (root)

```bash
sudo python3 paradox_wifi.py
sudo python3 paradox_netscan.py
python3 paradox_env.py
```

Termux: `su -c 'python3 paradox_wifi.py'`

## Note on sources

Full production sources are maintained outside the thin placeholders on this branch.
Clone, replace the placeholder files with the v3 sources, then:

```bash
git add -A && git commit -m "v3 full sources" && git push
```

Authorized testing only.
