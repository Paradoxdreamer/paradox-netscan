#!/data/data/com.termux/files/usr/bin/bash
# Fix Rich MarkupError + shrink banners for paradox-netscan
# Usage:
#   cd ~/paradox-netscan
#   bash termux_fix.sh
# Or:
#   curl -sL https://raw.githubusercontent.com/Paradoxdreamer/paradox-netscan/main/termux_fix.sh | bash

set -e
cd "${1:-$HOME/paradox-netscan}"

if [ ! -f paradox_env.py ]; then
  echo "[!] paradox_env.py not found in $(pwd)"
  echo "    git clone https://github.com/Paradoxdreamer/paradox-netscan.git"
  exit 1
fi

# Restore full file if it was corrupted to a placeholder
if [ "$(wc -c < paradox_env.py)" -lt 1000 ]; then
  echo "[*] paradox_env.py looks truncated — restoring from last good commit"
  git fetch origin 2>/dev/null || true
  git checkout 3b7a4e57c6351aa7977ec7bfd4d5a68dae60a635 -- paradox_env.py 2>/dev/null \
    || git show 3b7a4e57c6351aa7977ec7bfd4d5a68dae60a635:paradox_env.py > paradox_env.py
fi

python3 << 'PY'
from pathlib import Path
import re

p = Path("paradox_env.py")
t = p.read_text(encoding="utf-8")

old = """    console.print(f"\n[{env_color}]╔══════════════════════════════════════════════════════╗")
    console.print(f"║  PARADOX ENV ENGINE  |  {caps.env.upper():<10}  |  {'ROOT' if caps.is_root else 'NO ROOT':<8}  ║")
    console.print(f"╚══════════════════════════════════════════════════════╝[/{env_color}]")"""

new = """    root_lbl = "ROOT" if caps.is_root else "NO ROOT"
    console.print(
        f"\n[{env_color}]╔════════════════════════════════════════╗[/]\n"
        f"[{env_color}]║  ENV ENGINE | {caps.env.upper():<8} | {root_lbl:<8} ║[/]\n"
        f"[{env_color}]╚════════════════════════════════════════╝[/]"
    )"""

if old in t:
    t = t.replace(old, new)
    print("[+] fixed Rich MarkupError (print_env_menu)")
elif "ENV ENGINE |" in t and "[/{env_color}]" not in t:
    print("[*] markup already fixed")
else:
    print("[!] markup block not found — file may differ; try git pull")

t2, n = re.subn(
    r'BANNER = r"""[\s\S]*?"""',
    '''BANNER = r"""
[bold red]⛧ PARADOX TECH[/bold red]  [bold white]ENV ENGINE[/bold white]  [dim]v1.0[/dim]
[dim]cross-platform · termux · linux · macos · windows[/dim]
"""''',
    t,
    count=1,
)
if n:
    t = t2
    print("[+] shrunk ENV banner")
else:
    print("[*] ENV banner unchanged")

p.write_text(t, encoding="utf-8")
print("[+] wrote", p.resolve())
PY

for f in paradox_netscan.py paradox_wifi.py; do
  [ -f "$f" ] || continue
  python3 - "$f" << 'PY'
import sys, re
from pathlib import Path
p = Path(sys.argv[1])
t = p.read_text(encoding="utf-8")
if "netscan" in p.name:
    name, ver, sub = "NETSCAN", "v2.0.0", "network discovery · security assessment"
else:
    name, ver, sub = "WIFI", "v1.0", "wireless visibility · assessment"
new = f'''BANNER = r"""
[bold red]⛧ PARADOX TECH[/bold red]  [bold white]{name}[/bold white]  [dim]{ver}[/dim]
[dim]{sub}[/dim]
"""'''
t2, n = re.subn(r'BANNER = r"""[\s\S]*?"""', new, t, count=1)
if n:
    p.write_text(t2, encoding="utf-8")
    print(f"[+] shrunk banner in {p.name}")
else:
    print(f"[*] no banner change in {p.name}")
PY
done

echo
echo "Done. Run:  python paradox_env.py"
