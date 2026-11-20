#!/data/data/com.termux/files/usr/bin/bash
# Paradox NetScan — Termux restore + MarkupError fix + compact banners
# Usage:
#   cd ~/paradox-netscan && bash setup_termux.sh
#   curl -sL https://raw.githubusercontent.com/Paradoxdreamer/paradox-netscan/main/setup_termux.sh | bash

set -e
REPO="${1:-$HOME/paradox-netscan}"
GOOD_COMMIT="3b7a4e57c6351aa7977ec7bfd4d5a68dae60a635"

cd "$REPO" 2>/dev/null || {
  echo "[*] Cloning into $REPO ..."
  git clone https://github.com/Paradoxdreamer/paradox-netscan.git "$REPO"
  cd "$REPO"
}

echo "[*] Working in $(pwd)"

# Always restore full sources from known-good commit (fixes truncation + bad patches)
echo "[*] Restoring sources from $GOOD_COMMIT ..."
git fetch origin "$GOOD_COMMIT" 2>/dev/null || true
for f in paradox_env.py paradox_netscan.py paradox_wifi.py; do
  if git show "${GOOD_COMMIT}:$f" > "$f" 2>/dev/null; then
    echo "[+] restored $f"
  elif git checkout "$GOOD_COMMIT" -- "$f" 2>/dev/null; then
    echo "[+] restored $f (checkout)"
  else
    echo "[!] could not restore $f — is this a git clone of paradox-netscan?"
  fi
done

python3 << 'ENDPY'
from pathlib import Path
import re

def shrink_banner(path: Path, name: str, ver: str, sub: str) -> None:
    if not path.exists():
        return
    t = path.read_text(encoding="utf-8", errors="replace")
    new = (
        f'BANNER = r"""\n'
        f"[bold red]☋ PARADOX TECH[/bold red]  [bold white]{name}[/bold white]  [dim]{ver}[/dim]\n"
        f"[dim]{sub}[/dim]\n"
        f'"""'
    )
    t2, n = re.subn(r'BANNER = r"""[\s\S]*?"""', new, t, count=1)
    if n:
        path.write_text(t2, encoding="utf-8")
        print(f"[+] shrunk banner: {path.name}")
    else:
        print(f"[*] banner already compact or missing: {path.name}")

p = Path("paradox_env.py")
if p.exists():
    t = p.read_text(encoding="utf-8", errors="replace")
    fixed = False

    pat = re.compile(
        r'console\.print\(\s*f["\']\\n?\[\{env_color\}\]╔[^\n]*╗["\']\s*\)\s*\n'
        r'\s*console\.print\(\s*f["\']║[^"\']*║["\']\s*\)\s*\n'
        r'\s*console\.print\(\s*f["\']╚[^"\']*╝\[/\{env_color\}\]["\']\s*\)',
        re.M,
    )
    replacement = (
        'root_lbl = "ROOT" if caps.is_root else "NO ROOT"\n'
        '    console.print(\n'
        '        f"\\n[{env_color}]╔═════════════════════════════════════════╗[/]\\n"\n'
        '        f"[{env_color}]║  ENV ENGINE | {caps.env.upper():<8} | {root_lbl:<8} ║[/]\\n"\n'
        '        f"[{env_color}]╚═════════════════════════════════════════╝[/]"\n'
        '    )'
    )
    t2, n = pat.subn(replacement, t, count=1)
    if n:
        t = t2
        fixed = True
        print("[+] fixed Rich MarkupError (regex)")
    else:
        lines = t.splitlines(keepends=True)
        out = []
        i = 0
        while i < len(lines):
            line = lines[i]
            if (not fixed) and "def print_env_menu" in line:
                out.append(line)
                i += 1
                while i < len(lines):
                    if "╔" in lines[i] and "env_color" in lines[i]:
                        while i < len(lines) and any(c in lines[i] for c in ("╔", "║", "╚")):
                            i += 1
                        out.append('    root_lbl = "ROOT" if caps.is_root else "NO ROOT"\n')
                        out.append('    console.print(\n')
                        out.append('        f"\\n[{env_color}]╔═════════════════════════════════════════╗[/]\\n"\n')
                        out.append('        f"[{env_color}]║  ENV ENGINE | {caps.env.upper():<8} | {root_lbl:<8} ║[/]\\n"\n')
                        out.append('        f"[{env_color}]╚═════════════════════════════════════════╝[/]"\n')
                        out.append('    )\n')
                        fixed = True
                        break
                    out.append(lines[i])
                    i += 1
                continue
            out.append(line)
            i += 1
        if fixed:
            t = "".join(out)
            print("[+] fixed Rich MarkupError (fallback)")
        else:
            if "root_lbl" in t and "ENV ENGINE |" in t:
                print("[*] Markup already fixed")
            else:
                print("[!] could not auto-fix menu")

    t2, n = re.subn(
        r'BANNER = r"""[\s\S]*?"""',
        'BANNER = r"""\n[bold red]☋ PARADOX TECH[/bold red]  [bold white]ENV ENGINE[/bold white]  [dim]v1.0[/dim]\n[dim]cross-platform · termux · linux · macos · windows[/dim]\n"""',
        t,
        count=1,
    )
    if n:
        t = t2
        print("[+] shrunk ENV banner")
    p.write_text(t, encoding="utf-8")
    print("[+] wrote", p.resolve())

shrink_banner(Path("paradox_netscan.py"), "NETSCAN", "v2.0.0", "network discovery · security assessment")
shrink_banner(Path("paradox_wifi.py"), "WIFI", "v1.0", "wireless visibility · assessment")
print()
print("Done. Run:")
print("  python paradox_env.py")
print("  python paradox_netscan.py")
print("  python paradox_wifi.py")
ENDPY
