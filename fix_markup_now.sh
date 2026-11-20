#!/data/data/com.termux/files/usr/bin/bash
# One-shot fix for Rich MarkupError in paradox_env.py
set -e
cd "${1:-$HOME/paradox-netscan}"
if [ ! -f paradox_env.py ]; then
  echo "[!] paradox_env.py not found in $(pwd)"
  exit 1
fi

python3 << 'ENDPY'
from pathlib import Path
import re

p = Path("paradox_env.py")
t = p.read_text(encoding="utf-8")

fixed = False

# Pattern: three separate console.print calls that open/close a Rich color tag across prints
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
    print("[+] fixed Rich MarkupError (regex path)")
else:
    # Fallback: rewrite around the box lines inside print_env_menu
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
                    # skip all consecutive box lines
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
        print("[+] fixed Rich MarkupError (fallback path)")
    else:
        print("[!] could not locate menu box")
        print("    Manual: open paradox_env.py, find print_env_menu, make the 3 box prints one single console.print")

# Shrink banner if still large
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
print("Run:  python paradox_env.py")
ENDPY
