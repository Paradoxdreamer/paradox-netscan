#!/usr/bin/env bash
# Paradox — binary release builder (PyInstaller)
# Run on Linux (or WSL). Produces one-file binaries with no .py shipped.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

echo "[*] installing build deps..."
python3 -m pip install -q --upgrade pip
python3 -m pip install -q pyinstaller rich scapy requests

OUT="${ROOT}/dist"
mkdir -p "$OUT" build

build_one() {
  local name="$1"
  local entry="$2"
  echo "[*] building $name from $entry ..."
  pyinstaller \
    --onefile \
    --name "$name" \
    --clean \
    --noconfirm \
    --paths "$ROOT" \
    --hidden-import=scapy \
    --hidden-import=scapy.all \
    --hidden-import=rich \
    --hidden-import=rich.console \
    --hidden-import=rich.table \
    --hidden-import=rich.panel \
    --hidden-import=rich.prompt \
    --collect-all scapy \
    --collect-all rich \
    "$entry"
  echo "[+] $OUT/$name"
}

build_one "paradox-wifi"    "paradox_wifi.py"
build_one "paradox-netscan" "paradox_netscan.py"
build_one "paradox-env"     "paradox_env.py"

echo
echo "[done] binaries:"
ls -lh dist/paradox-* 2>/dev/null || ls -lh dist/
echo
echo "ship only the files in dist/ — do not ship .py sources"
