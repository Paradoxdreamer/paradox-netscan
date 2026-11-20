# Termux fix

## One command (recommended)

```bash
cd ~/paradox-netscan
bash setup_termux.sh
python paradox_env.py
```

Or without a local clone of the script:

```bash
cd ~/paradox-netscan
curl -sL https://raw.githubusercontent.com/Paradoxdreamer/paradox-netscan/main/setup_termux.sh | bash
python paradox_env.py
```

## What it does

1. Restores truncated `paradox_env.py` / `paradox_netscan.py` / `paradox_wifi.py` from known-good commit `3b7a4e57`
2. Fixes Rich MarkupError in `print_env_menu` (open/close tags must be in the same `console.print`)
3. Shrinks banners to compact 2-line versions

## MarkupError explained

```
rich.errors.MarkupError: closing tag '[/bold green]' doesn't match any open tag
```

Cause: tag opened in one `console.print`, closed in another. Each print is independent.
