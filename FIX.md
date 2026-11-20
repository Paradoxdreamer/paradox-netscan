# Quick fix (Termux)

Crash:
```
rich.errors.MarkupError: closing tag '[/bold green]' at position 56 doesn't match any open tag
```

Cause: `print_env_menu` opened a Rich color tag in one `console.print` and closed it in another. Each print is independent, so the close tag had nothing to match.

## One command

```bash
cd ~/paradox-netscan
curl -sL https://raw.githubusercontent.com/Paradoxdreamer/paradox-netscan/main/termux_fix.sh | bash
python paradox_env.py
```

Or:

```bash
cd ~/paradox-netscan
bash termux_fix.sh
```

If `paradox_env.py` was truncated on GitHub, the script restores it from commit `3b7a4e57` then applies the fix.
