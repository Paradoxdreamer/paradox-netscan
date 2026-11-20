# Paradox — Binary releases (no source to users)

## Goal

- Source stays in a **private** repo (or only on your machine)
- Users get **binaries** only → `git clone` is not how they install

## One-time setup (you)

```bash
# 1. Make GitHub repo private (Settings → Danger Zone / Change visibility)

# 2. On a Linux build machine (or WSL):
cd paradox-netscan
chmod +x build_binaries.sh
./build_binaries.sh
```

Output:

```
dist/paradox-wifi
dist/paradox-netscan
dist/paradox-env
```

## Ship to users

**Option A — GitHub Release (private repo)**  
- Releases → Draft → upload the three binaries  
- Only people with repo access can download  

**Option B — Direct link**  
- Upload `dist/*` to your host / drive  
- Send link + short run notes  

Users never get `.py` files.

## User run

```bash
chmod +x paradox-wifi paradox-netscan paradox-env
sudo ./paradox-wifi
sudo ./paradox-netscan
./paradox-env
```

Still needs: root for attacks, and system libs scapy expects (normal on Kali/Termux with deps installed).

## Harder reverse-engineering (optional)

```bash
pip install nuitka
python3 -m nuitka --onefile --standalone paradox_wifi.py
```

Nuitka compiles to C then native code — heavier build, harder to recover source than PyInstaller.

## Limits (honest)

- Binaries can still be reverse-engineered
- Raises the bar from “open the .py” to “reverse a binary”
- Does **not** equal perfect secrecy — only real secrecy is not distributing the tool

## Fast path summary

1. Repo → private  
2. `./build_binaries.sh`  
3. Upload `dist/` as a Release or direct download  
4. Users run binaries only  
