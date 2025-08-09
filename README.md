# cisco-hashgen

[![PyPI version](https://img.shields.io/pypi/v/cisco-hashgen.svg)](https://pypi.org/project/cisco-hashgen/)
[![Python versions](https://img.shields.io/pypi/pyversions/cisco-hashgen.svg)](https://pypi.org/project/cisco-hashgen/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/Krontab/cisco-hashgen/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Krontab/cisco-hashgen/actions/workflows/ci.yml)

<!-- Enable this once downloads look healthy :)
[![Downloads](https://static.pepy.tech/badge/cisco-hashgen)](https://pepy.tech/project/cisco-hashgen)
-->

> Generate and verify Cisco-compatible PBKDF2 password hashes for ASA & IOS/IOS-XE.

Generate and verify Cisco-compatible **PBKDF2** password hashes from the command line.

**Supported formats**
- **ASA**: PBKDF2-HMAC-SHA512 — `$sha512$<iter>$<Base64(salt)>$<Base64(dk16)>`
- **IOS / IOS-XE Type 8**: PBKDF2-HMAC-SHA256 — `$8$<Cisco64(salt10)>$<Cisco64(dk32)>`

## 🚀 Quick Install

**Recommended:** Use [pipx](https://pipx.pypa.io/) to install in an isolated environment.
This avoids dependency conflicts and works the same on Linux, macOS, and Windows.

### Ubuntu / Debian
```bash
sudo apt update
sudo apt install pipx
pipx ensurepath
pipx install cisco-hashgen
```

### macOS (Homebrew)
```bash
brew install pipx
pipx ensurepath
pipx install cisco-hashgen
```

### Windows (PowerShell)
```powershell
python -m pip install --user pipx
python -m pipx ensurepath
pipx install cisco-hashgen
```

### Verify installation
```bash
cisco-hashgen --help
```

> 💡 If you cannot use pipx, you can still install with:
> ```bash
> # Linux/macOS
> python3 -m pip install --user cisco-hashgen
> # Windows
> python -m pip install --user cisco-hashgen
> # On Debian/Ubuntu you may need:
> python3 -m pip install --user cisco-hashgen --break-system-packages
> ```


## Why this exists

1) **Bootstrap without plaintext**  
   Pre-generate hashes offline and embed them in config templates—without storing or echoing the clear text password.

2) **Verify existing hashes offline**  
   Check if a password matches a Cisco hash without touching the device.

> 💡 Hashes are only as strong as the password and parameters. Prefer long, random passphrases; keep iteration counts at Cisco defaults (or higher where supported); and protect generated hashes like any credential artifact.

## Quick start

### Generate ASA (PBKDF2-SHA512)
```bash
# interactive (masked)
cisco-hashgen
cisco-hashgen -asa
````
>💡 Note: cisco-hashgen defaults to -asa output, but you can specify -asa for clarity.

### Generate IOS/IOS-XE Type 8 (PBKDF2-SHA256)
```bash
# interactive (masked)
cisco-hashgen -ios8
```

### Verify a hash (offline)
```bash
# ASA
cisco-hashgen -v '$sha512$5000$...$...'

# IOS/IOS-XE Type 8
cisco-hashgen -v '$8$SALT$HASH'
```

### One-liner verify (stdin + -v) - Not Recommended
> 💡 When executed this way, a password is displayed on screen and likely saved in the systems command history or process list. It however illustrates the tool's flexibility.
>```bash
>echo 'My S3cr3t!' | cisco-hashgen -ios8 -quiet -v '$8$HxHoQOhOgadA7E==$HjROgK8oWfeM45/EHbOwxCC328xBBYz2IF2BevFOSok='
>```

## Supplying passwords securely

### A) Interactive (masked, safest)
```bash
cisco-hashgen -asa
```

### B) Shell read (no secret in history)
```bash
read -rs PW && printf '%s' "$PW" | cisco-hashgen -asa -quiet && unset PW
# or use env var:
read -rs PW && CISCO_HASHGEN_PWD="$PW" cisco-hashgen -ios8 -env CISCO_HASHGEN_PWD -quiet && unset PW
```

### C) macOS Keychain (GUI → CLI)
1. Open **Keychain Access** → add a new password item (e.g., Service: `HASHGEN_PW`).
2. Use it without revealing plaintext:
   ```bash
   security find-generic-password -w -s HASHGEN_PW | cisco-hashgen -asa -quiet
   ```
3. Remove later with: `security delete-generic-password -s HASHGEN_PW`

### D) pass (Password Store)
```bash
brew install pass gnupg
gpg --quick-generate-key "Your Name <you@example.com>" default default never
gpg --list-secret-keys --keyid-format LONG
pass init <YOUR_LONG_KEY_ID>

pass insert -m network/asa/admin <<'EOF'
Str0ngP@ss!
EOF

pass show network/asa/admin | head -n1 | cisco-hashgen -ios8 -quiet
```

### E) CI secret environment variable (GitHub Actions)
```yaml
- name: Generate ASA hash
  env:
    CISCO_HASHGEN_PWD: ${{ secrets.CISCO_HASHGEN_PWD }}
  run: |
    cisco-hashgen -asa -env CISCO_HASHGEN_PWD -quiet > hash.txt
```

## Quoting cheatsheet (very important)

- Always **single-quote** `$sha512...` / `$8$...` hashes to avoid `$` expansion:
  ```bash
  cisco-hashgen -v '$sha512$5000$...$...'
  ```
- For passwords with spaces or shell characters, prefer interactive input, `read -rs`, Keychain, or `pass`.
- If you must put a password on the command line (not recommended), single-quote it; if it contains a single quote, use:
  ```bash
  'pa'"'"'ss'
  ```

## CLI

```text
usage: cisco-hashgen [-asa | -ios8] [-v HASH] [-iter N] [-salt-bytes N]
                     [-minlen N] [-maxlen N] [-pwd STRING] [-env VAR]
                     [-quiet] [-no-color] [-no-prompt] [--version]
```

- `-asa` — Generate ASA PBKDF2 (SHA-512). Default mode.
- `-ios8` — Generate IOS/IOS-XE Type 8 PBKDF2-SHA256.
- `-v, -verify HASH` — Verify a candidate password against an existing hash.
- `-iter N` — Override iterations (ASA default **5000**; IOS8 fixed **20000**).
- `-salt-bytes N` — Override salt length (ASA default **16**; IOS8 default **10**).
- `-minlen N`, `-maxlen N` — Validation bounds (defaults **8** and **1024**).
- `-pwd STRING` — Password literal (quote it if it has spaces/shell chars).
- `-env VAR` — Read password from environment variable `VAR`.
- `-quiet` — Suppress banners and extra output.
- `-no-color` — Disable ANSI coloring in help/banners.
- `-no-prompt` — **Fail** if no non-interactive password is provided (stdin/`-pwd`/`-env`). Useful for CI.
- `--version` — Print version and exit.

## Exit codes
- `0` — Success / verified match  
- `1` — Verify mismatch  
- `2` — Unsupported/invalid hash format  
- `3` — Password validation error  
- `4` — No password provided and `-no-prompt` set  
- `130` — User interrupted (Ctrl-C)

## Technical notes

- **ASA**: PBKDF2-HMAC-SHA512; iterations stored; salt Base64; **first 16 bytes** of DK stored.  
- **IOS/IOS-XE Type 8**: PBKDF2-HMAC-SHA256; **20000** iterations (fixed); salt 10 bytes; Cisco Base64 alphabet (`./0..9A..Za..z`).

## Compatibility
- Python 3.8+ (tested on 3.8–3.13)  
- macOS / Linux / WSL

## License
MIT © Gilbert Mendoza

## Changelog
See the [docs/releases](docs/releases/) folder for complete version history, or visit the [GitHub Releases](https://github.com/Krontab/cisco-hashgen/releases) page.
