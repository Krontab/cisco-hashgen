# cisco-hashgen

[![PyPI version](https://img.shields.io/pypi/v/cisco-hashgen.svg)](https://pypi.org/project/cisco-hashgen/)
[![Python versions](https://img.shields.io/pypi/pyversions/cisco-hashgen.svg)](https://pypi.org/project/cisco-hashgen/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/Krontab/cisco-hashgen/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Krontab/cisco-hashgen/actions/workflows/ci.yml)

<!-- Enable this once downloads look healthy :)
[![Downloads](https://static.pepy.tech/badge/cisco-hashgen)](https://pepy.tech/project/cisco-hashgen)
-->

> Generate and verify Cisco-compatible password hashes for Cisco ASA & IOS/IOS-XE.

**cisco-hashgen** supports the generation and verification of the following formats:

- **Cisco ASA (PBKDF2-SHA512)** → `$sha512$<iter>$B64(salt)$B64(dk16)`
- **Cisco IOS/IOS-XE Type 5** (MD5-crypt) → `$1$<salt>$<hash>`
- **Cisco IOS/IOS-XE Type 8** (PBKDF2-SHA256) → `$8$<Cisco64(salt)>$<Cisco64(dk32)>`
- **Cisco IOS/IOS-XE Type 9** (scrypt) → `$9$<Cisco64(salt)>$<Cisco64(dk32)>`

## Capabilities

- Generate password hashes discretely in a masked (non-echoing) terminal session.
- Generate hashes offline and embed them in config templates.
- Piped input/output for easy integration with other tools like [pass](https://www.passwordstore.org/), [ansible-vault](https://docs.ansible.com/ansible/latest/user_guide/vault.html), or [GitHub Actions](https://docs.github.com/en/actions/security-guides/encrypted-secrets).
- Securely read passwords from the command line, shell, or environment variables.
- Securely read passwords from the macOS Keychain.
- Verify existing hashes offline without touching the device. (audit mode, brute force)

## Why this exists

1) **Generate Cisco-compatible hashes from any system**  
   - Now you don't have to have a Cisco switch or router to generate hashes.  
2) **Bootstrap device configs without plaintext passwords**
   - Pre-generate hashes offline and embed them in config templates.   
   - No more storing or echoing the clear text password.
3) **Verify existing hashes offline**  
   - Check if a password matches a Cisco hash without touching the device.
   - Script out the verification process of many password hashes looking for matches. 
4) **Shoulder surfing and screen share privacy**
   - Generate a valid hash with cisco-hashgen which masks your input by default. 
   - All you see is the hash which you paste into your config or command line.

> 💡 Hashes are only as strong as the password and parameters. Prefer long, random passphrases; keep iteration counts at Cisco defaults (or higher where supported); and protect generated hashes like any credential artifact.

## ⚠️ Cautions
- Hashes produced by this tool ***should*** be able to be used on many Cisco switches, routers, and firewalls but ***please*** test thoroughly before using in production.
- This tool does not support Type 1, 2, 3, 4, or 6. (yet)

## 🚀 Quick Install

**Recommended:** Use [pipx](https://pipx.pypa.io/) to install in an isolated environment.
This avoids dependency conflicts and works the same on Linux, macOS, and Windows.

### Ubuntu / Debian
```text
sudo apt update
sudo apt install pipx
pipx ensurepath
pipx install cisco-hashgen
```

### macOS (Homebrew)
```text
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
```text
cisco-hashgen --help
```

> 💡 If you cannot use pipx, you can still install with:
```text
# Linux/macOS
python3 -m pip install --user cisco-hashgen

# Windows
python -m pip install --user cisco-hashgen

# On Debian/Ubuntu you may need:
python3 -m pip install --user cisco-hashgen --break-system-packages
```

## Quick start

### Generate ASA (PBKDF2-SHA512)
Default operation is interactive password input (password is masked)

```text
~ >> cisco-hashgen -asa
Cisco HashGen v2.0.1rc2 — Generate and verify Cisco-compatible hashes
  ASA PBKDF2-SHA512 defaults: iterations=5000, salt-bytes=16
  IOS/IOS-XE Type 5 (MD5-crypt)
  IOS/IOS-XE Type 8 PBKDF2-SHA256 defaults: iterations=20000, salt-bytes=10
  IOS/IOS-XE Type 9 (scrypt) defaults: N=16384, r=1, p=1, salt-bytes=10
  Validation: minlen=8, maxlen=1024

[Generating ASA PBKDF2-SHA512 hash]
Enter password: ********
Retype to confirm: ********
$sha512$5000$ICO3MWp5LADdvY85gGkqYA==$kji0GEgm5nHqKum7VmoY/w==
```
>💡 Note: cisco-hashgen defaults to -asa output, but you can specify -asa for clarity.

### Generate IOS/IOS-XE Type 9 (ASCII Salt) and use hash in configuration
```text
~ >> cisco-hashgen -ios9 -ios9-salt-mode ascii -quiet
Enter password: ********
Retype to confirm: ********
$9$cFiaINGxv8Gp4U$qG0lKpyM56WpYvZ1B2IY8LX6fInUsHs5NmRbVpyqHDQ

# From Cisco device
switch1#configure terminal
switch1(config)#username admin secret 9 $9$cFiaINGxv8Gp4U$qG0lKpyM56WpYvZ1B2IY8LX6fInUsHs5NmRbVpyqHDQ
```

### Verify a hash (auto-detects hash type!) 
```text
>> cisco-hashgen -v '$sha512$5000$ICO3MWp5LADdvY85gGkqYA==$kji0GEgm5nHqKum7VmoY/w=='
[Verifying ASA PBKDF2-SHA512 hash]
[Enter password to verify against ASA PBKDF2-SHA512]
Enter password to verify: ********
[+] Password matches.
```

### One-liner verify (stdin + -v) - Insecure / Password is visible
```text
echo 'My S3cr3t!' | cisco-hashgen -v '$8$HxHoQOhOgadA7E==$HjROgK8oWfeM45/EHbOwxCC328xBBYz2IF2BevFOSok=' 
[Verifying IOS/IOS-XE Type 8 PBKDF2-SHA256 hash]
[+] Password matches.
```
> 💡 This above example illustrates the tool's flexibility for stdin/stdout. When executed this way, the password is displayed on screen and likely saved in the terminal history or process list. See more secure methods below.

## Supplying passwords securely

### A) Interactive (masked, safest)
```text
cisco-hashgen -asa
```

### B) Shell read (no secret in history)
```text
read -rs PW && printf '%s' "$PW" | cisco-hashgen -asa -quiet && unset PW
# or use env var:
read -rs PW && CISCO_HASHGEN_PWD="$PW" cisco-hashgen -ios8 -env CISCO_HASHGEN_PWD -quiet && unset PW
```

### C) macOS Keychain (GUI → CLI)
1. Open **Keychain Access** → add a new password item (e.g., Service: `HASHGEN_PW`).
2. Use it without revealing plaintext:
```text
security find-generic-password -w -s HASHGEN_PW | cisco-hashgen -asa -quiet
```
3. Remove later with: `security delete-generic-password -s HASHGEN_PW`

### D) pass (Password Store)
```text
brew install pass gnupg
gpg --quick-generate-key "Your Name <you@example.com>" default default never
gpg --list-secret-keys --keyid-format LONG
pass init <YOUR_LONG_KEY_ID>

pass insert -m network/asa/admin <<'EOF'
Str0ngP@ss!
EOF

pass show network/asa/admin | head -n1 | cisco-hashgen -ios8 -v
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
  ```text
  cisco-hashgen -v '$sha512$5000$...$...'
  ```
- For passwords with spaces or shell characters, prefer interactive input, `read -rs`, Keychain, or `pass`.
- If you must put a password on the command line (not recommended), single-quote it; if it contains a single quote, use:
  ```text
  'pa'"'"'ss'
  ```

## CLI

```text
cisco-hashgen -h
usage: cisco-hashgen [-h] [-asa | -ios5 | -ios8 | -ios9] [-verify HASH] [-iter ITER] [-salt-bytes SALT_BYTES]
                     [--ios9-salt-mode {cisco64,ascii,stdb64}] [-minlen MINLEN] [-maxlen MAXLEN] [-pwd STRING]
                     [-env VAR] [-quiet] [-no-color] [-no-prompt] [-V] [-ios9-debug]
```

### options
- `-h, --help` — show this help message and exit
- `-asa` — Generate ASA PBKDF2 (SHA-512) hash (default).
- `-ios5` — Generate IOS/IOS-XE Type 5 (MD5-crypt) hash.
- `-ios8` — Generate IOS/IOS-XE Type 8 (PBKDF2-SHA256) hash.
- `-ios9` — Generate IOS/IOS-XE Type 9 (scrypt) hash.
- `-verify, -v HASH` — Verify a password against an existing hash.
- `-iter ITER` — Override iterations (default: ASA=5000, IOS8=20000).
- `-salt-bytes SALT_BYTES` — Override salt length in bytes (default: ASA=16, IOS8=10, IOS9=10).
- `-ios9-debug` — Enable maximum IOS9 verify diagnostics
- `-ios9-salt-mode` `{cisco64, ascii, stdb64}` — IOS9 salt field mode.  
  - **cisco64** (default) stores Cisco64 text and uses decoded bytes for KDF.
  - **ascii** stores Cisco64 text but uses the literal ASCII text for KDF;
  - **stdb64** stores StdBase64 text and uses that literal ASCII for KDF.
- `-minlen MINLEN` — Minimum password length (default: 8).
- `-maxlen MAXLEN` — Maximum password length (default: 1024).
- `-pwd STRING` — Password provided directly (quote if it contains spaces/shell chars).
- `-env VAR` — Read password from environment variable VAR.
- `-quiet` — Suppress banners and extra output (script-friendly).
- `-no-color` — Disable ANSI colors in help/banners.
- `-no-prompt` — Fail if no password is provided via stdin/-pwd/-env (no interactive prompt).
- `-V, --version` — show program's version number and exit

## Exit codes
- `0` — Success / verified match  
- `1` — Verify mismatch  
- `2` — Unsupported/invalid hash format  
- `3` — Password validation error  
- `4` — No password provided and `-no-prompt` set  
- `130` — User interrupted (Ctrl-C)

## Technical notes

- **ASA**: PBKDF2-HMAC-SHA512; iterations stored; salt Base64; **first 16 bytes** of DK stored.  
  _Why it matters_: Only a portion of the derived key is stored, so reproducing the hash requires exact PBKDF2 parameters and truncation behavior.

- **IOS/IOS-XE Type 5**: MD5-based crypt (`md5crypt`); 1000 iterations (fixed); salt up to 8 chars; Cisco Base64 alphabet (`./0..9A..Za..z`).  
  _Why it matters_: Legacy format, still seen on older systems; uses a fixed iteration count and short salts, making it less secure but widely compatible.

- **IOS/IOS-XE Type 8**: PBKDF2-HMAC-SHA256; **20000** iterations (fixed); salt 10 bytes; Cisco Base64 alphabet (`./0..9A..Za..z`).  
  _Why it matters_: Modern, strong PBKDF2 with fixed parameters; hash reproduction must match iteration count exactly.

- **IOS/IOS-XE Type 9 – Canonical**: scrypt (N=16384, r=1, p=1); salt 14 bytes; Cisco Base64 alphabet (`./0..9A..Za..z`).  
  _Why it matters_: Strongest Cisco hash; requires exact scrypt parameters and binary salt encoding for compatibility.

- **IOS/IOS-XE Type 9 – ASCII Salt**: scrypt (N=16384, r=1, p=1); salt literal ASCII (non-canonical but accepted by some platforms); salt length 14 chars; Cisco Base64 alphabet for hash output only.  
  _Why it matters_: Some devices expect ASCII salt rather than binary; essential for login compatibility on these picky systems.

- **IOS/IOS-XE Type 9 – Mixed Salt**: scrypt (N=16384, r=1, p=1); salt may contain printable ASCII + Cisco64 characters (non-canonical); length still 14; Cisco Base64 alphabet for hash output.  
  _Why it matters_: Rare variant; sometimes seen when salts are generated inconsistently; necessary to replicate for exact hash matching.

## Supported Platforms
- Python 3.8+ (tested on 3.8–3.13)  
- macOS / Linux / Windows

## License
Cisco-Hashgen is available under the MIT license. See the LICENSE file for details.
Author: Gilbert Mendoza

## Changelog
See the [docs/releases](docs/releases/) folder for complete version history, or visit the [GitHub Releases](https://github.com/Krontab/cisco-hashgen/releases) page.
