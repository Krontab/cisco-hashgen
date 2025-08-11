#!/usr/bin/env python3
"""Cisco HashGen — Cisco-compatible password hashing CLI.

Supported:
- ASA: PBKDF2-HMAC-SHA512 -> $sha512$<iter>$<Base64(salt)>$<Base64(dk16)>
- IOS/IOS-XE Type 8: PBKDF2-HMAC-SHA256 -> $8$<Cisco64(salt10)>$<Cisco64(dk32)>
- IOS/IOS-XE Type 5: MD5-crypt -> $1$<salt up to 8 chars>$<crypt64>
- IOS/IOS-XE Type 9: scrypt -> $9$<Cisco64(salt)>$<Cisco64(dk32)>
"""
import sys, os, argparse, base64, hashlib, hmac, secrets

try:
    from . import __version__ as _VERSION
except Exception:
    _VERSION = "2.0.0"

# Defaults
ASA_DEFAULT_ITER = 5000
ASA_DEFAULT_SALT = 16
IOS8_DEFAULT_ITER = 20000
IOS8_DEFAULT_SALT = 10
IOS9_DEFAULT_SALT = 14  # Cisco commonly uses ~14 bytes
IOS9_DEFAULT_N = 16384  # 2^14
IOS9_DEFAULT_r = 1
IOS9_DEFAULT_p = 1
MINLEN_DEFAULT = 8
MAXLEN_DEFAULT = 1024

# ANSI helpers
ANSI = {
    "reset": "\x1b[0m",
    "bold":  "\x1b[1m",
    "blue":  "\x1b[34m",
    "green": "\x1b[32m",
    "cyan":  "\x1b[36m",
    "yellow":"\x1b[33m",
}
def colorize(s, *styles, use_color=True):
    if not use_color:
        return s
    prefix = "".join(ANSI.get(x, "") for x in styles)
    return f"{prefix}{s}{ANSI['reset']}"

def build_description(use_color):
    title = colorize(f"Cisco HashGen v{_VERSION} — Generate and verify Cisco-compatible hashes", "bold", "cyan", use_color=use_color)
    defaults_hdr = colorize("Defaults:", "bold", "green", use_color=use_color)
    quoting_hdr  = colorize("Quoting Guide (-verify and -pwd):", "bold", "blue", use_color=use_color)
    return f"""{title}
{defaults_hdr}
  {colorize('ASA PBKDF2-SHA512', 'yellow', use_color=use_color)}: iterations={ASA_DEFAULT_ITER}, salt-bytes={ASA_DEFAULT_SALT}
  {colorize('IOS/IOS-XE Type 8 PBKDF2-SHA256', 'yellow', use_color=use_color)}: iterations={IOS8_DEFAULT_ITER}, salt-bytes={IOS8_DEFAULT_SALT}
  {colorize('IOS/IOS-XE Type 5 MD5-crypt', 'yellow', use_color=use_color)}: salt up to 8 chars (system crypt)
  {colorize('IOS/IOS-XE Type 9 scrypt', 'yellow', use_color=use_color)}: N={IOS9_DEFAULT_N}, r={IOS9_DEFAULT_r}, p={IOS9_DEFAULT_p}, salt-bytes={IOS9_DEFAULT_SALT}
  Validation: minlen={MINLEN_DEFAULT}, maxlen={MAXLEN_DEFAULT}

{quoting_hdr}
  Hashes for -verify:
    Always wrap hashes in *single quotes* to prevent shell $-expansion:
      cisco-hashgen -v '$sha512$5000$abcd...$efgh...'
      cisco-hashgen -v '$8$SALT$HASH'
      cisco-hashgen -v '$1$SALT$HASH'
      cisco-hashgen -v '$9$SALT$HASH'

  Passwords for -pwd:
    Use single quotes when your password contains spaces or shell chars ($ ! etc):
      cisco-hashgen -pwd 'pa ss $weird!'
    If your password contains a single quote, close/open and insert it literally:
      cisco-hashgen -pwd 'pa'\"'\"'ss'

  Automation-safe:
    echo 'password' | cisco-hashgen -ios8 -quiet
    export CISCO_HASHGEN_PWD='password' && cisco-hashgen -env CISCO_HASHGEN_PWD -quiet
"""

# Cisco custom base64 alphabet for IOS/IOS-XE 8/9
_CISCO_B64_ALPHABET = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
def _cisco_b64(data: bytes) -> str:
    std = base64.b64encode(data)
    trans = bytes.maketrans(
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        _CISCO_B64_ALPHABET
    )
    return std.translate(trans).decode("ascii")

def _cisco_b64_decode(s: str) -> bytes:
    trans = bytes.maketrans(
        _CISCO_B64_ALPHABET,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    )
    std = s.encode("ascii").translate(trans)
    return base64.b64decode(std)

# --- Builders ---
def build_asa_pbkdf2_sha512(password: bytes, iterations=ASA_DEFAULT_ITER, salt_len=ASA_DEFAULT_SALT) -> str:
    salt = os.urandom(salt_len)
    dk = hashlib.pbkdf2_hmac("sha512", password, salt, iterations, dklen=16)  # ASA stores first 16 bytes
    return f"$sha512${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"

def build_ios_type8(password: bytes, iterations=IOS8_DEFAULT_ITER, salt_len=IOS8_DEFAULT_SALT) -> str:
    salt = os.urandom(salt_len)  # 10 bytes default
    dk = hashlib.pbkdf2_hmac("sha256", password, salt, iterations)  # 32-byte dk
    return f"$8${_cisco_b64(salt)}${_cisco_b64(dk)}"

def build_ios_type9_scrypt(password: bytes, salt_len=IOS9_DEFAULT_SALT, N=IOS9_DEFAULT_N, r=IOS9_DEFAULT_r, p=IOS9_DEFAULT_p, dklen=32) -> str:
    salt = os.urandom(salt_len)
    dk = hashlib.scrypt(password, salt=salt, n=N, r=r, p=p, dklen=dklen)
    return f"$9${_cisco_b64(salt)}${_cisco_b64(dk)}"

def build_ios_type5_md5crypt(password: str, salt: str = None) -> str:
    """Use system crypt(3) md5-crypt ($1$). Falls back to simple salt if crypt is unavailable."""
    try:
        import crypt  # type: ignore
        if salt is None:
            # prefer crypt.mksalt if METHOD_MD5 available
            if hasattr(crypt, "METHOD_MD5"):
                salt_full = crypt.mksalt(crypt.METHOD_MD5)
            else:
                # manual $1$<8chars>$
                alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                salt = "".join(secrets.choice(alphabet) for _ in range(8))
                salt_full = f"$1${salt}$"
        else:
            salt_full = salt if salt.startswith("$1$") else f"$1${salt}$"
        return crypt.crypt(password, salt_full)
    except Exception:
        raise RuntimeError("MD5-crypt generation requires system 'crypt' module with MD5 support.")

# --- Verify ---
def verify_password(candidate: str, hash_str: str) -> bool:
    if hash_str.startswith("$sha512$"):
        parts = hash_str.split("$")
        if len(parts) != 5:
            raise ValueError("Malformed ASA hash.")
        iterations = int(parts[2])
        salt = base64.b64decode(parts[3])
        dk_stored = base64.b64decode(parts[4])
        dk_test = hashlib.pbkdf2_hmac("sha512", candidate.encode(), salt, iterations, dklen=16)
        return hmac.compare_digest(dk_stored, dk_test)

    if hash_str.startswith("$8$"):
        parts = hash_str.split("$")
        if len(parts) != 4:
            raise ValueError("Malformed IOS Type 8 hash.")
        salt = _cisco_b64_decode(parts[2])
        dk_stored = _cisco_b64_decode(parts[3])
        iterations = IOS8_DEFAULT_ITER
        dk_test = hashlib.pbkdf2_hmac("sha256", candidate.encode(), salt, iterations)
        return hmac.compare_digest(dk_stored, dk_test)

    if hash_str.startswith("$1$"):
        # MD5-crypt
        try:
            import crypt  # type: ignore
        except Exception:
            raise RuntimeError("MD5-crypt verification requires system 'crypt' module.")
        return crypt.crypt(candidate, hash_str) == hash_str

    if hash_str.startswith("$9$"):
        parts = hash_str.split("$")
        if len(parts) != 4:
            raise ValueError("Malformed IOS Type 9 hash.")
        salt = _cisco_b64_decode(parts[2])
        dk_stored = _cisco_b64_decode(parts[3])
        dk_test = hashlib.scrypt(candidate.encode(), salt=salt, n=IOS9_DEFAULT_N, r=IOS9_DEFAULT_r, p=IOS9_DEFAULT_p, dklen=len(dk_stored))
        return hmac.compare_digest(dk_stored, dk_test)

    raise ValueError("Unsupported hash format")

def detect_hash_type(hash_str: str) -> str:
    if hash_str.startswith("$sha512$"): return "ASA"
    if hash_str.startswith("$8$"): return "IOS8"
    if hash_str.startswith("$1$"): return "IOS5"
    if hash_str.startswith("$9$"): return "IOS9"
    return "UNKNOWN"

def validate_password(pw: str, minlen: int, maxlen: int):
    if pw is None:
        raise ValueError("No password provided.")
    if len(pw) < minlen:
        raise ValueError(f"Password too short (min {minlen}).")
    if len(pw) > maxlen:
        raise ValueError(f"Password too long (max {maxlen}).")
    for ch in pw:
        if ch == "\x00":
            raise ValueError("Password contains NUL byte (\\x00), which is not allowed.")
        if ord(ch) < 32 and ch not in ("\t", " "):
            raise ValueError("Password contains control characters.")

def read_password_noninteractive(args):
    if args.pwd is not None:
        return args.pwd
    if args.env is not None:
        val = os.getenv(args.env)
        if val is None:
            raise ValueError(f"Environment variable '{args.env}' is not set.")
        return val
    if not sys.stdin.isatty():
        data = sys.stdin.read()
        if data == "":
            return None
        if data.endswith("\n"):
            data = data[:-1]
        return data
    return None

def main():
    if "-help" in sys.argv and "--help" not in sys.argv and "-h" not in sys.argv:
        sys.argv = [arg.replace("-help", "--help") for arg in sys.argv]

    pre_no_color = ("-no-color" in sys.argv)
    USE_COLOR = sys.stdout.isatty() and (not pre_no_color)

    ap = argparse.ArgumentParser(
        prog="cisco-hashgen",
        description=build_description(USE_COLOR),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True,
    )
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("-asa", action="store_true", help="Generate ASA PBKDF2 (SHA-512) hash (default).")
    mode.add_argument("-ios5", action="store_true", help="Generate IOS/IOS-XE Type 5 (MD5-crypt) hash.")
    mode.add_argument("-ios8", action="store_true", help="Generate IOS/IOS-XE Type 8 (PBKDF2-SHA256) hash.")
    mode.add_argument("-ios9", action="store_true", help="Generate IOS/IOS-XE Type 9 (scrypt) hash.")
    ap.add_argument("-verify", "-v", metavar="HASH", help="Verify a password against an existing hash.")
    ap.add_argument("-iter", type=int, help=f"Override iterations (default: ASA={ASA_DEFAULT_ITER}, IOS8={IOS8_DEFAULT_ITER}).")
    ap.add_argument("-salt-bytes", type=int, help=f"Override salt length in bytes (default: ASA={ASA_DEFAULT_SALT}, IOS8={IOS8_DEFAULT_SALT}, IOS9={IOS9_DEFAULT_SALT}).")
    ap.add_argument("--scrypt-N", dest="scrypt_N", type=int, default=IOS9_DEFAULT_N, help=f"scrypt N (Type 9) (default: {IOS9_DEFAULT_N}).")
    ap.add_argument("--scrypt-r", dest="scrypt_r", type=int, default=IOS9_DEFAULT_r, help=f"scrypt r (Type 9) (default: {IOS9_DEFAULT_r}).")
    ap.add_argument("--scrypt-p", dest="scrypt_p", type=int, default=IOS9_DEFAULT_p, help=f"scrypt p (Type 9) (default: {IOS9_DEFAULT_p}).")
    ap.add_argument("-minlen", type=int, default=MINLEN_DEFAULT, help=f"Minimum password length (default: {MINLEN_DEFAULT}).")
    ap.add_argument("-maxlen", type=int, default=MAXLEN_DEFAULT, help=f"Maximum password length (default: {MAXLEN_DEFAULT}).")
    ap.add_argument("-pwd", metavar="STRING", help="Password provided directly (quote if it contains spaces/shell chars).")
    ap.add_argument("-env", metavar="VAR", help="Read password from environment variable VAR.")
    ap.add_argument("-quiet", action="store_true", help="Suppress banners and extra output (script-friendly).")
    ap.add_argument("-no-color", action="store_true", help="Disable ANSI colors in help/banners.")
    ap.add_argument("-no-prompt", action="store_true", help="Fail if no password is provided via stdin/-pwd/-env (no interactive prompt).")
    ap.add_argument("--version", action="version", version=f"cisco-hashgen {_VERSION}")

    try:
        args = ap.parse_args()

        if args.no_color:
            USE_COLOR = False

        if not args.quiet and not args.verify:
            print(colorize(f"Cisco HashGen v{_VERSION} — Generate and verify Cisco-compatible hashes", "bold", "cyan", use_color=USE_COLOR))
            print(f"  {colorize('ASA PBKDF2-SHA512', 'yellow', use_color=USE_COLOR)} defaults: iterations={ASA_DEFAULT_ITER}, salt-bytes={ASA_DEFAULT_SALT}")
            print(f"  {colorize('IOS/IOS-XE Type 5 (MD5-crypt)', 'yellow', use_color=USE_COLOR)}")
            print(f"  {colorize('IOS/IOS-XE Type 8 PBKDF2-SHA256', 'yellow', use_color=USE_COLOR)} defaults: iterations={IOS8_DEFAULT_ITER}, salt-bytes={IOS8_DEFAULT_SALT}")
            print(f"  {colorize('IOS/IOS-XE Type 9 (scrypt)', 'yellow', use_color=USE_COLOR)} defaults: N={IOS9_DEFAULT_N}, r={IOS9_DEFAULT_r}, p={IOS9_DEFAULT_p}, salt-bytes={IOS9_DEFAULT_SALT}")
            print(f"  Validation: minlen={args.minlen}, maxlen={args.maxlen}\n")

        if args.verify:
            kind = detect_hash_type(args.verify)
            if kind == "UNKNOWN":
                print("Unsupported hash format. Expect $sha512$... (ASA), $1$... (IOS Type 5), $8$... (IOS/IOS-XE), or $9$... (IOS/IOS-XE).")
                sys.exit(2)
            if not args.quiet:
                label = {
                    "ASA": "ASA PBKDF2-SHA512",
                    "IOS5": "IOS/IOS-XE Type 5 (MD5-crypt)",
                    "IOS8": "IOS/IOS-XE Type 8 PBKDF2-SHA256",
                    "IOS9": "IOS/IOS-XE Type 9 (scrypt)",
                }[kind]
                print(colorize(f"[Verifying {label} hash]", "bold", "green", use_color=USE_COLOR))

            pw = read_password_noninteractive(args)
            if pw is None and getattr(args, "no_prompt", False):
                if not args.quiet:
                    print("[-] No password provided via stdin/-pwd/-env (no-prompt set).")
                sys.exit(4)
            if pw is None:
                pw = prompt_password("Enter password to verify: ", confirm=False)
            try:
                validate_password(pw, args.minlen, args.maxlen)
            except ValueError as e:
                if not args.quiet:
                    print(f"[-] {e}")
                sys.exit(3)

            ok = verify_password(pw, args.verify)
            if not args.quiet:
                print("[+] Password matches." if ok else "[-] Password does NOT match.")
            sys.exit(0 if ok else 1)

        pw = read_password_noninteractive(args)
        if pw is None:
            if args.no_prompt:
                if not args.quiet:
                    print("[-] No password provided via stdin/-pwd/-env and -no-prompt set; exiting.")
                sys.exit(4)
            pw = prompt_password("Enter password: ", confirm=True)

        try:
            validate_password(pw, args.minlen, args.maxlen)
        except ValueError as e:
            if not args.quiet:
                print(f"[-] {e}")
            sys.exit(3)

        pwd_bytes = pw.encode()

        # Generation modes
        if args.ios5:
            out = build_ios_type5_md5crypt(pw)
            print(out)
        elif args.ios8:
            iters = args.iter if args.iter else IOS8_DEFAULT_ITER
            salt_len = args.salt_bytes if args.salt_bytes else IOS8_DEFAULT_SALT
            print(build_ios_type8(pwd_bytes, iterations=iters, salt_len=salt_len))
        elif args.ios9:
            salt_len = args.salt_bytes if args.salt_bytes else IOS9_DEFAULT_SALT
            print(build_ios_type9_scrypt(
                pwd_bytes,
                salt_len=salt_len,
                N=args.scrypt_N,
                r=args.scrypt_r,
                p=args.scrypt_p,
                dklen=32,
            ))
        else:
            iters = args.iter if args.iter else ASA_DEFAULT_ITER
            salt_len = args.salt_bytes if args.salt_bytes else ASA_DEFAULT_SALT
            print(build_asa_pbkdf2_sha512(pwd_bytes, iterations=iters, salt_len=salt_len))

    except KeyboardInterrupt:
        print()
        sys.exit(130)

# Simple masked prompt using per-char reading
def _getch_posix():
    import tty, termios
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
    return ch

def _getch_windows():
    import msvcrt
    return msvcrt.getwch()

def prompt_password(prompt="Password: ", confirm=False):
    def _read(prompt_text):
        print(prompt_text, end="", flush=True)
        buf = []
        getch = _getch_windows if os.name == "nt" else _getch_posix
        while True:
            ch = getch()
            if ch in ("\r", "\n"):
                print()
                break
            if ord(ch) == 3:
                print()
                sys.exit(130)
            if ch in ("\b", "\x7f"):
                if buf:
                    buf.pop()
                    sys.stdout.write("\b \b"); sys.stdout.flush()
                continue
            if ch < " ":
                continue
            buf.append(ch)
            sys.stdout.write("*"); sys.stdout.flush()
        return "".join(buf)

    p1 = _read(prompt)
    if confirm:
        p2 = _read("Retype to confirm: ")
        if p1 != p2:
            raise ValueError("Passwords do not match.")
    return p1

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        sys.exit(130)
