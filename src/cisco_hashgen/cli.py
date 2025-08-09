#!/usr/bin/env python3
"""Cisco HashGen — Cisco-compatible PBKDF2 password hashing CLI."""
import sys, os, argparse, base64, hashlib, hmac

try:
    from . import __version__ as _VERSION
except Exception:
    _VERSION = "1.2.0"

ASA_DEFAULT_ITER = 5000
ASA_DEFAULT_SALT = 16
IOS8_DEFAULT_ITER = 20000
IOS8_DEFAULT_SALT = 10
MINLEN_DEFAULT = 8
MAXLEN_DEFAULT = 1024

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
    title = colorize(f"Cisco HashGen v{_VERSION} — Generate and verify Cisco-compatible PBKDF2 hashes", "bold", "cyan", use_color=use_color)
    defaults_hdr = colorize("Defaults:", "bold", "green", use_color=use_color)
    quoting_hdr  = colorize("Quoting Guide (-verify and -pwd):", "bold", "blue", use_color=use_color)
    return f"""{title}
{defaults_hdr}
  {colorize('ASA PBKDF2-SHA512', 'yellow', use_color=use_color)}: iterations={ASA_DEFAULT_ITER}, salt-bytes={ASA_DEFAULT_SALT}
  {colorize('IOS/IOS-XE Type 8 PBKDF2-SHA256', 'yellow', use_color=use_color)}: iterations={IOS8_DEFAULT_ITER}, salt-bytes={IOS8_DEFAULT_SALT}
  Validation: minlen={MINLEN_DEFAULT}, maxlen={MAXLEN_DEFAULT}

{quoting_hdr}
  Hashes for -verify:
    Always wrap hashes in *single quotes* to prevent shell $-expansion:
      cisco-hashgen -v '$sha512$5000$abcd...$efgh...'
      cisco-hashgen -v '$8$SALT$HASH'

  Passwords for -pwd:
    Use single quotes when your password contains spaces or shell chars ($ ! etc):
      cisco-hashgen -pwd 'pa ss $weird!'
    If your password contains a single quote, close/open and insert it literally:
      cisco-hashgen -pwd 'pa'"'"'ss'

  Automation-safe:
    echo 'password' | cisco-hashgen -ios8 -quiet
    export CISCO_HASHGEN_PWD='password' && cisco-hashgen -env CISCO_HASHGEN_PWD -quiet
"""

# Cisco custom base64 alphabet for IOS/IOS-XE
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

def build_asa_pbkdf2_sha512(password: bytes, iterations=ASA_DEFAULT_ITER, salt_len=ASA_DEFAULT_SALT) -> str:
    salt = os.urandom(salt_len)
    dk = hashlib.pbkdf2_hmac("sha512", password, salt, iterations, dklen=16)  # ASA stores first 16 bytes
    return f"$sha512${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"

def build_ios_type8(password: bytes, iterations=IOS8_DEFAULT_ITER, salt_len=IOS8_DEFAULT_SALT) -> str:
    salt = os.urandom(salt_len)  # 10 bytes default
    dk = hashlib.pbkdf2_hmac("sha256", password, salt, iterations)  # 32-byte dk
    return f"$8${_cisco_b64(salt)}${_cisco_b64(dk)}"

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
    elif hash_str.startswith("$8$"):
        parts = hash_str.split("$")
        if len(parts) != 4:
            raise ValueError("Malformed IOS Type 8 hash.")
        salt = _cisco_b64_decode(parts[2])
        dk_stored = _cisco_b64_decode(parts[3])
        iterations = IOS8_DEFAULT_ITER
        dk_test = hashlib.pbkdf2_hmac("sha256", candidate.encode(), salt, iterations)
        return hmac.compare_digest(dk_stored, dk_test)
    else:
        raise ValueError("Unsupported hash format")

def detect_hash_type(hash_str: str) -> str:
    if hash_str.startswith("$sha512$"): return "ASA"
    if hash_str.startswith("$8$"): return "IOS8"
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
    mode.add_argument("-ios8", action="store_true", help="Generate IOS/IOS-XE Type 8 PBKDF2-SHA256 hash.")
    ap.add_argument("-verify", "-v", metavar="HASH", help="Verify a password against an existing hash.")
    ap.add_argument("-iter", type=int, help=f"Override iterations (default: ASA={ASA_DEFAULT_ITER}, IOS8={IOS8_DEFAULT_ITER}).")
    ap.add_argument("-salt-bytes", type=int, help=f"Override salt length in bytes (default: ASA={ASA_DEFAULT_SALT}, IOS8={IOS8_DEFAULT_SALT}).")
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
            print(colorize(f"Cisco HashGen v{_VERSION} — Generate and verify Cisco-compatible PBKDF2 hashes", "bold", "cyan", use_color=USE_COLOR))
            print(f"  {colorize('ASA PBKDF2-SHA512', 'yellow', use_color=USE_COLOR)} defaults: iterations={ASA_DEFAULT_ITER}, salt-bytes={ASA_DEFAULT_SALT}")
            print(f"  {colorize('IOS/IOS-XE Type 8 PBKDF2-SHA256', 'yellow', use_color=USE_COLOR)} defaults: iterations={IOS8_DEFAULT_ITER}, salt-bytes={IOS8_DEFAULT_SALT}")
            print(f"  Validation: minlen={args.minlen}, maxlen={args.maxlen}\n")

        if args.verify:
            kind = detect_hash_type(args.verify)
            if kind == "UNKNOWN":
                print("Unsupported hash format. Expect $sha512$... (ASA) or $8$... (IOS/IOS-XE).")
                sys.exit(2)
            if not args.quiet:
                label = "ASA PBKDF2-SHA512" if kind == "ASA" else "IOS/IOS-XE Type 8 PBKDF2-SHA256"
                print(colorize(f"[Verifying {label} hash]", "bold", "green", use_color=USE_COLOR))

            pw = read_password_noninteractive(args)
            if pw is None:
                if args.no_prompt:
                    if not args.quiet:
                        print("[-] No password provided via stdin/-pwd/-env and -no-prompt set; exiting.")
                    sys.exit(4)
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

        if args.ios8:
            iters = args.iter if args.iter else IOS8_DEFAULT_ITER
            salt_len = args.salt_bytes if args.salt_bytes else IOS8_DEFAULT_SALT
            print(build_ios_type8(pwd_bytes, iterations=iters, salt_len=salt_len))
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
