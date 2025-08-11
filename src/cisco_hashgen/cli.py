#!/usr/bin/env python3
"""Cisco HashGen — Cisco-compatible password hashing CLI (ASA, IOS Type 5/8/9)."""
import sys, os, argparse, base64, hashlib, hmac, re\
#import secrets

# Version
try:
    from importlib.metadata import version as _pkgver, PackageNotFoundError  # Py3.8+
except ImportError:  # pragma: no cover
    _pkgver = None
    PackageNotFoundError = None  # type: ignore[assignment]

def _detect_version():
    # Prefer installed package metadata
    if _pkgver:
        try:
            return _pkgver("cisco-hashgen")
        except PackageNotFoundError:
            pass
    # Fallback to package attr if importable
    try:
        from . import __version__ as _v  # type: ignore
        return _v
    except (ImportError, ModuleNotFoundError, AttributeError, ValueError):
        return "0.0.0"

_VERSION = _detect_version()

# Defaults
ASA_DEFAULT_ITER = 5000
ASA_DEFAULT_SALT = 16

IOS5_SALT_LEN = 8  # md5-crypt uses up to 8 chars of salt
IOS8_DEFAULT_ITER = 20000
IOS8_DEFAULT_SALT = 10

IOS9_N = 16384
IOS9_r = 1
IOS9_p = 1
# Match common IOS/IOS-XE behavior for Type 9 — 10-byte salt encodes to 14 Cisco64 chars (no padding)
IOS9_SALT_BYTES = 10
IOS9_DKLEN = 32

MINLEN_DEFAULT = 8
MAXLEN_DEFAULT = 1024

# ANSI helpers
ANSI = {"reset":"\x1b[0m","bold":"\x1b[1m","blue":"\x1b[34m","green":"\x1b[32m","cyan":"\x1b[36m","yellow":"\x1b[33m"}
def colorize(s, *styles, use_color=True):
    if not use_color: return s
    prefix = "".join(ANSI.get(x,"") for x in styles)
    return f"{prefix}{s}{ANSI['reset']}"

def build_description(use_color):
    title = colorize(f"Cisco HashGen v{_VERSION} — Generate and verify Cisco-compatible hashes", "bold","cyan", use_color=use_color)
    defaults_hdr = colorize("Defaults:", "bold","green", use_color=use_color)
    quoting_hdr  = colorize("Quoting Guide (-verify and -pwd):", "bold","blue", use_color=use_color)
    return f"""{title}
{defaults_hdr}
  {colorize('ASA PBKDF2-SHA512', 'yellow', use_color=use_color)} defaults: iterations={ASA_DEFAULT_ITER}, salt-bytes={ASA_DEFAULT_SALT}
  {colorize('IOS/IOS-XE Type 5 (MD5-crypt)', 'yellow', use_color=use_color)}
  {colorize('IOS/IOS-XE Type 8 PBKDF2-SHA256', 'yellow', use_color=use_color)} defaults: iterations={IOS8_DEFAULT_ITER}, salt-bytes={IOS8_DEFAULT_SALT}
  {colorize('IOS/IOS-XE Type 9 (scrypt)', 'yellow', use_color=use_color)} defaults: N={IOS9_N}, r={IOS9_r}, p={IOS9_p}, salt-bytes={IOS9_SALT_BYTES}
  Validation: minlen={MINLEN_DEFAULT}, maxlen={MAXLEN_DEFAULT}

{quoting_hdr}
  Hashes for -verify:
    Always wrap hashes in *single quotes* to prevent shell $-expansion:
      cisco-hashgen -v '$sha512$5000$abcd...$efgh...'
      cisco-hashgen -v '$8$SALT$HASH'
      cisco-hashgen -v '$1$SALT$HASH'    # Type 5
      cisco-hashgen -v '$9$SALT$HASH'    # Type 9

  Passwords for -pwd:
    Use single quotes when your password contains spaces or shell chars ($ ! etc):
      cisco-hashgen -pwd 'pa ss $weird!'
    If your password contains a single quote, close/open and insert it literally:
      cisco-hashgen -pwd 'pa'"'"'ss'

  Automation-safe:
    echo 'password' | cisco-hashgen -ios8 -quiet
    export CISCO_HASHGEN_PWD='password' && cisco-hashgen -env CISCO_HASHGEN_PWD -quiet
"""

# Cisco base64 alphabet (aka Cisco64) used by Type 8/9
_CISCO_B64_ALPHABET = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

def _cisco_b64(data: bytes) -> str:
    # Encode to standard base64, translate to Cisco alphabet, and strip padding to match device formatting
    std = base64.b64encode(data)
    trans = bytes.maketrans(
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        _CISCO_B64_ALPHABET
    )
    out = std.translate(trans).decode("ascii")
    # Devices do not include '=' padding; remove it for canonical display
    return out.rstrip("=")

def _cisco_b64_decode(s: str) -> bytes:
    trans = bytes.maketrans(
        _CISCO_B64_ALPHABET,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    )
    std = s.encode("ascii").translate(trans)
    # Add '=' padding so length is a multiple of 4
    pad = (-len(std)) % 4
    if pad:
        std += b"=" * pad
    return base64.b64decode(std)

# ASA PBKDF2-SHA512 ($sha512$<iter>$B64(salt)$B64(dk16))
def build_asa_pbkdf2_sha512(password: bytes, iterations=ASA_DEFAULT_ITER, salt_len=ASA_DEFAULT_SALT) -> str:
    salt = os.urandom(salt_len)
    dk = hashlib.pbkdf2_hmac("sha512", password, salt, iterations, dklen=16)
    return f"$sha512${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"

# IOS Type 8 PBKDF2-SHA256 ($8$Cisco64(salt10)$Cisco64(dk32))
def build_ios_type8(password: bytes, iterations=IOS8_DEFAULT_ITER, salt_len=IOS8_DEFAULT_SALT) -> str:
    salt = os.urandom(salt_len)
    dk = hashlib.pbkdf2_hmac("sha256", password, salt, iterations)
    return f"$8${_cisco_b64(salt)}${_cisco_b64(dk)}"

# Pure-Python MD5-crypt (RFC 2288 variant used by $1$) adapted for small footprint
# Based on public-domain reference implementations.
def _md5crypt(password: bytes, salt: bytes, magic: bytes = b"$1$") -> str:
    import hashlib
    if b"$" in salt:
        salt = salt.split(b"$")[0]
    salt = salt[:8]
    # Initial
    ctx = hashlib.md5()
    ctx.update(password + magic + salt)
    alt = hashlib.md5(password + salt + password).digest()
    # Mix in alt sum for each char
    plen = len(password)
    for i in range(plen // 16):
        ctx.update(alt)
    ctx.update(alt[: plen % 16])
    # odd bit
    i = plen
    while i:
        if i & 1:
            ctx.update(b"\x00")
        else:
            ctx.update(password[:1])
        i >>= 1
    final = ctx.digest()

    # 1000 rounds
    for i in range(1000):
        ctx = hashlib.md5()
        if i % 2:
            ctx.update(password)
        else:
            ctx.update(final)
        if i % 3:
            ctx.update(salt)
        if i % 7:
            ctx.update(password)
        if i % 2:
            ctx.update(final)
        else:
            ctx.update(password)
        final = ctx.digest()

    # Base64-like encoding (crypt's custom order)
    def _b64from24(b2, b1, b0):
        it = (b2 << 16) | (b1 << 8) | b0
        al = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        out = []
        for _ in range(4):
            out.append(al[it & 0x3f])
            it >>= 6
        return bytes(out)

    def _reorder(f):
        o = b""
        o += _b64from24(f[0], f[6], f[12])
        o += _b64from24(f[1], f[7], f[13])
        o += _b64from24(f[2], f[8], f[14])
        o += _b64from24(f[3], f[9], f[15])
        o += _b64from24(f[4], f[10], f[5])
        o += _b64from24(0, 0, f[11])[:2]
        return o

    encoded = _reorder(final)
    return (magic + salt + b"$" + encoded).decode("ascii")

# IOS Type 5 (MD5-crypt) -> $1$<salt>$<hash>
def build_ios_type5_md5crypt(password: bytes, salt_len: int = IOS5_SALT_LEN) -> str:
    salt = base64.b64encode(os.urandom(12)).decode("ascii").replace("+","/").replace("=","")[:salt_len].encode("ascii")
    return _md5crypt(password, salt, magic=b"$1$")

# IOS Type 9 (scrypt) -> $9$Cisco64(salt)$Cisco64(dk32)
def build_ios_type9_scrypt(password: bytes,
                           salt_len: int = IOS9_SALT_BYTES,
                           n: int = IOS9_N, r: int = IOS9_r, p: int = IOS9_p,
                           dklen: int = IOS9_DKLEN) -> str:
    salt = os.urandom(salt_len)
    dk = hashlib.scrypt(password, salt=salt, n=n, r=r, p=p, dklen=dklen)
    return f"$9${_cisco_b64(salt)}${_cisco_b64(dk)}"

def detect_hash_type(hash_str: str) -> str:
    if hash_str.startswith("$sha512$"): return "ASA"
    if hash_str.startswith("$8$"): return "IOS8"
    if hash_str.startswith("$1$"): return "IOS5"
    if hash_str.startswith("$9$"): return "IOS9"
    return "UNKNOWN"

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
            raise ValueError("Malformed IOS8 hash.")
        salt = _cisco_b64_decode(parts[2])
        dk_stored = _cisco_b64_decode(parts[3])
        dk_test = hashlib.pbkdf2_hmac("sha256", candidate.encode(), salt, IOS8_DEFAULT_ITER)
        return hmac.compare_digest(dk_stored, dk_test)

    elif hash_str.startswith("$1$"):  # IOS/IOS-XE Type 5 (MD5-crypt)
        # $1$<salt>$<digest>, salt 1–8, digest 22, alphabet ./0-9A-Za-z
        m = re.match(r'^\$1\$([./0-9A-Za-z]{1,8})\$([./0-9A-Za-z]{22})$', hash_str)
        if not m:
            raise ValueError("Malformed IOS5 (MD5-crypt) hash.")
        salt = m.group(1).encode("ascii")
        test = _md5crypt(candidate.encode(), salt, magic=b"$1$")
        return hmac.compare_digest(test, hash_str)

    elif hash_str.startswith("$9$"):
        parts = hash_str.split("$")
        if len(parts) != 4:
            raise ValueError("Malformed IOS9 hash.")
        salt = _cisco_b64_decode(parts[2])
        dk_stored = _cisco_b64_decode(parts[3])
        dk_test = hashlib.scrypt(
            candidate.encode(),
            salt=salt,
            n=IOS9_N,
            r=IOS9_r,
            p=IOS9_p,
            dklen=len(dk_stored),
        )
        return hmac.compare_digest(dk_stored, dk_test)

    else:
        raise ValueError("Unsupported hash format.")

def validate_password(pw: str, minlen: int, maxlen: int):
    if pw is None: raise ValueError("No password provided.")
    if len(pw) < minlen: raise ValueError(f"Password too short (min {minlen}).")
    if len(pw) > maxlen: raise ValueError(f"Password too long (max {maxlen}).")
    for ch in pw:
        if ch == "\x00": raise ValueError("Password contains NUL byte (\\x00), which is not allowed.")
        if ord(ch) < 32 and ch not in ("\t"," "): raise ValueError("Password contains control characters.")

def read_password_noninteractive(args):
    if args.pwd is not None: return args.pwd
    if args.env is not None:
        val = os.getenv(args.env)
        if val is None: raise ValueError(f"Environment variable '{args.env}' is not set.")
        return val
    if not sys.stdin.isatty():
        data = sys.stdin.read()
        if data == "": return None
        if data.endswith("\n"): data = data[:-1]
        return data
    return None

# Masked prompt with clean Ctrl-C -> exit 130
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
    def _read(txt):
        print(txt, end="", flush=True)
        buf = []
        getch = _getch_windows if os.name == "nt" else _getch_posix
        while True:
            ch = getch()
            if ch in ("\r","\n"):
                print()
                break
            if ord(ch) == 3:  # Ctrl-C
                print()
                sys.exit(130)
            if ch in ("\b","\x7f"):
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

def main():
    if "-help" in sys.argv and "--help" not in sys.argv and "-h" not in sys.argv:
        sys.argv = [arg.replace("-help","--help") for arg in sys.argv]

    pre_no_color = ("-no-color" in sys.argv)
    use_color = sys.stdout.isatty() and (not pre_no_color)

    ap = argparse.ArgumentParser(
        prog="cisco-hashgen",
        description=build_description(use_color),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True,
    )
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("-asa", action="store_true", help="Generate ASA PBKDF2 (SHA-512) hash (default).")
    mode.add_argument("-ios5", action="store_true", help="Generate IOS/IOS-XE Type 5 (MD5-crypt) hash.")
    mode.add_argument("-ios8", action="store_true", help="Generate IOS/IOS-XE Type 8 (PBKDF2-SHA256) hash.")
    mode.add_argument("-ios9", action="store_true", help="Generate IOS/IOS-XE Type 9 (scrypt) hash.")

    ap.add_argument("-verify","-v", metavar="HASH", help="Verify a password against an existing hash.")
    ap.add_argument("-iter", type=int, help=f"Override iterations (default: ASA={ASA_DEFAULT_ITER}, IOS8={IOS8_DEFAULT_ITER}).")
    ap.add_argument("-salt-bytes", type=int, help=f"Override salt length in bytes (default: ASA={ASA_DEFAULT_SALT}, IOS8={IOS8_DEFAULT_SALT}, IOS9={IOS9_SALT_BYTES}).")
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
            use_color = False

        if not args.quiet and not args.verify:
            print(colorize(f"Cisco HashGen v{_VERSION} — Generate and verify Cisco-compatible hashes", "bold","cyan", use_color=use_color))
            print(f"  {colorize('ASA PBKDF2-SHA512', 'yellow', use_color=use_color)} defaults: iterations={ASA_DEFAULT_ITER}, salt-bytes={ASA_DEFAULT_SALT}")
            print(f"  {colorize('IOS/IOS-XE Type 5 (MD5-crypt)', 'yellow', use_color=use_color)}")
            print(f"  {colorize('IOS/IOS-XE Type 8 PBKDF2-SHA256', 'yellow', use_color=use_color)} defaults: iterations={IOS8_DEFAULT_ITER}, salt-bytes={IOS8_DEFAULT_SALT}")
            print(f"  {colorize('IOS/IOS-XE Type 9 (scrypt)', 'yellow', use_color=use_color)} defaults: N={IOS9_N}, r={IOS9_r}, p={IOS9_p}, salt-bytes={IOS9_SALT_BYTES}")
            print(f"  Validation: minlen={args.minlen}, maxlen={args.maxlen}\n")

        # Verify mode
        if args.verify:
            kind = detect_hash_type(args.verify)
            if kind == "UNKNOWN":
                print("Unsupported hash format. Expect $sha512$... (ASA), $1$... (IOS type 5), $8$... (IOS type 8), or $9$... (IOS type 9).")
                sys.exit(2)
            if not args.quiet:
                labels = {"ASA":"ASA PBKDF2-SHA512","IOS5":"IOS/IOS-XE Type 5 (MD5-crypt)","IOS8":"IOS/IOS-XE Type 8 PBKDF2-SHA256","IOS9":"IOS/IOS-XE Type 9 (scrypt)"}
                print(colorize(f"[Verifying {labels[kind]} hash]", "bold","green", use_color=use_color))

            pw = read_password_noninteractive(args)
            if pw is None and getattr(args,"no_prompt",False):
                if not args.quiet: print("[-] No password provided via stdin/-pwd/-env (no-prompt set).")
                sys.exit(4)
            if pw is None:
                pw = prompt_password("Enter password to verify: ", confirm=False)

            try:
                validate_password(pw, args.minlen, args.maxlen)
            except ValueError as e:
                if not args.quiet: print(f"[-] {e}")
                sys.exit(3)

            ok = verify_password(pw, args.verify)
            if not args.quiet:
                print("[+] Password matches." if ok else "[-] Password does NOT match.")
            sys.exit(0 if ok else 1)

        # Generate mode
        pw = read_password_noninteractive(args)
        if pw is None:
            if args.no_prompt:
                if not args.quiet: print("[-] No password provided via stdin/-pwd/-env and -no-prompt set; exiting.")
                sys.exit(4)
            pw = prompt_password("Enter password: ", confirm=True)

        try:
            validate_password(pw, args.minlen, args.maxlen)
        except ValueError as e:
            if not args.quiet: print(f"[-] {e}")
            sys.exit(3)

        pwd_bytes = pw.encode()

        if args.ios5:
            out = build_ios_type5_md5crypt(pwd_bytes, IOS5_SALT_LEN)
        elif args.ios8:
            iters = args.iter if args.iter else IOS8_DEFAULT_ITER
            salt_len = args.salt_bytes if args.salt_bytes else IOS8_DEFAULT_SALT
            out = build_ios_type8(pwd_bytes, iterations=iters, salt_len=salt_len)
        elif args.ios9:
            salt_len = args.salt_bytes if args.salt_bytes else IOS9_SALT_BYTES
            out = build_ios_type9_scrypt(pwd_bytes, salt_len=salt_len, n=IOS9_N, r=IOS9_r, p=IOS9_p, dklen=IOS9_DKLEN)
        else:
            iters = args.iter if args.iter else ASA_DEFAULT_ITER
            salt_len = args.salt_bytes if args.salt_bytes else ASA_DEFAULT_SALT
            out = build_asa_pbkdf2_sha512(pwd_bytes, iterations=iters, salt_len=salt_len)

        print(out)

    except KeyboardInterrupt:
        print()
        sys.exit(130)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        sys.exit(130)
