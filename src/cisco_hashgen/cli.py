#!/usr/bin/env python3
"""Cisco HashGen — Cisco-compatible password hashing CLI (ASA, IOS Type 5/8/9)."""
import sys, os, argparse, base64, hashlib, hmac, re, binascii

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
# Some IOS/IOS-XE images vary scrypt parameters. Keep verification flexible.
# Order matters: most common first to keep it fast.
IOS9_PARAM_CANDIDATES = [
    (16384, 1, 1),   # most common (default)
    (16384, 8, 1),   # seen on several XE trains
    (16384, 1, 2),   # occasional 'p=2'
    (16384, 2, 1),   # occasional 'r=2'
    (8192,  1, 1),   # lower N variants
    (8192,  8, 1),
    (4096,  1, 1),   # even lower N (rare)
    (4096,  8, 1),
    (32768, 1, 1),   # higher N variant
    (32768, 8, 1),
]

MINLEN_DEFAULT = 8
MAXLEN_DEFAULT = 1024

# ANSI helpers
ANSI = {
    "reset":"\x1b[0m",
    "bold":"\x1b[1m",
    "blue":"\x1b[34m",
    "green":"\x1b[32m",
    "cyan":"\x1b[36m",
    "yellow":"\x1b[33m",
    "red":"\x1b[31m",
    }
USE_COLOR = sys.stdout.isatty()

# Optional debug knob for Type 9 verification – set from argparse.
DEBUG_IOS9 = False
DEBUG_IOS9_VERBOSE = False

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

# IOS Type 9 (scrypt) -> $9$<salt_field>$Cisco64(dk32)
def build_ios_type9_scrypt(password: bytes,
                           salt_len: int = IOS9_SALT_BYTES,
                           n: int = IOS9_N, r: int = IOS9_r, p: int = IOS9_p,
                           dklen: int = IOS9_DKLEN,
                           salt_mode: str = "cisco64") -> str:
    """
    salt_mode:
      - "cisco64" (default, canonical): salt_field is Cisco64(random_bytes); KDF salt = random_bytes.
      - "ascii": The salt_field is Cisco64(random_bytes); KDF salt = that literal ASCII text.
      - "stdb64": The salt_field is StdBase64(random_bytes) without '=' padding; KDF salt = that literal ASCII text.
    """
    raw = os.urandom(salt_len)
    if salt_mode == "cisco64":
        salt_field = _cisco_b64(raw)
        salt_for_kdf = raw
    elif salt_mode == "ascii":
        salt_field = _cisco_b64(raw)
        salt_for_kdf = salt_field.encode("ascii")
    elif salt_mode == "stdb64":
        std = base64.b64encode(raw).decode("ascii").rstrip("=")
        salt_field = std
        salt_for_kdf = std.encode("ascii")
    else:
        raise ValueError(f"Unsupported ios9 salt mode: {salt_mode}")

    dk = hashlib.scrypt(password, salt=salt_for_kdf, n=n, r=r, p=p, dklen=dklen)
    return f"$9${salt_field}${_cisco_b64(dk)}"

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
        # Raw text fields (Cisco64 by spec)
        salt_c64 = parts[2]
        dk_c64   = parts[3]
        salt = _cisco_b64_decode(salt_c64)
        dk_stored = _cisco_b64_decode(dk_c64)
        pwd_bytes = candidate.encode()

        # Compute a Cisco64 round-trip of decoded salt/dk so we can detect non-canonical encodings
        rt_salt = _cisco_b64(salt)
        rt_dk   = _cisco_b64(dk_stored)
        ok_salt_rt = (rt_salt == salt_c64)
        ok_dk_rt   = (rt_dk == dk_c64.rstrip("="))

        if DEBUG_IOS9:
            # Lengths and a round-trip sanity check to catch any base64 translation issues.
            print(colorize(f"[debug-ios9] salt_len={len(salt)} bytes, dk_len={len(dk_stored)} bytes",
                           "yellow", use_color=USE_COLOR), file=sys.stderr)
            print(colorize(f"[debug-ios9] salt_c64='{salt_c64}' rt_ok={ok_salt_rt}", "yellow", use_color=USE_COLOR), file=sys.stderr)
            print(colorize(f"[debug-ios9] rt_salt ='{rt_salt}'", "yellow", use_color=USE_COLOR), file=sys.stderr)
            # Show raw salt bytes
            print(colorize(f"[debug-ios9] salt_hex={salt.hex()}", "yellow", use_color=USE_COLOR), file=sys.stderr)
            print(colorize(f"[debug-ios9] dk_c64   (len={len(dk_c64)}) rt_ok={ok_dk_rt}", "yellow", use_color=USE_COLOR), file=sys.stderr)

        # Build a parameter grid (common first)
        param_grid = list(IOS9_PARAM_CANDIDATES)
        if DEBUG_IOS9_VERBOSE:
            extra = []
            for N in (4096, 8192, 16384, 32768):
                for r in (1, 2, 4, 8):
                    for p in (1, 2):
                        tup = (N, r, p)
                        if tup not in param_grid:
                            extra.append(tup)
            param_grid.extend(extra)

        # Helper to try a parameter grid with a given salt, with an optional label for debug
        def _try_grid_with_salt(salt_bytes: bytes, label: str = "normal", debug_ios9_verbose=None) -> bool:
            for (n, rr, pp) in param_grid:
                if DEBUG_IOS9 and 'debug_ios9_verbose' in locals() and debug_ios9_verbose:
                    print(colorize(f"[debug-ios9] trying({label}) N={n}, r={rr}, p={pp}", "blue", use_color=USE_COLOR), file=sys.stderr)
                try:
                    test_dk = hashlib.scrypt(
                        password=pwd_bytes,
                        salt=salt_bytes,
                        n=n,
                        r=rr,
                        p=pp,
                        dklen=len(dk_stored),
                    )
                except ValueError:
                    # Skip unsupported parameter sets on this runtime (OpenSSL restrictions, etc.).
                    continue
                if hmac.compare_digest(dk_stored, test_dk):
                    if DEBUG_IOS9:
                        print(colorize(f"[debug-ios9] match({label}) with N={n}, r={rr}, p={pp}",
                                       "green", use_color=USE_COLOR), file=sys.stderr)
                    return True
            return False

        # Try interpretations in order (always):
        # 1) Canonical Cisco64-decoded bytes
        if _try_grid_with_salt(salt, "cisco64"):
            return True

        # 2) ASCII-literal: use the Cisco64 text literally as the salt
        salt_ascii = salt_c64.encode("ascii")
        if _try_grid_with_salt(salt_ascii, "ascii"):
            return True

        # 3) StdBase64-decoded bytes (pad to multiple of 4)
        try:
            std = salt_c64.encode("ascii")
            pad = (-len(std)) % 4
            if pad:
                std += b"=" * pad
            salt_std = base64.b64decode(std)
            if _try_grid_with_salt(salt_std, "stdb64"):
                return True
        except (binascii.Error, ValueError):
            pass

        if DEBUG_IOS9:
            print(colorize("[debug-ios9] no (N,r,p) candidate matched",
                           "red", use_color=USE_COLOR), file=sys.stderr)
        return False

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
    # IOS9 salt-mode selector: default canonical Cisco64; allow literal ASCII or StdB64 text salt usage.
    ap.add_argument("-ios9-salt-mode",
                    choices=("cisco64", "ascii", "stdb64"),
                    default="cisco64",
                    help="IOS9 only: how to use the $9$ salt field. "
                         "'cisco64' (default) stores Cisco64 text and uses decoded bytes for KDF; "
                         "'ascii' stores Cisco64 text but uses the literal ASCII text for KDF; "
                         "'stdb64' stores StdBase64 text and uses that literal ASCII for KDF.")
    ap.add_argument("-minlen", type=int, default=MINLEN_DEFAULT, help=f"Minimum password length (default: {MINLEN_DEFAULT}).")
    ap.add_argument("-maxlen", type=int, default=MAXLEN_DEFAULT, help=f"Maximum password length (default: {MAXLEN_DEFAULT}).")
    ap.add_argument("-pwd", metavar="STRING", help="Password provided directly (quote if it contains spaces/shell chars).")
    ap.add_argument("-env", metavar="VAR", help="Read password from environment variable VAR.")
    ap.add_argument("-quiet", action="store_true", help="Suppress banners and extra output (script-friendly).")
    ap.add_argument("-no-color", action="store_true", help="Disable ANSI colors in help/banners.")
    ap.add_argument("-no-prompt", action="store_true", help="Fail if no password is provided via stdin/-pwd/-env (no interactive prompt).")
    ap.add_argument("-V", "--version", action="version", version=f"cisco-hashgen {_VERSION}")
    # Debugging helper (off by default): prints decoded lengths and parameter tuple tried/matched.
    ap.add_argument(
        "-ios9-debug",
        action="store_true",
        help="Enable maximum IOS9 verify diagnostics"
    )

    try:
        args = ap.parse_args()
        if args.no_color:
            use_color = False

        # Enforce -ios9-debug usage:
        # - must be used with -v/--verify
        # - the provided hash must be Type 9 ($9$...)
        if getattr(args, "ios9_debug", False):
            if not args.verify:
                print(
                    "The -ios9-debug flag is only valid with -v/--verify and a $9$ (Type 9) hash.",
                    file=sys.stderr,
                )
                print(
                    "Usage: cisco-hashgen -ios9-debug -v '$9$SALT$HASH'",
                    file=sys.stderr,
                )
                sys.exit(2)
            kind_for_debug = detect_hash_type(args.verify)
            if kind_for_debug != "IOS9":
                print(
                    f"The -ios9-debug flag only applies to $9$ (Type 9) hashes; got {kind_for_debug}.",
                    file=sys.stderr,
                )
                sys.exit(2)

        # set global debug flags (single switch => max verbosity internally for Type 9)
        global DEBUG_IOS9, DEBUG_IOS9_VERBOSE
        DEBUG_IOS9 = bool(getattr(args, "ios9_debug", False))
        DEBUG_IOS9_VERBOSE = bool(getattr(args, "ios9_debug", False))

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
            if pw is None:
                if args.no_prompt:
                    if not args.quiet:
                        print("[-] No password provided via stdin/-pwd/-env and -no-prompt set; exiting.")
                    sys.exit(4)

                # Verify mode: single prompt, no confirmation, with explicit cue
                if not args.quiet:
                    labels = {"ASA":"ASA PBKDF2-SHA512","IOS5":"IOS/IOS-XE Type 5 (MD5-crypt)","IOS8":"IOS/IOS-XE Type 8 PBKDF2-SHA256","IOS9":"IOS/IOS-XE Type 9 (scrypt)"}
                    print(colorize(f"[Enter password to verify against {labels[kind]}]", "bold", "green", use_color=use_color))
                pw = prompt_password("Enter password to verify: ", confirm=False)

            try:
                validate_password(pw, args.minlen, args.maxlen)
            except ValueError as e:
                if not args.quiet: print(f"[-] {e}")
                sys.exit(3)

            ok = verify_password(pw, args.verify)
            if not args.quiet:
                if ok:
                    print(colorize("[+] Password matches.", "green", use_color=USE_COLOR))
                else:
                    print(colorize("[-] Password does NOT match.", "red", use_color=USE_COLOR))
            sys.exit(0 if ok else 1)

        # Generate mode
        pw = read_password_noninteractive(args)
        if pw is None:
            if args.no_prompt:
                if not args.quiet: print("[-] No password provided via stdin/-pwd/-env and -no-prompt set; exiting.")
                sys.exit(4)
            # Announce which hash we’re about to generate (interactive, non-quiet)
            if not args.quiet:
                if getattr(args, "asa", False):
                    gen_label = "ASA PBKDF2-SHA512"
                elif getattr(args, "ios5", False):
                    gen_label = "IOS/IOS-XE Type 5 (MD5-crypt)"
                elif getattr(args, "ios8", False):
                    gen_label = "IOS/IOS-XE Type 8 PBKDF2-SHA256"
                elif getattr(args, "ios9", False):
                    gen_label = "IOS/IOS-XE Type 9 (scrypt)"
                else:
                    # default when no mode flag is given
                    gen_label = "ASA PBKDF2-SHA512"
                print(colorize(f"[Generating {gen_label} hash]", "bold", "green", use_color=use_color))
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
            salt_mode = getattr(args, "ios9_salt_mode", "cisco64")
            out = build_ios_type9_scrypt(
                pwd_bytes,
                salt_len=salt_len,
                n=IOS9_N,
                r=IOS9_r,
                p=IOS9_p,
                dklen=IOS9_DKLEN,
                salt_mode=salt_mode,
            )
        else:
            iters = args.iter if args.iter else ASA_DEFAULT_ITER
            salt_len = args.salt_bytes if args.salt_bytes else ASA_DEFAULT_SALT
            out = build_asa_pbkdf2_sha512(pwd_bytes, iterations=iters, salt_len=salt_len)

        print(out)

    except KeyboardInterrupt:
        print()
        sys.exit(130)

if __name__ == "__main__":
    main()