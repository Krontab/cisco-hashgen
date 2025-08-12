#!/usr/bin/env python3
"""
Cross-platform QA for cisco-hashgen.

- Verifies generation and verification for ASA, IOS5, IOS8, IOS9
- Checks hash structure via regex before verifying
- Exercises multiple input methods: stdin, -pwd, -env

Default: quiet (prints only the final success/fail summary).
Use '-verbose' for detailed per-test logs.
'Use -show-hash' prints generated hashes (even if not '-verbose').
'Use -success-only' or '-fail-only' filter per-test logs (only effective with '-verbose').
Keeps going on failures by default; use '-no-keep-going' to stop on the first failure.
"""

import argparse
import getpass
import os
import re
import subprocess
import sys
import tempfile
from shutil import which

# ---------- Global flags (set from CLI) ----------
VERBOSE = False
KEEP_GOING = True
SUCCESS_ONLY = False
FAIL_ONLY = False

# ---------- Pretty output ----------
def _use_color():
    return sys.stdout.isatty()

def _c(s, code):
    return f"\033[{code}m{s}\033[0m" if _use_color() else s

BOLD = lambda s: _c(s, "1")
RED = lambda s: _c(s, "31")
GREEN = lambda s: _c(s, "32")
YELLOW = lambda s: _c(s, "33")
CYAN = lambda s: _c(s, "36")

def _print_if_verbose(msg, kind=None):
    if not VERBOSE:
        return
    # kind: "pass" | "fail" | "info"
    if kind == "pass" and FAIL_ONLY:
        return
    if kind == "fail" and SUCCESS_ONLY:
        return
    print(msg)

def note(msg): _print_if_verbose(f"{CYAN('[*]')} {msg}", kind="info")
def warn(msg): _print_if_verbose(f"{YELLOW('[!]')} {msg}", kind="info")
def ok(msg):   _print_if_verbose(f"{GREEN('[OK]')} {msg}", kind="pass")
def bad(msg):  _print_if_verbose(f"{RED('[XX]')} {msg}", kind="fail")
def version_header(msg): print(f"{CYAN('[*]')} {msg}")

def section_header(title: str):
    if VERBOSE:
        print(CYAN(BOLD(f"== {title} ==")))

# ---------- Regex guards ----------
RE_ASA = re.compile(r'^\$sha512\$[0-9]+\$[A-Za-z0-9+/]+={0,2}\$[A-Za-z0-9+/]+={0,2}$')
RE_IOS5 = re.compile(r'^\$1\$[./0-9A-Za-z]{1,8}\$[./0-9A-Za-z]{22}$')
RE_IOS8 = re.compile(r'^\$8\$[./0-9A-Za-z]{14}\$[./0-9A-Za-z]{43}$')
RE_IOS9 = re.compile(r'^\$9\$[./0-9A-Za-z]{14}\$[./0-9A-Za-z]{43}$')

DEFAULT_PW = "TestP@ssw0rd!"

# ---------- Counters ----------
TESTS = 0
OKS = 0
FAILS = 0
FIRST_FAILURE_MSG = None

def pass_test(msg):
    global TESTS, OKS
    TESTS += 1
    OKS += 1
    ok(msg)

def fail_test(msg):
    global TESTS, FAILS, FIRST_FAILURE_MSG
    TESTS += 1
    FAILS += 1
    if FIRST_FAILURE_MSG is None:
        FIRST_FAILURE_MSG = msg
    bad(msg)
    if not KEEP_GOING:
        summary_and_exit()

def assert_regex(value: str, rx: re.Pattern, label: str):
    if rx.match(value):
        pass_test(f"structure ok: {label}")
    else:
        if VERBOSE:
            print("Got:", value, file=sys.stderr)
        fail_test(f"regex failed for {label}")

# ---------- Manual prompt (masked/visible) ----------


def prompt_masked(prompt_text="Enter password: "):
    # Use getpass for a cross-platform masked prompt; Ctrl-C exits with 130.
    try:
        return getpass.getpass(prompt_text)
    except KeyboardInterrupt:
        print()
        sys.exit(130)

def prompt_visible(prompt_text="Enter password: "):
    try:
        return input(prompt_text)
    except KeyboardInterrupt:
        print()
        sys.exit(130)

# ---------- CLI helpers ----------
def _expected_prefix(gen_args):
    # gen_args is a list like ["-asa"] or ["-ios8"] (and possibly with extra options)
    if "-asa" in gen_args:  return "$sha512$"
    if "-ios5" in gen_args: return "$1$"
    if "-ios8" in gen_args: return "$8$"
    if "-ios9" in gen_args: return "$9$"
    # The default mode of cisco-hashgen is ASA
    return "$sha512$"

def _actual_prefix(hash_str: str) -> str:
    if hash_str.startswith("$sha512$"):
        return "$sha512$"
    if hash_str.startswith("$1$"):
        return "$1$"
    if hash_str.startswith("$8$"):
        return "$8$"
    if hash_str.startswith("$9$"):
        return "$9$"
    return "<unknown>"

def call_gen(bin_path, args, mode, pw):
    # Returns generated hash string (stdout.strip())
    if mode == "pwd":
        cmd = [bin_path, *args, "-pwd", pw, "-quiet"]
        out = subprocess.check_output(cmd, text=True)
        return out.strip()
    elif mode == "env":
        var = f"QA_PW_{os.getpid()}"
        env = os.environ.copy()
        env[var] = pw
        cmd = [bin_path, *args, "-env", var, "-quiet"]
        out = subprocess.check_output(cmd, text=True, env=env)
        return out.strip()
    elif mode == "stdin":
        cmd = [bin_path, *args, "-quiet"]
        out = subprocess.check_output(cmd, input=pw, text=True)
        return out.strip()
    else:
        raise RuntimeError(f"Unknown input mode: {mode}")

def call_verify(bin_path, hash_str, pw, extra_flags=None):
    # Returns True on match; False on mismatch.
    extra_flags = extra_flags or []
    cmd = [bin_path, *extra_flags, "-v", hash_str, "-pwd", pw, "-quiet"]
    # capture stderr to allow surfacing of debug notes (if needed later)
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp_path = tmp.name
    rc = 1
    try:
        with open(tmp_path, "w") as err:
            proc = subprocess.run(cmd, stderr=err, text=True)
        rc = proc.returncode
    finally:
        try: os.unlink(tmp_path)
        except OSError: pass
    return rc == 0

def run_case(bin_path, name, gen_args, rx, label, mode, pw,
             ios9_dbg=False, ios9_dbg_verbose=False,
             show_hash=False, check_prefix=False, show_prefix=False):
    note(f"[{name}] generating ({mode}) …")
    try:
        h = call_gen(bin_path, gen_args, mode, pw)
    except subprocess.CalledProcessError as e:
        fail_test(f"generate FAILED: {label} ({e})")
        return

    if show_hash:
        # Always show hash output when requested
        print(f"{name}: {h}")

    # Always print prefix when either display or validation is requested
    if show_prefix or check_prefix:
        expected = _expected_prefix(gen_args)
        actual = _actual_prefix(h)
        status = "OK" if h.startswith(expected) else "BAD"
        print(f"{name}: prefix expected = {expected}, actual = {actual} -> {status}")

    if check_prefix:
        expected = _expected_prefix(gen_args)
        if h.startswith(expected):
            pass_test(f"prefix ok: {label} -> {expected}")
        else:
            fail_test(f"wrong prefix for {label}: expected {expected}")

    assert_regex(h, rx, label)

    note(f"[{name}] verifying …")
    verify_flags = []
    if ios9_dbg_verbose:
        verify_flags.append("-debug-ios9-verbose")
    elif ios9_dbg:
        verify_flags.append("-debug-ios9")
    ok_match = call_verify(bin_path, h, pw, verify_flags)
    if ok_match:
        pass_test(f"verify ok: {label}")
    else:
        fail_test(f"verify FAILED: {label}")

def summary_and_exit():
    print()
    if FAILS == 0:
        print(GREEN("QA SUCCESS — All checks passed."))
        print(f"Tests: {TESTS} OK: {OKS} FAIL: {FAILS}")
        sys.exit(0)
    else:
        print(RED("QA FAILED"))
        if not VERBOSE and FIRST_FAILURE_MSG:
            # In quiet mode, show the first failure line so users get at least one hint.
            print(f"- {FIRST_FAILURE_MSG}")
        print(f"Tests: {TESTS} OK: {OKS} FAIL: {FAILS}")
        sys.exit(1)

def main():
    global VERBOSE, KEEP_GOING, SUCCESS_ONLY, FAIL_ONLY

    ap = argparse.ArgumentParser(description="Cross-platform QA for cisco-hashgen")
    ap.add_argument("-bin", default="cisco-hashgen", help='Path to cisco-hashgen (default: "cisco-hashgen")')
    ap.add_argument("-manual", action="store_true", help="Prompt for test password (still quiet unless -verbose)")
    ap.add_argument("-no-mask", action="store_true", help="When used with -manual, show input in clear (no masking)")
    ap.add_argument("-verbose", "-v", action="store_true", help="Verbose per-test logging")
    ap.add_argument("-ios9-debug", action="store_true", help="Pass -debug-ios9 to verification")
    ap.add_argument("-ios9-debug-verbose", action="store_true", help="Pass -debug-ios9-verbose to verification")
    ap.add_argument("-no-structure", action="store_true", help="Skip regex checks (only run generate/verify)")
    ap.add_argument("-show-hash", action="store_true", help="Print each generated hash (even if not -verbose)")
    ap.add_argument("-check-prefix", action="store_true",
                help="Validate and print expected prefix for each case ($sha512$, $1$, $8$, $9)")
    ap.add_argument("-show-prefix", action="store_true",
                help="Print expected prefix for each case (no validation)")

    # Convenience 'go loud' preset
    ap.add_argument("-volume11", action="store_true",
                help="Equivalent to: -verbose -show-hash -check-prefix")

    # Keep-going behavior (default: True)
    kg = ap.add_mutually_exclusive_group()
    kg.add_argument("-keep-going", dest="keep_going", action="store_true", help="Keep running after failures (default)")
    kg.add_argument("-no-keep-going", dest="keep_going", action="store_false", help="Stop at first failure")
    ap.set_defaults(keep_going=True)

    # Print filters (This is effective only with the "-verbose" option.)
    pf = ap.add_mutually_exclusive_group()
    pf.add_argument("-success-only", action="store_true", help="When -verbose, print only successful per-test lines")
    pf.add_argument("-fail-only", action="store_true", help="When -verbose, print only failed per-test lines")

    args = ap.parse_args()

    # After args = ap.parse_args() and before using flags
    VERBOSE = bool(args.verbose)
    KEEP_GOING = bool(args.keep_going)
    SUCCESS_ONLY = bool(args.success_only)
    FAIL_ONLY = bool(args.fail_only)

    # Apply the volume preset
    if args.volume11:
        VERBOSE = True
        args.show_hash = True
        args.check_prefix = True

    bin_path = args.bin
    if not which(bin_path):
        fail_test(f"Cannot find '{bin_path}'. Provide -bin PATH or add it to PATH.")
        return

    try:
        ver = subprocess.check_output([bin_path, "--version"], text=True).strip()
    except (subprocess.CalledProcessError, OSError):
        ver = bin_path
    version_header(f"Testing: {ver}")

    # Manual password prompt (masked by default, visible with "-no-mask")
    if args.manual:
        prompt_txt = "Enter a test password to use for all cases: "
        pw = prompt_visible(prompt_txt) if args.no_mask else prompt_masked(prompt_txt)
        if not pw:
            fail_test("Empty password not allowed for manual mode")
            if not KEEP_GOING:
                return
            summary_and_exit()
            return
    else:
        pw = DEFAULT_PW

    # Sectioned, verbose-only headers
    # ASA
    section_header("ASA (PBKDF2-SHA512)")
    for (name, gen_args, rx, label, mode) in [
        ("ASA: -pwd",   ["-asa"],  RE_ASA,  "ASA (pbkdf2-sha512) via -pwd",   "pwd"),
        ("ASA: -env",   ["-asa"],  RE_ASA,  "ASA (pbkdf2-sha512) via -env",   "env"),
        ("ASA: stdin",  ["-asa"],  RE_ASA,  "ASA (pbkdf2-sha512) via stdin",  "stdin"),
    ]:
        rx_to_use = re.compile(r".*") if args.no_structure else rx
        run_case(bin_path, name, gen_args, rx_to_use, label, mode, pw,
                 ios9_dbg=args.ios9_debug, ios9_dbg_verbose=args.ios9_debug_verbose,
                 show_hash=args.show_hash, check_prefix=args.check_prefix, show_prefix=args.show_prefix)

    # IOS5
    section_header("IOS5 (MD5-crypt)")
    for (name, gen_args, rx, label, mode) in [
        ("IOS5: -pwd",  ["-ios5"], RE_IOS5, "IOS5 (md5-crypt) via -pwd",      "pwd"),
        ("IOS5: -env",  ["-ios5"], RE_IOS5, "IOS5 (md5-crypt) via -env",      "env"),
        ("IOS5: stdin", ["-ios5"], RE_IOS5, "IOS5 (md5-crypt) via stdin",     "stdin"),
    ]:
        rx_to_use = re.compile(r".*") if args.no_structure else rx
        run_case(bin_path, name, gen_args, rx_to_use, label, mode, pw,
                 ios9_dbg=args.ios9_debug, ios9_dbg_verbose=args.ios9_debug_verbose,
                 show_hash=args.show_hash, check_prefix=args.check_prefix, show_prefix=args.show_prefix)

    # IOS8
    section_header("IOS8 (PBKDF2-SHA256)")
    for (name, gen_args, rx, label, mode) in [
        ("IOS8: -pwd",  ["-ios8"], RE_IOS8, "IOS8 (pbkdf2-sha256) via -pwd",  "pwd"),
        ("IOS8: -env",  ["-ios8"], RE_IOS8, "IOS8 (pbkdf2-sha256) via -env",  "env"),
        ("IOS8: stdin", ["-ios8"], RE_IOS8, "IOS8 (pbkdf2-sha256) via stdin", "stdin"),
    ]:
        rx_to_use = re.compile(r".*") if args.no_structure else rx
        run_case(bin_path, name, gen_args, rx_to_use, label, mode, pw,
                 ios9_dbg=args.ios9_debug, ios9_dbg_verbose=args.ios9_debug_verbose,
                 show_hash=args.show_hash, check_prefix=args.check_prefix, show_prefix=args.show_prefix)

    # IOS9 canonical (Cisco64 salt)
    section_header("IOS9 (scrypt) — salt=cisco64 (canonical)")
    for (name, gen_args, rx, label, mode) in [
        ("IOS9: -pwd",  ["-ios9"], RE_IOS9, "IOS9 (scrypt) via -pwd",         "pwd"),
        ("IOS9: -env",  ["-ios9"], RE_IOS9, "IOS9 (scrypt) via -env",         "env"),
        ("IOS9: stdin", ["-ios9"], RE_IOS9, "IOS9 (scrypt) via stdin",        "stdin"),
    ]:
        rx_to_use = re.compile(r".*") if args.no_structure else rx
        run_case(bin_path, name, gen_args, rx_to_use, label, mode, pw,
                 ios9_dbg=args.ios9_debug, ios9_dbg_verbose=args.ios9_debug_verbose,
                 show_hash=args.show_hash, check_prefix=args.check_prefix, show_prefix=args.show_prefix)

    # IOS9 salt=ascii (non-canonical)
    section_header("IOS9 (scrypt) — salt=ascii (non-canonical)")
    for (name, gen_args, rx, label, mode) in [
        ("IOS9(ascii): -pwd", ["-ios9", "-ios9-salt-mode", "ascii"], RE_IOS9, "IOS9 (scrypt, salt=ascii) via -pwd", "pwd"),
    ]:
        rx_to_use = re.compile(r".*") if args.no_structure else rx
        run_case(bin_path, name, gen_args, rx_to_use, label, mode, pw,
                 ios9_dbg=args.ios9_debug, ios9_dbg_verbose=args.ios9_debug_verbose,
                 show_hash=args.show_hash, check_prefix=args.check_prefix, show_prefix=args.show_prefix)

    # IOS9 salt=stdb64 (non-canonical)
    section_header("IOS9 (scrypt) — salt=stdb64 (non-canonical)")
    for (name, gen_args, rx, label, mode) in [
        ("IOS9(stdb64): -pwd", ["-ios9", "-ios9-salt-mode", "stdb64"], RE_IOS9, "IOS9 (scrypt, salt=stdb64) via -pwd", "pwd"),
    ]:
        rx_to_use = re.compile(r".*") if args.no_structure else rx
        run_case(bin_path, name, gen_args, rx_to_use, label, mode, pw,
                 ios9_dbg=args.ios9_debug, ios9_dbg_verbose=args.ios9_debug_verbose,
                 show_hash=args.show_hash, check_prefix=args.check_prefix, show_prefix=args.show_prefix)

    summary_and_exit()

if __name__ == "__main__":
    main()