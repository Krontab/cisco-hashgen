## What’s new
- `--version` flag
- `-no-prompt` mode for CI: fail fast if no password via stdin/`-pwd`/`-env` (exit 4)
- One-liner verify via stdin now works cleanly with `-v`
- Improved help text (quoting guide)
- Graceful Ctrl-C (exit 130)
- Official support: Python 3.8–3.13
- Improved README

## Installation
    python3 -m pip install cisco-hashgen

## Examples
# Generate IOS/IOS-XE Type 8 (stdin one-liner)
    echo 'My S3cr3t!' | cisco-hashgen -ios8 -quiet

# Verify (verbose)
    echo 'My S3cr3t!' | cisco-hashgen -ios8 -v '$8$HxHoQOhOgadA7E==$HjROgK8oWfeM45/EHbOwxCC328xBBYz2IF2BevFOSok='
