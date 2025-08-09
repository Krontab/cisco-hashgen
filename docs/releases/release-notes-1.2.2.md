# Cisco HashGen — Release Notes v1.2.2
**Release date:** 2025-08-09

## Changes
- Docs: Add cross-platform **Quick Install** (pipx) instructions to README.
- README polish: fixed ASA example typo; clarified macOS Keychain steps; added Windows pip note.

## Exit Codes
- 0 — success
- 1 — verification failed
- 2 — unsupported/invalid hash format
- 3 — password validation error
- 4 — no password provided with -no-prompt
- 130 — interrupted (Ctrl+C)
