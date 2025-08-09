# Cisco HashGen — Release Notes v1.2.1

**Release date:** 2025-08-08

## Changes
- **Added `-no-prompt` automation safeguard:**  
  When `-no-prompt` is specified and no password is provided via `stdin`, `-pwd`, or `-env`, the program now exits immediately with code `4` rather than prompting interactively.  
  This behavior applies to both hash generation and `-verify` mode.

## Exit Codes
- `0` — Success (hash generated or password verified)  
- `1` — Password verification failed  
- `2` — Unsupported hash format  
- `3` — Password validation error  
- `4` — No password provided and `-no-prompt` set  
- `130` — Interrupted by user (`Ctrl+C`)

---

For older changes, see [previous release notes](./release-notes-1.2.0.md).
