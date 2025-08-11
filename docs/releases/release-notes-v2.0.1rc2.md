## v2.0.1rc2 — Added Cisco Type 5 and Type 9 password hashing

### New features
- **Type 5 (MD5-crypt)** generation and verification:
  - Generates `$1$<salt>$<hash>` using system `crypt(3)`
  - Random salt automatically generated (8 chars)
  - Works on most Unix-like systems (Linux, macOS); not supported on Windows

- **Type 9 (scrypt)** generation and verification:
  - Uses `hashlib.scrypt` with Cisco defaults (N=16384, r=1, p=1)
  - Salt length: 14 bytes, encoded in Cisco64 alphabet
  - Optional CLI overrides for `N`, `r`, and `p`
  - Same Cisco64 alphabet as Type 8 PBKDF2-SHA256

### Notes
- No changes to existing Type 0, 4, 7, or 8 behavior
- CLI updated with `-ios5` and `-ios9` flags
- Verification automatically detects `$1$` (Type 5) and `$9$` (Type 9) formats

