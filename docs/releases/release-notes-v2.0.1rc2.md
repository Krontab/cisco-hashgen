# Release Notes: v2.0.1

## 🚀 New Features
- **Cisco Type 9 (SCRYPT) Support**  
  - Added support for generating IOS/IOS-XE Type 9 hashes.
  - Ensures compatibility with certain Cisco devices that reject canonical (Cisco64) binary-salt scrypt hashes.
  - Controlled via new CLI flag `-ios9-salt-mode {cisco64,ascii,stdb64}`.
  - `-ios9-debug` displays Type 9 salt details when verifying \$9\$ hashes.

- **IOS/IOS-XE Type 5 (MD5) Support**
  - Cisco Type 5 MD5-based crypt password hashes.

- **New Quality Assurance (QA) Framework**
  - `qa.py` — Added in scripts directory for devs and users looking to test app functionality. 
  - New test cases for ASCII salt and mixed salt Type 9 variants.
  - Improved regex flexibility — allows custom regex patterns for advanced hash verification.
  - Enhanced manual/verbose mode success banners for clearer QA results.

## 🛠 Improvements
- Improved CLI argument handling
- Color output for hash verification results, debugs, etc.
- **Documentation**
  - Technical notes for all supported Cisco hash formats.
  - Details on canonical and non-canonical Cisco64 variants for Type 9 (SCRIPT).
  - Detailed usage examples in README.

## 🐛 Bug Fixes
- Fixed an issue where QA success banners were skipped in certain flag combinations.
- Corrected salt-handling logic for picky IOS/IOS-XE devices when using Type 9 scrypt hashes.

## 😅 Known Issues
- Devs: QA script (`qa.py`) may fail with certain passwords containing special characters and escape sequences. Input validation is not as robust as the tool itself. More testing is required.

## 🔍 Technical Summary
- **Type 5**: MD5crypt (1000 iterations, short salt).  
- **Type 8**: PBKDF2-HMAC-SHA256 (20000 iterations, 10-byte salt).  
- **Type 9**: scrypt (N=16384, r=1, p=1, 14-byte salt) — now supports binary, ASCII, and mixed salt modes.  
- **ASA**: PBKDF2-HMAC-SHA512 (variable iterations, Base64 salt, truncated DK).
