# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.1rc5] - 2025-08-12
### Added
- Added support for IOS/IOS-XE Type 9 (SCRYPT) hashes.
- Added support for IOS/IOS-XE Type 5 (MD5) hashes.
- Added Quality Assurance (QA) script for development testing.

### Changed
- Improved CLI argument handling
- Color output for hash verification results, debugs, etc.
- Documentation enhancements
- Most options now use single hyphens instead of double hyphens.

### Fixed
- Resolved missing success banners in certain flag combinations.
- Fixed salt-handling for Type 9 scrypt hashes to work on picky IOS/IOS-XE devices.

[2.0.1rc5]: https://github.com/Krontab/cisco-hashgen/releases/tag/v2.0.1rc2
