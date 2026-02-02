# Changelog

All notable changes to the Optical BlackBox project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Multi-file batch encryption
- Directory encryption
- Cloud storage integration
- Web-based file viewer

## [2.0.0] - 2026-02-02

### Changed - Major Architecture Simplification
- **BREAKING**: Removed all file parsing logic (no longer parse .zmx files)
- **BREAKING**: Removed optical calculations (EFL, NA, paraxial)
- **BREAKING**: Simplified to raw byte encryption/decryption
- **BREAKING**: Removed GUI module (0% test coverage)
- Reduced codebase by 36.4% (~1,420 lines removed)
- Simplified metadata model (5 fields vs 10+)
- Updated documentation to reflect byte-based architecture

### Added
- `extract` command to decrypt .obb files
- Comprehensive test fixtures
- New TESTING.md documentation
- Byte-for-byte identity verification in tests

### Removed
- All parsing modules (parsers/, optics/, surfaces/)
- Surface type definitions and calculations
- Glass catalog and refractive index database
- JSON codec for structured data
- Selective encryption feature
- GUI application

### Fixed
- All import errors after module removal
- Test fixtures for unit tests
- Metadata validation tests

## [1.0.0] - 2026-01-30 (Legacy Version)

### Added
- **Core Encryption**: ECDH key exchange + AES-256-GCM hybrid encryption
- **Digital Signatures**: ECDSA P-256 signatures for vendor authentication
- **OBB File Format**: Binary format with magic bytes, header, encrypted payload
- **CLI Tool**: `obb` command-line interface
- **Type Safety**: Pydantic v2 models with strict validation
- **Result Type**: Rust-inspired error handling pattern

### Security
- NIST P-256 elliptic curve cryptography
- AES-256-GCM authenticated encryption
- HKDF-SHA256 key derivation
- Key management with PEM format support
- Basic encryption/decryption prototype
- Zemax .zmx parsing (surface data only)
- Simple CLI prototype

---

## Release Notes

**Note**: Version 1.0.0 below describes a legacy architecture that parsed optical files. This was completely replaced in v2.0.0 with a simpler byte-based encryption approach.

### Version 2.0.0 - Architecture Simplification

Major rewrite focusing on simple file encryption rather than optical parsing:
- Removed all file parsing logic
- Removed optical calculations
- Simplified to byte-in, byte-out encryption
- 36% code reduction
- Perfect byte-for-byte restoration

### Version 1.0.0 - MVP Release (Legacy)

This is the first stable release of Optical BlackBox, providing a secure format for distributing encrypted optical lens designs.

**Key Features:**
- ✅ Zemax .zmx/.zar parsing (sequential systems)
- ✅ Standard and even asphere surfaces
- ✅ Hybrid encryption (ECDH + AES-256-GCM)
- ✅ Digital signatures (ECDSA P-256)
- ✅ Paraxial optical calculations
- ✅ Basic glass catalog (Schott)

**Known Limitations:**
- Parser supports sequential ray tracing only
- Limited surface types (no toroidal, odd asphere)
- Minimal glass catalog (40 glasses)
- No chromatic aberration calculations
- Single wavelength refractive index (d-line)

See [docs/MVP_LIMITATIONS.md](docs/MVP_LIMITATIONS.md) for detailed scope.

**Breaking Changes:**
- None (initial release)

**Migration Guide:**
- N/A (initial release)

---

## Versioning Policy

- **Major version** (X.0.0): Breaking API changes, file format changes
- **Minor version** (1.X.0): New features, backward-compatible
- **Patch version** (1.0.X): Bug fixes, documentation updates

## Links

- [GitHub Repository](https://github.com/ThibautA/obb)
- [Issue Tracker](https://github.com/ThibautA/obb/issues)
- [Security Policy](SECURITY.md)
- [Contributing Guide](CONTRIBUTING.md)
