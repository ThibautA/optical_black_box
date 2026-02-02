# Optical BlackBox (OBB) v2.0

[![PyPI version](https://badge.fury.io/py/optical-blackbox.svg)](https://badge.fury.io/py/optical-blackbox)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

Create encrypted optical design files (`.obb`) for secure distribution with **single or multi-recipient** encryption.

## Overview

Optical BlackBox allows optical component manufacturers to distribute their optical designs in an encrypted format that:

- **Protects IP**: Complete file encrypted with AES-256-GCM
- **Multi-recipient support (v2.0)**: Encrypt once, multiple platforms can decrypt
- **Post-distribution management**: Add or revoke recipients without re-encryption (via sidecar)
- **Perfect restoration**: Decrypt to get the exact original file byte-for-byte
- **Simple workflow**: Encrypt raw file → Decrypt → Restore original
- **Minimal metadata**: Only vendor ID, model ID, and original filename exposed
- **Backwards compatible**: Supports both v1.0 (single recipient) and v2.0 (multi-recipient) formats

## Installation

```bash
pip install optical-blackbox
```

## Quick Start

### 1. Generate encryption keys

**For v2.0 (multi-recipient - RSA-2048):**
```bash
obb keygen ./keys --prefix platform --type rsa
```

**For v1.0 (single recipient - ECDSA P-256):**
```bash
obb keygen ./keys --prefix platform
```

This creates:
- `platform_private.pem` - Keep this **SECRET** (for decryption)
- `platform_public.pem` - Share with vendors (for encryption)

### 2. Create an encrypted file

**V2.0 - Multi-recipient (recommended):**
```bash
obb create-v2 lens.zmx lens.obb \
    -k platform1_public.pem \
    -k platform2_public.pem \
    -n "Zemax OpticStudio" \
    -n "CODE V" \
    -v acme-optics \
    -m lens-50mm \
    -d "50mm imaging lens"
```

**V1.0 - Single recipient:**
```bash
obb create lens.zmx lens.obb \
    -k platform_public.pem \
    -v acme-optics \
    -m lens-50mm \
    -d "50mm imaging lens"
```

### 3. Extract the encrypted file

```bash
obb extract lens.obb lens_restored.zmx \
    -k platform_private.pem
```

The restored file is **byte-for-byte identical** to the original. Works with both v1.0 and v2.0 files automatically.

### 4. Inspect metadata (no decryption needed)

```bash
obb inspect lens.obb
```

Output:
```
┌─────────────────────────────────┐
│        OBB Metadata             │
├──────────────┬──────────────────┤
│ Version      │ 1.0.0            │
│ Vendor ID    │ acme-optics      │
│ Model ID     │ lens-50mm        │
│ Description  │ 50mm imaging lens│
│ Original     │ lens.zmx         │
│ Created      │ 2026-02-02...    │
└──────────────┴──────────────────┘
```

## Security Model

### V1.0 - Single Recipient (ECDH)
```
┌──────────────────────────────────────────────────────────────────┐
│                      .obb FILE v1.0                              │
├──────────────────────────────────────────────────────────────────┤
│  PUBLIC HEADER (JSON)           │  ENCRYPTED PAYLOAD             │
│  ─────────────────────          │  ────────────────────          │
│  • version: "1.0"               │  • Complete raw file bytes     │
│  • vendor_id                    │  • Original file format        │
│  • model_id                     │  • All original content        │
│  • description (optional)       │  (AES-256-GCM encrypted)       │
│  • original_filename            │                                │
│  • created_at                   │                                │
│  • ephemeral_public_key (ECDH)  │                                │
└──────────────────────────────────────────────────────────────────┘
```

- **Encryption**: ECDH + AES-256-GCM
- **One platform** can decrypt with matching private key

### V2.0 - Multi-Recipient (RSA-OAEP)
```
┌──────────────────────────────────────────────────────────────────┐
│                      .obb FILE v2.0                              │
├──────────────────────────────────────────────────────────────────┤
│  PUBLIC HEADER (JSON)           │  ENCRYPTED PAYLOAD             │
│  ─────────────────────          │  ────────────────────          │
│  • version: "2.0"               │  • Complete raw file bytes     │
│  • vendor_id                    │  • Original file format        │
│  • model_id                     │  • All original content        │
│  • description (optional)       │  (AES-256-GCM encrypted)       │
│  • original_filename            │                                │
│  • created_at                   │                                │
│  • recipients[] - list of:      │  • Single DEK used             │
│    - platform_fingerprint       │                                │
│    - wrapped_dek (RSA-OAEP)     │                                │
│    - platform_name (optional)   │                                │
│  • sidecar_url (optional)       │                                │
└──────────────────────────────────────────────────────────────────┘
```

- **Encryption**: One DEK (Data Encryption Key) encrypted with AES-256-GCM
- **Each recipient** gets the DEK wrapped with RSA-OAEP using their public key
- **Multiple platforms** can decrypt with their respective private keys
- **Sidecar support**: Add/revoke recipients after distribution (see below)

### Common Properties
- **Anyone** can read the public metadata
- **Perfect roundtrip**: Decrypted file is byte-for-byte identical to original
- **Backwards compatible**: v2.0 readers can detect and handle v1.0 files

## Post-Distribution Management (V2.0 Sidecar)

V2.0 introduces **sidecar JSON files** for managing recipients after distribution:

```bash
# Create sidecar with initial recipients
obb sidecar create \
    -i lens-50mm \
    -v acme-optics \
    -m lens-50mm \
    -d dek.bin \
    -k platform1.pub -k platform2.pub \
    -o sidecar.json

# Add new recipient
obb sidecar add-recipient sidecar.json \
    -d dek.bin \
    -k new_platform.pub \
    -n "New Platform"

# Revoke recipient (future downloads only)
obb sidecar revoke sidecar.json \
    -f a1b2c3d4...  # platform fingerprint
```

**Important limitation**: Sidecar revocation only affects future downloads. Already-downloaded files cannot be remotely revoked (offline decryption property).

## Graphical Interface

Launch the GUI for easy file management:

```bash
obb gui
```

Features:
- Create v1.0 or v2.0 files with drag-and-drop
- Extract and decrypt files (auto-detects version)
- Inspect metadata without decryption
- Generate RSA-2048 or ECDSA P-256 keys
- Multi-recipient management for v2.0

## CLI Commands

| Command | Description |
|---------|-------------|
| `obb keygen` | Generate RSA-2048 or ECDSA P-256 key pair |
| `obb create` | Encrypt file to .obb v1.0 (single recipient) |
| `obb create-v2` | Encrypt file to .obb v2.0 (multi-recipient) |
| `obb extract` | Decrypt .obb and restore original (auto-detects version) |
| `obb inspect` | View public metadata without decryption |
| `obb sidecar` | Manage sidecar files (create/add/revoke recipients) |
| `obb gui` | Launch graphical interface |

## Supported Formats

### Input
- Any optical design file (`.zmx`, `.zar`, `.zos`, etc.)
- Raw bytes are encrypted - no parsing required

### Output
- `.obb` (Optical BlackBox format) - encrypted file with metadata

## Development

```bash
# Clone the repository
git clone https://github.com/ThibautA/obb.git
cd obb

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Type checking
mypy src/

# Linting
ruff check src/
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.
