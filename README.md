# Optical BlackBox (OBB)

[![PyPI version](https://badge.fury.io/py/optical-blackbox.svg)](https://badge.fury.io/py/optical-blackbox)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

Create encrypted optical design files (`.obb`) for secure distribution.

## Overview

Optical BlackBox allows optical component manufacturers to distribute their optical designs in an encrypted format that:

- **Protects IP**: Complete file encrypted with AES-256-GCM
- **Perfect restoration**: Decrypt to get the exact original file byte-for-byte
- **Simple workflow**: Encrypt raw file → Decrypt → Restore original
- **Minimal metadata**: Only vendor ID, model ID, and original filename exposed

## Installation

```bash
pip install optical-blackbox
```

## Quick Start

### 1. Generate encryption keys

```bash
obb keygen ./keys --prefix platform
```

This creates:
- `platform_private.pem` - Keep this **SECRET** (for decryption)
- `platform_public.pem` - Share with vendors (for encryption)

### 2. Create an encrypted file

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

The restored file is **byte-for-byte identical** to the original.

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

```
┌──────────────────────────────────────────────────────────────────┐
│                         .obb FILE                                │
├──────────────────────────────────────────────────────────────────┤
│  PUBLIC HEADER (JSON)           │  ENCRYPTED PAYLOAD             │
│  ─────────────────────          │  ────────────────────          │
│  • version                      │  • Complete raw file bytes     │
│  • vendor_id                    │  • Original file format        │
│  • model_id                     │  • All original content        │
│  • description (optional)       │  (AES-256-GCM encrypted)       │
│  • original_filename            │                                │
│  • created_at                   │                                │
│  • ephemeral_public_key (ECDH)  │                                │
└──────────────────────────────────────────────────────────────────┘
```

- **Platform Public Key**: Used to encrypt file via ECDH + AES-256-GCM
- **Only the platform** with the matching private key can decrypt
- **Anyone** can read the public metadata
- **Perfect roundtrip**: Decrypted file is byte-for-byte identical to original

## CLI Commands

| Command | Description |
|---------|-------------|
| `obb keygen` | Generate ECDSA P-256 key pair |
| `obb create` | Encrypt an optical design file to .obb |
| `obb extract` | Decrypt .obb and restore original file |
| `obb inspect` | View public metadata without decryption |

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
