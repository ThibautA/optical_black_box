# Optical BlackBox (OBB) - Technical Specification v2.0

## Overview

Open-source framework enabling optical component manufacturers to distribute their optical designs in encrypted form while allowing decryption by authorized platforms.

**Version 2.0** introduces **multi-recipient encryption** and **post-distribution management** via sidecar files.

**Simplified principle**: 
- **V1.0**: Encrypt with ECDH → One platform can decrypt
- **V2.0**: Encrypt once with AES → Multiple platforms can decrypt (RSA-OAEP wrapped DEKs)

---

## Simplified Architecture

```
┌─────────────────────────────────────────┐      ┌─────────────────────────────────┐
│  STANDALONE TOOL                         │      │  PLATFORM (Etendue Agent)       │
│  "optical-blackbox" (PyPI)              │      │                                 │
│                                         │      │                                 │
│  • CLI: obb keygen / create / extract   │      │  • Import .obb files            │
│  • CLI: obb create-v2 / sidecar        │      │  • Auto-detect version          │
│  • Read raw file (bytes)                │  →   │  • Decryption (v1.0 or v2.0)   │
│  • V1.0: ECDH + AES-256-GCM            │ .obb │  • Original file restoration    │
│  • V2.0: RSA-OAEP + AES-256-GCM        │      │  • Use for raytracing           │
│  • GUI: Modern interface                │      │                                 │
│  • 100% local, no web dependencies      │      │                                 │
└─────────────────────────────────────────┘      └─────────────────────────────────┘
         AT VENDOR SITE                                   PLATFORM
```

---

## 1. .obb File Format

### 1.1 V1.0 Binary Structure (Single Recipient)

```
┌─────────────────────────────────────────────────────────────────┐
│                      .obb FILE v1.0                             │
├─────────────────────────────────────────────────────────────────┤
│  [MAGIC: 4 bytes]  "OBB\x00"                                    │
├─────────────────────────────────────────────────────────────────┤
│  [VERSION: 1 byte]  0x01                                        │
├─────────────────────────────────────────────────────────────────┤
│  [HEADER_LENGTH: 4 bytes]  Length of JSON header                │
├─────────────────────────────────────────────────────────────────┤
│  [HEADER: N bytes]  JSON with public metadata                   │
├─────────────────────────────────────────────────────────────────┤
│  [ENCRYPTED_PAYLOAD: M bytes]                                   │
│    • [Nonce: 12 bytes]  AES-GCM nonce                          │
│    • [Ciphertext: X bytes]  Encrypted file + auth tag          │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 V2.0 Binary Structure (Multi-Recipient)

```
┌─────────────────────────────────────────────────────────────────┐
│                      .obb FILE v2.0                             │
├─────────────────────────────────────────────────────────────────┤
│  [MAGIC: 4 bytes]  "OBB\x00"                                    │
├─────────────────────────────────────────────────────────────────┤
│  [VERSION: 1 byte]  0x02                                        │
├─────────────────────────────────────────────────────────────────┤
│  [METADATA_LENGTH: 4 bytes]  Length of JSON metadata            │
├─────────────────────────────────────────────────────────────────┤
│  [METADATA: N bytes]  JSON with recipients and metadata         │
├─────────────────────────────────────────────────────────────────┤
│  [ENCRYPTED_PAYLOAD: M bytes]                                   │
│    • [Nonce: 12 bytes]  AES-GCM nonce                          │
│    • [Ciphertext: X bytes]  Encrypted file + auth tag          │
└─────────────────────────────────────────────────────────────────┘
```

**Key difference**: V2.0 uses a single DEK (Data Encryption Key) for the payload,
and includes multiple RSA-OAEP wrapped copies of this DEK in the metadata, one
for each authorized recipient.

### 1.3 JSON Metadata Examples

**V1.0 Metadata (Single Recipient)**:
```json
{
  "version": "1.0",
  "vendor_id": "acme-optics",
  "model_id": "lens-50mm",
  "created_at": "2026-02-02T15:30:00Z",
  "description": "50mm imaging lens",
  "original_filename": "lens.zmx",
  "ephemeral_public_key": "-----BEGIN PUBLIC KEY-----\n..."
}
```

**V2.0 Metadata (Multi-Recipient)**:
```json
{
  "version": "2.0",
  "vendor_id": "acme-optics",
  "model_id": "lens-50mm",
  "created_at": "2026-02-02T15:30:00Z",
  "description": "50mm imaging lens",
  "original_filename": "lens.zmx",
  "recipients": [
    {
      "platform_fingerprint": "a1b2c3d4e5f6...",
      "wrapped_dek": "base64_encoded_rsa_oaep_wrapped_dek",
      "platform_name": "Zemax OpticStudio"
    },
    {
      "platform_fingerprint": "f6e5d4c3b2a1...",
      "wrapped_dek": "base64_encoded_rsa_oaep_wrapped_dek",
      "platform_name": "CODE V"
    }
  ],
  "sidecar_url": "https://vendor.com/api/sidecar/lens-50mm.json"
}
```

**Fields**:
- `version`: OBB format version ("1.0" or "2.0")
- `vendor_id`: Manufacturer identifier (lowercase, alphanumeric + hyphens)
- `model_id`: Model identifier (lowercase, alphanumeric + hyphens)
- `created_at`: Creation date/time (ISO 8601 with Z suffix)
- `description`: Optional description
- `original_filename`: Original file name
- `ephemeral_public_key`: (V1.0 only) Ephemeral public key for ECDH (PEM)
- `recipients`: (V2.0 only) List of authorized recipients
  - `platform_fingerprint`: SHA-256 fingerprint of recipient's RSA public key (hex)
  - `wrapped_dek`: RSA-OAEP encrypted Data Encryption Key (base64)
  - `platform_name`: Optional human-readable platform name
- `sidecar_url`: (V2.0 only) Optional URL to sidecar JSON for post-distribution updates

### 1.4 Encrypted Payload

The payload contains the raw bytes of the original file encrypted with AES-256-GCM.

**V1.0 Process**:
1. Generate ephemeral ECDH key pair (SECP256R1)
2. Derive AES-256 key via ECDH with platform's public key
3. Encrypt raw file with AES-256-GCM
4. Store: nonce (12 bytes) + ciphertext (with auth tag 16 bytes)

**V2.0 Process**:
1. Generate random DEK (32 bytes for AES-256)
2. Encrypt raw file with DEK using AES-256-GCM
3. For each recipient:
   - Wrap DEK with recipient's RSA public key using RSA-OAEP
   - Store wrapped DEK in metadata
4. Store: nonce (12 bytes) + ciphertext (with auth tag 16 bytes)

---

## 2. Cryptography

### 2.1 V1.0 Cryptography (Single Recipient)

**ECDH (Elliptic Curve Diffie-Hellman)**

**Curve**: SECP256R1 (NIST P-256)

**Encryption process**:
1. Platform generates a key pair (private, public)
2. Vendor receives the platform's public key
3. For each file, vendor generates an ephemeral pair
4. Compute shared secret: `ECDH(ephemeral_private, platform_public)`
5. Derive AES key via HKDF-SHA256
6. Encrypt payload with AES-256-GCM

**Decryption process**:
1. Read ephemeral public key from header
2. Compute shared secret: `ECDH(platform_private, ephemeral_public)`
3. Derive the same AES key
4. Decrypt payload with AES-256-GCM

### 2.2 V2.0 Cryptography (Multi-Recipient)

**RSA-OAEP (RSA Optimal Asymmetric Encryption Padding)**

**Key size**: 2048 bits
**Padding**: OAEP with SHA-256 and MGF1

**Encryption process**:
1. Each platform generates an RSA-2048 key pair (private, public)
2. Vendor receives all platforms' public keys
3. For each file:
   - Generate random DEK (32 bytes for AES-256)
   - Encrypt payload with DEK using AES-256-GCM
   - For each recipient:
     * Wrap DEK: `RSA_OAEP_ENCRYPT(dek, recipient_public_key)`
     * Compute fingerprint: `SHA256(recipient_public_key_DER)`
     * Store wrapped DEK + fingerprint in metadata

**Decryption process**:
1. Read metadata and identify platform's wrapped DEK by fingerprint
2. Unwrap DEK: `RSA_OAEP_DECRYPT(wrapped_dek, platform_private_key)`
3. Decrypt payload with unwrapped DEK using AES-256-GCM

**Fingerprints**:
- SHA-256 hash of the public key's DER encoding
- Used to identify which wrapped DEK belongs to which platform
- 64-character hex string

### 2.3 AES-256-GCM (Both Versions)

**Parameters**:
- Mode: GCM (Galois/Counter Mode)
- Key size: 256 bits (32 bytes)
- Nonce: 96 bits (12 bytes) - random for each file
- Authentication tag: 128 bits (16 bytes)

**Advantages**:
- Encryption + authentication in a single pass
- Protection against ciphertext modification
- High performance

---

## 3. Sidecar Files (V2.0 Post-Distribution Management)

### 3.1 Purpose

Sidecar JSON files enable vendors to manage recipients **after** initial distribution:
- Add new platforms without re-encrypting the .obb file
- Revoke platforms (affects future downloads only)
- Track recipient history

**Important limitation**: Cannot revoke already-downloaded files (offline decryption).

### 3.2 Sidecar JSON Structure

```json
{
  "obb_file_id": "lens-50mm",
  "vendor_id": "acme-optics",
  "model_id": "lens-50mm",
  "version": "1.0",
  "created_at": "2026-02-02T15:30:00Z",
  "updated_at": "2026-02-03T10:15:00Z",
  "recipients": [
    {
      "platform_fingerprint": "a1b2c3d4e5f6...",
      "wrapped_dek": "base64_encoded_rsa_oaep_wrapped_dek",
      "platform_name": "Zemax OpticStudio",
      "added_at": "2026-02-02T15:30:00Z",
      "revoked": false,
      "revoked_at": null
    },
    {
      "platform_fingerprint": "f6e5d4c3b2a1...",
      "wrapped_dek": "base64_encoded_rsa_oaep_wrapped_dek",
      "platform_name": "New Platform",
      "added_at": "2026-02-03T10:15:00Z",
      "revoked": false,
      "revoked_at": null
    }
  ]
}
```

### 3.3 Workflow

1. **Create sidecar** with initial recipients (requires access to original DEK)
2. **Host sidecar** on vendor's server (URL in .obb metadata)
3. **Platform checks** sidecar URL before decryption
4. **Merge** sidecar recipients with .obb metadata
5. **Filter out** revoked recipients
6. **Decrypt** with platform's private key

---

## 4. CLI Commands

### 4.1 Key Generation

```bash
# RSA-2048 (for v2.0 multi-recipient)
obb keygen OUTPUT_DIR --prefix KEYNAME --type rsa

# ECDSA P-256 (for v1.0 single recipient)
obb keygen OUTPUT_DIR --prefix KEYNAME

# Example
obb keygen ./keys --prefix platform --type rsa

# Generates:
# - platform_private.pem  (secret, for decryption)
# - platform_public.pem   (public, for encryption)
```

**Options**:
- `OUTPUT_DIR`: Destination folder (must exist)
- `--prefix`: Filename prefix
- `--type`: Key type (`rsa` for V2.0, `ecdsa` for V1.0, default: `ecdsa`)
- `--force`: Overwrite existing files

### 4.2 V1.0 Creating .obb File (Single Recipient)

```bash
obb create INPUT_FILE OUTPUT_FILE \
    -k PLATFORM_PUBLIC_KEY \
    -v VENDOR_ID \
    -m MODEL_ID \
    [-d DESCRIPTION] \
    [--optical-config JSON_FILE]

# Example
obb create lens.zmx lens.obb \
    -k platform_public.pem \
    -v acme-optics \
    -m lens-50mm \
    -d "50mm imaging lens" \
    --optical-config lens_config.json
```

**Arguments**:
- `INPUT_FILE`: File to encrypt (any format)
- `OUTPUT_FILE`: Output .obb file
- `-k, --platform-key`: Platform's public key (PEM, ECDSA P-256)
- `-v, --vendor-id`: Manufacturer ID (3-50 chars, lowercase alphanumeric + hyphens)
- `-m, --model-id`: Model ID (3-50 chars, lowercase alphanumeric + hyphens)
- `-d, --description`: Optional description
- `--optical-config`: Optional JSON file with optical configuration
- `--force`: Overwrite output file if it exists

### 4.3 V2.0 Creating .obb File (Multi-Recipient)

```bash
obb create-v2 INPUT_FILE OUTPUT_FILE \
    --recipient-key KEY1.pem \
    --recipient-key KEY2.pem \
    --recipient-key KEY3.pem \
    -v VENDOR_ID \
    -m MODEL_ID \
    [-d DESCRIPTION] \
    [--optical-config JSON_FILE] \
    [--sidecar-url URL]

# Example
obb create-v2 lens.zmx lens.obb \
    --recipient-key zemax_public.pem \
    --recipient-key lumerical_public.pem \
    --recipient-key comsol_public.pem \
    -v acme-optics \
    -m lens-50mm \
    -d "50mm imaging lens" \
    --optical-config lens_config.json \
    --sidecar-url https://api.acme-optics.com/sidecar/lens-50mm
```

**Arguments**:
- `INPUT_FILE`: File to encrypt (any format)
- `OUTPUT_FILE`: Output .obb file
- `--recipient-key`: Platform's public key (PEM, RSA-2048) - can be repeated
- `-v, --vendor-id`: Manufacturer ID
- `-m, --model-id`: Model ID
- `-d, --description`: Optional description
- `--optical-config`: Optional JSON file with optical configuration
- `--sidecar-url`: Optional URL to sidecar JSON for post-distribution management
- `--force`: Overwrite output file if it exists

### 4.4 Extracting .obb File (V1.0 and V2.0)

```bash
obb extract INPUT_FILE OUTPUT_FILE \
    -k PLATFORM_PRIVATE_KEY

# Example
obb extract lens.obb lens_restored.zmx \
    -k platform_private.pem
```

**Arguments**:
- `INPUT_FILE`: .obb file to decrypt
- `OUTPUT_FILE`: Restored file
- `-k, --platform-key`: Platform's private key (PEM, ECDSA or RSA)
- `--force`: Overwrite output file if it exists

**Guarantee**: The restored file is **byte-for-byte identical** to the original.

### 4.5 Sidecar Management (V2.0 Only)

**Create sidecar from existing .obb file:**

```bash
obb sidecar create OBB_FILE OUTPUT_SIDECAR \
    --dek-file DEK_FILE

# Example
obb sidecar create lens.obb lens.sidecar.json \
    --dek-file lens_dek.bin
```

**Add recipient to sidecar:**

```bash
obb sidecar add-recipient SIDECAR_FILE \
    --recipient-key PUBLIC_KEY \
    --dek-file DEK_FILE \
    [--name "Platform Name"]

# Example
obb sidecar add-recipient lens.sidecar.json \
    --recipient-key newplatform_public.pem \
    --dek-file lens_dek.bin \
    --name "New CAD Platform"
```

**Revoke recipient:**

```bash
obb sidecar revoke SIDECAR_FILE \
    --fingerprint FINGERPRINT

# Example
obb sidecar revoke lens.sidecar.json \
    --fingerprint a1b2c3d4e5f6789...
```

**List recipients:**

```bash
obb sidecar list SIDECAR_FILE

# Example
obb sidecar list lens.sidecar.json
```

### 4.6 Metadata Inspection

```bash
obb inspect INPUT_FILE [--json]

# Example
obb inspect lens.obb
obb inspect lens.obb --json
```

**Options**:
- `--json`: JSON format output instead of table

**Output** (without decryption):
```
                   OBB Metadata                   
┏━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Property          ┃ Value                      ┃
┡━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Version           │ 1.0.0                      │
│ Vendor ID         │ acme-optics                │
│ Model ID          │ lens-50mm                  │
│ Description       │ 50mm imaging lens          │
│ Original Filename │ lens.zmx                   │
│ Created           │ 2026-02-02T15:30:00.123456 │
└───────────────────┴────────────────────────────┘
```

---

## 5. Python API

### 5.1 Key Generation

```python
from optical_blackbox import KeyManager
from pathlib import Path

# V1.0: Generate ECDSA P-256 key pair
private_key, public_key = KeyManager.generate_keypair()

# V2.0: Generate RSA-2048 key pair
private_key, public_key = KeyManager.generate_rsa_keypair()

# Save keys
KeyManager.save_private_key(private_key, Path("platform_private.pem"))
KeyManager.save_public_key(public_key, Path("platform_public.pem"))

# Load keys
private_key = KeyManager.load_private_key(Path("platform_private.pem"))
public_key = KeyManager.load_public_key(Path("platform_public.pem"))
```

### 5.2 V1.0 Creating .obb File (Single Recipient)

```python
from optical_blackbox import OBBWriter, OBBMetadata, KeyManager
from pathlib import Path
from datetime import datetime

# Load platform's public key (ECDSA)
platform_public = KeyManager.load_public_key(Path("platform_public.pem"))

# Read file to encrypt
input_file = Path("lens.zmx")
file_bytes = input_file.read_bytes()

# Create metadata
metadata = OBBMetadata(
    version="1.0.0",
    vendor_id="acme-optics",
    model_id="lens-50mm",
    created_at=datetime.utcnow(),
    description="50mm imaging lens",
    original_filename=input_file.name,
)

# Create .obb file (V1.0 single recipient)
OBBWriter.write(
    output_path=Path("lens.obb"),
    payload_bytes=file_bytes,
    metadata=metadata,
    platform_public_key=platform_public,
)
```

### 5.3 V2.0 Creating .obb File (Multi-Recipient)

```python
from optical_blackbox.formats.obb_file_v2 import OBBWriterV2
from optical_blackbox import OBBMetadata, KeyManager
from pathlib import Path
from datetime import datetime

# Load multiple platforms' public keys (RSA)
zemax_public = KeyManager.load_public_key(Path("zemax_public.pem"))
lumerical_public = KeyManager.load_public_key(Path("lumerical_public.pem"))
comsol_public = KeyManager.load_public_key(Path("comsol_public.pem"))

recipient_keys = [zemax_public, lumerical_public, comsol_public]

# Read file to encrypt
input_file = Path("lens.zmx")
file_bytes = input_file.read_bytes()

# Create metadata
metadata = OBBMetadata(
    version="2.0.0",
    vendor_id="acme-optics",
    model_id="lens-50mm",
    created_at=datetime.utcnow(),
    description="50mm imaging lens",
    original_filename=input_file.name,
    sidecar_url="https://api.acme-optics.com/sidecar/lens-50mm",
)

# Create .obb file (V2.0 multi-recipient)
OBBWriterV2.write(
    output_path=Path("lens.obb"),
    payload_bytes=file_bytes,
    metadata=metadata,
    recipient_public_keys=recipient_keys,
)
```

### 5.4 Extracting .obb File (V1.0 and V2.0)

```python
from optical_blackbox import OBBReader, KeyManager
from pathlib import Path

# Load platform's private key (ECDSA or RSA)
platform_private = KeyManager.load_private_key(Path("platform_private.pem"))

# Read and decrypt .obb file (auto-detects V1.0 or V2.0)
metadata, file_bytes = OBBReader.read_and_decrypt(
    path=Path("lens.obb"),
    platform_private_key=platform_private,
)

# Save restored file
Path("lens_restored.zmx").write_bytes(file_bytes)

# Access metadata
print(f"Vendor: {metadata.vendor_id}")
print(f"Model: {metadata.model_id}")
print(f"Original: {metadata.original_filename}")
```

### 5.5 Reading Metadata Only

```python
from optical_blackbox import OBBReader
from pathlib import Path

# Read metadata without decrypting
metadata = OBBReader.read_metadata(Path("lens.obb"))

print(f"Vendor: {metadata.vendor_id}")
print(f"Model: {metadata.model_id}")
print(f"Description: {metadata.description}")
print(f"Version: {metadata.version}")

# V2.0 specific
if hasattr(metadata, 'recipients'):
    print(f"Recipients: {len(metadata.recipients)}")
    for recipient in metadata.recipients:
        print(f"  - {recipient.get('platform_name', 'Unknown')}")
```

### 5.6 Sidecar Management (V2.0 Only)

```python
from optical_blackbox.formats.sidecar import SidecarManager
from optical_blackbox import KeyManager
from pathlib import Path

# Load DEK (Data Encryption Key) - saved during .obb creation
dek_bytes = Path("lens_dek.bin").read_bytes()

# Create sidecar from existing .obb file
sidecar = SidecarManager.create_from_obb(
    obb_path=Path("lens.obb"),
    dek_bytes=dek_bytes,
)

# Add new recipient
new_platform_public = KeyManager.load_public_key(Path("newplatform_public.pem"))
SidecarManager.add_recipient(
    sidecar=sidecar,
    public_key=new_platform_public,
    dek_bytes=dek_bytes,
    platform_name="New CAD Platform",
)

# Save sidecar
SidecarManager.save(sidecar, Path("lens.sidecar.json"))

# Revoke recipient by fingerprint
SidecarManager.revoke_recipient(
    sidecar=sidecar,
    fingerprint="a1b2c3d4e5f6789...",
)

# List active recipients
active_recipients = SidecarManager.list_active_recipients(sidecar)
for recipient in active_recipients:
    print(f"{recipient['platform_name']}: {recipient['platform_fingerprint'][:16]}...")
```

---

## 6. Code Structure

## 6. Code Structure

### 6.1 Module Organization

```
src/optical_blackbox/
├── __init__.py              # Public API
├── cli/                     # Command-line interface
│   ├── main.py              # CLI entry point
│   ├── commands/
│   │   ├── keygen.py        # Key generation (RSA/ECDSA)
│   │   ├── create.py        # V1.0 .obb creation
│   │   ├── create_v2.py     # V2.0 .obb creation
│   │   ├── extract.py       # .obb extraction (V1/V2)
│   │   ├── inspect.py       # Metadata inspection
│   │   ├── sidecar.py       # Sidecar management
│   │   └── gui.py           # GUI launcher
│   └── output/
│       ├── console.py       # Console formatting
│       └── formatters.py    # Rich tables
├── crypto/                  # Cryptography
│   ├── keys.py              # Key management (ECDSA/RSA)
│   ├── ecdh.py              # V1.0 ECDH + HKDF
│   ├── hybrid.py            # V2.0 RSA-OAEP + AES
│   ├── aes_gcm.py           # AES-256-GCM encryption
│   └── signing.py           # ECDSA signatures
├── formats/                 # .obb format
│   ├── obb_file.py          # V1.0 OBBWriter/OBBReader
│   ├── obb_file_v2.py       # V2.0 OBBWriterV2/OBBReaderV2
│   ├── obb_header.py        # JSON header serialization
│   ├── obb_payload.py       # Payload encryption/decryption
│   ├── obb_constants.py     # Magic bytes, constants
│   └── sidecar.py           # Sidecar JSON management
├── models/                  # Data models
│   ├── metadata.py          # OBBMetadata (Pydantic)
│   ├── optical_config.py    # Optical configuration
│   ├── surface.py           # Surface data
│   ├── surface_group.py     # Surface groups
│   └── vendor.py            # Vendor information
├── parsers/                 # File format parsers
│   ├── zmx_parser.py        # Zemax .zmx parser
│   ├── zmx_tokens.py        # .zmx token definitions
│   ├── zmx_surface_mapper.py # Surface mapping
│   └── zar_extractor.py     # .zar archive extraction
├── serialization/           # Serialization
│   ├── binary.py            # Binary read/write
│   ├── pem.py               # Key ↔ PEM conversion
│   └── json_codec.py        # JSON encoding/decoding
├── surface_types/           # Surface type definitions
│   ├── standard.py          # Standard surfaces
│   ├── even_asphere.py      # Even asphere surfaces
│   └── registry.py          # Surface type registry
├── gui/                     # Graphical interface
│   ├── __init__.py
│   └── app.py               # GUI application (V1/V2 support)
└── core/                    # Utilities
    ├── constants.py         # Global constants
    └── validators.py        # ID validation
```

### 6.2 Main Data Model

```python
from pydantic import BaseModel, Field, field_validator
from datetime import datetime

class OBBMetadata(BaseModel):
    """Public metadata of an .obb file"""
    
    version: str = Field(default="1.0.0")
    vendor_id: str = Field(min_length=3, max_length=50)
    model_id: str = Field(min_length=3, max_length=50)
    created_at: datetime
    description: str | None = None
    original_filename: str
    
    # V2.0 specific fields
    recipients: list[dict] | None = None  # For V2.0 multi-recipient
    sidecar_url: str | None = None  # URL for post-distribution management
    
    @field_validator('vendor_id', 'model_id')
    def validate_id_format(cls, v: str) -> str:
        """Validate format: lowercase alphanumeric + hyphens"""
        if not v.replace('-', '').isalnum() or not v.islower():
            raise ValueError("Must be lowercase alphanumeric with hyphens")
        return v
```

---

## 7. Testing

## 7. Testing

### 7.1 V1.0 Roundtrip Tests

```python
def test_v1_roundtrip_bytes():
    """Test that V1.0 encryption/decryption is perfect"""
    
    # Original data
    original_bytes = b"Test data" * 100
    
    # Generate keys (ECDSA P-256)
    platform_private, platform_public = KeyManager.generate_keypair()
    
    # Encrypt
    OBBWriter.write(
        output_path=Path("test.obb"),
        payload_bytes=original_bytes,
        metadata=metadata,
        platform_public_key=platform_public,
    )
    
    # Decrypt
    _, decrypted_bytes = OBBReader.read_and_decrypt(
        path=Path("test.obb"),
        platform_private_key=platform_private,
    )
    
    # Verify
    assert decrypted_bytes == original_bytes
```

### 7.2 V2.0 Multi-Recipient Tests

```python
def test_v2_multi_recipient():
    """Test that V2.0 works with multiple recipients"""
    
    # Generate 3 platform key pairs (RSA-2048)
    keys = []
    for i in range(3):
        private, public = KeyManager.generate_rsa_keypair()
        keys.append((private, public))
    
    # Encrypt for all 3 platforms
    original_bytes = b"Test data" * 100
    public_keys = [pub for _, pub in keys]
    
    OBBWriterV2.write(
        output_path=Path("test.obb"),
        payload_bytes=original_bytes,
        metadata=metadata,
        recipient_public_keys=public_keys,
    )
    
    # Each platform should be able to decrypt
    for private, _ in keys:
        _, decrypted_bytes = OBBReader.read_and_decrypt(
            path=Path("test.obb"),
            platform_private_key=private,
        )
        assert decrypted_bytes == original_bytes
```

### 7.3 Real File Tests

```python
def test_real_zmx_file():
    """Test with a real .zmx file"""
    
    original_file = Path("testdata/lens.zmx")
    original_bytes = original_file.read_bytes()
    
    # Encrypt
    OBBWriter.write(...)
    
    # Decrypt
    _, decrypted_bytes = OBBReader.read_and_decrypt(...)
    
    # Verify byte-for-byte identity
    assert decrypted_bytes == original_bytes
```

---

## 8. Security

### 8.1 V1.0 Threats Addressed

| Threat | Protection |
|--------|-----------|
| File reading | AES-256-GCM with ECDH-derived key |
| File modification | GCM authentication tag (16 bytes) |
| Replay attack | Unique ephemeral key per file |
| Platform key compromise | Only future files affected |

### 8.2 V2.0 Threats Addressed

| Threat | Protection |
|--------|-----------|
| File reading | AES-256-GCM with RSA-wrapped DEK |
| File modification | GCM authentication tag (16 bytes) |
| Key compromise | Per-recipient wrapped DEK isolation |
| Unauthorized decryption | SHA-256 fingerprint matching |
| Post-distribution access control | Sidecar-based revocation |

### 8.3 Best Practices

**For vendors**:
- Never share the platform's private key
- Verify the platform's public key (fingerprint)
- Use `--force` with caution
- Secure DEK storage for sidecar management (V2.0)
- Regular sidecar updates for recipient management

**For platforms**:
- Protect the private key (HSM, KMS if possible)
- Regular key rotation (progressive migration)
- Audit key access
- Validate sidecar signatures before applying
- Check revocation status before decryption (V2.0)

---

## 9. Performance

### 9.1 Encryption Overhead

**V1.0 (Single Recipient)**:
- **Header**: ~500 bytes (JSON metadata + ephemeral key PEM)
- **Nonce**: 12 bytes
- **Auth tag**: 16 bytes
- **Total overhead**: ~530 bytes

**V2.0 (Multi-Recipient)**:
- **Base header**: ~300 bytes (JSON metadata)
- **Per recipient**: ~350 bytes (wrapped DEK + fingerprint + metadata)
- **Nonce**: 12 bytes
- **Auth tag**: 16 bytes
- **Total overhead**: ~330 + (350 × N recipients) bytes

**Example**: 
- 10 KB .zmx file → ~10.5 KB .obb (V1.0, 1 recipient)
- 10 KB .zmx file → ~11.4 KB .obb (V2.0, 3 recipients)

### 9.2 Speed

On a modern processor:
- **Encryption**: ~500 MB/s (V1.0), ~450 MB/s (V2.0 with 3 recipients)
- **Decryption**: ~500 MB/s (both versions)
- **RSA wrapping**: ~5 ms per recipient (V2.0)

---

## 10. Future Enhancements

### 10.1 Implemented in V2.0

- ✅ Multiple platform keys (multi-recipient)
- ✅ Post-distribution recipient management (sidecar)
- ✅ Graphical user interface
- ✅ RSA-OAEP encryption

### 10.2 Potential Future Features

- Vendor ECDSA signature (authentication)
- Compression before encryption
- Full directory encryption
- Web interface for secure visualization
- Cloud storage integration (S3, Azure Blob)
- Sidecar signature verification
- Time-limited access control

### 10.3 Additional Formats

- Automatic file type detection
- Support for arbitrary binary formats
- Preservation of file system metadata
- Optical configuration validation

---

## 11. FAQ

**Q: Can I use .obb for other file types?**  
A: Yes! The current architecture encrypts raw bytes, so any file works.

**Q: Is the decrypted file really identical?**  
A: Yes, byte-for-byte. Tested and validated for both V1.0 and V2.0.

**Q: Should I use V1.0 or V2.0?**  
A: Use V2.0 if you need multiple recipients or post-distribution management. Use V1.0 for simpler single-recipient scenarios.

**Q: Can I have multiple platform keys?**  
A: Yes, in V2.0! Use the `create-v2` command with multiple `--recipient-key` arguments.

**Q: What happens if I lose the private key?**  
A: .obb files can no longer be decrypted. Back up your keys!

**Q: Is the ephemeral key reused (V1.0)?**  
A: No, a new ephemeral pair is generated for each file.

**Q: Can I revoke access after distribution (V2.0)?**  
A: Yes, using sidecar files. However, this only affects future downloads - already-downloaded files remain decryptable offline.

**Q: How do I migrate from V1.0 to V2.0?**  
A: You need to re-encrypt files with `create-v2`. V1.0 and V2.0 use different cryptography and cannot be converted without decryption.

---

## Appendix A: PEM Key Format

### ECDSA P-256 Private Key (V1.0)

```
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXoUQDQgAEYYYYYYYYYYYYYYYYYYYYYYYYYYYYY
YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY==
-----END PRIVATE KEY-----
```

### ECDSA P-256 Public Key (V1.0)

```
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYYYYYYYYYYYYYYYYYYYYYYYYYYYYY
YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY==
-----END PUBLIC KEY-----
```

### RSA-2048 Private Key (V2.0)

```
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
...
-----END PRIVATE KEY-----
```

### RSA-2048 Public Key (V2.0)

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1XXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX==
-----END PUBLIC KEY-----
```

---

## Appendix B: Metadata Examples

### V1.0 Minimal Example

```json
{
  "version": "1.0.0",
  "vendor_id": "acme",
  "model_id": "lens-001",
  "created_at": "2026-02-02T15:30:00.123456",
  "original_filename": "lens.zmx",
  "ephemeral_public_key": "-----BEGIN PUBLIC KEY-----\n..."
}
```

### V1.0 Complete Example

```json
{
  "version": "1.0.0",
  "vendor_id": "thorlabs-inc",
  "model_id": "ac254-050-a-ml",
  "created_at": "2026-02-02T15:30:00.123456",
  "description": "AC254-050-A-ML - Achromatic Doublet, f=50mm, Ø1\", 400-700nm",
  "original_filename": "AC254-050-A-ML.zmx",
  "ephemeral_public_key": "-----BEGIN PUBLIC KEY-----\nMFkw..."
}
```

### V2.0 Multi-Recipient Example

```json
{
  "version": "2.0.0",
  "vendor_id": "thorlabs-inc",
  "model_id": "ac254-050-a-ml",
  "created_at": "2026-02-02T15:30:00.123456",
  "description": "AC254-050-A-ML - Achromatic Doublet, f=50mm, Ø1\", 400-700nm",
  "original_filename": "AC254-050-A-ML.zmx",
  "sidecar_url": "https://api.thorlabs.com/sidecar/ac254-050-a-ml",
  "recipients": [
    {
      "platform_fingerprint": "a1b2c3d4e5f6789...",
      "wrapped_dek": "base64_encoded_rsa_wrapped_dek_256_bytes",
      "platform_name": "Zemax OpticStudio",
      "added_at": "2026-02-02T15:30:00Z"
    },
    {
      "platform_fingerprint": "f6e5d4c3b2a1987...",
      "wrapped_dek": "base64_encoded_rsa_wrapped_dek_256_bytes",
      "platform_name": "Lumerical",
      "added_at": "2026-02-02T15:30:00Z"
    }
  ]
}
```

---

## License

MIT License - Open-source framework for secure optical design distribution.

