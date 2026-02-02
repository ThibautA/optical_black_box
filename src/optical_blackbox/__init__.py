"""Optical BlackBox - Create encrypted optical component files (.obb).

This package provides tools for optical component manufacturers to distribute
their optical designs in an encrypted format that protects intellectual property
while enabling authorized platforms to decrypt and use them.

Supports both v1.0 (single recipient) and v2.0 (multi-recipient) formats.

Example:
    >>> from optical_blackbox import OBBReader, OBBWriter, KeyManager
    >>> # Generate platform keys
    >>> private_key, public_key = KeyManager.generate_keypair()
    >>> # Read metadata from .obb file
    >>> metadata = OBBReader.read_metadata("component.obb")
    >>> print(f"Vendor: {metadata.vendor_id}")
    
    >>> # Multi-recipient v2.0
    >>> from optical_blackbox import OBBReaderV2, OBBWriterV2
    >>> # Create file that multiple platforms can decrypt
    >>> result = OBBWriterV2.write(
    ...     output_path="component.obb",
    ...     payload_bytes=data,
    ...     metadata=metadata_v2,
    ...     recipient_public_keys=[(key1, "Platform1"), (key2, "Platform2")],
    ... )
"""

__version__ = "2.0.0"

# Public API - v1.0 (backwards compatible)
from optical_blackbox.models.metadata import OBBMetadata
from optical_blackbox.formats.obb_file import OBBReader, OBBWriter
from optical_blackbox.crypto.keys import KeyManager

# Public API - v2.0
from optical_blackbox.models.metadata import OBBMetadataV2, RecipientInfo
from optical_blackbox.formats.obb_file_v2 import OBBReaderV2, OBBWriterV2
from optical_blackbox.models.sidecar import Sidecar, SidecarRecipient
from optical_blackbox.sidecar import SidecarGenerator, fetch_sidecar
from optical_blackbox.core.version import detect_obb_version

__all__ = [
    # Version
    "__version__",
    # Models - v1.0
    "OBBMetadata",
    # Models - v2.0
    "OBBMetadataV2",
    "RecipientInfo",
    "Sidecar",
    "SidecarRecipient",
    # Format - v1.0
    "OBBReader",
    "OBBWriter",
    # Format - v2.0
    "OBBReaderV2",
    "OBBWriterV2",
    # Crypto
    "KeyManager",
    # Sidecar
    "SidecarGenerator",
    "fetch_sidecar",
    # Utilities
    "detect_obb_version",
]
