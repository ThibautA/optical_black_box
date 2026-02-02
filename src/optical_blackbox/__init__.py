"""Optical BlackBox - Create encrypted optical component files (.obb).

This package provides tools for optical component manufacturers to distribute
their optical designs in an encrypted format that protects intellectual property
while enabling authorized platforms to decrypt and use them.

Example:
    >>> from optical_blackbox import OBBReader, OBBWriter, KeyManager
    >>> # Generate platform keys
    >>> private_key, public_key = KeyManager.generate_keypair()
    >>> # Read metadata from .obb file
    >>> metadata = OBBReader.read_metadata("component.obb")
    >>> print(f"Vendor: {metadata.vendor_id}")
"""

__version__ = "1.0.0"

# Public API
from optical_blackbox.models.metadata import OBBMetadata
from optical_blackbox.formats.obb_file import OBBReader, OBBWriter
from optical_blackbox.crypto.keys import KeyManager

__all__ = [
    # Version
    "__version__",
    # Models
    "OBBMetadata",
    # Format
    "OBBReader",
    "OBBWriter",
    # Crypto
    "KeyManager",
]
