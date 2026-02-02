"""OBB file format constants.

Centralized constants for the .obb binary file format.
Re-exports from core.constants for convenience.
"""

from optical_blackbox.core.constants import (
    OBB_MAGIC,
    OBB_VERSION,
    OBB_EXTENSION,
    AES_NONCE_SIZE,
)

__all__ = [
    "OBB_MAGIC",
    "OBB_VERSION",
    "OBB_EXTENSION",
    "AES_NONCE_SIZE",
]
