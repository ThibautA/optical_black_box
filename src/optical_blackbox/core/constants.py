"""Constants for Optical BlackBox.

All magic numbers, file signatures, and configuration values are centralized here.
"""

from typing import Final

# =============================================================================
# File Format Constants
# =============================================================================

# Magic bytes to identify .obb files
OBB_MAGIC: Final[bytes] = b"OBB\x01"

# Current format version
OBB_VERSION: Final[str] = "1.0"

# File extension
OBB_EXTENSION: Final[str] = ".obb"

# =============================================================================
# Cryptographic Constants
# =============================================================================

# Elliptic curve for ECDSA/ECDH
ECDSA_CURVE_NAME: Final[str] = "secp256r1"

# AES-256-GCM parameters
AES_KEY_SIZE: Final[int] = 32  # bytes (256 bits)
AES_NONCE_SIZE: Final[int] = 12  # bytes (96 bits, GCM standard)
AES_TAG_SIZE: Final[int] = 16  # bytes (128 bits)

# HKDF info string for key derivation
HKDF_INFO: Final[bytes] = b"obb-encryption-v1"

# =============================================================================
# Parser Constants
# =============================================================================

# Supported Zemax file extensions
ZEMAX_EXTENSIONS: Final[tuple[str, ...]] = (".zmx", ".zar")

# Zemax file encoding (UTF-16 LE with BOM)
ZEMAX_ENCODING: Final[str] = "utf-16-le"

# =============================================================================
# Optical Constants
# =============================================================================

# Default wavelength (Helium d-line)
DEFAULT_WAVELENGTH_NM: Final[float] = 587.56

# Common spectral lines (nm)
SPECTRAL_LINES: Final[dict[str, float]] = {
    "i": 365.01,  # Mercury
    "h": 404.66,  # Mercury
    "g": 435.84,  # Mercury
    "F": 486.13,  # Hydrogen
    "e": 546.07,  # Mercury
    "d": 587.56,  # Helium
    "D": 589.29,  # Sodium (D1+D2 average)
    "C": 656.27,  # Hydrogen
    "r": 706.52,  # Helium
    "t": 1013.98,  # Mercury
}

# Air refractive index (standard conditions)
AIR_INDEX: Final[float] = 1.0

# Default index for unknown materials
DEFAULT_UNKNOWN_INDEX: Final[float] = 1.5

# =============================================================================
# Validation Constants
# =============================================================================

# Vendor ID constraints
VENDOR_ID_MIN_LENGTH: Final[int] = 3
VENDOR_ID_MAX_LENGTH: Final[int] = 50
VENDOR_ID_PATTERN: Final[str] = r"^[a-z0-9][a-z0-9\-]{2,49}$"

# Component name constraints
COMPONENT_NAME_MAX_LENGTH: Final[int] = 100
