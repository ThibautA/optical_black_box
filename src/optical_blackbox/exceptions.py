"""Custom exceptions for Optical BlackBox.

All exceptions are centralized here for easy maintenance and consistent error handling.
"""

from typing import Optional


class OBBError(Exception):
    """Base exception for all Optical BlackBox errors."""

    def __init__(self, message: str, details: Optional[str] = None):
        self.message = message
        self.details = details
        super().__init__(message)

    def __str__(self) -> str:
        if self.details:
            return f"{self.message}: {self.details}"
        return self.message


# =============================================================================
# Validation Errors
# =============================================================================


class ValidationError(OBBError):
    """Raised when input validation fails."""

    pass


class InvalidVendorIdError(ValidationError):
    """Raised when vendor ID format is invalid."""

    def __init__(self, vendor_id: str):
        super().__init__(
            "Invalid vendor ID",
            f"'{vendor_id}' must be 3-50 lowercase alphanumeric characters with hyphens",
        )


class InvalidPathError(ValidationError):
    """Raised when a file path is invalid or file doesn't exist."""

    def __init__(self, path: str, reason: str = "File not found"):
        super().__init__(f"Invalid path: {path}", reason)


# =============================================================================
# File Format Errors
# =============================================================================


class FileFormatError(OBBError):
    """Base class for file format errors."""

    pass


class InvalidOBBFileError(FileFormatError):
    """Raised when .obb file is malformed or corrupted."""

    def __init__(self, reason: str):
        super().__init__("Invalid OBB file", reason)


class InvalidMagicBytesError(InvalidOBBFileError):
    """Raised when file doesn't have correct magic bytes."""

    def __init__(self):
        super().__init__("Bad magic bytes - not a valid .obb file")


class UnsupportedVersionError(InvalidOBBFileError):
    """Raised when .obb file version is not supported."""

    def __init__(self, version: str):
        super().__init__(f"Unsupported version: {version}")


# =============================================================================
# Parser Errors
# =============================================================================
# Cryptographic Errors
# =============================================================================


class CryptoError(OBBError):
    """Base class for cryptographic errors."""

    pass


class KeyError(CryptoError):
    """Raised when there's an issue with cryptographic keys."""

    pass


class InvalidKeyError(KeyError):
    """Raised when a key is invalid or malformed."""

    def __init__(self, key_type: str, reason: str):
        super().__init__(f"Invalid {key_type} key", reason)


class KeyNotFoundError(KeyError):
    """Raised when a required key file is not found."""

    def __init__(self, path: str):
        super().__init__("Key file not found", path)


class DecryptionError(CryptoError):
    """Raised when decryption fails."""

    def __init__(self, reason: str = "Decryption failed"):
        super().__init__(reason, "Key mismatch or corrupted data")


class SignatureError(CryptoError):
    """Base class for signature-related errors."""

    pass


class InvalidSignatureError(SignatureError):
    """Raised when signature verification fails."""

    def __init__(self):
        super().__init__(
            "Invalid signature",
            "File may be corrupted or tampered with",
        )


class SigningError(SignatureError):
    """Raised when signing operation fails."""

    def __init__(self, reason: str):
        super().__init__("Signing failed", reason)


# =============================================================================
# Vendor Errors
# =============================================================================


class VendorError(OBBError):
    """Base class for vendor-related errors."""

    pass


class UnknownVendorError(VendorError):
    """Raised when vendor is not found in registry."""

    def __init__(self, vendor_id: str):
        super().__init__(
            f"Unknown vendor: {vendor_id}",
            "Vendor must be registered on the platform",
        )



