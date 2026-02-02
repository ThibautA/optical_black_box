"""Key derivation functions for cryptographic operations.

This module provides HKDF (HMAC-based Key Derivation Function) for deriving
cryptographic keys from shared secrets or master keys.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive_key(
    input_key_material: bytes,
    length: int = 32,
    salt: bytes | None = None,
    info: bytes | None = None,
) -> bytes:
    """Derive a cryptographic key using HKDF-SHA256.
    
    Args:
        input_key_material: Source key material (e.g., shared secret)
        length: Desired output key length in bytes (default: 32 for AES-256)
        salt: Optional salt value (recommended for additional entropy)
        info: Optional context/application-specific info
        
    Returns:
        Derived key of specified length
    """
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return kdf.derive(input_key_material)
