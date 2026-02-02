"""AES-256-GCM encryption for Optical BlackBox.

Provides authenticated encryption using AES-256 in GCM mode.
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from optical_blackbox.core.constants import AES_KEY_SIZE, AES_NONCE_SIZE
from optical_blackbox.exceptions import DecryptionError


def generate_nonce() -> bytes:
    """Generate a cryptographically secure random nonce.

    Returns:
        Random 12-byte nonce for AES-GCM
    """
    return os.urandom(AES_NONCE_SIZE)


def encrypt(
    plaintext: bytes,
    key: bytes,
    nonce: bytes | None = None,
    associated_data: bytes | None = None,
) -> tuple[bytes, bytes]:
    """Encrypt data using AES-256-GCM.

    Args:
        plaintext: Data to encrypt
        key: 32-byte AES key
        nonce: 12-byte nonce (generated if not provided)
        associated_data: Optional additional authenticated data

    Returns:
        Tuple of (nonce, ciphertext_with_tag)

    Raises:
        ValueError: If key size is incorrect
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"Key must be {AES_KEY_SIZE} bytes, got {len(key)}")

    if nonce is None:
        nonce = generate_nonce()

    if len(nonce) != AES_NONCE_SIZE:
        raise ValueError(f"Nonce must be {AES_NONCE_SIZE} bytes, got {len(nonce)}")

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

    return nonce, ciphertext


def decrypt(
    nonce: bytes,
    ciphertext: bytes,
    key: bytes,
    associated_data: bytes | None = None,
) -> bytes:
    """Decrypt data using AES-256-GCM.

    Args:
        nonce: 12-byte nonce used for encryption
        ciphertext: Ciphertext with authentication tag
        key: 32-byte AES key
        associated_data: Optional additional authenticated data

    Returns:
        Decrypted plaintext

    Raises:
        DecryptionError: If decryption or authentication fails
        ValueError: If key or nonce size is incorrect
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"Key must be {AES_KEY_SIZE} bytes, got {len(key)}")

    if len(nonce) != AES_NONCE_SIZE:
        raise ValueError(f"Nonce must be {AES_NONCE_SIZE} bytes, got {len(nonce)}")

    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
        return plaintext
    except Exception as e:
        raise DecryptionError(f"AES-GCM decryption failed: {e}") from e


def encrypt_with_nonce_prefix(
    plaintext: bytes,
    key: bytes,
    associated_data: bytes | None = None,
) -> bytes:
    """Encrypt and prepend nonce to ciphertext.

    Convenience function that returns nonce || ciphertext.

    Args:
        plaintext: Data to encrypt
        key: 32-byte AES key
        associated_data: Optional additional authenticated data

    Returns:
        Bytes: nonce (12 bytes) || ciphertext || tag (16 bytes)
    """
    nonce, ciphertext = encrypt(plaintext, key, associated_data=associated_data)
    return nonce + ciphertext


def decrypt_with_nonce_prefix(
    data: bytes,
    key: bytes,
    associated_data: bytes | None = None,
) -> bytes:
    """Decrypt data with prepended nonce.

    Args:
        data: nonce (12 bytes) || ciphertext || tag
        key: 32-byte AES key
        associated_data: Optional additional authenticated data

    Returns:
        Decrypted plaintext

    Raises:
        DecryptionError: If decryption fails
        ValueError: If data is too short
    """
    if len(data) < AES_NONCE_SIZE:
        raise ValueError(f"Data too short: must be at least {AES_NONCE_SIZE} bytes")

    nonce = data[:AES_NONCE_SIZE]
    ciphertext = data[AES_NONCE_SIZE:]

    return decrypt(nonce, ciphertext, key, associated_data)
