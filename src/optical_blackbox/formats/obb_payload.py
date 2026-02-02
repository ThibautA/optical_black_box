"""
Payload encryption/decryption for OBB files.

This module handles the core encryption/decryption of raw optical design file bytes.
Simplified to work directly with bytes without parsing or structuring.
"""

import os
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..exceptions import DecryptionError


def encrypt_payload(
    payload_bytes: bytes,
    aes_key: bytes
) -> Tuple[bytes, bytes]:
    """
    Encrypt raw optical design file bytes using AES-256-GCM.
    
    Args:
        payload_bytes: The raw file bytes to encrypt
        aes_key: 256-bit AES key (32 bytes)
        
    Returns:
        Tuple of (nonce, ciphertext)
        
    Raises:
        ValueError: If the key length is invalid
    """
    if len(aes_key) != 32:
        raise ValueError("AES key must be 32 bytes for AES-256")
    
    # Generate random nonce for GCM mode
    nonce = os.urandom(12)  # 96 bits recommended for GCM
    
    # Encrypt with AES-GCM (provides authentication)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, payload_bytes, None)
    
    return nonce, ciphertext


def decrypt_payload(
    nonce: bytes,
    ciphertext: bytes,
    aes_key: bytes
) -> bytes:
    """
    Decrypt encrypted optical design file bytes using AES-256-GCM.
    
    Args:
        nonce: The nonce used during encryption (12 bytes)
        ciphertext: The encrypted data
        aes_key: 256-bit AES key (32 bytes)
        
    Returns:
        The decrypted raw file bytes
        
    Raises:
        DecryptionError: If decryption fails (wrong key, corrupted data, etc.)
    """
    if len(aes_key) != 32:
        raise ValueError("AES key must be 32 bytes for AES-256")
    
    try:
        aesgcm = AESGCM(aes_key)
        payload_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return payload_bytes
    except Exception as e:
        raise DecryptionError(
            f"Failed to decrypt payload. This usually means the key is incorrect "
            f"or the file is corrupted: {e}"
        )
