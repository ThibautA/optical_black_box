"""Fingerprint generation for platform public keys.

This module provides utilities to generate unique fingerprints for RSA public keys,
used to identify recipients in multi-recipient .obb files.
"""

import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def compute_key_fingerprint(public_key_pem: bytes) -> str:
    """Compute SHA-256 fingerprint of an RSA public key.
    
    The fingerprint is computed from the public key's DER encoding
    and returned as a hex string.
    
    Args:
        public_key_pem: PEM-encoded RSA public key
        
    Returns:
        64-character hex string (SHA-256 hash)
        
    Raises:
        ValueError: If public key is invalid
    """
    try:
        # Load and re-serialize to DER for consistent fingerprinting
        public_key = serialization.load_pem_public_key(public_key_pem)
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("Not an RSA public key")
        
        der_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        
        # Compute SHA-256 hash
        return hashlib.sha256(der_bytes).hexdigest()
    
    except Exception as e:
        raise ValueError(f"Failed to compute fingerprint: {e}") from e


def format_fingerprint(fingerprint: str) -> str:
    """Format a fingerprint for human-readable display.
    
    Formats a 64-character hex string as colon-separated groups of 2 characters.
    Example: "a1b2...cd" -> "a1:b2:c3:...:cd"
    
    Args:
        fingerprint: 64-character hex string
        
    Returns:
        Colon-separated fingerprint string
    """
    if len(fingerprint) != 64:
        raise ValueError(f"Invalid fingerprint length: expected 64, got {len(fingerprint)}")
    
    return ":".join(fingerprint[i : i + 2] for i in range(0, 64, 2))
