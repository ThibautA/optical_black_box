"""PEM encoding/decoding utilities.

Provides helper functions for working with PEM-encoded keys,
abstracting away the cryptography library details.
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def public_key_to_pem(key: ec.EllipticCurvePublicKey) -> str:
    """Convert a public key to PEM string.

    Args:
        key: ECDSA public key

    Returns:
        PEM-encoded string
    """
    pem_bytes = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem_bytes.decode("ascii")


def public_key_from_pem(pem: str | bytes) -> ec.EllipticCurvePublicKey:
    """Load a public key from PEM string.

    Args:
        pem: PEM-encoded string or bytes

    Returns:
        ECDSA public key

    Raises:
        ValueError: If PEM is invalid
    """
    if isinstance(pem, str):
        pem = pem.encode("ascii")

    key = serialization.load_pem_public_key(pem)

    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("Expected EC public key")

    return key


def private_key_to_pem(
    key: ec.EllipticCurvePrivateKey,
    password: str | None = None,
) -> str:
    """Convert a private key to PEM string.

    Args:
        key: ECDSA private key
        password: Optional password to encrypt the key

    Returns:
        PEM-encoded string
    """
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode("utf-8"))
    else:
        encryption = serialization.NoEncryption()

    pem_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    return pem_bytes.decode("ascii")


def private_key_from_pem(
    pem: str | bytes,
    password: str | None = None,
) -> ec.EllipticCurvePrivateKey:
    """Load a private key from PEM string.

    Args:
        pem: PEM-encoded string or bytes
        password: Password if key is encrypted

    Returns:
        ECDSA private key

    Raises:
        ValueError: If PEM is invalid or password is wrong
    """
    if isinstance(pem, str):
        pem = pem.encode("ascii")

    pwd_bytes = password.encode("utf-8") if password else None
    key = serialization.load_pem_private_key(pem, password=pwd_bytes)

    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError("Expected EC private key")

    return key
