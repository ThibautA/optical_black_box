"""ECDSA signing for Optical BlackBox.

Provides digital signature functionality using ECDSA with SHA-256.
"""

import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from optical_blackbox.exceptions import InvalidSignatureError, SigningError


def sign(data: bytes, private_key: ec.EllipticCurvePrivateKey) -> bytes:
    """Sign data using ECDSA with SHA-256.

    Args:
        data: Data to sign
        private_key: ECDSA private key

    Returns:
        Signature bytes (DER encoded)

    Raises:
        SigningError: If signing fails
    """
    try:
        signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        return signature
    except Exception as e:
        raise SigningError(str(e)) from e


def sign_base64(data: bytes, private_key: ec.EllipticCurvePrivateKey) -> str:
    """Sign data and return base64-encoded signature.

    Args:
        data: Data to sign
        private_key: ECDSA private key

    Returns:
        Base64-encoded signature string
    """
    signature = sign(data, private_key)
    return base64.b64encode(signature).decode("ascii")


def verify(
    data: bytes,
    signature: bytes,
    public_key: ec.EllipticCurvePublicKey,
) -> bool:
    """Verify an ECDSA signature.

    Args:
        data: Original signed data
        signature: Signature bytes (DER encoded)
        public_key: ECDSA public key

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def verify_base64(
    data: bytes,
    signature_b64: str,
    public_key: ec.EllipticCurvePublicKey,
) -> bool:
    """Verify a base64-encoded ECDSA signature.

    Args:
        data: Original signed data
        signature_b64: Base64-encoded signature string
        public_key: ECDSA public key

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        signature = base64.b64decode(signature_b64)
        return verify(data, signature, public_key)
    except Exception:
        return False


def verify_or_raise(
    data: bytes,
    signature: bytes,
    public_key: ec.EllipticCurvePublicKey,
) -> None:
    """Verify signature and raise if invalid.

    Args:
        data: Original signed data
        signature: Signature bytes (DER encoded)
        public_key: ECDSA public key

    Raises:
        InvalidSignatureError: If signature is invalid
    """
    if not verify(data, signature, public_key):
        raise InvalidSignatureError()


def verify_base64_or_raise(
    data: bytes,
    signature_b64: str,
    public_key: ec.EllipticCurvePublicKey,
) -> None:
    """Verify base64 signature and raise if invalid.

    Args:
        data: Original signed data
        signature_b64: Base64-encoded signature string
        public_key: ECDSA public key

    Raises:
        InvalidSignatureError: If signature is invalid
    """
    if not verify_base64(data, signature_b64, public_key):
        raise InvalidSignatureError()
