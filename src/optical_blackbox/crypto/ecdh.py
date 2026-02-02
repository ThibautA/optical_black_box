"""ECDH key exchange for Optical BlackBox.

Provides Elliptic Curve Diffie-Hellman key exchange functionality
for deriving shared secrets.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from optical_blackbox.core.constants import AES_KEY_SIZE, HKDF_INFO


def generate_ephemeral_keypair() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Generate an ephemeral key pair for ECDH.

    Returns:
        Tuple of (ephemeral_private_key, ephemeral_public_key)
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def derive_shared_key(
    private_key: ec.EllipticCurvePrivateKey,
    peer_public_key: ec.EllipticCurvePublicKey,
    key_length: int = AES_KEY_SIZE,
    info: bytes = HKDF_INFO,
) -> bytes:
    """Derive a shared symmetric key using ECDH + HKDF.

    Performs ECDH key exchange and then derives a symmetric key
    using HKDF-SHA256.

    Args:
        private_key: Our private key
        peer_public_key: The other party's public key
        key_length: Length of derived key in bytes (default: 32 for AES-256)
        info: Context info for HKDF (default: b"obb-encryption-v1")

    Returns:
        Derived symmetric key bytes
    """
    # Perform ECDH to get shared secret
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

    # Derive AES key using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=None,
        info=info,
    ).derive(shared_secret)

    return derived_key


def compute_encryption_key(
    ephemeral_private: ec.EllipticCurvePrivateKey,
    recipient_public: ec.EllipticCurvePublicKey,
) -> bytes:
    """Compute encryption key from ephemeral private and recipient public key.

    Used by the sender to derive the AES key.

    Args:
        ephemeral_private: Sender's ephemeral private key
        recipient_public: Recipient's long-term public key

    Returns:
        AES-256 key bytes
    """
    return derive_shared_key(ephemeral_private, recipient_public)


def compute_decryption_key(
    recipient_private: ec.EllipticCurvePrivateKey,
    ephemeral_public: ec.EllipticCurvePublicKey,
) -> bytes:
    """Compute decryption key from recipient private and ephemeral public key.

    Used by the recipient to derive the AES key.

    Args:
        recipient_private: Recipient's long-term private key
        ephemeral_public: Sender's ephemeral public key

    Returns:
        AES-256 key bytes
    """
    return derive_shared_key(recipient_private, ephemeral_public)
