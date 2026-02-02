"""Hybrid encryption facade for Optical BlackBox.

Combines ECDH key exchange + AES-256-GCM encryption + ECDSA signing
into a simple high-level interface.
"""

from cryptography.hazmat.primitives.asymmetric import ec

from optical_blackbox.crypto import ecdh
from optical_blackbox.crypto import aes_gcm
from optical_blackbox.crypto import signing
from optical_blackbox.serialization.pem import public_key_to_pem, public_key_from_pem


class OBBEncryptor:
    """Hybrid encryption using ECDH + AES-256-GCM.

    This class provides a simple interface for encrypting data where:
    - An ephemeral key pair is generated for each encryption
    - ECDH is used to derive a shared secret with the recipient
    - AES-256-GCM encrypts the actual data
    - The ephemeral public key is included with the ciphertext

    Example:
        >>> # Encrypt data for a recipient
        >>> encrypted, ephemeral_pub = OBBEncryptor.encrypt(data, recipient_public_key)
        >>>
        >>> # Decrypt with recipient's private key
        >>> decrypted = OBBEncryptor.decrypt(encrypted, ephemeral_pub, recipient_private_key)
    """

    @classmethod
    def encrypt(
        cls,
        plaintext: bytes,
        recipient_public_key: ec.EllipticCurvePublicKey,
    ) -> tuple[bytes, ec.EllipticCurvePublicKey]:
        """Encrypt data using hybrid ECDH + AES-256-GCM.

        Args:
            plaintext: Data to encrypt
            recipient_public_key: Recipient's public key

        Returns:
            Tuple of (encrypted_payload, ephemeral_public_key)
            The encrypted_payload contains: nonce || ciphertext || tag
        """
        # Generate ephemeral key pair
        ephemeral_private, ephemeral_public = ecdh.generate_ephemeral_keypair()

        # Derive AES key from ECDH
        aes_key = ecdh.compute_encryption_key(ephemeral_private, recipient_public_key)

        # Encrypt with AES-GCM
        encrypted_payload = aes_gcm.encrypt_with_nonce_prefix(plaintext, aes_key)

        return encrypted_payload, ephemeral_public

    @classmethod
    def decrypt(
        cls,
        encrypted_payload: bytes,
        ephemeral_public_key: ec.EllipticCurvePublicKey,
        recipient_private_key: ec.EllipticCurvePrivateKey,
    ) -> bytes:
        """Decrypt data using hybrid ECDH + AES-256-GCM.

        Args:
            encrypted_payload: nonce || ciphertext || tag
            ephemeral_public_key: Sender's ephemeral public key
            recipient_private_key: Recipient's private key

        Returns:
            Decrypted plaintext

        Raises:
            DecryptionError: If decryption fails
        """
        # Derive AES key from ECDH
        aes_key = ecdh.compute_decryption_key(recipient_private_key, ephemeral_public_key)

        # Decrypt with AES-GCM
        return aes_gcm.decrypt_with_nonce_prefix(encrypted_payload, aes_key)

    @classmethod
    def encrypt_with_pem_key(
        cls,
        plaintext: bytes,
        recipient_public_key_pem: str,
    ) -> tuple[bytes, str]:
        """Encrypt data, accepting and returning PEM strings.

        Convenience method for working with PEM-encoded keys.

        Args:
            plaintext: Data to encrypt
            recipient_public_key_pem: Recipient's public key in PEM format

        Returns:
            Tuple of (encrypted_payload, ephemeral_public_key_pem)
        """
        recipient_key = public_key_from_pem(recipient_public_key_pem)
        encrypted, ephemeral_pub = cls.encrypt(plaintext, recipient_key)
        ephemeral_pem = public_key_to_pem(ephemeral_pub)
        return encrypted, ephemeral_pem


class OBBSigner:
    """ECDSA signing for OBB files.

    Provides methods for signing encrypted payloads and verifying signatures.

    Example:
        >>> # Sign encrypted data
        >>> signature = OBBSigner.sign(encrypted_data, vendor_private_key)
        >>>
        >>> # Verify signature
        >>> is_valid = OBBSigner.verify(encrypted_data, signature, vendor_public_key)
    """

    @classmethod
    def sign(cls, data: bytes, private_key: ec.EllipticCurvePrivateKey) -> str:
        """Sign data and return base64-encoded signature.

        Args:
            data: Data to sign (typically the encrypted payload)
            private_key: Signer's private key

        Returns:
            Base64-encoded signature string
        """
        return signing.sign_base64(data, private_key)

    @classmethod
    def verify(
        cls,
        data: bytes,
        signature_b64: str,
        public_key: ec.EllipticCurvePublicKey,
    ) -> bool:
        """Verify a signature.

        Args:
            data: Original signed data
            signature_b64: Base64-encoded signature
            public_key: Signer's public key

        Returns:
            True if signature is valid
        """
        return signing.verify_base64(data, signature_b64, public_key)

    @classmethod
    def verify_or_raise(
        cls,
        data: bytes,
        signature_b64: str,
        public_key: ec.EllipticCurvePublicKey,
    ) -> None:
        """Verify signature and raise if invalid.

        Args:
            data: Original signed data
            signature_b64: Base64-encoded signature
            public_key: Signer's public key

        Raises:
            InvalidSignatureError: If signature is invalid
        """
        signing.verify_base64_or_raise(data, signature_b64, public_key)
