"""ECDSA key management for Optical BlackBox.

Handles generation, loading, and saving of ECDSA P-256 key pairs.
"""

from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ec

from optical_blackbox.serialization.pem import (
    public_key_to_pem,
    public_key_from_pem,
    private_key_to_pem,
    private_key_from_pem,
)
from optical_blackbox.exceptions import InvalidKeyError, KeyNotFoundError


class KeyManager:
    """Manages ECDSA P-256 key pairs for vendors and platform.

    Provides methods for:
    - Generating new key pairs
    - Saving keys to PEM files
    - Loading keys from PEM files
    - Converting between key objects and PEM strings

    Example:
        >>> # Generate a new key pair
        >>> private_key, public_key = KeyManager.generate_keypair()
        >>>
        >>> # Save to files
        >>> KeyManager.save_private_key(private_key, Path("vendor_private.pem"))
        >>> KeyManager.save_public_key(public_key, Path("vendor_public.pem"))
        >>>
        >>> # Load from files
        >>> private_key = KeyManager.load_private_key(Path("vendor_private.pem"))
    """

    # Standard curve for OBB (NIST P-256)
    CURVE = ec.SECP256R1()

    @classmethod
    def generate_keypair(cls) -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        """Generate a new ECDSA P-256 key pair.

        Returns:
            Tuple of (private_key, public_key)
        """
        private_key = ec.generate_private_key(cls.CURVE)
        public_key = private_key.public_key()
        return private_key, public_key

    @classmethod
    def save_private_key(
        cls,
        key: ec.EllipticCurvePrivateKey,
        path: Path,
        password: Optional[str] = None,
    ) -> None:
        """Save a private key to a PEM file.

        Args:
            key: Private key to save
            path: Path to write the PEM file
            password: Optional password to encrypt the key

        Raises:
            IOError: If file cannot be written
        """
        pem = private_key_to_pem(key, password)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(pem, encoding="ascii")

    @classmethod
    def save_public_key(cls, key: ec.EllipticCurvePublicKey, path: Path) -> None:
        """Save a public key to a PEM file.

        Args:
            key: Public key to save
            path: Path to write the PEM file

        Raises:
            IOError: If file cannot be written
        """
        pem = public_key_to_pem(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(pem, encoding="ascii")

    @classmethod
    def load_private_key(
        cls,
        path: Path,
        password: Optional[str] = None,
    ) -> ec.EllipticCurvePrivateKey:
        """Load a private key from a PEM file.

        Args:
            path: Path to the PEM file
            password: Password if the key is encrypted

        Returns:
            Private key object

        Raises:
            KeyNotFoundError: If file doesn't exist
            InvalidKeyError: If key format is invalid
        """
        if not path.exists():
            raise KeyNotFoundError(str(path))

        try:
            pem = path.read_text(encoding="ascii")
            return private_key_from_pem(pem, password)
        except Exception as e:
            raise InvalidKeyError("private", str(e)) from e

    @classmethod
    def load_public_key(cls, path: Path) -> ec.EllipticCurvePublicKey:
        """Load a public key from a PEM file.

        Args:
            path: Path to the PEM file

        Returns:
            Public key object

        Raises:
            KeyNotFoundError: If file doesn't exist
            InvalidKeyError: If key format is invalid
        """
        if not path.exists():
            raise KeyNotFoundError(str(path))

        try:
            pem = path.read_text(encoding="ascii")
            return public_key_from_pem(pem)
        except Exception as e:
            raise InvalidKeyError("public", str(e)) from e

    @classmethod
    def public_key_to_pem(cls, key: ec.EllipticCurvePublicKey) -> str:
        """Convert a public key to PEM string.

        Args:
            key: Public key object

        Returns:
            PEM-encoded string
        """
        return public_key_to_pem(key)

    @classmethod
    def public_key_from_pem(cls, pem: str) -> ec.EllipticCurvePublicKey:
        """Load a public key from PEM string.

        Args:
            pem: PEM-encoded string

        Returns:
            Public key object
        """
        return public_key_from_pem(pem)
