"""OBB file reader and writer.

Provides high-level interface for reading and writing .obb files.
Simplified to work with raw file bytes without parsing.
"""

from pathlib import Path
from datetime import datetime
from typing import BinaryIO

from cryptography.hazmat.primitives.asymmetric import ec

from optical_blackbox.models.metadata import OBBMetadata
from optical_blackbox.serialization.binary import BinaryReader, BinaryWriter
from optical_blackbox.formats.obb_constants import OBB_MAGIC
from optical_blackbox.formats.obb_header import (
    build_header,
    serialize_header,
    deserialize_header,
    extract_metadata,
    extract_ephemeral_key,
)
from optical_blackbox.formats.obb_payload import (
    encrypt_payload,
    decrypt_payload,
)
from optical_blackbox.crypto.ecdh import derive_shared_key
from optical_blackbox.exceptions import (
    InvalidMagicBytesError,
    InvalidOBBFileError,
)


class OBBWriter:
    """Writes .obb files.

    Example:
        >>> OBBWriter.write(
        ...     output_path=Path("component.obb"),
        ...     payload_bytes=zmx_file_bytes,
        ...     metadata=metadata,
        ...     platform_public_key=platform_key,
        ... )
    """

    @classmethod
    def write(
        cls,
        output_path: Path,
        payload_bytes: bytes,
        metadata: OBBMetadata,
        platform_public_key: ec.EllipticCurvePublicKey,
    ) -> None:
        """Write a .obb file from raw optical design file bytes.

        Args:
            output_path: Path for the output file
            payload_bytes: Raw optical design file bytes to encrypt
            metadata: Public metadata
            platform_public_key: Platform's key for encryption
        """
        # Ensure parent directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "wb") as f:
            cls._write_to_stream(
                f,
                payload_bytes,
                metadata,
                platform_public_key,
            )

    @classmethod
    def _write_to_stream(
        cls,
        stream: BinaryIO,
        payload_bytes: bytes,
        metadata: OBBMetadata,
        platform_public_key: ec.EllipticCurvePublicKey,
    ) -> None:
        """Write .obb data to a stream.

        Args:
            stream: Binary stream to write to
            payload_bytes: Raw optical design file bytes to encrypt
            metadata: Public metadata
            platform_public_key: Platform's key for encryption
        """
        writer = BinaryWriter(stream)

        # Generate ephemeral key pair for ECDH
        ephemeral_private = ec.generate_private_key(ec.SECP256R1())
        ephemeral_public = ephemeral_private.public_key()

        # Derive shared AES key using ECDH
        aes_key = derive_shared_key(ephemeral_private, platform_public_key)

        # Encrypt payload
        nonce, ciphertext = encrypt_payload(payload_bytes, aes_key)

        # Combine nonce + ciphertext for storage
        encrypted_payload = nonce + ciphertext

        # Update metadata with timestamp
        metadata.created_at = datetime.utcnow()

        # Build and serialize header
        header = build_header(metadata, ephemeral_public)
        header_bytes = serialize_header(header)

        # Write file structure:
        # [MAGIC][HEADER_LENGTH][HEADER][ENCRYPTED_PAYLOAD]
        writer.write_magic(OBB_MAGIC)
        writer.write_length_prefixed(header_bytes)
        writer.write_bytes(encrypted_payload)


class OBBReader:
    """Reads .obb files.

    Example:
        >>> # Read metadata only (no decryption)
        >>> metadata = OBBReader.read_metadata(Path("component.obb"))
        >>>
        >>> # Full read with decryption
        >>> metadata, file_bytes = OBBReader.read_and_decrypt(
        ...     path=Path("component.obb"),
        ...     platform_private_key=platform_key,
        ... )
    """

    @classmethod
    def read_metadata(cls, path: Path) -> OBBMetadata:
        """Read only the public metadata (no decryption).

        Args:
            path: Path to the .obb file

        Returns:
            OBBMetadata object

        Raises:
            InvalidMagicBytesError: If file is not a valid .obb
            InvalidOBBFileError: If file is malformed
        """
        with open(path, "rb") as f:
            reader = BinaryReader(f)

            # Verify magic bytes
            if not reader.read_and_verify_magic(OBB_MAGIC):
                raise InvalidMagicBytesError()

            # Read header
            header_bytes = reader.read_length_prefixed()
            header = deserialize_header(header_bytes)

            return extract_metadata(header)

    @classmethod
    def read_and_decrypt(
        cls,
        path: Path,
        platform_private_key: ec.EllipticCurvePrivateKey,
    ) -> tuple[OBBMetadata, bytes]:
        """Read and decrypt a .obb file.

        Args:
            path: Path to the .obb file
            platform_private_key: Platform's private key for decryption

        Returns:
            Tuple of (metadata, decrypted_file_bytes)

        Raises:
            InvalidMagicBytesError: If file is not a valid .obb
            DecryptionError: If decryption fails
        """
        with open(path, "rb") as f:
            reader = BinaryReader(f)

            # Verify magic bytes
            if not reader.read_and_verify_magic(OBB_MAGIC):
                raise InvalidMagicBytesError()

            # Read header
            header_bytes = reader.read_length_prefixed()
            header = deserialize_header(header_bytes)

            # Read encrypted payload
            encrypted_payload = reader.read_rest()

        # Extract metadata and ephemeral key
        metadata = extract_metadata(header)
        ephemeral_public = extract_ephemeral_key(header)

        # Derive shared AES key using ECDH
        aes_key = derive_shared_key(platform_private_key, ephemeral_public)

        # Split nonce and ciphertext
        nonce = encrypted_payload[:12]  # First 12 bytes
        ciphertext = encrypted_payload[12:]  # Rest

        # Decrypt payload
        file_bytes = decrypt_payload(nonce, ciphertext, aes_key)

        return metadata, file_bytes

    @classmethod
    def read(
        cls,
        path: Path,
        platform_private_key: ec.EllipticCurvePrivateKey,
    ) -> tuple[OBBMetadata, bytes]:
        """Alias for read_and_decrypt for convenience.

        Args:
            path: Path to the .obb file
            platform_private_key: Platform's private key for decryption

        Returns:
            Tuple of (metadata, decrypted_file_bytes)

        Raises:
            InvalidMagicBytesError: If file is not a valid .obb
            DecryptionError: If decryption fails
        """
        return cls.read_and_decrypt(path, platform_private_key)

    @classmethod
    def is_valid_obb_file(cls, path: Path) -> bool:
        """Check if a file is a valid .obb file.

        Args:
            path: Path to check

        Returns:
            True if file has valid magic bytes
        """
        try:
            with open(path, "rb") as f:
                magic = f.read(len(OBB_MAGIC))
                return magic == OBB_MAGIC
        except Exception:
            return False
