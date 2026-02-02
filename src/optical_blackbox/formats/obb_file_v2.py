"""OBB v2.0 file format for multi-recipient encryption.

Provides reader/writer for .obb v2.0 files with support for multiple recipients.
Each recipient can decrypt the file using their own RSA private key.
"""

import os
from datetime import datetime
from pathlib import Path
from typing import BinaryIO

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..core.result import Err, Ok, Result
from ..crypto.fingerprint import compute_key_fingerprint
from ..crypto.rsa_oaep import unwrap_dek, wrap_dek
from ..exceptions import DecryptionError, EncryptionError, InvalidMagicBytesError, InvalidOBBFileError
from ..formats.obb_constants import OBB_MAGIC
from ..models.metadata import OBBMetadataV2, RecipientInfo
from ..serialization.binary import BinaryReader, BinaryWriter
from ..serialization.json_codec import encode_json, decode_json


class OBBWriterV2:
    """Writes .obb v2.0 files with multi-recipient support.
    
    Example:
        >>> writer = OBBWriterV2()
        >>> writer.write(
        ...     output_path=Path("component.obb"),
        ...     payload_bytes=zmx_file_bytes,
        ...     metadata=metadata_v2,
        ...     recipient_public_keys=[platform1_pubkey, platform2_pubkey],
        ... )
    """
    
    @classmethod
    def write(
        cls,
        output_path: Path,
        payload_bytes: bytes,
        metadata: OBBMetadataV2,
        recipient_public_keys: list[tuple[bytes, str | None]],
    ) -> Result[None, EncryptionError]:
        """Write a .obb v2.0 file with multi-recipient encryption.
        
        Args:
            output_path: Path for the output file
            payload_bytes: Raw optical design file bytes to encrypt
            metadata: Public metadata (v2.0)
            recipient_public_keys: List of (public_key_pem, platform_name) tuples
            
        Returns:
            Ok(None) on success, Err(EncryptionError) on failure
        """
        # Ensure parent directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(output_path, "wb") as f:
                return cls._write_to_stream(
                    f,
                    payload_bytes,
                    metadata,
                    recipient_public_keys,
                )
        except OSError as e:
            return Err(EncryptionError(f"Failed to write file: {e}"))
    
    @classmethod
    def _write_to_stream(
        cls,
        stream: BinaryIO,
        payload_bytes: bytes,
        metadata: OBBMetadataV2,
        recipient_public_keys: list[tuple[bytes, str | None]],
    ) -> Result[None, EncryptionError]:
        """Write .obb v2.0 data to a stream."""
        writer = BinaryWriter(stream)
        
        # Generate random DEK (Data Encryption Key) for AES-256-GCM
        dek = os.urandom(32)
        
        # Encrypt payload with DEK
        nonce = os.urandom(12)  # 96 bits for GCM
        aesgcm = AESGCM(dek)
        ciphertext = aesgcm.encrypt(nonce, payload_bytes, None)
        encrypted_payload = nonce + ciphertext
        
        # Wrap DEK for each recipient
        recipients = []
        for public_key_pem, platform_name in recipient_public_keys:
            # Compute fingerprint
            try:
                fingerprint = compute_key_fingerprint(public_key_pem)
            except ValueError as e:
                return Err(EncryptionError(f"Invalid public key: {e}"))
            
            # Wrap DEK with recipient's public key
            wrap_result = wrap_dek(dek, public_key_pem)
            if isinstance(wrap_result, Err):
                return wrap_result  # Propagate error
            
            wrapped_dek = wrap_result.value
            
            recipients.append(
                RecipientInfo(
                    platform_fingerprint=fingerprint,
                    wrapped_dek=wrapped_dek,
                    platform_name=platform_name,
                )
            )
        
        # Update metadata
        metadata.created_at = datetime.utcnow()
        metadata.recipients = recipients
        metadata.version = "2.0"
        
        # Serialize metadata to JSON
        try:
            metadata_json = encode_json(metadata.model_dump())
        except Exception as e:
            return Err(EncryptionError(f"Failed to serialize metadata: {e}"))
        
        # Write file structure:
        # [MAGIC][VERSION=2][METADATA_LENGTH][METADATA_JSON][ENCRYPTED_PAYLOAD]
        writer.write_magic(OBB_MAGIC)
        writer.write_bytes(bytes([2]))  # Version byte
        writer.write_length_prefixed(metadata_json)
        writer.write_bytes(encrypted_payload)
        
        return Ok(None)


class OBBReaderV2:
    """Reads .obb v2.0 files with multi-recipient support.
    
    Example:
        >>> reader = OBBReaderV2()
        >>> # Read metadata only
        >>> metadata = reader.read_metadata(Path("component.obb"))
        >>>
        >>> # Decrypt with platform key
        >>> result = reader.read_and_decrypt(
        ...     path=Path("component.obb"),
        ...     platform_private_key=platform_key_pem,
        ... )
        >>> if isinstance(result, Ok):
        ...     metadata, file_bytes = result.value
    """
    
    @classmethod
    def read_metadata(cls, path: Path) -> Result[OBBMetadataV2, InvalidOBBFileError]:
        """Read only the public metadata (no decryption).
        
        Args:
            path: Path to the .obb file
            
        Returns:
            Ok with OBBMetadataV2, or Err with InvalidOBBFileError
        """
        try:
            with open(path, "rb") as f:
                reader = BinaryReader(f)
                
                # Verify magic bytes
                if not reader.read_and_verify_magic(OBB_MAGIC):
                    return Err(InvalidMagicBytesError("Invalid magic bytes"))
                
                # Verify version
                version_byte = reader.read_bytes(1)
                version = version_byte[0]
                if version != 2:
                    return Err(InvalidOBBFileError(f"Expected v2.0, got v{version}"))
                
                # Read metadata JSON
                metadata_json = reader.read_length_prefixed()
                metadata_dict = decode_json(metadata_json)
                
                # Parse metadata
                metadata = OBBMetadataV2(**metadata_dict)
                return Ok(metadata)
        
        except Exception as e:
            return Err(InvalidOBBFileError(f"Failed to read metadata: {e}"))
    
    @classmethod
    def read_and_decrypt(
        cls,
        path: Path,
        platform_private_key: bytes,
    ) -> Result[tuple[OBBMetadataV2, bytes], DecryptionError]:
        """Read and decrypt a .obb v2.0 file.
        
        Args:
            path: Path to the .obb file
            platform_private_key: Platform's RSA private key (PEM format)
            
        Returns:
            Ok with (metadata, decrypted_bytes), or Err with DecryptionError
        """
        try:
            with open(path, "rb") as f:
                reader = BinaryReader(f)
                
                # Verify magic bytes
                if not reader.read_and_verify_magic(OBB_MAGIC):
                    return Err(DecryptionError("Invalid magic bytes"))
                
                # Verify version
                version_byte = reader.read_bytes(1)
                version = version_byte[0]
                if version != 2:
                    return Err(DecryptionError(f"Expected v2.0, got v{version}"))
                
                # Read metadata
                metadata_json = reader.read_length_prefixed()
                metadata_dict = decode_json(metadata_json)
                metadata = OBBMetadataV2(**metadata_dict)
                
                # Read encrypted payload
                encrypted_payload = reader.read_rest()
        
        except Exception as e:
            return Err(DecryptionError(f"Failed to read file: {e}"))
        
        # Compute fingerprint of our private key
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            
            private_key_obj = serialization.load_pem_private_key(
                platform_private_key,
                password=None,
            )
            if not isinstance(private_key_obj, rsa.RSAPrivateKey):
                return Err(DecryptionError("Invalid RSA private key"))
            
            public_key_obj = private_key_obj.public_key()
            public_key_pem = public_key_obj.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            our_fingerprint = compute_key_fingerprint(public_key_pem)
        
        except Exception as e:
            return Err(DecryptionError(f"Failed to process private key: {e}"))
        
        # Find our wrapped DEK in recipients list
        wrapped_dek = None
        for recipient in metadata.recipients:
            if recipient.platform_fingerprint == our_fingerprint:
                wrapped_dek = recipient.wrapped_dek
                break
        
        if wrapped_dek is None:
            return Err(DecryptionError("Platform not authorized (fingerprint not found in recipients)"))
        
        # Unwrap DEK
        unwrap_result = unwrap_dek(wrapped_dek, platform_private_key)
        if isinstance(unwrap_result, Err):
            return Err(unwrap_result.error)
        
        dek = unwrap_result.value
        
        # Split nonce and ciphertext
        if len(encrypted_payload) < 12:
            return Err(DecryptionError("Invalid encrypted payload (too short)"))
        
        nonce = encrypted_payload[:12]
        ciphertext = encrypted_payload[12:]
        
        # Decrypt payload
        try:
            aesgcm = AESGCM(dek)
            file_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            return Err(DecryptionError(f"Failed to decrypt payload: {e}"))
        
        return Ok((metadata, file_bytes))
    
    @classmethod
    def list_recipients(cls, path: Path) -> Result[list[RecipientInfo], InvalidOBBFileError]:
        """List all recipients who can decrypt this file.
        
        Args:
            path: Path to the .obb file
            
        Returns:
            Ok with list of RecipientInfo, or Err with InvalidOBBFileError
        """
        metadata_result = cls.read_metadata(path)
        if isinstance(metadata_result, Err):
            return metadata_result
        
        return Ok(metadata_result.value.recipients)
