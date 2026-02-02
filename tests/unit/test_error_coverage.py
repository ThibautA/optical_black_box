"""Additional tests to cover error paths and edge cases."""

import pytest
from pathlib import Path
import os

from cryptography.hazmat.primitives.asymmetric import ec

from optical_blackbox.crypto.keys import KeyManager
from optical_blackbox.crypto.signing import sign, verify
from optical_blackbox.exceptions import InvalidKeyError, SigningError, InvalidSignatureError


class TestKeyManagerErrors:
    """Tests for error paths in KeyManager."""

    def test_load_public_key_invalid_pem(self, tmp_path):
        """Should raise InvalidKeyError for invalid PEM format."""
        invalid_pem = tmp_path / "invalid.pem"
        invalid_pem.write_text("NOT A VALID PEM FILE", encoding="ascii")

        with pytest.raises(InvalidKeyError, match="public"):
            KeyManager.load_public_key(invalid_pem)

    def test_load_private_key_wrong_password(self, tmp_path):
        """Should raise InvalidKeyError when password is wrong."""
        key_path = tmp_path / "encrypted.pem"
        priv, _ = KeyManager.generate_keypair()

        # Save with password
        KeyManager.save_private_key(priv, key_path, password="correct")

        # Try to load with wrong password
        with pytest.raises(InvalidKeyError, match="private"):
            KeyManager.load_private_key(key_path, password="wrong")


class TestSigningErrors:
    """Tests for error paths in signing operations."""

    def test_sign_with_invalid_key_type(self):
        """Should raise SigningError when given invalid key type."""
        # Generate a public key (wrong type for signing)
        _, pub = KeyManager.generate_keypair()
        data = b"test data"

        # Signing requires private key, public key should fail
        with pytest.raises((SigningError, AttributeError)):
            sign(data, pub)  # type: ignore

    def test_verify_with_tampered_signature(self):
        """Should return False for tampered signature."""
        priv, pub = KeyManager.generate_keypair()
        data = b"original data"
        signature = sign(data, priv)

        # Tamper with signature
        tampered_sig = bytearray(signature)
        tampered_sig[0] ^= 0xFF
        tampered_signature = bytes(tampered_sig)

        # Should return False, not raise exception
        assert verify(data, tampered_signature, pub) is False


class TestOBBFileErrors:
    """Tests for error paths in OBB file operations."""

    def test_read_truncated_file(self, tmp_path):
        """Should handle truncated .obb file gracefully."""
        from optical_blackbox.formats.obb_file import OBBReader
        from optical_blackbox.formats.obb_constants import OBB_MAGIC
        from optical_blackbox.exceptions import InvalidOBBFileError

        truncated_file = tmp_path / "truncated.obb"

        # Write only magic bytes and partial header length
        truncated_file.write_bytes(OBB_MAGIC + b"\x00\x00")

        # Should raise error when trying to read
        with pytest.raises((InvalidOBBFileError, EOFError, OSError)):
            OBBReader.read_metadata(truncated_file)

    def test_is_valid_obb_file_nonexistent(self, tmp_path):
        """Should return False for nonexistent file."""
        from optical_blackbox.formats.obb_file import OBBReader

        nonexistent = tmp_path / "does_not_exist.obb"
        assert OBBReader.is_valid_obb_file(nonexistent) is False

    def test_is_valid_obb_file_invalid_magic(self, tmp_path):
        """Should return False for file with wrong magic bytes."""
        from optical_blackbox.formats.obb_file import OBBReader

        invalid_file = tmp_path / "invalid.obb"
        invalid_file.write_bytes(b"WRONG_MAGIC")

        assert OBBReader.is_valid_obb_file(invalid_file) is False

    def test_read_alias_method(self, tmp_path):
        """Should test the read() alias method."""
        from optical_blackbox.formats.obb_file import OBBWriter, OBBReader
        from optical_blackbox.models.metadata import OBBMetadata
        from optical_blackbox.crypto.keys import KeyManager

        priv, pub = KeyManager.generate_keypair()
        output_path = tmp_path / "test.obb"

        metadata = OBBMetadata(vendor_id="vendor-id", model_id="model-id")
        original_data = b"test data"

        OBBWriter.write(
            output_path=output_path,
            payload_bytes=original_data,
            metadata=metadata,
            platform_public_key=pub,
        )

        # Use the read() alias instead of read_and_decrypt()
        read_meta, decrypted = OBBReader.read(output_path, priv)

        assert decrypted == original_data
        assert read_meta.vendor_id == "vendor-id"


class TestSerializationErrors:
    """Tests for error paths in serialization."""

    def test_binary_reader_unexpected_eof(self, tmp_path):
        """Should raise error when trying to read past EOF."""
        from optical_blackbox.serialization.binary import BinaryReader

        short_file = tmp_path / "short.bin"
        short_file.write_bytes(b"\x00\x01\x02")  # Only 3 bytes

        with open(short_file, "rb") as f:
            reader = BinaryReader(f)

            # Try to read more bytes than available
            with pytest.raises((EOFError, ValueError, OSError)):
                reader.read_bytes(100)

    def test_binary_writer_invalid_length(self, tmp_path):
        """Should handle writing very large length-prefixed data."""
        from optical_blackbox.serialization.binary import BinaryWriter

        output = tmp_path / "output.bin"

        with open(output, "wb") as f:
            writer = BinaryWriter(f)

            # Write a very large chunk (tests length encoding edge case)
            large_data = os.urandom(1024 * 1024)  # 1MB
            writer.write_length_prefixed(large_data)

        # Verify it was written
        assert output.stat().st_size > 1024 * 1024


class TestExceptionInstantiation:
    """Tests to cover exception instantiation."""

    def test_invalid_key_error_instantiation(self):
        """Should create InvalidKeyError with message."""
        from optical_blackbox.exceptions import InvalidKeyError

        error = InvalidKeyError("private", "test reason")
        assert "private" in str(error).lower()
        assert "test reason" in str(error)

    def test_signing_error_instantiation(self):
        """Should create SigningError with message."""
        from optical_blackbox.exceptions import SigningError

        error = SigningError("signing failed")
        assert "signing failed" in str(error)

    def test_verification_error_instantiation(self):
        """Should create InvalidSignatureError with no arguments."""
        from optical_blackbox.exceptions import InvalidSignatureError

        error = InvalidSignatureError()
        assert "signature" in str(error).lower()

    def test_decryption_error_instantiation(self):
        """Should create DecryptionError with message."""
        from optical_blackbox.exceptions import DecryptionError

        error = DecryptionError("decryption failed")
        assert "decryption failed" in str(error)

    def test_key_not_found_error_instantiation(self):
        """Should create KeyNotFoundError with path."""
        from optical_blackbox.exceptions import KeyNotFoundError

        error = KeyNotFoundError("/path/to/key.pem")
        assert "/path/to/key.pem" in str(error)

    def test_invalid_obb_file_error_instantiation(self):
        """Should create InvalidOBBFileError with message."""
        from optical_blackbox.exceptions import InvalidOBBFileError

        error = InvalidOBBFileError("corrupted header")
        assert "corrupted header" in str(error)


class TestPEMSerializationErrors:
    """Tests for PEM serialization error paths."""

    def test_private_key_from_pem_invalid(self):
        """Should raise error for invalid private key PEM."""
        from optical_blackbox.serialization.pem import private_key_from_pem

        invalid_pem = "-----BEGIN PRIVATE KEY-----\nINVALID\n-----END PRIVATE KEY-----"

        with pytest.raises((ValueError, Exception)):
            private_key_from_pem(invalid_pem)

    def test_public_key_from_pem_invalid(self):
        """Should raise error for invalid public key PEM."""
        from optical_blackbox.serialization.pem import public_key_from_pem

        invalid_pem = "-----BEGIN PUBLIC KEY-----\nINVALID\n-----END PUBLIC KEY-----"

        with pytest.raises((ValueError, Exception)):
            public_key_from_pem(invalid_pem)
