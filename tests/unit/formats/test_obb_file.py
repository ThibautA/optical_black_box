"""Tests for OBB file I/O (OBBWriter and OBBReader)."""

import pytest
from pathlib import Path
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import ec

from optical_blackbox.formats.obb_file import OBBWriter, OBBReader
from optical_blackbox.models.metadata import OBBMetadata
from optical_blackbox.exceptions import (
    InvalidMagicBytesError,
    DecryptionError,
)


@pytest.fixture
def platform_keypair():
    """Generate a platform keypair for testing."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture
def vendor_keypair():
    """Generate a different keypair for testing wrong key scenarios."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


class TestOBBWriter:
    """Tests for OBBWriter."""

    def test_write_creates_valid_file(self, tmp_path, platform_keypair):
        """Should create a valid .obb file."""
        _, platform_pub = platform_keypair
        output_path = tmp_path / "test.obb"

        plaintext = b"Test data content"
        metadata = OBBMetadata(
            vendor_id="test-vendor",
            model_id="test-model",
        )

        OBBWriter.write(
            output_path=output_path,
            payload_bytes=plaintext,
            metadata=metadata,
            platform_public_key=platform_pub,
        )

        assert output_path.exists()
        assert output_path.stat().st_size > 0


class TestOBBReader:
    """Tests for OBBReader."""

    def test_read_metadata_only(self, tmp_path, platform_keypair):
        """Should read only metadata without decrypting."""
        _, platform_pub = platform_keypair
        output_path = tmp_path / "test.obb"

        original_metadata = OBBMetadata(
            vendor_id="acme-corp",
            model_id="lens-x1",
            description="Test lens",
        )

        OBBWriter.write(
            output_path=output_path,
            payload_bytes=b"secret data",
            metadata=original_metadata,
            platform_public_key=platform_pub,
        )

        # Read metadata only (no key needed)
        metadata = OBBReader.read_metadata(output_path)

        assert metadata.vendor_id == "acme-corp"
        assert metadata.model_id == "lens-x1"
        assert metadata.description == "Test lens"

    def test_read_and_decrypt(self, tmp_path, platform_keypair):
        """Should decrypt and return plaintext."""
        platform_priv, platform_pub = platform_keypair
        output_path = tmp_path / "test.obb"

        original_data = b"Original plaintext data"
        metadata = OBBMetadata(
            vendor_id="vendor-test",
            model_id="model-test",
        )

        OBBWriter.write(
            output_path=output_path,
            payload_bytes=original_data,
            metadata=metadata,
            platform_public_key=platform_pub,
        )

        # Read and decrypt
        read_metadata, decrypted_data = OBBReader.read_and_decrypt(
            path=output_path,
            platform_private_key=platform_priv,
        )

        assert decrypted_data == original_data
        assert read_metadata.vendor_id == "vendor-test"

    def test_read_invalid_magic_bytes(self, tmp_path):
        """Should raise InvalidMagicBytesError for invalid file."""
        bad_file = tmp_path / "bad.obb"
        bad_file.write_bytes(b"INVALID_MAGIC_BYTES_HEADER")

        with pytest.raises(InvalidMagicBytesError):
            OBBReader.read_metadata(bad_file)

    def test_read_wrong_private_key(self, tmp_path, platform_keypair, vendor_keypair):
        """Should raise DecryptionError with wrong key."""
        _, platform_pub = platform_keypair
        vendor_priv, _ = vendor_keypair

        output_path = tmp_path / "test.obb"

        OBBWriter.write(
            output_path=output_path,
            payload_bytes=b"secret",
            metadata=OBBMetadata(vendor_id="vendor-id", model_id="model-id"),
            platform_public_key=platform_pub,
        )

        # Try to decrypt with wrong private key
        with pytest.raises(DecryptionError):
            OBBReader.read_and_decrypt(
                path=output_path,
                platform_private_key=vendor_priv,
            )

    def test_read_nonexistent_file(self, tmp_path):
        """Should raise FileNotFoundError for missing file."""
        nonexistent = tmp_path / "does_not_exist.obb"

        with pytest.raises(FileNotFoundError):
            OBBReader.read_metadata(nonexistent)
