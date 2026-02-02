"""Tests for OBB v2.0 file format with multi-recipient support."""

import os
from pathlib import Path

import pytest

from optical_blackbox.core.result import Err, Ok
from optical_blackbox.crypto.rsa_oaep import generate_rsa_keypair
from optical_blackbox.formats.obb_file_v2 import OBBReaderV2, OBBWriterV2
from optical_blackbox.models.metadata import OBBMetadataV2


class TestOBBFileV2:
    """Test .obb v2.0 file format operations."""
    
    def test_write_and_read_single_recipient(self, tmp_path):
        """Test writing and reading v2.0 file with single recipient."""
        # Generate keypair
        private_pem, public_pem = generate_rsa_keypair(2048)
        
        # Create metadata
        metadata = OBBMetadataV2(
            vendor_id="test-vendor",
            model_id="test-model",
            description="Test component",
            original_filename="test.zmx",
        )
        
        # Create test payload
        payload = b"This is test optical design data" * 100
        
        # Write file
        output_path = tmp_path / "test.obb"
        result = OBBWriterV2.write(
            output_path=output_path,
            payload_bytes=payload,
            metadata=metadata,
            recipient_public_keys=[(public_pem, "Test Platform")],
        )
        
        assert isinstance(result, Ok)
        assert output_path.exists()
        
        # Read and decrypt
        read_result = OBBReaderV2.read_and_decrypt(output_path, private_pem)
        assert isinstance(read_result, Ok)
        
        recovered_metadata, recovered_payload = read_result.value
        
        # Verify metadata
        assert recovered_metadata.vendor_id == "test-vendor"
        assert recovered_metadata.model_id == "test-model"
        assert recovered_metadata.version == "2.0"
        assert len(recovered_metadata.recipients) == 1
        assert recovered_metadata.recipients[0].platform_name == "Test Platform"
        
        # Verify payload
        assert recovered_payload == payload
    
    def test_write_and_read_multiple_recipients(self, tmp_path):
        """Test v2.0 file with multiple recipients."""
        # Generate 3 keypairs
        keypairs = [generate_rsa_keypair(2048) for _ in range(3)]
        platform_names = ["Platform 1", "Platform 2", "Platform 3"]
        
        metadata = OBBMetadataV2(
            vendor_id="test-vendor",
            model_id="multi-test",
        )
        
        payload = b"Multi-recipient test data" * 50
        
        # Write with all recipients
        output_path = tmp_path / "multi.obb"
        recipient_keys = [
            (pub, name) for (_, pub), name in zip(keypairs, platform_names)
        ]
        
        result = OBBWriterV2.write(
            output_path=output_path,
            payload_bytes=payload,
            metadata=metadata,
            recipient_public_keys=recipient_keys,
        )
        
        assert isinstance(result, Ok)
        
        # Each recipient should be able to decrypt
        for i, (priv, _) in enumerate(keypairs):
            read_result = OBBReaderV2.read_and_decrypt(output_path, priv)
            assert isinstance(read_result, Ok)
            
            recovered_metadata, recovered_payload = read_result.value
            assert len(recovered_metadata.recipients) == 3
            assert recovered_payload == payload
    
    def test_read_metadata_only(self, tmp_path):
        """Test reading metadata without decryption."""
        _, public_pem = generate_rsa_keypair(2048)
        
        metadata = OBBMetadataV2(
            vendor_id="vendor-abc",
            model_id="model-xyz",
            description="Test description",
            sidecar_url="https://example.com/sidecar.json",
        )
        
        payload = b"test data"
        
        output_path = tmp_path / "metadata_test.obb"
        result = OBBWriterV2.write(
            output_path=output_path,
            payload_bytes=payload,
            metadata=metadata,
            recipient_public_keys=[(public_pem, "Test")],
        )
        
        assert isinstance(result, Ok)
        
        # Read metadata only (no private key needed)
        metadata_result = OBBReaderV2.read_metadata(output_path)
        assert isinstance(metadata_result, Ok)
        
        recovered = metadata_result.value
        assert recovered.vendor_id == "vendor-abc"
        assert recovered.model_id == "model-xyz"
        assert recovered.description == "Test description"
        assert recovered.sidecar_url == "https://example.com/sidecar.json"
        assert len(recovered.recipients) == 1
    
    def test_decrypt_with_unauthorized_key(self, tmp_path):
        """Test decryption attempt with unauthorized key."""
        # Generate keypair for authorized recipient
        _, public_pem1 = generate_rsa_keypair(2048)
        
        # Generate different keypair for unauthorized attempt
        private_pem2, _ = generate_rsa_keypair(2048)
        
        metadata = OBBMetadataV2(
            vendor_id="test",
            model_id="test",
        )
        
        payload = b"secret data"
        
        output_path = tmp_path / "authorized.obb"
        result = OBBWriterV2.write(
            output_path=output_path,
            payload_bytes=payload,
            metadata=metadata,
            recipient_public_keys=[(public_pem1, "Authorized")],
        )
        
        assert isinstance(result, Ok)
        
        # Try to decrypt with unauthorized key
        decrypt_result = OBBReaderV2.read_and_decrypt(output_path, private_pem2)
        assert isinstance(decrypt_result, Err)
        assert "not authorized" in str(decrypt_result.error).lower()
    
    def test_list_recipients(self, tmp_path):
        """Test listing recipients from file."""
        keypairs = [generate_rsa_keypair(2048) for _ in range(2)]
        names = ["Platform A", "Platform B"]
        
        metadata = OBBMetadataV2(
            vendor_id="test",
            model_id="test",
        )
        
        output_path = tmp_path / "recipients.obb"
        recipient_keys = [(pub, name) for (_, pub), name in zip(keypairs, names)]
        
        result = OBBWriterV2.write(
            output_path=output_path,
            payload_bytes=b"data",
            metadata=metadata,
            recipient_public_keys=recipient_keys,
        )
        
        assert isinstance(result, Ok)
        
        # List recipients
        list_result = OBBReaderV2.list_recipients(output_path)
        assert isinstance(list_result, Ok)
        
        recipients = list_result.value
        assert len(recipients) == 2
        assert recipients[0].platform_name == "Platform A"
        assert recipients[1].platform_name == "Platform B"
        assert all(len(r.platform_fingerprint) == 64 for r in recipients)
    
    def test_large_payload(self, tmp_path):
        """Test v2.0 with large payload."""
        private_pem, public_pem = generate_rsa_keypair(2048)
        
        metadata = OBBMetadataV2(
            vendor_id="test",
            model_id="large",
        )
        
        # 5 MB payload
        payload = os.urandom(5 * 1024 * 1024)
        
        output_path = tmp_path / "large.obb"
        write_result = OBBWriterV2.write(
            output_path=output_path,
            payload_bytes=payload,
            metadata=metadata,
            recipient_public_keys=[(public_pem, None)],
        )
        
        assert isinstance(write_result, Ok)
        
        # Decrypt
        read_result = OBBReaderV2.read_and_decrypt(output_path, private_pem)
        assert isinstance(read_result, Ok)
        
        _, recovered_payload = read_result.value
        assert recovered_payload == payload
