"""Test round-trip encryption/decryption of optical design files."""

import tempfile
from pathlib import Path
from datetime import datetime

import pytest

from optical_blackbox.crypto.keys import KeyManager
from optical_blackbox.models.metadata import OBBMetadata
from optical_blackbox.formats.obb_file import OBBWriter, OBBReader


def test_roundtrip_bytes():
    """Test that encrypting and decrypting bytes gives exact original."""
    
    # Create test data
    original_bytes = b"This is test optical design file content.\n" * 100
    
    # Generate keys
    platform_private, platform_public = KeyManager.generate_keypair()
    
    # Create metadata
    metadata = OBBMetadata(
        version="1.0.0",
        vendor_id="test-vendor",
        model_id="test-model",
        created_at=datetime.utcnow(),
        description="Test file",
        original_filename="test.zmx",
    )
    
    # Encrypt
    with tempfile.NamedTemporaryFile(suffix=".obb", delete=False) as f:
        obb_path = Path(f.name)
    
    try:
        OBBWriter.write(
            output_path=obb_path,
            payload_bytes=original_bytes,
            metadata=metadata,
            platform_public_key=platform_public,
        )
        
        # Decrypt
        read_metadata, decrypted_bytes = OBBReader.read_and_decrypt(
            path=obb_path,
            platform_private_key=platform_private,
        )
        
        # Verify
        assert decrypted_bytes == original_bytes, "Decrypted bytes don't match original"
        assert read_metadata.vendor_id == metadata.vendor_id
        assert read_metadata.model_id == metadata.model_id
        assert read_metadata.original_filename == metadata.original_filename
        
        print(f"✓ Round-trip successful: {len(original_bytes)} bytes")
        
    finally:
        # Cleanup
        if obb_path.exists():
            obb_path.unlink()


def test_roundtrip_real_zmx_file():
    """Test with a real .zmx file if available."""
    
    # Find a real .zmx file
    testdata_dir = Path(__file__).parent.parent / "testdata"
    zmx_files = list(testdata_dir.rglob("*.zmx"))
    
    if not zmx_files:
        pytest.skip("No .zmx files found in testdata")
    
    zmx_path = zmx_files[0]
    print(f"\nTesting with: {zmx_path.name}")
    
    # Read original file
    original_bytes = zmx_path.read_bytes()
    print(f"File size: {len(original_bytes)} bytes")
    
    # Generate keys
    platform_private, platform_public = KeyManager.generate_keypair()
    
    # Create metadata
    metadata = OBBMetadata(
        version="1.0.0",
        vendor_id="test-vendor",
        model_id="test-model",
        created_at=datetime.utcnow(),
        description=f"Test of {zmx_path.name}",
        original_filename=zmx_path.name,
    )
    
    # Encrypt
    with tempfile.NamedTemporaryFile(suffix=".obb", delete=False) as f:
        obb_path = Path(f.name)
    
    try:
        OBBWriter.write(
            output_path=obb_path,
            payload_bytes=original_bytes,
            metadata=metadata,
            platform_public_key=platform_public,
        )
        
        obb_size = obb_path.stat().st_size
        print(f"OBB file size: {obb_size} bytes")
        
        # Decrypt
        read_metadata, decrypted_bytes = OBBReader.read_and_decrypt(
            path=obb_path,
            platform_private_key=platform_private,
        )
        
        # Verify
        assert decrypted_bytes == original_bytes, "Decrypted .zmx doesn't match original"
        assert read_metadata.original_filename == zmx_path.name
        
        print(f"✓ Real file round-trip successful")
        
    finally:
        # Cleanup
        if obb_path.exists():
            obb_path.unlink()


def test_metadata_only_read():
    """Test reading metadata without decryption."""
    
    # Create test data
    original_bytes = b"Test data"
    
    # Generate keys
    platform_private, platform_public = KeyManager.generate_keypair()
    
    # Create metadata
    metadata = OBBMetadata(
        version="1.0.0",
        vendor_id="vendor-123",
        model_id="model-abc",
        created_at=datetime.utcnow(),
        description="Test metadata reading",
        original_filename="test.zmx",
    )
    
    # Encrypt
    with tempfile.NamedTemporaryFile(suffix=".obb", delete=False) as f:
        obb_path = Path(f.name)
    
    try:
        OBBWriter.write(
            output_path=obb_path,
            payload_bytes=original_bytes,
            metadata=metadata,
            platform_public_key=platform_public,
        )
        
        # Read metadata only (no key needed)
        read_metadata = OBBReader.read_metadata(obb_path)
        
        # Verify
        assert read_metadata.vendor_id == metadata.vendor_id
        assert read_metadata.model_id == metadata.model_id
        assert read_metadata.description == metadata.description
        assert read_metadata.original_filename == metadata.original_filename
        
        print("✓ Metadata-only read successful")
        
    finally:
        # Cleanup
        if obb_path.exists():
            obb_path.unlink()


if __name__ == "__main__":
    """Run tests directly."""
    print("Running round-trip tests...")
    print("=" * 60)
    
    test_roundtrip_bytes()
    print()
    
    test_roundtrip_real_zmx_file()
    print()
    
    test_metadata_only_read()
    print()
    
    print("=" * 60)
    print("All tests passed!")
