"""Unit tests for models/metadata.py - Simplified OBBMetadata model."""

import pytest
from datetime import datetime

from optical_blackbox.models.metadata import OBBMetadata


class TestOBBMetadataCreation:
    """Tests for OBBMetadata creation."""

    def test_minimal_creation(self):
        """Should create with required fields only."""
        metadata = OBBMetadata(
            version="1.0.0",
            vendor_id="test-vendor",
            model_id="test-model",
            created_at=datetime.utcnow(),
            original_filename="test.zmx",
        )
        
        assert metadata.vendor_id == "test-vendor"
        assert metadata.model_id == "test-model"
        assert metadata.original_filename == "test.zmx"
        assert metadata.description is None

    def test_full_creation(self):
        """Should create with all fields."""
        now = datetime.utcnow()
        metadata = OBBMetadata(
            version="1.0.0",
            vendor_id="acme-optics",
            model_id="lens-50mm",
            created_at=now,
            description="50mm lens design",
            original_filename="lens.zmx",
        )
        
        assert metadata.version == "1.0.0"
        assert metadata.vendor_id == "acme-optics"
        assert metadata.model_id == "lens-50mm"
        assert metadata.created_at == now
        assert metadata.description == "50mm lens design"
        assert metadata.original_filename == "lens.zmx"

    def test_default_description(self):
        """Description should be optional."""
        metadata = OBBMetadata(
            version="1.0.0",
            vendor_id="test",
            model_id="model",
            created_at=datetime.utcnow(),
            original_filename="test.zmx",
        )
        assert metadata.description is None


class TestOBBMetadataValidation:
    """Tests for OBBMetadata field validation."""

    def test_vendor_id_min_length(self):
        """vendor_id must be at least 3 characters."""
        with pytest.raises(ValueError):
            OBBMetadata(
                version="1.0.0",
                vendor_id="ab",  # Too short
                model_id="model",
                created_at=datetime.utcnow(),
                original_filename="test.zmx",
            )

    def test_vendor_id_max_length(self):
        """vendor_id must be at most 50 characters."""
        with pytest.raises(ValueError):
            OBBMetadata(
                version="1.0.0",
                vendor_id="a" * 51,  # Too long
                model_id="model",
                created_at=datetime.utcnow(),
                original_filename="test.zmx",
            )

    def test_model_id_min_length(self):
        """model_id must be at least 1 character."""
        # Min length is 1, empty string should fail
        with pytest.raises(ValueError):
            OBBMetadata(
                version="1.0.0",
                vendor_id="vendor",
                model_id="",  # Empty
                created_at=datetime.utcnow(),
                original_filename="test.zmx",
            )

    def test_model_id_max_length(self):
        """model_id must not exceed 100 characters."""
        with pytest.raises(ValueError):
            OBBMetadata(
                version="1.0.0",
                vendor_id="vendor",
                model_id="a" * 101,  # > 100 chars
                created_at=datetime.utcnow(),
                original_filename="test.zmx",
            )


class TestOBBMetadataSerialization:
    """Tests for metadata serialization."""

    def test_dict_serialization(self):
        """Should serialize to dict."""
        now = datetime.utcnow()
        metadata = OBBMetadata(
            version="1.0.0",
            vendor_id="test-vendor",
            model_id="test-model",
            created_at=now,
            description="Test",
            original_filename="test.zmx",
        )
        
        data = metadata.model_dump()
        assert data["vendor_id"] == "test-vendor"
        assert data["model_id"] == "test-model"
        assert data["description"] == "Test"
        assert data["original_filename"] == "test.zmx"

    def test_json_serialization(self):
        """Should serialize to JSON."""
        metadata = OBBMetadata(
            version="1.0.0",
            vendor_id="test-vendor",
            model_id="test-model",
            created_at=datetime.utcnow(),
            original_filename="test.zmx",
        )
        
        json_str = metadata.model_dump_json()
        assert "test-vendor" in json_str
        assert "test-model" in json_str

    def test_roundtrip(self):
        """Should roundtrip through dict."""
        original = OBBMetadata(
            version="1.0.0",
            vendor_id="test-vendor",
            model_id="test-model",
            created_at=datetime.utcnow(),
            description="Test",
            original_filename="test.zmx",
        )
        
        data = original.model_dump()
        restored = OBBMetadata(**data)
        
        assert restored.vendor_id == original.vendor_id
        assert restored.model_id == original.model_id
        assert restored.description == original.description
        assert restored.original_filename == original.original_filename
