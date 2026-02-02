"""Shared pytest fixtures for OpticalBlackBox tests.

Provides common fixtures for cryptographic keys and metadata.
"""

import pytest
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import ec

from optical_blackbox.crypto.keys import KeyManager
from optical_blackbox.models.metadata import OBBMetadata


# =============================================================================
# Cryptographic Fixtures
# =============================================================================


@pytest.fixture
def vendor_keypair() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Generate a vendor ECDSA P-256 keypair for tests."""
    return KeyManager.generate_keypair()


@pytest.fixture
def platform_keypair() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Generate a platform ECDSA P-256 keypair for tests."""
    return KeyManager.generate_keypair()


@pytest.fixture
def vendor_private_key(vendor_keypair) -> ec.EllipticCurvePrivateKey:
    """Get vendor private key."""
    return vendor_keypair[0]


@pytest.fixture
def vendor_public_key(vendor_keypair) -> ec.EllipticCurvePublicKey:
    """Get vendor public key."""
    return vendor_keypair[1]


@pytest.fixture
def platform_private_key(platform_keypair) -> ec.EllipticCurvePrivateKey:
    """Get platform private key."""
    return platform_keypair[0]


@pytest.fixture
def platform_public_key(platform_keypair) -> ec.EllipticCurvePublicKey:
    """Get platform public key."""
    return platform_keypair[1]


@pytest.fixture
def aes_key() -> bytes:
    """Generate a valid 32-byte AES-256 key."""
    import os
    return os.urandom(32)


@pytest.fixture
def aes_nonce() -> bytes:
    """Generate a valid 12-byte AES-GCM nonce."""
    import os
    return os.urandom(12)


# =============================================================================
# Data Fixtures
# =============================================================================


@pytest.fixture
def sample_plaintext() -> bytes:
    """Generate sample plaintext data for encryption tests."""
    return b"This is sample plaintext data for testing encryption."


@pytest.fixture
def large_plaintext() -> bytes:
    """Generate large plaintext data for testing."""
    return b"X" * (10 * 1024 * 1024)  # 10 MB


@pytest.fixture
def tmp_key_dir(tmp_path):
    """Create a temporary directory for key files."""
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    return key_dir


@pytest.fixture
def sample_zmx_file(tmp_path):
    """Create a temporary .zmx file for testing."""
    zmx_file = tmp_path / "test.zmx"
    zmx_file.write_text("VERS 140101\nMODE SEQ\nEND\n")
    return zmx_file


@pytest.fixture
def tmp_zmx_file(tmp_path):
    """Create a temporary .zmx file for testing."""
    zmx_file = tmp_path / "test.zmx"
    zmx_file.write_text("VERS 140101\nMODE SEQ\nEND\n")
    return zmx_file


# =============================================================================
# Metadata Fixtures
# =============================================================================


@pytest.fixture
def sample_metadata() -> OBBMetadata:
    """Create a sample metadata object for tests."""
    return OBBMetadata(
        version="1.0.0",
        vendor_id="test-vendor",
        model_id="test-model",
        created_at=datetime.utcnow(),
        description="Test optical component",
        original_filename="test.zmx",
    )
