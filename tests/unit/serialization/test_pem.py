"""Unit tests for serialization/pem.py - PEM encoding/decoding utilities."""

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

from optical_blackbox.serialization.pem import (
    public_key_to_pem,
    public_key_from_pem,
    private_key_to_pem,
    private_key_from_pem,
)


@pytest.fixture
def ec_keypair():
    """Generate an EC keypair for testing."""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


class TestPublicKeyToPem:
    """Tests for public_key_to_pem."""

    def test_returns_string(self, ec_keypair):
        """Should return a string."""
        _, public_key = ec_keypair
        
        pem = public_key_to_pem(public_key)
        
        assert isinstance(pem, str)

    def test_pem_format(self, ec_keypair):
        """Should have proper PEM format."""
        _, public_key = ec_keypair
        
        pem = public_key_to_pem(public_key)
        
        assert pem.startswith("-----BEGIN PUBLIC KEY-----")
        assert pem.strip().endswith("-----END PUBLIC KEY-----")

    def test_ascii_encoding(self, ec_keypair):
        """Should be ASCII-only."""
        _, public_key = ec_keypair
        
        pem = public_key_to_pem(public_key)
        
        # Should not raise
        pem.encode("ascii")


class TestPublicKeyFromPem:
    """Tests for public_key_from_pem."""

    def test_from_string(self, ec_keypair):
        """Should load from string."""
        _, public_key = ec_keypair
        pem = public_key_to_pem(public_key)
        
        loaded = public_key_from_pem(pem)
        
        assert isinstance(loaded, ec.EllipticCurvePublicKey)

    def test_from_bytes(self, ec_keypair):
        """Should load from bytes."""
        _, public_key = ec_keypair
        pem = public_key_to_pem(public_key)
        
        loaded = public_key_from_pem(pem.encode("ascii"))
        
        assert isinstance(loaded, ec.EllipticCurvePublicKey)

    def test_invalid_pem(self):
        """Should raise for invalid PEM."""
        with pytest.raises(Exception):  # Could be ValueError or other
            public_key_from_pem("not a valid pem")

    def test_roundtrip(self, ec_keypair):
        """Should roundtrip public key."""
        _, public_key = ec_keypair
        
        pem = public_key_to_pem(public_key)
        loaded = public_key_from_pem(pem)
        
        # Keys should have same public numbers
        orig_nums = public_key.public_numbers()
        loaded_nums = loaded.public_numbers()
        
        assert orig_nums.x == loaded_nums.x
        assert orig_nums.y == loaded_nums.y


class TestPrivateKeyToPem:
    """Tests for private_key_to_pem."""

    def test_returns_string(self, ec_keypair):
        """Should return a string."""
        private_key, _ = ec_keypair
        
        pem = private_key_to_pem(private_key)
        
        assert isinstance(pem, str)

    def test_pem_format_unencrypted(self, ec_keypair):
        """Should have proper PEM format (unencrypted)."""
        private_key, _ = ec_keypair
        
        pem = private_key_to_pem(private_key)
        
        assert "-----BEGIN PRIVATE KEY-----" in pem
        assert "-----END PRIVATE KEY-----" in pem

    def test_pem_format_encrypted(self, ec_keypair):
        """Should have encrypted PEM format with password."""
        private_key, _ = ec_keypair
        
        pem = private_key_to_pem(private_key, password="test123")
        
        assert "-----BEGIN ENCRYPTED PRIVATE KEY-----" in pem
        assert "-----END ENCRYPTED PRIVATE KEY-----" in pem


class TestPrivateKeyFromPem:
    """Tests for private_key_from_pem."""

    def test_from_string(self, ec_keypair):
        """Should load from string."""
        private_key, _ = ec_keypair
        pem = private_key_to_pem(private_key)
        
        loaded = private_key_from_pem(pem)
        
        assert isinstance(loaded, ec.EllipticCurvePrivateKey)

    def test_from_bytes(self, ec_keypair):
        """Should load from bytes."""
        private_key, _ = ec_keypair
        pem = private_key_to_pem(private_key)
        
        loaded = private_key_from_pem(pem.encode("ascii"))
        
        assert isinstance(loaded, ec.EllipticCurvePrivateKey)

    def test_invalid_pem(self):
        """Should raise for invalid PEM."""
        with pytest.raises(Exception):
            private_key_from_pem("not a valid pem")

    def test_roundtrip_unencrypted(self, ec_keypair):
        """Should roundtrip unencrypted private key."""
        private_key, _ = ec_keypair
        
        pem = private_key_to_pem(private_key)
        loaded = private_key_from_pem(pem)
        
        # Keys should have same private value
        orig_nums = private_key.private_numbers()
        loaded_nums = loaded.private_numbers()
        
        assert orig_nums.private_value == loaded_nums.private_value


class TestPrivateKeyWithPassword:
    """Tests for password-protected private keys."""

    def test_roundtrip_with_password(self, ec_keypair):
        """Should roundtrip with password."""
        private_key, _ = ec_keypair
        password = "secure_password_123"
        
        pem = private_key_to_pem(private_key, password=password)
        loaded = private_key_from_pem(pem, password=password)
        
        orig_nums = private_key.private_numbers()
        loaded_nums = loaded.private_numbers()
        
        assert orig_nums.private_value == loaded_nums.private_value

    def test_wrong_password_fails(self, ec_keypair):
        """Should fail with wrong password."""
        private_key, _ = ec_keypair
        
        pem = private_key_to_pem(private_key, password="correct")
        
        with pytest.raises(Exception):  # ValueError or TypeError
            private_key_from_pem(pem, password="wrong")

    def test_missing_password_fails(self, ec_keypair):
        """Should fail when password required but not provided."""
        private_key, _ = ec_keypair
        
        pem = private_key_to_pem(private_key, password="secret")
        
        with pytest.raises(Exception):
            private_key_from_pem(pem)  # No password


class TestKeyDerivePublic:
    """Tests for deriving public key from private."""

    def test_loaded_private_has_public(self, ec_keypair):
        """Loaded private key should derive correct public key."""
        private_key, public_key = ec_keypair
        
        pem = private_key_to_pem(private_key)
        loaded_private = private_key_from_pem(pem)
        derived_public = loaded_private.public_key()
        
        # Compare public key numbers
        orig_nums = public_key.public_numbers()
        derived_nums = derived_public.public_numbers()
        
        assert orig_nums.x == derived_nums.x
        assert orig_nums.y == derived_nums.y


class TestDifferentCurves:
    """Tests for different EC curves (if supported)."""

    def test_secp384r1(self):
        """Should work with SECP384R1 curve."""
        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        public_key = private_key.public_key()
        
        # Public key
        pub_pem = public_key_to_pem(public_key)
        loaded_pub = public_key_from_pem(pub_pem)
        assert isinstance(loaded_pub, ec.EllipticCurvePublicKey)
        
        # Private key
        priv_pem = private_key_to_pem(private_key)
        loaded_priv = private_key_from_pem(priv_pem)
        assert isinstance(loaded_priv, ec.EllipticCurvePrivateKey)
