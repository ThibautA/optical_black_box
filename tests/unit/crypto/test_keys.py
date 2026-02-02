"""Unit tests for crypto/keys.py - KeyManager."""

import pytest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

from optical_blackbox.crypto.keys import KeyManager
from optical_blackbox.exceptions import InvalidKeyError, KeyNotFoundError


class TestKeyManagerGeneration:
    """Tests for key pair generation."""

    def test_generate_keypair_returns_tuple(self):
        """generate_keypair should return a tuple of (private, public)."""
        result = KeyManager.generate_keypair()
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_generate_keypair_private_key_type(self):
        """Private key should be EllipticCurvePrivateKey."""
        private_key, _ = KeyManager.generate_keypair()
        assert isinstance(private_key, ec.EllipticCurvePrivateKey)

    def test_generate_keypair_public_key_type(self):
        """Public key should be EllipticCurvePublicKey."""
        _, public_key = KeyManager.generate_keypair()
        assert isinstance(public_key, ec.EllipticCurvePublicKey)

    def test_generate_keypair_uses_p256_curve(self):
        """Keys should use SECP256R1 (P-256) curve."""
        private_key, public_key = KeyManager.generate_keypair()
        assert private_key.curve.name == "secp256r1"
        assert public_key.curve.name == "secp256r1"

    def test_generate_keypair_keys_are_paired(self):
        """Public key should match private key."""
        private_key, public_key = KeyManager.generate_keypair()
        derived_public = private_key.public_key()
        
        # Compare by serializing to PEM
        pub_pem = KeyManager.public_key_to_pem(public_key)
        derived_pem = KeyManager.public_key_to_pem(derived_public)
        assert pub_pem == derived_pem

    def test_generate_keypair_unique_each_call(self):
        """Each call should generate different keys."""
        keypair1 = KeyManager.generate_keypair()
        keypair2 = KeyManager.generate_keypair()
        
        # Private keys should be different
        assert keypair1[0] != keypair2[0]


class TestKeyManagerSaveLoad:
    """Tests for saving and loading keys."""

    def test_save_load_private_key_roundtrip(self, tmp_key_dir, vendor_private_key):
        """Private key should survive save/load roundtrip."""
        key_path = tmp_key_dir / "private.pem"
        
        KeyManager.save_private_key(vendor_private_key, key_path)
        loaded_key = KeyManager.load_private_key(key_path)
        
        assert isinstance(loaded_key, ec.EllipticCurvePrivateKey)
        assert loaded_key.curve.name == vendor_private_key.curve.name

    def test_save_load_public_key_roundtrip(self, tmp_key_dir, vendor_public_key):
        """Public key should survive save/load roundtrip."""
        key_path = tmp_key_dir / "public.pem"
        
        KeyManager.save_public_key(vendor_public_key, key_path)
        loaded_key = KeyManager.load_public_key(key_path)
        
        assert isinstance(loaded_key, ec.EllipticCurvePublicKey)
        assert loaded_key.curve.name == vendor_public_key.curve.name

    def test_save_private_key_with_password(self, tmp_key_dir, vendor_private_key):
        """Private key can be saved with password encryption."""
        key_path = tmp_key_dir / "private_encrypted.pem"
        password = "secure_password_123"
        
        KeyManager.save_private_key(vendor_private_key, key_path, password=password)
        loaded_key = KeyManager.load_private_key(key_path, password=password)
        
        assert isinstance(loaded_key, ec.EllipticCurvePrivateKey)

    def test_load_private_key_wrong_password_fails(self, tmp_key_dir, vendor_private_key):
        """Loading with wrong password should fail."""
        key_path = tmp_key_dir / "private_encrypted.pem"
        
        KeyManager.save_private_key(vendor_private_key, key_path, password="correct")
        
        with pytest.raises(InvalidKeyError):
            KeyManager.load_private_key(key_path, password="wrong")

    def test_save_creates_parent_directories(self, tmp_path, vendor_private_key):
        """save_private_key should create parent directories."""
        key_path = tmp_path / "nested" / "dirs" / "private.pem"
        
        KeyManager.save_private_key(vendor_private_key, key_path)
        
        assert key_path.exists()

    def test_load_nonexistent_private_key_raises_error(self, tmp_path):
        """Loading nonexistent key should raise KeyNotFoundError."""
        key_path = tmp_path / "nonexistent.pem"
        
        with pytest.raises(KeyNotFoundError):
            KeyManager.load_private_key(key_path)

    def test_load_nonexistent_public_key_raises_error(self, tmp_path):
        """Loading nonexistent public key should raise KeyNotFoundError."""
        key_path = tmp_path / "nonexistent.pem"
        
        with pytest.raises(KeyNotFoundError):
            KeyManager.load_public_key(key_path)

    def test_load_invalid_pem_raises_error(self, tmp_path):
        """Loading invalid PEM content should raise InvalidKeyError."""
        key_path = tmp_path / "invalid.pem"
        key_path.write_text("This is not a valid PEM file")
        
        with pytest.raises(InvalidKeyError):
            KeyManager.load_private_key(key_path)

    def test_saved_file_contains_pem_markers(self, tmp_key_dir, vendor_private_key):
        """Saved key file should contain PEM markers."""
        key_path = tmp_key_dir / "private.pem"
        
        KeyManager.save_private_key(vendor_private_key, key_path)
        content = key_path.read_text()
        
        assert "-----BEGIN" in content
        assert "-----END" in content


class TestKeyManagerPEMConversion:
    """Tests for PEM string conversion."""

    def test_public_key_to_pem_returns_string(self, vendor_public_key):
        """public_key_to_pem should return a string."""
        pem = KeyManager.public_key_to_pem(vendor_public_key)
        
        assert isinstance(pem, str)
        assert "-----BEGIN PUBLIC KEY-----" in pem
        assert "-----END PUBLIC KEY-----" in pem

    def test_public_key_from_pem_roundtrip(self, vendor_public_key):
        """Public key should survive PEM string roundtrip."""
        pem = KeyManager.public_key_to_pem(vendor_public_key)
        loaded_key = KeyManager.public_key_from_pem(pem)
        
        assert isinstance(loaded_key, ec.EllipticCurvePublicKey)
        assert loaded_key.curve.name == vendor_public_key.curve.name

    def test_public_key_from_pem_accepts_bytes(self, vendor_public_key):
        """public_key_from_pem should accept bytes input."""
        pem = KeyManager.public_key_to_pem(vendor_public_key)
        loaded_key = KeyManager.public_key_from_pem(pem.encode("ascii"))
        
        assert isinstance(loaded_key, ec.EllipticCurvePublicKey)

    def test_private_key_save_load_roundtrip(self, vendor_private_key, tmp_key_dir):
        """Private key should survive save/load roundtrip via files."""
        key_path = tmp_key_dir / "test_private.pem"
        
        KeyManager.save_private_key(vendor_private_key, key_path)
        loaded_key = KeyManager.load_private_key(key_path)
        
        assert isinstance(loaded_key, ec.EllipticCurvePrivateKey)
        assert loaded_key.curve.name == vendor_private_key.curve.name
