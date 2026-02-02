"""Unit tests for crypto/hybrid.py - OBBEncryptor and OBBSigner."""

import pytest

from optical_blackbox.crypto.hybrid import OBBEncryptor, OBBSigner
from optical_blackbox.crypto.keys import KeyManager
from optical_blackbox.exceptions import DecryptionError, InvalidSignatureError


class TestOBBEncryptor:
    """Tests for OBBEncryptor hybrid encryption."""

    def test_encrypt_returns_tuple(self, platform_public_key, sample_plaintext):
        """encrypt should return (encrypted_payload, ephemeral_public_key)."""
        result = OBBEncryptor.encrypt(sample_plaintext, platform_public_key)
        
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_encrypt_returns_bytes_payload(self, platform_public_key, sample_plaintext):
        """Encrypted payload should be bytes."""
        encrypted, _ = OBBEncryptor.encrypt(sample_plaintext, platform_public_key)
        assert isinstance(encrypted, bytes)

    def test_encrypt_returns_public_key(self, platform_public_key, sample_plaintext):
        """Should return ephemeral public key."""
        _, ephemeral_pub = OBBEncryptor.encrypt(sample_plaintext, platform_public_key)
        
        from cryptography.hazmat.primitives.asymmetric import ec
        assert isinstance(ephemeral_pub, ec.EllipticCurvePublicKey)

    def test_encrypted_differs_from_plaintext(self, platform_public_key, sample_plaintext):
        """Encrypted payload should differ from plaintext."""
        encrypted, _ = OBBEncryptor.encrypt(sample_plaintext, platform_public_key)
        assert encrypted != sample_plaintext

    def test_decrypt_roundtrip(self, platform_keypair, sample_plaintext):
        """Encrypt then decrypt should return original plaintext."""
        platform_priv, platform_pub = platform_keypair
        
        encrypted, ephemeral_pub = OBBEncryptor.encrypt(sample_plaintext, platform_pub)
        decrypted = OBBEncryptor.decrypt(encrypted, ephemeral_pub, platform_priv)
        
        assert decrypted == sample_plaintext

    def test_decrypt_empty_roundtrip(self, platform_keypair):
        """Should handle empty plaintext."""
        platform_priv, platform_pub = platform_keypair
        
        encrypted, ephemeral_pub = OBBEncryptor.encrypt(b"", platform_pub)
        decrypted = OBBEncryptor.decrypt(encrypted, ephemeral_pub, platform_priv)
        
        assert decrypted == b""

    def test_decrypt_large_roundtrip(self, platform_keypair, large_plaintext):
        """Should handle large plaintext."""
        platform_priv, platform_pub = platform_keypair
        
        encrypted, ephemeral_pub = OBBEncryptor.encrypt(large_plaintext, platform_pub)
        decrypted = OBBEncryptor.decrypt(encrypted, ephemeral_pub, platform_priv)
        
        assert decrypted == large_plaintext

    def test_decrypt_wrong_private_key_fails(self, platform_keypair, vendor_keypair, sample_plaintext):
        """Decryption with wrong private key should fail."""
        _, platform_pub = platform_keypair
        vendor_priv, _ = vendor_keypair
        
        encrypted, ephemeral_pub = OBBEncryptor.encrypt(sample_plaintext, platform_pub)
        
        with pytest.raises(DecryptionError):
            OBBEncryptor.decrypt(encrypted, ephemeral_pub, vendor_priv)

    def test_different_encryptions_different_ephemeral_keys(self, platform_public_key, sample_plaintext):
        """Each encryption should use different ephemeral keys."""
        _, eph1 = OBBEncryptor.encrypt(sample_plaintext, platform_public_key)
        _, eph2 = OBBEncryptor.encrypt(sample_plaintext, platform_public_key)
        
        # Keys should be different (different ephemeral pairs)
        assert eph1 != eph2


class TestOBBEncryptorWithPEM:
    """Tests for OBBEncryptor PEM convenience methods."""

    def test_encrypt_with_pem_key_returns_pem_ephemeral(self, platform_keypair, sample_plaintext):
        """encrypt_with_pem_key should return ephemeral key as PEM string."""
        _, platform_pub = platform_keypair
        platform_pub_pem = KeyManager.public_key_to_pem(platform_pub)
        
        encrypted, ephemeral_pem = OBBEncryptor.encrypt_with_pem_key(
            sample_plaintext, platform_pub_pem
        )
        
        assert isinstance(encrypted, bytes)
        assert isinstance(ephemeral_pem, str)
        assert "-----BEGIN PUBLIC KEY-----" in ephemeral_pem

    def test_pem_roundtrip(self, platform_keypair, sample_plaintext):
        """Should roundtrip with PEM keys."""
        platform_priv, platform_pub = platform_keypair
        platform_pub_pem = KeyManager.public_key_to_pem(platform_pub)
        
        encrypted, ephemeral_pem = OBBEncryptor.encrypt_with_pem_key(
            sample_plaintext, platform_pub_pem
        )
        
        # Convert ephemeral PEM back to key for decryption
        ephemeral_pub = KeyManager.public_key_from_pem(ephemeral_pem)
        decrypted = OBBEncryptor.decrypt(encrypted, ephemeral_pub, platform_priv)
        
        assert decrypted == sample_plaintext


class TestOBBSigner:
    """Tests for OBBSigner."""

    def test_sign_returns_base64_string(self, vendor_private_key, sample_plaintext):
        """sign should return base64 string."""
        signature = OBBSigner.sign(sample_plaintext, vendor_private_key)
        
        assert isinstance(signature, str)
        # Verify it's valid base64
        import base64
        decoded = base64.b64decode(signature)
        assert isinstance(decoded, bytes)

    def test_verify_valid_signature_returns_true(self, vendor_keypair, sample_plaintext):
        """verify should return True for valid signature."""
        private_key, public_key = vendor_keypair
        
        signature = OBBSigner.sign(sample_plaintext, private_key)
        result = OBBSigner.verify(sample_plaintext, signature, public_key)
        
        assert result is True

    def test_verify_wrong_key_returns_false(self, vendor_keypair, platform_keypair, sample_plaintext):
        """verify should return False for wrong public key."""
        vendor_priv, _ = vendor_keypair
        _, platform_pub = platform_keypair
        
        signature = OBBSigner.sign(sample_plaintext, vendor_priv)
        result = OBBSigner.verify(sample_plaintext, signature, platform_pub)
        
        assert result is False

    def test_verify_tampered_data_returns_false(self, vendor_keypair, sample_plaintext):
        """verify should return False for tampered data."""
        private_key, public_key = vendor_keypair
        
        signature = OBBSigner.sign(sample_plaintext, private_key)
        result = OBBSigner.verify(b"tampered", signature, public_key)
        
        assert result is False

    def test_verify_or_raise_valid(self, vendor_keypair, sample_plaintext):
        """verify_or_raise should not raise for valid signature."""
        private_key, public_key = vendor_keypair
        
        signature = OBBSigner.sign(sample_plaintext, private_key)
        # Should not raise
        OBBSigner.verify_or_raise(sample_plaintext, signature, public_key)

    def test_verify_or_raise_invalid(self, vendor_keypair, sample_plaintext):
        """verify_or_raise should raise InvalidSignatureError for invalid signature."""
        _, public_key = vendor_keypair
        
        with pytest.raises(InvalidSignatureError):
            OBBSigner.verify_or_raise(sample_plaintext, "invalid", public_key)


class TestIntegration:
    """Integration tests combining encryption and signing."""

    def test_full_encrypt_sign_verify_decrypt_workflow(
        self, vendor_keypair, platform_keypair, sample_plaintext
    ):
        """Test complete workflow: encrypt → sign → verify → decrypt."""
        vendor_priv, vendor_pub = vendor_keypair
        platform_priv, platform_pub = platform_keypair
        
        # 1. Encrypt data for platform
        encrypted, ephemeral_pub = OBBEncryptor.encrypt(sample_plaintext, platform_pub)
        
        # 2. Sign encrypted data with vendor key
        signature = OBBSigner.sign(encrypted, vendor_priv)
        
        # 3. Verify signature with vendor public key
        assert OBBSigner.verify(encrypted, signature, vendor_pub)
        
        # 4. Decrypt with platform private key
        decrypted = OBBEncryptor.decrypt(encrypted, ephemeral_pub, platform_priv)
        
        assert decrypted == sample_plaintext
