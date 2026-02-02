"""Unit tests for crypto/aes_gcm.py - AES-256-GCM encryption."""

import pytest
import os

from optical_blackbox.crypto.aes_gcm import (
    generate_nonce,
    encrypt,
    decrypt,
    encrypt_with_nonce_prefix,
    decrypt_with_nonce_prefix,
)
from optical_blackbox.core.constants import AES_KEY_SIZE, AES_NONCE_SIZE
from optical_blackbox.exceptions import DecryptionError


class TestGenerateNonce:
    """Tests for nonce generation."""

    def test_returns_correct_length(self):
        """Should return 12-byte nonce."""
        nonce = generate_nonce()
        assert len(nonce) == AES_NONCE_SIZE  # 12 bytes

    def test_returns_bytes(self):
        """Should return bytes."""
        nonce = generate_nonce()
        assert isinstance(nonce, bytes)

    def test_generates_unique_nonces(self):
        """Each call should generate different nonces."""
        nonces = [generate_nonce() for _ in range(100)]
        unique_nonces = set(nonces)
        assert len(unique_nonces) == 100


class TestEncrypt:
    """Tests for AES-256-GCM encryption."""

    def test_returns_tuple_of_nonce_and_ciphertext(self, aes_key, sample_plaintext):
        """Should return (nonce, ciphertext) tuple."""
        nonce, ciphertext = encrypt(sample_plaintext, aes_key)
        
        assert isinstance(nonce, bytes)
        assert isinstance(ciphertext, bytes)
        assert len(nonce) == AES_NONCE_SIZE

    def test_ciphertext_different_from_plaintext(self, aes_key, sample_plaintext):
        """Ciphertext should differ from plaintext."""
        _, ciphertext = encrypt(sample_plaintext, aes_key)
        assert ciphertext != sample_plaintext

    def test_uses_provided_nonce(self, aes_key, aes_nonce, sample_plaintext):
        """Should use provided nonce if given."""
        returned_nonce, _ = encrypt(sample_plaintext, aes_key, nonce=aes_nonce)
        assert returned_nonce == aes_nonce

    def test_generates_nonce_if_not_provided(self, aes_key, sample_plaintext):
        """Should generate nonce if not provided."""
        nonce, _ = encrypt(sample_plaintext, aes_key)
        assert len(nonce) == AES_NONCE_SIZE

    def test_wrong_key_size_raises_error(self, sample_plaintext):
        """Should raise ValueError for wrong key size."""
        wrong_key = os.urandom(16)  # 16 bytes instead of 32
        
        with pytest.raises(ValueError, match="Key must be"):
            encrypt(sample_plaintext, wrong_key)

    def test_wrong_nonce_size_raises_error(self, aes_key, sample_plaintext):
        """Should raise ValueError for wrong nonce size."""
        wrong_nonce = os.urandom(8)  # 8 bytes instead of 12
        
        with pytest.raises(ValueError, match="Nonce must be"):
            encrypt(sample_plaintext, aes_key, nonce=wrong_nonce)

    def test_empty_plaintext(self, aes_key):
        """Should handle empty plaintext."""
        nonce, ciphertext = encrypt(b"", aes_key)
        
        assert len(nonce) == AES_NONCE_SIZE
        # GCM tag adds 16 bytes even for empty plaintext
        assert len(ciphertext) == 16

    def test_large_plaintext(self, aes_key, large_plaintext):
        """Should handle large plaintext."""
        nonce, ciphertext = encrypt(large_plaintext, aes_key)
        
        assert len(nonce) == AES_NONCE_SIZE
        # Ciphertext = plaintext length + 16 byte tag
        assert len(ciphertext) == len(large_plaintext) + 16

    def test_with_associated_data(self, aes_key, sample_plaintext):
        """Should encrypt with AAD."""
        aad = b"additional authenticated data"
        nonce, ciphertext = encrypt(sample_plaintext, aes_key, associated_data=aad)
        
        assert len(nonce) == AES_NONCE_SIZE
        assert len(ciphertext) > len(sample_plaintext)


class TestDecrypt:
    """Tests for AES-256-GCM decryption."""

    def test_roundtrip_encrypt_decrypt(self, aes_key, sample_plaintext):
        """Encrypt then decrypt should return original plaintext."""
        nonce, ciphertext = encrypt(sample_plaintext, aes_key)
        decrypted = decrypt(nonce, ciphertext, aes_key)
        
        assert decrypted == sample_plaintext

    def test_empty_plaintext_roundtrip(self, aes_key):
        """Should handle empty plaintext roundtrip."""
        nonce, ciphertext = encrypt(b"", aes_key)
        decrypted = decrypt(nonce, ciphertext, aes_key)
        
        assert decrypted == b""

    def test_large_plaintext_roundtrip(self, aes_key, large_plaintext):
        """Should handle large plaintext roundtrip."""
        nonce, ciphertext = encrypt(large_plaintext, aes_key)
        decrypted = decrypt(nonce, ciphertext, aes_key)
        
        assert decrypted == large_plaintext

    def test_wrong_key_raises_error(self, aes_key, sample_plaintext):
        """Decryption with wrong key should raise DecryptionError."""
        nonce, ciphertext = encrypt(sample_plaintext, aes_key)
        wrong_key = os.urandom(32)
        
        with pytest.raises(DecryptionError):
            decrypt(nonce, ciphertext, wrong_key)

    def test_tampered_ciphertext_raises_error(self, aes_key, sample_plaintext):
        """Tampered ciphertext should raise DecryptionError."""
        nonce, ciphertext = encrypt(sample_plaintext, aes_key)
        
        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF  # Flip bits in first byte
        
        with pytest.raises(DecryptionError):
            decrypt(nonce, bytes(tampered), aes_key)

    def test_wrong_nonce_raises_error(self, aes_key, sample_plaintext):
        """Decryption with wrong nonce should raise DecryptionError."""
        nonce, ciphertext = encrypt(sample_plaintext, aes_key)
        wrong_nonce = os.urandom(12)
        
        with pytest.raises(DecryptionError):
            decrypt(wrong_nonce, ciphertext, aes_key)

    def test_aad_mismatch_raises_error(self, aes_key, sample_plaintext):
        """AAD mismatch should raise DecryptionError."""
        aad = b"correct aad"
        nonce, ciphertext = encrypt(sample_plaintext, aes_key, associated_data=aad)
        
        # Decrypt with wrong AAD
        with pytest.raises(DecryptionError):
            decrypt(nonce, ciphertext, aes_key, associated_data=b"wrong aad")

    def test_aad_roundtrip(self, aes_key, sample_plaintext):
        """Should decrypt correctly with matching AAD."""
        aad = b"additional authenticated data"
        nonce, ciphertext = encrypt(sample_plaintext, aes_key, associated_data=aad)
        decrypted = decrypt(nonce, ciphertext, aes_key, associated_data=aad)
        
        assert decrypted == sample_plaintext

    def test_wrong_key_size_raises_error(self, sample_plaintext, aes_nonce):
        """Should raise ValueError for wrong key size."""
        wrong_key = os.urandom(16)
        
        with pytest.raises(ValueError, match="Key must be"):
            decrypt(aes_nonce, b"ciphertext", wrong_key)

    def test_wrong_nonce_size_raises_error(self, aes_key, sample_plaintext):
        """Should raise ValueError for wrong nonce size."""
        wrong_nonce = os.urandom(8)
        
        with pytest.raises(ValueError, match="Nonce must be"):
            decrypt(wrong_nonce, b"ciphertext", aes_key)


class TestEncryptWithNoncePrefix:
    """Tests for encrypt_with_nonce_prefix."""

    def test_returns_nonce_prepended(self, aes_key, sample_plaintext):
        """Should return nonce || ciphertext."""
        result = encrypt_with_nonce_prefix(sample_plaintext, aes_key)
        
        # First 12 bytes should be nonce
        assert len(result) >= AES_NONCE_SIZE + 16  # nonce + tag minimum

    def test_nonce_is_first_12_bytes(self, aes_key, sample_plaintext):
        """Nonce should be first 12 bytes."""
        result = encrypt_with_nonce_prefix(sample_plaintext, aes_key)
        nonce = result[:AES_NONCE_SIZE]
        
        assert len(nonce) == AES_NONCE_SIZE


class TestDecryptWithNoncePrefix:
    """Tests for decrypt_with_nonce_prefix."""

    def test_roundtrip(self, aes_key, sample_plaintext):
        """Should roundtrip with encrypt_with_nonce_prefix."""
        encrypted = encrypt_with_nonce_prefix(sample_plaintext, aes_key)
        decrypted = decrypt_with_nonce_prefix(encrypted, aes_key)
        
        assert decrypted == sample_plaintext

    def test_empty_roundtrip(self, aes_key):
        """Should handle empty plaintext."""
        encrypted = encrypt_with_nonce_prefix(b"", aes_key)
        decrypted = decrypt_with_nonce_prefix(encrypted, aes_key)
        
        assert decrypted == b""

    def test_large_roundtrip(self, aes_key, large_plaintext):
        """Should handle large plaintext."""
        encrypted = encrypt_with_nonce_prefix(large_plaintext, aes_key)
        decrypted = decrypt_with_nonce_prefix(encrypted, aes_key)
        
        assert decrypted == large_plaintext

    def test_wrong_key_raises_error(self, aes_key, sample_plaintext):
        """Wrong key should raise DecryptionError."""
        encrypted = encrypt_with_nonce_prefix(sample_plaintext, aes_key)
        wrong_key = os.urandom(32)
        
        with pytest.raises(DecryptionError):
            decrypt_with_nonce_prefix(encrypted, wrong_key)

    def test_data_too_short_raises_error(self, aes_key):
        """Data shorter than nonce should raise ValueError."""
        short_data = b"short"  # Less than 12 bytes
        
        with pytest.raises(ValueError, match="too short"):
            decrypt_with_nonce_prefix(short_data, aes_key)
