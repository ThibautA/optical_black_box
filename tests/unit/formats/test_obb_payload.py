"""Tests for OBB payload encryption/decryption."""

import pytest
import os

from optical_blackbox.formats.obb_payload import encrypt_payload, decrypt_payload
from optical_blackbox.exceptions import DecryptionError


class TestEncryptPayload:
    """Tests for encrypt_payload function."""

    def test_encrypt_returns_tuple(self):
        """Should return (nonce, ciphertext) tuple."""
        plaintext = b"Test plaintext data"
        aes_key = os.urandom(32)  # 256-bit key

        nonce, ciphertext = encrypt_payload(plaintext, aes_key)

        assert isinstance(nonce, bytes)
        assert isinstance(ciphertext, bytes)
        assert len(nonce) == 12  # GCM nonce
        assert len(ciphertext) > len(plaintext)  # Contains auth tag

    def test_encrypt_different_each_time(self):
        """Should produce different ciphertext each time (random nonce)."""
        plaintext = b"Same data"
        aes_key = os.urandom(32)

        nonce1, ciphertext1 = encrypt_payload(plaintext, aes_key)
        nonce2, ciphertext2 = encrypt_payload(plaintext, aes_key)

        # Different nonces
        assert nonce1 != nonce2
        # Different ciphertexts
        assert ciphertext1 != ciphertext2

    def test_encrypt_invalid_key_length(self):
        """Should raise ValueError for wrong key length."""
        plaintext = b"Data"
        short_key = os.urandom(16)  # Only 128 bits

        with pytest.raises(ValueError, match="32 bytes"):
            encrypt_payload(plaintext, short_key)


class TestDecryptPayload:
    """Tests for decrypt_payload function."""

    def test_decrypt_roundtrip(self):
        """Should decrypt data encrypted with matching key."""
        original = b"Original plaintext message"
        aes_key = os.urandom(32)

        nonce, ciphertext = encrypt_payload(original, aes_key)
        decrypted = decrypt_payload(nonce, ciphertext, aes_key)

        assert decrypted == original

    def test_decrypt_with_wrong_key_fails(self):
        """Should raise DecryptionError with wrong key."""
        plaintext = b"Secret data"
        key1 = os.urandom(32)
        key2 = os.urandom(32)

        nonce, ciphertext = encrypt_payload(plaintext, key1)

        with pytest.raises(DecryptionError, match="decrypt payload"):
            decrypt_payload(nonce, ciphertext, key2)

    def test_decrypt_tampered_data_fails(self):
        """Should raise DecryptionError with tampered ciphertext."""
        plaintext = b"Original data"
        aes_key = os.urandom(32)

        nonce, ciphertext = encrypt_payload(plaintext, aes_key)

        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF  # Flip bits
        tampered_ciphertext = bytes(tampered)

        with pytest.raises(DecryptionError):
            decrypt_payload(nonce, tampered_ciphertext, aes_key)

    def test_decrypt_invalid_key_length(self):
        """Should raise ValueError for wrong key length."""
        nonce = os.urandom(12)
        ciphertext = b"some ciphertext"
        short_key = os.urandom(16)

        with pytest.raises(ValueError, match="32 bytes"):
            decrypt_payload(nonce, ciphertext, short_key)
