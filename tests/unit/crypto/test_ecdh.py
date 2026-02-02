"""Unit tests for crypto/ecdh.py - ECDH key exchange."""

import pytest

from cryptography.hazmat.primitives.asymmetric import ec

from optical_blackbox.crypto.ecdh import (
    generate_ephemeral_keypair,
    derive_shared_key,
    compute_encryption_key,
    compute_decryption_key,
)
from optical_blackbox.core.constants import AES_KEY_SIZE, HKDF_INFO


class TestGenerateEphemeralKeypair:
    """Tests for ephemeral key pair generation."""

    def test_returns_tuple_of_two(self):
        """Should return (private, public) tuple."""
        result = generate_ephemeral_keypair()
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_private_key_type(self):
        """Private key should be EllipticCurvePrivateKey."""
        private, _ = generate_ephemeral_keypair()
        assert isinstance(private, ec.EllipticCurvePrivateKey)

    def test_public_key_type(self):
        """Public key should be EllipticCurvePublicKey."""
        _, public = generate_ephemeral_keypair()
        assert isinstance(public, ec.EllipticCurvePublicKey)

    def test_uses_p256_curve(self):
        """Should use SECP256R1 (P-256) curve."""
        private, public = generate_ephemeral_keypair()
        assert private.curve.name == "secp256r1"
        assert public.curve.name == "secp256r1"

    def test_each_call_unique(self):
        """Each call should generate different keys."""
        kp1 = generate_ephemeral_keypair()
        kp2 = generate_ephemeral_keypair()
        assert kp1[0] != kp2[0]


class TestDeriveSharedKey:
    """Tests for shared key derivation."""

    def test_derives_correct_length_key(self, vendor_keypair, platform_keypair):
        """Should derive key of correct length."""
        vendor_priv, _ = vendor_keypair
        _, platform_pub = platform_keypair
        
        key = derive_shared_key(vendor_priv, platform_pub)
        
        assert len(key) == AES_KEY_SIZE  # 32 bytes

    def test_returns_bytes(self, vendor_keypair, platform_keypair):
        """Should return bytes."""
        vendor_priv, _ = vendor_keypair
        _, platform_pub = platform_keypair
        
        key = derive_shared_key(vendor_priv, platform_pub)
        
        assert isinstance(key, bytes)

    def test_symmetric_derivation(self, vendor_keypair, platform_keypair):
        """ECDH should be symmetric: both parties derive same key."""
        vendor_priv, vendor_pub = vendor_keypair
        platform_priv, platform_pub = platform_keypair
        
        # Vendor derives key using platform's public key
        key_vendor = derive_shared_key(vendor_priv, platform_pub)
        
        # Platform derives key using vendor's public key
        key_platform = derive_shared_key(platform_priv, vendor_pub)
        
        assert key_vendor == key_platform

    def test_different_pairs_different_keys(self, vendor_keypair, platform_keypair):
        """Different key pairs should produce different shared keys."""
        vendor_priv, vendor_pub = vendor_keypair
        platform_priv, platform_pub = platform_keypair
        
        # Derive with different combinations
        key1 = derive_shared_key(vendor_priv, platform_pub)
        
        # Generate new keypair
        new_priv, new_pub = generate_ephemeral_keypair()
        key2 = derive_shared_key(vendor_priv, new_pub)
        
        assert key1 != key2

    def test_custom_key_length(self, vendor_keypair, platform_keypair):
        """Should support custom key lengths."""
        vendor_priv, _ = vendor_keypair
        _, platform_pub = platform_keypair
        
        key_16 = derive_shared_key(vendor_priv, platform_pub, key_length=16)
        key_64 = derive_shared_key(vendor_priv, platform_pub, key_length=64)
        
        assert len(key_16) == 16
        assert len(key_64) == 64

    def test_custom_hkdf_info(self, vendor_keypair, platform_keypair):
        """Different HKDF info should produce different keys."""
        vendor_priv, _ = vendor_keypair
        _, platform_pub = platform_keypair
        
        key1 = derive_shared_key(vendor_priv, platform_pub, info=b"info1")
        key2 = derive_shared_key(vendor_priv, platform_pub, info=b"info2")
        
        assert key1 != key2

    def test_default_hkdf_info(self, vendor_keypair, platform_keypair):
        """Should use default HKDF info from constants."""
        vendor_priv, _ = vendor_keypair
        _, platform_pub = platform_keypair
        
        # Derive with default
        key_default = derive_shared_key(vendor_priv, platform_pub)
        
        # Derive with explicit default
        key_explicit = derive_shared_key(vendor_priv, platform_pub, info=HKDF_INFO)
        
        assert key_default == key_explicit


class TestComputeEncryptionKey:
    """Tests for sender-side key derivation."""

    def test_returns_32_bytes(self, vendor_keypair, platform_keypair):
        """Should return 32-byte AES key."""
        ephemeral_priv, _ = generate_ephemeral_keypair()
        _, platform_pub = platform_keypair
        
        key = compute_encryption_key(ephemeral_priv, platform_pub)
        
        assert len(key) == 32
        assert isinstance(key, bytes)


class TestComputeDecryptionKey:
    """Tests for recipient-side key derivation."""

    def test_returns_32_bytes(self, platform_keypair):
        """Should return 32-byte AES key."""
        platform_priv, _ = platform_keypair
        _, ephemeral_pub = generate_ephemeral_keypair()
        
        key = compute_decryption_key(platform_priv, ephemeral_pub)
        
        assert len(key) == 32
        assert isinstance(key, bytes)

    def test_matches_encryption_key(self, platform_keypair):
        """Encryption and decryption keys should match."""
        platform_priv, platform_pub = platform_keypair
        ephemeral_priv, ephemeral_pub = generate_ephemeral_keypair()
        
        # Sender computes encryption key
        enc_key = compute_encryption_key(ephemeral_priv, platform_pub)
        
        # Recipient computes decryption key
        dec_key = compute_decryption_key(platform_priv, ephemeral_pub)
        
        assert enc_key == dec_key
