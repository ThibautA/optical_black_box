"""Unit tests for crypto/signing.py - ECDSA signing."""

import pytest
import base64

from optical_blackbox.crypto.signing import (
    sign,
    sign_base64,
    verify,
    verify_base64,
    verify_or_raise,
    verify_base64_or_raise,
)
from optical_blackbox.exceptions import InvalidSignatureError


class TestSign:
    """Tests for ECDSA signing."""

    def test_returns_bytes(self, vendor_private_key, sample_plaintext):
        """Should return signature as bytes."""
        signature = sign(sample_plaintext, vendor_private_key)
        assert isinstance(signature, bytes)

    def test_signature_not_empty(self, vendor_private_key, sample_plaintext):
        """Signature should not be empty."""
        signature = sign(sample_plaintext, vendor_private_key)
        assert len(signature) > 0

    def test_different_data_different_signature(self, vendor_private_key):
        """Different data should produce different signatures."""
        sig1 = sign(b"data1", vendor_private_key)
        sig2 = sign(b"data2", vendor_private_key)
        assert sig1 != sig2

    def test_same_data_different_signatures(self, vendor_private_key):
        """Same data may produce different signatures (ECDSA is non-deterministic)."""
        # Note: ECDSA uses random k, so signatures can differ
        sig1 = sign(b"same data", vendor_private_key)
        sig2 = sign(b"same data", vendor_private_key)
        # Both should verify, but may differ
        assert len(sig1) > 0
        assert len(sig2) > 0

    def test_empty_data(self, vendor_private_key):
        """Should sign empty data."""
        signature = sign(b"", vendor_private_key)
        assert isinstance(signature, bytes)
        assert len(signature) > 0


class TestSignBase64:
    """Tests for base64-encoded signing."""

    def test_returns_string(self, vendor_private_key, sample_plaintext):
        """Should return base64 string."""
        signature = sign_base64(sample_plaintext, vendor_private_key)
        assert isinstance(signature, str)

    def test_valid_base64(self, vendor_private_key, sample_plaintext):
        """Should be valid base64."""
        signature = sign_base64(sample_plaintext, vendor_private_key)
        # Should not raise
        decoded = base64.b64decode(signature)
        assert isinstance(decoded, bytes)


class TestVerify:
    """Tests for signature verification."""

    def test_valid_signature_returns_true(self, vendor_keypair, sample_plaintext):
        """Valid signature should return True."""
        private_key, public_key = vendor_keypair
        
        signature = sign(sample_plaintext, private_key)
        result = verify(sample_plaintext, signature, public_key)
        
        assert result is True

    def test_wrong_public_key_returns_false(self, vendor_keypair, platform_keypair, sample_plaintext):
        """Wrong public key should return False."""
        vendor_priv, _ = vendor_keypair
        _, platform_pub = platform_keypair
        
        signature = sign(sample_plaintext, vendor_priv)
        result = verify(sample_plaintext, signature, platform_pub)
        
        assert result is False

    def test_tampered_data_returns_false(self, vendor_keypair, sample_plaintext):
        """Tampered data should return False."""
        private_key, public_key = vendor_keypair
        
        signature = sign(sample_plaintext, private_key)
        result = verify(b"tampered data", signature, public_key)
        
        assert result is False

    def test_tampered_signature_returns_false(self, vendor_keypair, sample_plaintext):
        """Tampered signature should return False."""
        private_key, public_key = vendor_keypair
        
        signature = sign(sample_plaintext, private_key)
        # Tamper with signature
        tampered_sig = bytes([b ^ 0xFF for b in signature])
        result = verify(sample_plaintext, tampered_sig, public_key)
        
        assert result is False

    def test_invalid_signature_format_returns_false(self, vendor_public_key, sample_plaintext):
        """Invalid signature format should return False, not raise."""
        result = verify(sample_plaintext, b"not a valid signature", vendor_public_key)
        assert result is False

    def test_empty_data(self, vendor_keypair):
        """Should verify empty data."""
        private_key, public_key = vendor_keypair
        
        signature = sign(b"", private_key)
        result = verify(b"", signature, public_key)
        
        assert result is True


class TestVerifyBase64:
    """Tests for base64 signature verification."""

    def test_valid_signature_returns_true(self, vendor_keypair, sample_plaintext):
        """Valid base64 signature should return True."""
        private_key, public_key = vendor_keypair
        
        signature_b64 = sign_base64(sample_plaintext, private_key)
        result = verify_base64(sample_plaintext, signature_b64, public_key)
        
        assert result is True

    def test_invalid_base64_returns_false(self, vendor_public_key, sample_plaintext):
        """Invalid base64 should return False, not raise."""
        result = verify_base64(sample_plaintext, "not valid base64!!!", vendor_public_key)
        assert result is False

    def test_wrong_data_returns_false(self, vendor_keypair, sample_plaintext):
        """Wrong data should return False."""
        private_key, public_key = vendor_keypair
        
        signature_b64 = sign_base64(sample_plaintext, private_key)
        result = verify_base64(b"different data", signature_b64, public_key)
        
        assert result is False


class TestVerifyOrRaise:
    """Tests for verify_or_raise."""

    def test_valid_signature_no_exception(self, vendor_keypair, sample_plaintext):
        """Valid signature should not raise."""
        private_key, public_key = vendor_keypair
        
        signature = sign(sample_plaintext, private_key)
        # Should not raise
        verify_or_raise(sample_plaintext, signature, public_key)

    def test_invalid_signature_raises(self, vendor_keypair, platform_keypair, sample_plaintext):
        """Invalid signature should raise InvalidSignatureError."""
        vendor_priv, _ = vendor_keypair
        _, platform_pub = platform_keypair
        
        signature = sign(sample_plaintext, vendor_priv)
        
        with pytest.raises(InvalidSignatureError):
            verify_or_raise(sample_plaintext, signature, platform_pub)


class TestVerifyBase64OrRaise:
    """Tests for verify_base64_or_raise."""

    def test_valid_signature_no_exception(self, vendor_keypair, sample_plaintext):
        """Valid signature should not raise."""
        private_key, public_key = vendor_keypair
        
        signature_b64 = sign_base64(sample_plaintext, private_key)
        # Should not raise
        verify_base64_or_raise(sample_plaintext, signature_b64, public_key)

    def test_invalid_signature_raises(self, vendor_keypair, sample_plaintext):
        """Invalid signature should raise InvalidSignatureError."""
        _, public_key = vendor_keypair
        
        with pytest.raises(InvalidSignatureError):
            verify_base64_or_raise(sample_plaintext, "invalid_sig", public_key)

    def test_tampered_data_raises(self, vendor_keypair, sample_plaintext):
        """Tampered data should raise InvalidSignatureError."""
        private_key, public_key = vendor_keypair
        
        signature_b64 = sign_base64(sample_plaintext, private_key)
        
        with pytest.raises(InvalidSignatureError):
            verify_base64_or_raise(b"tampered", signature_b64, public_key)
