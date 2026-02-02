"""Tests for key fingerprint generation."""

import pytest

from optical_blackbox.crypto.fingerprint import compute_key_fingerprint, format_fingerprint
from optical_blackbox.crypto.rsa_oaep import generate_rsa_keypair


class TestFingerprint:
    """Test public key fingerprint operations."""
    
    def test_compute_fingerprint(self):
        """Test fingerprint computation."""
        _, public_pem = generate_rsa_keypair(2048)
        
        fingerprint = compute_key_fingerprint(public_pem)
        
        # Should be 64-char hex string (SHA-256)
        assert len(fingerprint) == 64
        assert all(c in "0123456789abcdef" for c in fingerprint)
    
    def test_fingerprint_deterministic(self):
        """Test that same key produces same fingerprint."""
        _, public_pem = generate_rsa_keypair(2048)
        
        fp1 = compute_key_fingerprint(public_pem)
        fp2 = compute_key_fingerprint(public_pem)
        
        assert fp1 == fp2
    
    def test_fingerprint_unique(self):
        """Test that different keys produce different fingerprints."""
        _, public_pem1 = generate_rsa_keypair(2048)
        _, public_pem2 = generate_rsa_keypair(2048)
        
        fp1 = compute_key_fingerprint(public_pem1)
        fp2 = compute_key_fingerprint(public_pem2)
        
        assert fp1 != fp2
    
    def test_compute_fingerprint_invalid_key(self):
        """Test fingerprint with invalid key."""
        invalid_key = b"not a valid key"
        
        with pytest.raises(ValueError, match="Failed to compute fingerprint"):
            compute_key_fingerprint(invalid_key)
    
    def test_format_fingerprint(self):
        """Test fingerprint formatting for display."""
        fingerprint = "a" * 64
        
        formatted = format_fingerprint(fingerprint)
        
        # Should be colon-separated
        assert formatted.startswith("aa:")
        assert formatted.count(":") == 31  # 32 groups - 1
        assert len(formatted) == 64 + 31  # 64 chars + 31 colons
    
    def test_format_fingerprint_invalid_length(self):
        """Test formatting with invalid fingerprint length."""
        invalid_fp = "a" * 32  # Too short
        
        with pytest.raises(ValueError, match="Invalid fingerprint length"):
            format_fingerprint(invalid_fp)
