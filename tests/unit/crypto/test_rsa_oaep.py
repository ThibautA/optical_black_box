"""Tests for RSA-OAEP key wrapping/unwrapping."""

import pytest

from optical_blackbox.crypto.rsa_oaep import generate_rsa_keypair, unwrap_dek, wrap_dek
from optical_blackbox.core.result import Err, Ok


class TestRSAOAEP:
    """Test RSA-OAEP key wrapping operations."""
    
    def test_generate_keypair(self):
        """Test RSA keypair generation."""
        private_pem, public_pem = generate_rsa_keypair(2048)
        
        assert private_pem.startswith(b"-----BEGIN PRIVATE KEY-----")
        assert public_pem.startswith(b"-----BEGIN PUBLIC KEY-----")
        assert len(private_pem) > 1000
        assert len(public_pem) > 200
    
    def test_wrap_unwrap_dek_success(self):
        """Test successful DEK wrapping and unwrapping."""
        # Generate keypair
        private_pem, public_pem = generate_rsa_keypair(2048)
        
        # Generate DEK
        import os
        dek = os.urandom(32)
        
        # Wrap DEK
        wrap_result = wrap_dek(dek, public_pem)
        assert isinstance(wrap_result, Ok)
        wrapped_dek = wrap_result.value
        assert len(wrapped_dek) == 256  # RSA-2048 produces 256-byte ciphertext
        
        # Unwrap DEK
        unwrap_result = unwrap_dek(wrapped_dek, private_pem)
        assert isinstance(unwrap_result, Ok)
        recovered_dek = unwrap_result.value
        
        # Verify DEK matches
        assert recovered_dek == dek
    
    def test_wrap_with_invalid_key(self):
        """Test wrapping with invalid public key."""
        import os
        dek = os.urandom(32)
        
        invalid_key = b"not a valid key"
        result = wrap_dek(dek, invalid_key)
        
        assert isinstance(result, Err)
        assert "Failed to wrap DEK" in str(result.error)
    
    def test_unwrap_with_invalid_key(self):
        """Test unwrapping with invalid private key."""
        wrapped_dek = b"fake wrapped dek"
        invalid_key = b"not a valid key"
        
        result = unwrap_dek(wrapped_dek, invalid_key)
        
        assert isinstance(result, Err)
        assert "Failed to unwrap DEK" in str(result.error)
    
    def test_unwrap_with_wrong_key(self):
        """Test unwrapping with wrong private key."""
        # Generate two keypairs
        private_pem1, public_pem1 = generate_rsa_keypair(2048)
        private_pem2, public_pem2 = generate_rsa_keypair(2048)
        
        import os
        dek = os.urandom(32)
        
        # Wrap with key1
        wrap_result = wrap_dek(dek, public_pem1)
        assert isinstance(wrap_result, Ok)
        wrapped_dek = wrap_result.value
        
        # Try to unwrap with key2
        unwrap_result = unwrap_dek(wrapped_dek, private_pem2)
        assert isinstance(unwrap_result, Err)
        assert "Failed to unwrap DEK" in str(unwrap_result.error)
    
    def test_wrap_multiple_recipients(self):
        """Test wrapping same DEK for multiple recipients."""
        import os
        dek = os.urandom(32)
        
        # Generate 3 keypairs
        keypairs = [generate_rsa_keypair(2048) for _ in range(3)]
        
        # Wrap DEK for each recipient
        wrapped_deks = []
        for private_pem, public_pem in keypairs:
            result = wrap_dek(dek, public_pem)
            assert isinstance(result, Ok)
            wrapped_deks.append(result.value)
        
        # Each wrapped DEK should be different (probabilistic encryption)
        assert wrapped_deks[0] != wrapped_deks[1]
        assert wrapped_deks[1] != wrapped_deks[2]
        
        # But all should unwrap to same DEK
        for i, (private_pem, _) in enumerate(keypairs):
            result = unwrap_dek(wrapped_deks[i], private_pem)
            assert isinstance(result, Ok)
            assert result.value == dek
