"""Tests for sidecar generation and management."""

import base64
import os
from pathlib import Path

import pytest

from optical_blackbox.core.result import Err, Ok
from optical_blackbox.crypto.fingerprint import compute_key_fingerprint
from optical_blackbox.crypto.rsa_oaep import generate_rsa_keypair, unwrap_dek
from optical_blackbox.sidecar import SidecarGenerator


class TestSidecarGenerator:
    """Test sidecar generation and management."""
    
    def test_create_sidecar(self):
        """Test creating a new sidecar."""
        dek = os.urandom(32)
        
        # Generate keypairs
        keypairs = [generate_rsa_keypair(2048) for _ in range(2)]
        recipient_keys = [
            (pub, f"Platform {i+1}") for i, (_, pub) in enumerate(keypairs)
        ]
        
        result = SidecarGenerator.create(
            obb_file_id="test-file",
            vendor_id="test-vendor",
            model_id="test-model",
            dek=dek,
            initial_recipients=recipient_keys,
        )
        
        assert isinstance(result, Ok)
        sidecar = result.value
        
        assert sidecar.obb_file_id == "test-file"
        assert sidecar.vendor_id == "test-vendor"
        assert sidecar.model_id == "test-model"
        assert len(sidecar.recipients) == 2
        assert sidecar.recipients[0].platform_name == "Platform 1"
        assert sidecar.recipients[1].platform_name == "Platform 2"
        assert not sidecar.recipients[0].revoked
    
    def test_sidecar_wrapped_deks_valid(self):
        """Test that sidecar contains valid wrapped DEKs."""
        dek = os.urandom(32)
        
        keypairs = [generate_rsa_keypair(2048) for _ in range(2)]
        recipient_keys = [(pub, None) for _, pub in keypairs]
        
        result = SidecarGenerator.create(
            obb_file_id="test",
            vendor_id="vendor",
            model_id="model",
            dek=dek,
            initial_recipients=recipient_keys,
        )
        
        assert isinstance(result, Ok)
        sidecar = result.value
        
        # Verify each recipient can unwrap DEK
        for i, (priv, _) in enumerate(keypairs):
            wrapped_dek_b64 = sidecar.recipients[i].wrapped_dek
            wrapped_dek = base64.b64decode(wrapped_dek_b64)
            
            unwrap_result = unwrap_dek(wrapped_dek, priv)
            assert isinstance(unwrap_result, Ok)
            assert unwrap_result.value == dek
    
    def test_add_recipient(self):
        """Test adding a new recipient to sidecar."""
        dek = os.urandom(32)
        
        # Create sidecar with one recipient
        _, pub1 = generate_rsa_keypair(2048)
        result = SidecarGenerator.create(
            obb_file_id="test",
            vendor_id="vendor",
            model_id="model",
            dek=dek,
            initial_recipients=[(pub1, "Platform 1")],
        )
        
        assert isinstance(result, Ok)
        sidecar = result.value
        assert len(sidecar.recipients) == 1
        
        # Add second recipient
        priv2, pub2 = generate_rsa_keypair(2048)
        add_result = SidecarGenerator.add_recipient(
            sidecar=sidecar,
            dek=dek,
            public_key_pem=pub2,
            platform_name="Platform 2",
        )
        
        assert isinstance(add_result, Ok)
        updated_sidecar = add_result.value
        
        assert len(updated_sidecar.recipients) == 2
        assert updated_sidecar.recipients[1].platform_name == "Platform 2"
        
        # Verify new recipient can unwrap DEK
        wrapped_dek_b64 = updated_sidecar.recipients[1].wrapped_dek
        wrapped_dek = base64.b64decode(wrapped_dek_b64)
        
        unwrap_result = unwrap_dek(wrapped_dek, priv2)
        assert isinstance(unwrap_result, Ok)
        assert unwrap_result.value == dek
    
    def test_add_duplicate_recipient(self):
        """Test adding same recipient twice (should be idempotent)."""
        dek = os.urandom(32)
        
        _, pub = generate_rsa_keypair(2048)
        result = SidecarGenerator.create(
            obb_file_id="test",
            vendor_id="vendor",
            model_id="model",
            dek=dek,
            initial_recipients=[(pub, "Platform 1")],
        )
        
        assert isinstance(result, Ok)
        sidecar = result.value
        
        # Try to add same recipient again
        add_result = SidecarGenerator.add_recipient(
            sidecar=sidecar,
            dek=dek,
            public_key_pem=pub,
            platform_name="Platform 1",
        )
        
        assert isinstance(add_result, Ok)
        updated_sidecar = add_result.value
        
        # Should still have only 1 recipient
        assert len(updated_sidecar.recipients) == 1
    
    def test_revoke_recipient(self):
        """Test revoking a recipient."""
        dek = os.urandom(32)
        
        _, pub = generate_rsa_keypair(2048)
        fingerprint = compute_key_fingerprint(pub)
        
        result = SidecarGenerator.create(
            obb_file_id="test",
            vendor_id="vendor",
            model_id="model",
            dek=dek,
            initial_recipients=[(pub, "Platform 1")],
        )
        
        assert isinstance(result, Ok)
        sidecar = result.value
        
        # Revoke recipient
        revoke_result = SidecarGenerator.revoke_recipient(sidecar, fingerprint)
        
        assert isinstance(revoke_result, Ok)
        updated_sidecar = revoke_result.value
        
        assert updated_sidecar.recipients[0].revoked
        assert updated_sidecar.recipients[0].revoked_at is not None
    
    def test_revoke_nonexistent_recipient(self):
        """Test revoking non-existent recipient."""
        dek = os.urandom(32)
        
        _, pub = generate_rsa_keypair(2048)
        result = SidecarGenerator.create(
            obb_file_id="test",
            vendor_id="vendor",
            model_id="model",
            dek=dek,
            initial_recipients=[(pub, "Platform 1")],
        )
        
        assert isinstance(result, Ok)
        sidecar = result.value
        
        # Try to revoke non-existent fingerprint
        fake_fingerprint = "a" * 64
        revoke_result = SidecarGenerator.revoke_recipient(sidecar, fake_fingerprint)
        
        assert isinstance(revoke_result, Err)
    
    def test_unrevoke_recipient(self):
        """Test un-revoking a previously revoked recipient."""
        dek = os.urandom(32)
        
        _, pub = generate_rsa_keypair(2048)
        fingerprint = compute_key_fingerprint(pub)
        
        result = SidecarGenerator.create(
            obb_file_id="test",
            vendor_id="vendor",
            model_id="model",
            dek=dek,
            initial_recipients=[(pub, "Platform 1")],
        )
        
        sidecar = result.value
        
        # Revoke
        revoke_result = SidecarGenerator.revoke_recipient(sidecar, fingerprint)
        sidecar = revoke_result.value
        assert sidecar.recipients[0].revoked
        
        # Un-revoke by adding again
        add_result = SidecarGenerator.add_recipient(
            sidecar=sidecar,
            dek=dek,
            public_key_pem=pub,
            platform_name="Platform 1",
        )
        
        sidecar = add_result.value
        assert not sidecar.recipients[0].revoked
        assert sidecar.recipients[0].revoked_at is None
    
    def test_save_and_load_sidecar(self, tmp_path):
        """Test saving and loading sidecar to/from JSON."""
        dek = os.urandom(32)
        
        _, pub = generate_rsa_keypair(2048)
        result = SidecarGenerator.create(
            obb_file_id="test",
            vendor_id="vendor",
            model_id="model",
            dek=dek,
            initial_recipients=[(pub, "Platform 1")],
        )
        
        sidecar = result.value
        
        # Save
        output_path = tmp_path / "sidecar.json"
        save_result = SidecarGenerator.save(sidecar, output_path)
        
        assert isinstance(save_result, Ok)
        assert output_path.exists()
        
        # Load
        load_result = SidecarGenerator.load(output_path)
        
        assert isinstance(load_result, Ok)
        loaded_sidecar = load_result.value
        
        assert loaded_sidecar.obb_file_id == "test"
        assert loaded_sidecar.vendor_id == "vendor"
        assert loaded_sidecar.model_id == "model"
        assert len(loaded_sidecar.recipients) == 1
        assert loaded_sidecar.recipients[0].platform_name == "Platform 1"
