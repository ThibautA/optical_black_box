"""Sidecar generator for post-distribution recipient management.

Enables vendors to create and update sidecar JSON files that add or revoke
recipients without re-encrypting or re-distributing the .obb file.
"""

import base64
from datetime import datetime
from pathlib import Path

from ..core.result import Err, Ok, Result
from ..crypto.fingerprint import compute_key_fingerprint
from ..crypto.rsa_oaep import wrap_dek
from ..exceptions import EncryptionError
from ..models.sidecar import Sidecar, SidecarRecipient
from ..serialization.json_codec import encode_json, decode_json


class SidecarGenerator:
    """Generates and updates sidecar JSON files for .obb v2.0 files.
    
    The sidecar enables:
    - Adding new recipients after distribution
    - Revoking existing recipients
    - Tracking recipient history
    
    Limitation: Revocation only affects future downloads; cannot revoke
    access to already-downloaded files (offline decryption).
    """
    
    @classmethod
    def create(
        cls,
        obb_file_id: str,
        vendor_id: str,
        model_id: str,
        dek: bytes,
        initial_recipients: list[tuple[bytes, str | None]],
    ) -> Result[Sidecar, EncryptionError]:
        """Create a new sidecar with initial recipients.
        
        Args:
            obb_file_id: Identifier for the .obb file
            vendor_id: Vendor who created the file
            model_id: Component model identifier
            dek: The Data Encryption Key (32 bytes) from the .obb file
            initial_recipients: List of (public_key_pem, platform_name) tuples
            
        Returns:
            Ok with Sidecar object, or Err with EncryptionError
        """
        now = datetime.utcnow()
        recipients = []
        
        for public_key_pem, platform_name in initial_recipients:
            # Compute fingerprint
            try:
                fingerprint = compute_key_fingerprint(public_key_pem)
            except ValueError as e:
                return Err(EncryptionError(f"Invalid public key: {e}"))
            
            # Wrap DEK
            wrap_result = wrap_dek(dek, public_key_pem)
            if isinstance(wrap_result, Err):
                return wrap_result
            
            wrapped_dek_bytes = wrap_result.value
            wrapped_dek_b64 = base64.b64encode(wrapped_dek_bytes).decode("ascii")
            
            recipients.append(
                SidecarRecipient(
                    platform_fingerprint=fingerprint,
                    wrapped_dek=wrapped_dek_b64,
                    platform_name=platform_name,
                    added_at=now,
                    revoked=False,
                )
            )
        
        sidecar = Sidecar(
            obb_file_id=obb_file_id,
            vendor_id=vendor_id,
            model_id=model_id,
            created_at=now,
            updated_at=now,
            recipients=recipients,
        )
        
        return Ok(sidecar)
    
    @classmethod
    def add_recipient(
        cls,
        sidecar: Sidecar,
        dek: bytes,
        public_key_pem: bytes,
        platform_name: str | None = None,
    ) -> Result[Sidecar, EncryptionError]:
        """Add a new recipient to an existing sidecar.
        
        Args:
            sidecar: Existing sidecar to update
            dek: The Data Encryption Key (32 bytes)
            public_key_pem: New recipient's public key
            platform_name: Optional platform name
            
        Returns:
            Ok with updated Sidecar, or Err with EncryptionError
        """
        # Compute fingerprint
        try:
            fingerprint = compute_key_fingerprint(public_key_pem)
        except ValueError as e:
            return Err(EncryptionError(f"Invalid public key: {e}"))
        
        # Check if recipient already exists
        for recipient in sidecar.recipients:
            if recipient.platform_fingerprint == fingerprint:
                if recipient.revoked:
                    # Un-revoke if previously revoked
                    recipient.revoked = False
                    recipient.revoked_at = None
                    sidecar.updated_at = datetime.utcnow()
                    return Ok(sidecar)
                else:
                    # Already exists and not revoked
                    return Ok(sidecar)
        
        # Wrap DEK
        wrap_result = wrap_dek(dek, public_key_pem)
        if isinstance(wrap_result, Err):
            return wrap_result
        
        wrapped_dek_bytes = wrap_result.value
        wrapped_dek_b64 = base64.b64encode(wrapped_dek_bytes).decode("ascii")
        
        # Add new recipient
        new_recipient = SidecarRecipient(
            platform_fingerprint=fingerprint,
            wrapped_dek=wrapped_dek_b64,
            platform_name=platform_name,
            added_at=datetime.utcnow(),
            revoked=False,
        )
        
        sidecar.recipients.append(new_recipient)
        sidecar.updated_at = datetime.utcnow()
        
        return Ok(sidecar)
    
    @classmethod
    def revoke_recipient(
        cls,
        sidecar: Sidecar,
        platform_fingerprint: str,
    ) -> Result[Sidecar, ValueError]:
        """Revoke a recipient's access (affects future downloads only).
        
        Args:
            sidecar: Existing sidecar to update
            platform_fingerprint: Fingerprint of recipient to revoke
            
        Returns:
            Ok with updated Sidecar, or Err if recipient not found
        """
        for recipient in sidecar.recipients:
            if recipient.platform_fingerprint == platform_fingerprint:
                if not recipient.revoked:
                    recipient.revoked = True
                    recipient.revoked_at = datetime.utcnow()
                    sidecar.updated_at = datetime.utcnow()
                return Ok(sidecar)
        
        return Err(ValueError(f"Recipient not found: {platform_fingerprint}"))
    
    @classmethod
    def save(cls, sidecar: Sidecar, output_path: Path) -> Result[None, OSError]:
        """Save sidecar to JSON file.
        
        Args:
            sidecar: Sidecar object to save
            output_path: Path for output JSON file
            
        Returns:
            Ok(None) on success, Err(OSError) on failure
        """
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            json_bytes = encode_json(sidecar.model_dump())
            output_path.write_bytes(json_bytes)
            return Ok(None)
        except OSError as e:
            return Err(e)
    
    @classmethod
    def load(cls, path: Path) -> Result[Sidecar, Exception]:
        """Load sidecar from JSON file.
        
        Args:
            path: Path to sidecar JSON file
            
        Returns:
            Ok with Sidecar object, or Err with exception
        """
        try:
            json_bytes = path.read_bytes()
            data = decode_json(json_bytes)
            sidecar = Sidecar(**data)
            return Ok(sidecar)
        except Exception as e:
            return Err(e)
