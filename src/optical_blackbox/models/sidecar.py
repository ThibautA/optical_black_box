"""Sidecar models for post-distribution key management.

The sidecar JSON file enables post-distribution updates to recipient lists
without re-encrypting or re-distributing the .obb file itself.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class SidecarRecipient(BaseModel):
    """Recipient entry in a sidecar file.
    
    Attributes:
        platform_fingerprint: SHA-256 fingerprint of recipient's public key
        wrapped_dek: RSA-OAEP encrypted Data Encryption Key
        platform_name: Optional human-readable platform name
        added_at: When this recipient was added
        revoked: Whether this recipient has been revoked
        revoked_at: When this recipient was revoked (if applicable)
    """
    
    platform_fingerprint: str = Field(
        ...,
        min_length=64,
        max_length=64,
        description="SHA-256 hex fingerprint of recipient's public key",
    )
    wrapped_dek: str = Field(
        ...,
        description="Base64-encoded RSA-OAEP encrypted DEK",
    )
    platform_name: Optional[str] = Field(
        default=None,
        max_length=100,
        description="Optional human-readable platform name",
    )
    added_at: datetime = Field(
        ...,
        description="When this recipient was added (UTC)",
    )
    revoked: bool = Field(
        default=False,
        description="Whether this recipient's access has been revoked",
    )
    revoked_at: Optional[datetime] = Field(
        default=None,
        description="When access was revoked (UTC), if applicable",
    )


class Sidecar(BaseModel):
    """Sidecar JSON for post-distribution recipient management.
    
    The sidecar enables vendors to:
    - Add new recipients after distribution
    - Revoke existing recipients (affects future downloads only)
    - Track recipient history
    
    Limitation: Cannot revoke access to already-downloaded files (offline decryption).
    This is an inherent limitation documented honestly like Zemax Black Box.
    
    Attributes:
        obb_file_id: Identifier linking to the .obb file (e.g., hash or model_id)
        vendor_id: Vendor who created the .obb file
        model_id: Component model identifier
        created_at: When the sidecar was first created
        updated_at: Last update timestamp
        recipients: Current list of recipients (includes revoked for history)
        version: Sidecar format version
    """
    
    obb_file_id: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Identifier for the .obb file (hash or model_id)",
    )
    vendor_id: str = Field(
        ...,
        min_length=3,
        max_length=50,
        description="Vendor who created the .obb file",
    )
    model_id: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Component model identifier",
    )
    created_at: datetime = Field(
        ...,
        description="When the sidecar was first created (UTC)",
    )
    updated_at: datetime = Field(
        ...,
        description="Last update timestamp (UTC)",
    )
    recipients: list[SidecarRecipient] = Field(
        default_factory=list,
        description="List of all recipients (includes revoked for audit trail)",
    )
    version: str = Field(
        default="1.0",
        description="Sidecar format version",
    )
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "obb_file_id": "ac254-050-a",
                "vendor_id": "thorlabs",
                "model_id": "AC254-050-A",
                "version": "1.0",
                "created_at": "2026-02-02T14:32:00Z",
                "updated_at": "2026-02-02T16:45:00Z",
                "recipients": [
                    {
                        "platform_fingerprint": "a1b2c3d4...",
                        "wrapped_dek": "base64_encoded_wrapped_dek",
                        "platform_name": "Zemax OpticStudio",
                        "added_at": "2026-02-02T14:32:00Z",
                        "revoked": False,
                    }
                ],
            }
        }
    }
