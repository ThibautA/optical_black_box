"""OBB Metadata models.

Defines the public (unencrypted) metadata stored in .obb files.
Includes models for both v1.0 (single recipient) and v2.0 (multi-recipient) formats.
"""

import base64
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, field_serializer, field_validator


class OBBMetadata(BaseModel):
    """Public metadata for .obb files.

    This information is stored unencrypted in the file header and can
    be read by anyone without the decryption key.

    Simplified to essential fields only - the .obb file is a simple
    encrypted container for the original design file.

    Attributes:
        version: OBB format version (e.g., "1.0")
        vendor_id: Unique vendor identifier
        model_id: Component/product model identifier
        created_at: Creation timestamp
        description: Optional description
        original_filename: Original source file name (e.g., "lens.zmx")

    Example:
        >>> metadata = OBBMetadata(
        ...     vendor_id="thorlabs",
        ...     model_id="AC254-050-A",
        ...     original_filename="ac254-050-a.zmx",
        ... )
    """

    version: str = Field(
        default="1.0",
        description="OBB format version",
    )
    vendor_id: str = Field(
        ...,
        min_length=3,
        max_length=50,
        description="Unique vendor identifier",
    )
    model_id: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Component or product model identifier",
    )

    # Timestamps
    created_at: Optional[datetime] = Field(
        default=None,
        description="Creation timestamp (UTC)",
    )

    # Optional info
    description: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Optional description of the component",
    )
    original_filename: Optional[str] = Field(
        default=None,
        max_length=255,
        description="Original source file name (e.g., lens.zmx)",
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "version": "1.0",
                "vendor_id": "thorlabs",
                "model_id": "AC254-050-A",
                "created_at": "2026-01-30T14:32:00Z",
                "original_filename": "ac254-050-a.zmx",
            }
        }
    }


class RecipientInfo(BaseModel):
    """Information about a recipient in a v2.0 multi-recipient .obb file.
    
    Each recipient has a wrapped DEK (Data Encryption Key) that they can
    unwrap using their RSA private key to access the file content.
    
    Attributes:
        platform_fingerprint: SHA-256 fingerprint of the recipient's RSA public key
        wrapped_dek: RSA-OAEP encrypted DEK (Data Encryption Key)
        platform_name: Optional human-readable platform name
    """
    
    platform_fingerprint: str = Field(
        ...,
        min_length=64,
        max_length=64,
        description="SHA-256 hex fingerprint of recipient's public key",
    )
    wrapped_dek: bytes = Field(
        ...,
        description="RSA-OAEP encrypted Data Encryption Key",
    )
    platform_name: Optional[str] = Field(
        default=None,
        max_length=100,
        description="Optional human-readable platform name",
    )
    
    @field_serializer('wrapped_dek')
    def serialize_wrapped_dek(self, value: bytes) -> str:
        """Serialize wrapped_dek as base64 string for JSON."""
        return base64.b64encode(value).decode('ascii')
    
    @field_validator('wrapped_dek', mode='before')
    @classmethod
    def validate_wrapped_dek(cls, value):
        """Deserialize wrapped_dek from base64 string if needed."""
        if isinstance(value, str):
            return base64.b64decode(value)
        return value


class OBBMetadataV2(BaseModel):
    """Public metadata for v2.0 multi-recipient .obb files.
    
    Extends the v1.0 metadata with support for multiple recipients,
    each identified by their platform key fingerprint.
    
    Attributes:
        version: OBB format version ("2.0")
        vendor_id: Unique vendor identifier
        model_id: Component/product model identifier
        created_at: Creation timestamp
        description: Optional description
        original_filename: Original source file name
        recipients: List of recipients who can decrypt this file
        sidecar_url: Optional URL to sidecar JSON for post-distribution updates
    """
    
    version: str = Field(
        default="2.0",
        description="OBB format version",
    )
    vendor_id: str = Field(
        ...,
        min_length=3,
        max_length=50,
        description="Unique vendor identifier",
    )
    model_id: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Component or product model identifier",
    )
    
    # Timestamps
    created_at: Optional[datetime] = Field(
        default=None,
        description="Creation timestamp (UTC)",
    )
    
    # Optional info
    description: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Optional description of the component",
    )
    original_filename: Optional[str] = Field(
        default=None,
        max_length=255,
        description="Original source file name (e.g., lens.zmx)",
    )
    
    # Multi-recipient support
    recipients: list[RecipientInfo] = Field(
        default_factory=list,
        description="List of recipients (platforms) who can decrypt this file",
    )
    
    sidecar_url: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Optional URL to sidecar JSON for post-distribution updates",
    )
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "version": "2.0",
                "vendor_id": "thorlabs",
                "model_id": "AC254-050-A",
                "created_at": "2026-02-02T14:32:00Z",
                "original_filename": "ac254-050-a.zmx",
                "recipients": [
                    {
                        "platform_fingerprint": "a1b2c3d4...",
                        "platform_name": "Zemax OpticStudio",
                    }
                ],
                "sidecar_url": "https://vendor.com/api/sidecar/ac254-050-a.json",
            }
        }
    }
