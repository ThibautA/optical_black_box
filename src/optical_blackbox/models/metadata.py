"""OBB Metadata model.

Defines the public (unencrypted) metadata stored in .obb files.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


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

