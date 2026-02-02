"""Sidecar fetcher for retrieving and merging sidecar updates.

Enables platforms to fetch sidecar JSON files from vendor URLs
and merge updated recipient lists with .obb file metadata.
"""

from pathlib import Path
from urllib.parse import urlparse

from ..core.result import Err, Ok, Result
from ..models.metadata import OBBMetadataV2
from ..models.sidecar import Sidecar
from ..serialization.json_codec import decode_json


def fetch_sidecar(url: str) -> Result[Sidecar, Exception]:
    """Fetch sidecar JSON from a URL.
    
    Args:
        url: URL to the sidecar JSON file
        
    Returns:
        Ok with Sidecar object, or Err with exception
        
    Note:
        For MVP, only supports file:// URLs (local files).
        HTTP/HTTPS support can be added later with requests library.
    """
    try:
        parsed = urlparse(url)
        
        if parsed.scheme == "file" or not parsed.scheme:
            # Local file
            path = Path(parsed.path)
            json_bytes = path.read_bytes()
            data = decode_json(json_bytes)
            sidecar = Sidecar(**data)
            return Ok(sidecar)
        
        elif parsed.scheme in ("http", "https"):
            # HTTP(S) - requires requests library
            return Err(NotImplementedError("HTTP(S) fetching not yet implemented. Use file:// URLs for MVP."))
        
        else:
            return Err(ValueError(f"Unsupported URL scheme: {parsed.scheme}"))
    
    except Exception as e:
        return Err(e)


def merge_sidecar_with_metadata(
    metadata: OBBMetadataV2,
    sidecar: Sidecar,
) -> Result[OBBMetadataV2, ValueError]:
    """Merge sidecar recipient list with .obb file metadata.
    
    Replaces the metadata's recipient list with the sidecar's list,
    filtering out revoked recipients.
    
    Args:
        metadata: Original metadata from .obb file
        sidecar: Sidecar with potentially updated recipients
        
    Returns:
        Ok with updated metadata, or Err if IDs don't match
    """
    # Verify this sidecar belongs to this file
    if sidecar.vendor_id != metadata.vendor_id or sidecar.model_id != metadata.model_id:
        return Err(ValueError(
            f"Sidecar mismatch: expected {metadata.vendor_id}/{metadata.model_id}, "
            f"got {sidecar.vendor_id}/{sidecar.model_id}"
        ))
    
    # Filter active (non-revoked) recipients
    from ..models.metadata import RecipientInfo
    import base64
    
    active_recipients = []
    for sidecar_recipient in sidecar.recipients:
        if not sidecar_recipient.revoked:
            # Convert base64 wrapped_dek back to bytes
            wrapped_dek_bytes = base64.b64decode(sidecar_recipient.wrapped_dek)
            
            active_recipients.append(
                RecipientInfo(
                    platform_fingerprint=sidecar_recipient.platform_fingerprint,
                    wrapped_dek=wrapped_dek_bytes,
                    platform_name=sidecar_recipient.platform_name,
                )
            )
    
    # Update metadata
    metadata.recipients = active_recipients
    
    return Ok(metadata)
