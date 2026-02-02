"""JSON encoding and decoding utilities.

Provides consistent JSON serialization for .obb v2.0 metadata and sidecar files.
"""

import json
from datetime import datetime
from typing import Any


def encode_json(data: dict[str, Any]) -> bytes:
    """Encode dictionary to JSON bytes with consistent formatting.
    
    Args:
        data: Dictionary to encode
        
    Returns:
        UTF-8 encoded JSON bytes
        
    Note:
        Uses custom encoder to handle datetime objects.
    """
    json_str = json.dumps(data, cls=_OBBJSONEncoder, indent=2, sort_keys=False)
    return json_str.encode("utf-8")


def decode_json(json_bytes: bytes) -> dict[str, Any]:
    """Decode JSON bytes to dictionary.
    
    Args:
        json_bytes: UTF-8 encoded JSON bytes
        
    Returns:
        Decoded dictionary
        
    Raises:
        json.JSONDecodeError: If JSON is invalid
    """
    json_str = json_bytes.decode("utf-8")
    return json.loads(json_str, object_hook=_obb_json_decoder_hook)


class _OBBJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder for OBB data structures."""
    
    def default(self, obj: Any) -> Any:
        """Handle special types during encoding."""
        if isinstance(obj, datetime):
            # ISO 8601 format with 'Z' suffix for UTC
            return obj.isoformat() + "Z" if obj.tzinfo is None else obj.isoformat()
        
        if isinstance(obj, bytes):
            # Encode bytes as base64 (though we typically handle this explicitly)
            import base64
            return base64.b64encode(obj).decode("ascii")
        
        # Let the base class raise TypeError for unsupported types
        return super().default(obj)


def _obb_json_decoder_hook(obj: dict[str, Any]) -> dict[str, Any]:
    """Custom decoder hook for OBB JSON data.
    
    Converts ISO 8601 datetime strings back to datetime objects.
    """
    for key, value in obj.items():
        if isinstance(value, str):
            # Try to parse as datetime
            if value.endswith("Z"):
                # UTC timestamp
                try:
                    obj[key] = datetime.fromisoformat(value.rstrip("Z"))
                except ValueError:
                    pass  # Not a datetime, leave as string
            elif "T" in value and ("+" in value or value.count("-") >= 2):
                # Possible datetime with timezone
                try:
                    obj[key] = datetime.fromisoformat(value)
                except ValueError:
                    pass
    
    return obj
