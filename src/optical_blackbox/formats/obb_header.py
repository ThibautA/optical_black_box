"""OBB file header handling.

Provides serialization and deserialization of OBB file headers.
"""

import json
from typing import Any
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import ec

from optical_blackbox.models.metadata import OBBMetadata
from optical_blackbox.serialization.pem import public_key_to_pem, public_key_from_pem


def build_header(
    metadata: OBBMetadata,
    ephemeral_public_key: ec.EllipticCurvePublicKey,
) -> dict[str, Any]:
    """Build header dictionary from metadata and ephemeral key.

    Args:
        metadata: OBB metadata
        ephemeral_public_key: Ephemeral public key for ECDH

    Returns:
        Header dictionary ready for JSON serialization
    """
    # Convert metadata to dict
    header = metadata.model_dump(mode="json")

    # Add ephemeral public key
    header["ephemeral_public_key"] = public_key_to_pem(ephemeral_public_key)

    # Ensure created_at is set
    if header.get("created_at") is None:
        header["created_at"] = datetime.utcnow().isoformat()

    return header


def serialize_header(header: dict[str, Any]) -> bytes:
    """Serialize header to JSON bytes.

    Args:
        header: Header dictionary

    Returns:
        UTF-8 encoded JSON bytes
    """
    return json.dumps(header, indent=2, default=str).encode("utf-8")


def deserialize_header(header_bytes: bytes) -> dict[str, Any]:
    """Deserialize header from JSON bytes.

    Args:
        header_bytes: UTF-8 encoded JSON bytes

    Returns:
        Header dictionary
    """
    return json.loads(header_bytes.decode("utf-8"))


def extract_metadata(header: dict[str, Any]) -> OBBMetadata:
    """Extract OBBMetadata from header dictionary.

    Args:
        header: Header dictionary

    Returns:
        OBBMetadata object
    """
    # Remove ephemeral key before creating metadata
    header_copy = header.copy()
    header_copy.pop("ephemeral_public_key", None)

    return OBBMetadata(**header_copy)


def extract_ephemeral_key(header: dict[str, Any]) -> ec.EllipticCurvePublicKey:
    """Extract ephemeral public key from header.

    Args:
        header: Header dictionary

    Returns:
        Ephemeral public key
    """
    pem = header.get("ephemeral_public_key", "")
    return public_key_from_pem(pem)
