"""Serialization utilities for Optical BlackBox."""

from optical_blackbox.serialization.binary import BinaryReader, BinaryWriter
from optical_blackbox.serialization.pem import (
    public_key_to_pem,
    public_key_from_pem,
    private_key_to_pem,
    private_key_from_pem,
)

__all__ = [
    # Binary I/O
    "BinaryReader",
    "BinaryWriter",
    # PEM
    "public_key_to_pem",
    "public_key_from_pem",
    "private_key_to_pem",
    "private_key_from_pem",
]
