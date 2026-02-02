"""Core type aliases for Optical BlackBox.

Centralized type definitions for consistent typing across the codebase.
"""

from pathlib import Path
from typing import Union, TypeAlias

# Path types
PathLike: TypeAlias = Union[str, Path]

# PEM-encoded key strings
PEMString: TypeAlias = str

# Binary data
Bytes: TypeAlias = bytes

# Identifiers
VendorId: TypeAlias = str
ComponentName: TypeAlias = str
