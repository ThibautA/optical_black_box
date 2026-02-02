"""Format version detection for .obb files.

This module provides utilities to detect the format version of .obb files
by reading the version byte that follows the magic bytes.
"""

from pathlib import Path
from typing import Literal

from ..exceptions import InvalidOBBFileError, OBBError


OBBVersion = Literal[1, 2]


def detect_obb_version(file_path: Path) -> OBBVersion:
    """Detect the format version of an .obb file.
    
    Args:
        file_path: Path to the .obb file
        
    Returns:
        1 for v1.0 format, 2 for v2.0 format
        
    Raises:
        InvalidOBBFileError: If magic bytes are invalid or version is unsupported
        OBBError: If file cannot be read
    """
    try:
        with open(file_path, "rb") as f:
            # Read magic bytes (4 bytes: 'O', 'B', 'B', 0x00)
            magic = f.read(4)
            if magic != b"OBB\x00":
                raise InvalidOBBFileError(f"Invalid magic bytes: {magic.hex()}")
            
            # Read version byte
            version_byte = f.read(1)
            if not version_byte:
                raise InvalidOBBFileError("Missing version byte")
            
            version = version_byte[0]
            if version == 1:
                return 1
            elif version == 2:
                return 2
            else:
                raise InvalidOBBFileError(f"Unsupported OBB version: {version}")
    
    except OSError as e:
        raise OBBError(f"Failed to read file: {e}") from e
