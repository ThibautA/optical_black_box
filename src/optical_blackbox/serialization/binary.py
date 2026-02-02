"""Binary I/O utilities for file format handling.

Provides consistent binary read/write operations to avoid struct.pack/unpack
duplication across the codebase.
"""

import struct
from typing import BinaryIO


class BinaryWriter:
    """Wrapper for consistent binary writing operations.

    Provides a clean interface for writing binary data with
    proper endianness handling.

    Example:
        >>> with open("file.bin", "wb") as f:
        ...     writer = BinaryWriter(f)
        ...     writer.write_magic(b"OBB\\x01")
        ...     writer.write_u32_le(1234)
        ...     writer.write_length_prefixed(b"hello")
    """

    def __init__(self, file: BinaryIO):
        """Initialize with a binary file handle.

        Args:
            file: Binary file opened for writing
        """
        self._file = file

    def write_bytes(self, data: bytes) -> int:
        """Write raw bytes.

        Args:
            data: Bytes to write

        Returns:
            Number of bytes written
        """
        return self._file.write(data)

    def write_magic(self, magic: bytes) -> int:
        """Write magic bytes (file signature).

        Args:
            magic: Magic bytes to write

        Returns:
            Number of bytes written
        """
        return self.write_bytes(magic)

    def write_u32_le(self, value: int) -> int:
        """Write unsigned 32-bit integer (little-endian).

        Args:
            value: Integer value to write (0 to 2^32-1)

        Returns:
            Number of bytes written (4)
        """
        return self._file.write(struct.pack("<I", value))

    def write_u16_le(self, value: int) -> int:
        """Write unsigned 16-bit integer (little-endian).

        Args:
            value: Integer value to write (0 to 65535)

        Returns:
            Number of bytes written (2)
        """
        return self._file.write(struct.pack("<H", value))

    def write_length_prefixed(self, data: bytes) -> int:
        """Write data with a 32-bit length prefix.

        Format: [u32 length][data bytes]

        Args:
            data: Bytes to write

        Returns:
            Total bytes written (4 + len(data))
        """
        self.write_u32_le(len(data))
        return 4 + self.write_bytes(data)


class BinaryReader:
    """Wrapper for consistent binary reading operations.

    Provides a clean interface for reading binary data with
    proper endianness handling and validation.

    Example:
        >>> with open("file.bin", "rb") as f:
        ...     reader = BinaryReader(f)
        ...     if reader.read_and_verify_magic(b"OBB\\x01"):
        ...         length = reader.read_u32_le()
        ...         data = reader.read_bytes(length)
    """

    def __init__(self, file: BinaryIO):
        """Initialize with a binary file handle.

        Args:
            file: Binary file opened for reading
        """
        self._file = file

    def read_bytes(self, n: int) -> bytes:
        """Read exactly n bytes.

        Args:
            n: Number of bytes to read

        Returns:
            Bytes read

        Raises:
            EOFError: If fewer than n bytes available
        """
        data = self._file.read(n)
        if len(data) < n:
            raise EOFError(f"Expected {n} bytes, got {len(data)}")
        return data

    def read_magic(self, expected_length: int) -> bytes:
        """Read magic bytes.

        Args:
            expected_length: Number of bytes to read

        Returns:
            Magic bytes read
        """
        return self.read_bytes(expected_length)

    def read_and_verify_magic(self, expected: bytes) -> bool:
        """Read and verify magic bytes.

        Args:
            expected: Expected magic bytes

        Returns:
            True if magic matches, False otherwise
        """
        actual = self._file.read(len(expected))
        return actual == expected

    def read_u32_le(self) -> int:
        """Read unsigned 32-bit integer (little-endian).

        Returns:
            Integer value
        """
        data = self.read_bytes(4)
        return struct.unpack("<I", data)[0]

    def read_u16_le(self) -> int:
        """Read unsigned 16-bit integer (little-endian).

        Returns:
            Integer value
        """
        data = self.read_bytes(2)
        return struct.unpack("<H", data)[0]

    def read_length_prefixed(self) -> bytes:
        """Read length-prefixed data.

        Reads a 32-bit length, then that many bytes.

        Returns:
            Data bytes (without length prefix)
        """
        length = self.read_u32_le()
        return self.read_bytes(length)

    def read_rest(self) -> bytes:
        """Read all remaining bytes in the file.

        Returns:
            All remaining bytes
        """
        return self._file.read()

    def tell(self) -> int:
        """Get current file position.

        Returns:
            Current position in bytes from start
        """
        return self._file.tell()

    def seek(self, position: int) -> int:
        """Seek to a position in the file.

        Args:
            position: Byte position from start

        Returns:
            New position
        """
        return self._file.seek(position)
