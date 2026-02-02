"""Unit tests for serialization/binary.py - BinaryWriter and BinaryReader."""

import io
import pytest

from optical_blackbox.serialization.binary import BinaryWriter, BinaryReader


class TestBinaryWriterBasics:
    """Tests for BinaryWriter basic operations."""

    def test_write_bytes(self):
        """Should write raw bytes."""
        buf = io.BytesIO()
        writer = BinaryWriter(buf)
        
        n = writer.write_bytes(b"hello")
        
        assert n == 5
        assert buf.getvalue() == b"hello"

    def test_write_magic(self):
        """Should write magic bytes."""
        buf = io.BytesIO()
        writer = BinaryWriter(buf)
        
        n = writer.write_magic(b"OBB\x01")
        
        assert n == 4
        assert buf.getvalue() == b"OBB\x01"

    def test_write_u32_le(self):
        """Should write u32 little-endian."""
        buf = io.BytesIO()
        writer = BinaryWriter(buf)
        
        n = writer.write_u32_le(0x12345678)
        
        assert n == 4
        # Little-endian: least significant byte first
        assert buf.getvalue() == b"\x78\x56\x34\x12"

    def test_write_u16_le(self):
        """Should write u16 little-endian."""
        buf = io.BytesIO()
        writer = BinaryWriter(buf)
        
        n = writer.write_u16_le(0x1234)
        
        assert n == 2
        assert buf.getvalue() == b"\x34\x12"

    def test_write_length_prefixed(self):
        """Should write length-prefixed data."""
        buf = io.BytesIO()
        writer = BinaryWriter(buf)
        
        n = writer.write_length_prefixed(b"abc")
        
        assert n == 7  # 4 (length) + 3 (data)
        # First 4 bytes are length (3) in little-endian
        assert buf.getvalue() == b"\x03\x00\x00\x00abc"


class TestBinaryWriterEdgeCases:
    """Tests for BinaryWriter edge cases."""

    def test_write_empty_bytes(self):
        """Should write empty bytes."""
        buf = io.BytesIO()
        writer = BinaryWriter(buf)
        
        n = writer.write_bytes(b"")
        
        assert n == 0
        assert buf.getvalue() == b""

    def test_write_length_prefixed_empty(self):
        """Should write length-prefixed empty data."""
        buf = io.BytesIO()
        writer = BinaryWriter(buf)
        
        n = writer.write_length_prefixed(b"")
        
        assert n == 4  # Just the length prefix
        assert buf.getvalue() == b"\x00\x00\x00\x00"

    def test_write_u32_zero(self):
        """Should write u32 zero."""
        buf = io.BytesIO()
        writer = BinaryWriter(buf)
        
        writer.write_u32_le(0)
        
        assert buf.getvalue() == b"\x00\x00\x00\x00"

    def test_write_u32_max(self):
        """Should write u32 max value."""
        buf = io.BytesIO()
        writer = BinaryWriter(buf)
        
        writer.write_u32_le(0xFFFFFFFF)
        
        assert buf.getvalue() == b"\xFF\xFF\xFF\xFF"

    def test_write_u16_max(self):
        """Should write u16 max value."""
        buf = io.BytesIO()
        writer = BinaryWriter(buf)
        
        writer.write_u16_le(0xFFFF)
        
        assert buf.getvalue() == b"\xFF\xFF"


class TestBinaryReaderBasics:
    """Tests for BinaryReader basic operations."""

    def test_read_bytes(self):
        """Should read exact number of bytes."""
        buf = io.BytesIO(b"hello world")
        reader = BinaryReader(buf)
        
        data = reader.read_bytes(5)
        
        assert data == b"hello"

    def test_read_u32_le(self):
        """Should read u32 little-endian."""
        buf = io.BytesIO(b"\x78\x56\x34\x12")
        reader = BinaryReader(buf)
        
        value = reader.read_u32_le()
        
        assert value == 0x12345678

    def test_read_u16_le(self):
        """Should read u16 little-endian."""
        buf = io.BytesIO(b"\x34\x12")
        reader = BinaryReader(buf)
        
        value = reader.read_u16_le()
        
        assert value == 0x1234

    def test_read_length_prefixed(self):
        """Should read length-prefixed data."""
        buf = io.BytesIO(b"\x03\x00\x00\x00abc")
        reader = BinaryReader(buf)
        
        data = reader.read_length_prefixed()
        
        assert data == b"abc"


class TestBinaryReaderMagic:
    """Tests for magic byte verification."""

    def test_verify_magic_success(self):
        """Should return True for matching magic."""
        buf = io.BytesIO(b"OBB\x01rest of file")
        reader = BinaryReader(buf)
        
        result = reader.read_and_verify_magic(b"OBB\x01")
        
        assert result is True

    def test_verify_magic_failure(self):
        """Should return False for non-matching magic."""
        buf = io.BytesIO(b"XXX\x01rest of file")
        reader = BinaryReader(buf)
        
        result = reader.read_and_verify_magic(b"OBB\x01")
        
        assert result is False

    def test_verify_magic_advances_position(self):
        """Should advance file position after reading magic."""
        buf = io.BytesIO(b"OBB\x01\x10\x00\x00\x00")
        reader = BinaryReader(buf)
        
        reader.read_and_verify_magic(b"OBB\x01")
        value = reader.read_u32_le()
        
        assert value == 16


class TestBinaryRoundtrip:
    """Tests for write/read roundtrip."""

    def test_u32_roundtrip(self):
        """Should roundtrip u32 values."""
        buf = io.BytesIO()
        writer = BinaryWriter(buf)
        
        writer.write_u32_le(12345)
        writer.write_u32_le(0)
        writer.write_u32_le(0xFFFFFFFF)
        
        buf.seek(0)
        reader = BinaryReader(buf)
        
        assert reader.read_u32_le() == 12345
        assert reader.read_u32_le() == 0
        assert reader.read_u32_le() == 0xFFFFFFFF

    def test_u16_roundtrip(self):
        """Should roundtrip u16 values."""
        buf = io.BytesIO()
        writer = BinaryWriter(buf)
        
        writer.write_u16_le(1234)
        writer.write_u16_le(0)
        writer.write_u16_le(0xFFFF)
        
        buf.seek(0)
        reader = BinaryReader(buf)
        
        assert reader.read_u16_le() == 1234
        assert reader.read_u16_le() == 0
        assert reader.read_u16_le() == 0xFFFF

    def test_length_prefixed_roundtrip(self):
        """Should roundtrip length-prefixed data."""
        buf = io.BytesIO()
        writer = BinaryWriter(buf)
        
        writer.write_length_prefixed(b"hello")
        writer.write_length_prefixed(b"")
        writer.write_length_prefixed(b"world")
        
        buf.seek(0)
        reader = BinaryReader(buf)
        
        assert reader.read_length_prefixed() == b"hello"
        assert reader.read_length_prefixed() == b""
        assert reader.read_length_prefixed() == b"world"

    def test_mixed_operations_roundtrip(self):
        """Should roundtrip mixed operations."""
        buf = io.BytesIO()
        writer = BinaryWriter(buf)
        
        writer.write_magic(b"TEST")
        writer.write_u16_le(1)  # version
        writer.write_u32_le(100)  # size
        writer.write_length_prefixed(b"payload data")
        
        buf.seek(0)
        reader = BinaryReader(buf)
        
        assert reader.read_and_verify_magic(b"TEST")
        assert reader.read_u16_le() == 1
        assert reader.read_u32_le() == 100
        assert reader.read_length_prefixed() == b"payload data"
