"""Unit tests for core/validators.py - Validation functions."""

import pytest
from pathlib import Path

from optical_blackbox.core.validators import (
    validate_vendor_id,
    validate_component_name,
    validate_file_exists,
    validate_zemax_file,
    validate_obb_file,
    validate_positive,
    validate_non_negative,
    validate_wavelength,
)
from optical_blackbox.core.result import Ok, Err
from optical_blackbox.exceptions import ValidationError


class TestValidateVendorId:
    """Tests for vendor ID validation."""

    @pytest.mark.parametrize("valid_id", [
        "thorlabs",
        "my-vendor",
        "vendor123",
        "abc",  # Minimum 3 chars
        "a" * 50,  # Maximum 50 chars
        "vendor-with-hyphens",
        "123vendor",  # Can start with number
    ])
    def test_valid_vendor_ids(self, valid_id):
        """Valid vendor IDs should return Ok."""
        result = validate_vendor_id(valid_id)
        assert isinstance(result, Ok)
        assert result.unwrap() == valid_id

    @pytest.mark.parametrize("invalid_id,reason", [
        ("", "empty"),
        ("ab", "too short"),
        ("AB", "uppercase not allowed"),
        ("THORLABS", "uppercase not allowed"),
        ("my_vendor", "underscore not allowed"),
        ("my vendor", "space not allowed"),
        ("-vendor", "starts with hyphen"),
        ("a" * 51, "too long"),
        ("vendor!", "special character"),
        ("vendor@company", "special character"),
    ])
    def test_invalid_vendor_ids(self, invalid_id, reason):
        """Invalid vendor IDs should return Err."""
        result = validate_vendor_id(invalid_id)
        assert isinstance(result, Err), f"Should fail for: {reason}"
        assert isinstance(result.error, ValidationError)


class TestValidateComponentName:
    """Tests for component name validation."""

    @pytest.mark.parametrize("valid_name", [
        "AC254-050-A",
        "Simple Lens",
        "x",  # Single character is valid
        " Trimmed Name ",  # Should be stripped
    ])
    def test_valid_component_names(self, valid_name):
        """Valid component names should return Ok."""
        result = validate_component_name(valid_name)
        assert isinstance(result, Ok)

    def test_strips_whitespace(self):
        """Should strip leading/trailing whitespace."""
        result = validate_component_name("  Lens Name  ")
        assert isinstance(result, Ok)
        assert result.unwrap() == "Lens Name"

    @pytest.mark.parametrize("invalid_name,reason", [
        ("", "empty"),
        ("   ", "whitespace only"),
    ])
    def test_invalid_component_names(self, invalid_name, reason):
        """Invalid component names should return Err."""
        result = validate_component_name(invalid_name)
        assert isinstance(result, Err), f"Should fail for: {reason}"

    def test_too_long_name(self):
        """Name exceeding max length should return Err."""
        # Component name max is 200 characters based on constants
        long_name = "x" * 300
        result = validate_component_name(long_name)
        assert isinstance(result, Err)


class TestValidateFileExists:
    """Tests for file existence validation."""

    def test_existing_file_returns_ok(self, tmp_path):
        """Existing file should return Ok with Path."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")
        
        result = validate_file_exists(test_file)
        assert isinstance(result, Ok)
        assert result.unwrap() == test_file

    def test_nonexistent_file_returns_err(self, tmp_path):
        """Non-existent file should return Err."""
        result = validate_file_exists(tmp_path / "nonexistent.txt")
        assert isinstance(result, Err)
        assert isinstance(result.error, ValidationError)

    def test_directory_returns_err(self, tmp_path):
        """Directory path should return Err."""
        result = validate_file_exists(tmp_path)
        assert isinstance(result, Err)

    def test_accepts_string_path(self, tmp_path):
        """Should accept string path."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")
        
        result = validate_file_exists(str(test_file))
        assert isinstance(result, Ok)
        assert isinstance(result.unwrap(), Path)

    def test_validates_extension(self, tmp_path):
        """Should validate extension if specified."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")
        
        # Valid extension
        result = validate_file_exists(test_file, extensions=(".txt",))
        assert isinstance(result, Ok)
        
        # Invalid extension
        result = validate_file_exists(test_file, extensions=(".zmx",))
        assert isinstance(result, Err)

    def test_extension_case_insensitive(self, tmp_path):
        """Extension check should be case insensitive."""
        test_file = tmp_path / "test.TXT"
        test_file.write_text("content")
        
        result = validate_file_exists(test_file, extensions=(".txt",))
        assert isinstance(result, Ok)


class TestValidateZemaxFile:
    """Tests for Zemax file validation."""

    def test_valid_zmx_file(self, tmp_zmx_file):
        """Valid .zmx file should return Ok."""
        result = validate_zemax_file(tmp_zmx_file)
        assert isinstance(result, Ok)

    def test_valid_zar_file(self, tmp_path):
        """Valid .zar file should return Ok."""
        zar_file = tmp_path / "test.zar"
        zar_file.write_bytes(b"fake zip content")  # Just existence check
        
        result = validate_zemax_file(zar_file)
        assert isinstance(result, Ok)

    def test_wrong_extension_returns_err(self, tmp_path):
        """Non-Zemax extension should return Err."""
        other_file = tmp_path / "test.txt"
        other_file.write_text("content")
        
        result = validate_zemax_file(other_file)
        assert isinstance(result, Err)


class TestValidateObbFile:
    """Tests for OBB file validation."""

    def test_valid_obb_file(self, tmp_path):
        """Valid .obb file should return Ok."""
        obb_file = tmp_path / "test.obb"
        obb_file.write_bytes(b"content")
        
        result = validate_obb_file(obb_file)
        assert isinstance(result, Ok)

    def test_wrong_extension_returns_err(self, tmp_path):
        """Non-.obb extension should return Err."""
        other_file = tmp_path / "test.zmx"
        other_file.write_text("content")
        
        result = validate_obb_file(other_file)
        assert isinstance(result, Err)


class TestValidatePositive:
    """Tests for positive value validation."""

    @pytest.mark.parametrize("value", [0.001, 1, 100, 1e10])
    def test_positive_values(self, value):
        """Positive values should return Ok."""
        result = validate_positive(value, "test")
        assert isinstance(result, Ok)
        assert result.unwrap() == value

    @pytest.mark.parametrize("value", [0, -1, -0.001])
    def test_non_positive_values(self, value):
        """Zero and negative values should return Err."""
        result = validate_positive(value, "test")
        assert isinstance(result, Err)

    def test_error_message_includes_name(self):
        """Error message should include value name."""
        result = validate_positive(-1, "focal_length")
        assert isinstance(result, Err)
        assert "focal_length" in str(result.error)


class TestValidateNonNegative:
    """Tests for non-negative value validation."""

    @pytest.mark.parametrize("value", [0, 0.001, 1, 100])
    def test_non_negative_values(self, value):
        """Zero and positive values should return Ok."""
        result = validate_non_negative(value, "test")
        assert isinstance(result, Ok)
        assert result.unwrap() == value

    @pytest.mark.parametrize("value", [-1, -0.001])
    def test_negative_values(self, value):
        """Negative values should return Err."""
        result = validate_non_negative(value, "test")
        assert isinstance(result, Err)


class TestValidateWavelength:
    """Tests for wavelength validation."""

    @pytest.mark.parametrize("wavelength", [
        100.0,   # UV
        587.56,  # d-line
        1550.0,  # IR telecom
        10000.0, # Far IR
    ])
    def test_valid_wavelengths(self, wavelength):
        """Valid wavelengths should return Ok."""
        result = validate_wavelength(wavelength)
        assert isinstance(result, Ok)
        assert result.unwrap() == wavelength

    @pytest.mark.parametrize("wavelength", [
        0,       # Zero
        -100,    # Negative
        50.0,    # Too low (below UV)
    ])
    def test_invalid_wavelengths(self, wavelength):
        """Invalid wavelengths should return Err."""
        result = validate_wavelength(wavelength)
        assert isinstance(result, Err)
