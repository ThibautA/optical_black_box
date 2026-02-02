"""Validation utilities for Optical BlackBox.

Provides consistent validation functions used across the codebase.
All validators return Result[T, ValidationError] for explicit error handling.
"""

import re
from pathlib import Path
from typing import TypeVar

from optical_blackbox.core.constants import (
    VENDOR_ID_PATTERN,
    COMPONENT_NAME_MAX_LENGTH,
    ZEMAX_EXTENSIONS,
    OBB_EXTENSION,
)
from optical_blackbox.core.result import Result, Ok, Err
from optical_blackbox.exceptions import ValidationError

T = TypeVar("T")


def validate_vendor_id(vendor_id: str) -> Result[str, ValidationError]:
    """Validate vendor ID format.

    Vendor ID must be:
    - 3-50 characters
    - Lowercase alphanumeric with hyphens
    - Start with alphanumeric character

    Args:
        vendor_id: The vendor identifier to validate

    Returns:
        Ok(vendor_id) if valid, Err(ValidationError) if invalid
    """
    if not vendor_id:
        return Err(ValidationError("Vendor ID cannot be empty"))

    if not re.match(VENDOR_ID_PATTERN, vendor_id):
        return Err(
            ValidationError(
                f"Invalid vendor ID: '{vendor_id}'",
                "Must be 3-50 lowercase alphanumeric characters with hyphens, "
                "starting with alphanumeric",
            )
        )

    return Ok(vendor_id)


def validate_component_name(name: str) -> Result[str, ValidationError]:
    """Validate component name.

    Args:
        name: The component name to validate

    Returns:
        Ok(name) if valid, Err(ValidationError) if invalid
    """
    if not name:
        return Err(ValidationError("Component name cannot be empty"))

    if len(name) > COMPONENT_NAME_MAX_LENGTH:
        return Err(
            ValidationError(
                f"Component name too long: {len(name)} characters",
                f"Maximum allowed: {COMPONENT_NAME_MAX_LENGTH}",
            )
        )

    # Strip whitespace and validate
    name = name.strip()
    if not name:
        return Err(ValidationError("Component name cannot be only whitespace"))

    return Ok(name)


def validate_file_exists(
    path: Path | str,
    extensions: tuple[str, ...] | None = None,
) -> Result[Path, ValidationError]:
    """Validate that a file exists and has an allowed extension.

    Args:
        path: Path to the file
        extensions: Tuple of allowed extensions (e.g., ('.zmx', '.zar'))
                   If None, any extension is allowed

    Returns:
        Ok(Path) if valid, Err(ValidationError) if invalid
    """
    path = Path(path) if isinstance(path, str) else path

    if not path.exists():
        return Err(ValidationError(f"File not found: {path}"))

    if not path.is_file():
        return Err(ValidationError(f"Not a file: {path}"))

    if extensions is not None:
        ext = path.suffix.lower()
        if ext not in extensions:
            return Err(
                ValidationError(
                    f"Invalid file extension: {ext}",
                    f"Expected one of: {', '.join(extensions)}",
                )
            )

    return Ok(path)


def validate_zemax_file(path: Path | str) -> Result[Path, ValidationError]:
    """Validate a Zemax input file.

    Args:
        path: Path to the Zemax file

    Returns:
        Ok(Path) if valid, Err(ValidationError) if invalid
    """
    return validate_file_exists(path, ZEMAX_EXTENSIONS)


def validate_obb_file(path: Path | str) -> Result[Path, ValidationError]:
    """Validate an OBB file.

    Args:
        path: Path to the OBB file

    Returns:
        Ok(Path) if valid, Err(ValidationError) if invalid
    """
    return validate_file_exists(path, (OBB_EXTENSION,))


def validate_positive(value: float, name: str) -> Result[float, ValidationError]:
    """Validate that a value is positive.

    Args:
        value: The numeric value to validate
        name: Name of the value for error messages

    Returns:
        Ok(value) if positive, Err(ValidationError) if not
    """
    if value <= 0:
        return Err(ValidationError(f"{name} must be positive, got {value}"))
    return Ok(value)


def validate_non_negative(value: float, name: str) -> Result[float, ValidationError]:
    """Validate that a value is non-negative.

    Args:
        value: The numeric value to validate
        name: Name of the value for error messages

    Returns:
        Ok(value) if non-negative, Err(ValidationError) if negative
    """
    if value < 0:
        return Err(ValidationError(f"{name} must be non-negative, got {value}"))
    return Ok(value)


def validate_wavelength(wavelength_nm: float) -> Result[float, ValidationError]:
    """Validate a wavelength value.

    Args:
        wavelength_nm: Wavelength in nanometers

    Returns:
        Ok(wavelength_nm) if valid, Err(ValidationError) if invalid
    """
    if wavelength_nm <= 0:
        return Err(ValidationError(f"Wavelength must be positive, got {wavelength_nm} nm"))

    # Reasonable optical range: 100nm (UV) to 20000nm (IR)
    if wavelength_nm < 100 or wavelength_nm > 20000:
        return Err(
            ValidationError(
                f"Wavelength {wavelength_nm} nm is outside typical optical range",
                "Expected 100-20000 nm",
            )
        )

    return Ok(wavelength_nm)
