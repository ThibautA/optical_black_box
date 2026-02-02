"""Core utilities for Optical BlackBox."""

from optical_blackbox.core.result import Result, Ok, Err, try_result
from optical_blackbox.core.constants import (
    OBB_MAGIC,
    OBB_VERSION,
    OBB_EXTENSION,
    AES_KEY_SIZE,
    AES_NONCE_SIZE,
    DEFAULT_WAVELENGTH_NM,
)
from optical_blackbox.core.validators import (
    validate_vendor_id,
    validate_component_name,
    validate_file_exists,
    validate_zemax_file,
    validate_obb_file,
    validate_positive,
    validate_wavelength,
)

__all__ = [
    # Result pattern
    "Result",
    "Ok",
    "Err",
    "try_result",
    # Constants
    "OBB_MAGIC",
    "OBB_VERSION",
    "OBB_EXTENSION",
    "AES_KEY_SIZE",
    "AES_NONCE_SIZE",
    "DEFAULT_WAVELENGTH_NM",
    # Validators
    "validate_vendor_id",
    "validate_component_name",
    "validate_file_exists",
    "validate_zemax_file",
    "validate_obb_file",
    "validate_positive",
    "validate_wavelength",
]
