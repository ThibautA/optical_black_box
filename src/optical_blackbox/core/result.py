"""Result type for explicit error handling.

Provides a Rust-style Result[T, E] pattern for operations that can fail,
making error handling explicit and composable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypeVar, Generic, Callable, Union

T = TypeVar("T")
U = TypeVar("U")
E = TypeVar("E", bound=Exception)


@dataclass(frozen=True, slots=True)
class Ok(Generic[T]):
    """Represents a successful result containing a value."""

    value: T

    def is_ok(self) -> bool:
        """Check if this is a success."""
        return True

    def is_err(self) -> bool:
        """Check if this is an error."""
        return False

    def unwrap(self) -> T:
        """Get the value, or raise if error.

        Returns:
            The contained value

        Raises:
            Never raises for Ok
        """
        return self.value

    def unwrap_or(self, default: T) -> T:
        """Get the value or a default.

        Args:
            default: Default value (unused for Ok)

        Returns:
            The contained value
        """
        return self.value

    def map(self, func: Callable[[T], U]) -> Ok[U]:
        """Transform the value with a function.

        Args:
            func: Function to apply to the value

        Returns:
            Ok with transformed value
        """
        return Ok(func(self.value))

    def and_then(self, func: Callable[[T], Result[U, E]]) -> Result[U, E]:
        """Chain with another Result-returning function.

        Args:
            func: Function that returns a Result

        Returns:
            Result from the function
        """
        return func(self.value)


@dataclass(frozen=True, slots=True)
class Err(Generic[E]):
    """Represents an error result containing an exception."""

    error: E

    def is_ok(self) -> bool:
        """Check if this is a success."""
        return False

    def is_err(self) -> bool:
        """Check if this is an error."""
        return True

    def unwrap(self) -> None:
        """Get the value, or raise if error.

        Raises:
            The contained error
        """
        raise self.error

    def unwrap_or(self, default: T) -> T:
        """Get the value or a default.

        Args:
            default: Default value to return

        Returns:
            The default value
        """
        return default

    def map(self, func: Callable[[T], U]) -> Err[E]:
        """Transform the value with a function (no-op for Err).

        Args:
            func: Function to apply (not called)

        Returns:
            Self unchanged
        """
        return self

    def and_then(self, func: Callable[[T], Result[U, E]]) -> Err[E]:
        """Chain with another Result-returning function (no-op for Err).

        Args:
            func: Function that returns a Result (not called)

        Returns:
            Self unchanged
        """
        return self


# Type alias for Result
Result = Union[Ok[T], Err[E]]


def try_result(func: Callable[[], T], exception_type: type[E] = Exception) -> Result[T, E]:
    """Execute a function and wrap the result.

    Args:
        func: Function to execute
        exception_type: Exception type to catch (default: Exception)

    Returns:
        Ok(result) if successful, Err(exception) if failed
    """
    try:
        return Ok(func())
    except exception_type as e:
        return Err(e)
