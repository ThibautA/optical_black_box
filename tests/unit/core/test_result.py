"""Unit tests for core/result.py - Result type pattern."""

import pytest

from optical_blackbox.core.result import Ok, Err, Result, try_result


class TestOk:
    """Tests for Ok success type."""

    def test_is_ok_returns_true(self):
        """is_ok should return True for Ok."""
        result = Ok(42)
        assert result.is_ok() is True

    def test_is_err_returns_false(self):
        """is_err should return False for Ok."""
        result = Ok(42)
        assert result.is_err() is False

    def test_unwrap_returns_value(self):
        """unwrap should return contained value."""
        result = Ok("hello")
        assert result.unwrap() == "hello"

    def test_unwrap_or_returns_value(self):
        """unwrap_or should return contained value, not default."""
        result = Ok(42)
        assert result.unwrap_or(0) == 42

    def test_map_transforms_value(self):
        """map should transform the contained value."""
        result = Ok(5)
        mapped = result.map(lambda x: x * 2)
        
        assert isinstance(mapped, Ok)
        assert mapped.unwrap() == 10

    def test_map_chains(self):
        """map should be chainable."""
        result = Ok(2)
        chained = result.map(lambda x: x + 1).map(lambda x: x * 2)
        
        assert chained.unwrap() == 6

    def test_and_then_chains_results(self):
        """and_then should chain with Result-returning function."""
        def double_if_positive(x: int) -> Result[int, ValueError]:
            if x > 0:
                return Ok(x * 2)
            return Err(ValueError("negative"))
        
        result = Ok(5)
        chained = result.and_then(double_if_positive)
        
        assert isinstance(chained, Ok)
        assert chained.unwrap() == 10

    def test_and_then_propagates_err(self):
        """and_then should propagate Err from function."""
        def always_err(x: int) -> Result[int, ValueError]:
            return Err(ValueError("always fails"))
        
        result = Ok(5)
        chained = result.and_then(always_err)
        
        assert isinstance(chained, Err)

    def test_ok_with_none_value(self):
        """Ok can contain None."""
        result = Ok(None)
        assert result.is_ok() is True
        assert result.unwrap() is None

    def test_ok_with_complex_value(self):
        """Ok can contain complex values."""
        data = {"key": [1, 2, 3], "nested": {"value": True}}
        result = Ok(data)
        assert result.unwrap() == data

    def test_ok_equality(self):
        """Ok values with same content should be equal."""
        ok1 = Ok(42)
        ok2 = Ok(42)
        assert ok1 == ok2

    def test_ok_inequality(self):
        """Ok values with different content should not be equal."""
        ok1 = Ok(42)
        ok2 = Ok(43)
        assert ok1 != ok2


class TestErr:
    """Tests for Err error type."""

    def test_is_ok_returns_false(self):
        """is_ok should return False for Err."""
        result = Err(ValueError("error"))
        assert result.is_ok() is False

    def test_is_err_returns_true(self):
        """is_err should return True for Err."""
        result = Err(ValueError("error"))
        assert result.is_err() is True

    def test_unwrap_raises_contained_error(self):
        """unwrap should raise the contained exception."""
        error = ValueError("test error")
        result = Err(error)
        
        with pytest.raises(ValueError, match="test error"):
            result.unwrap()

    def test_unwrap_or_returns_default(self):
        """unwrap_or should return default for Err."""
        result = Err(ValueError("error"))
        assert result.unwrap_or(42) == 42

    def test_map_returns_self(self):
        """map should return self unchanged for Err."""
        error = ValueError("error")
        result = Err(error)
        mapped = result.map(lambda x: x * 2)
        
        assert isinstance(mapped, Err)
        assert mapped.error == error

    def test_and_then_returns_self(self):
        """and_then should return self unchanged for Err."""
        error = ValueError("error")
        result = Err(error)
        chained = result.and_then(lambda x: Ok(x * 2))
        
        assert isinstance(chained, Err)
        assert chained.error == error

    def test_err_with_different_exception_types(self):
        """Err can contain different exception types."""
        type_err = Err(TypeError("type"))
        key_err = Err(KeyError("key"))
        
        assert type_err.is_err()
        assert key_err.is_err()

    def test_err_equality(self):
        """Err values with same error should be equal."""
        # Note: comparing by identity for exceptions
        error = ValueError("test")
        err1 = Err(error)
        err2 = Err(error)
        assert err1 == err2


class TestTryResult:
    """Tests for try_result function."""

    def test_try_result_success(self):
        """try_result should return Ok for successful function."""
        def succeed():
            return 42
        
        result = try_result(succeed)
        assert isinstance(result, Ok)
        assert result.unwrap() == 42

    def test_try_result_exception(self):
        """try_result should return Err for raising function."""
        def fail():
            raise ValueError("failed")
        
        result = try_result(fail)
        assert isinstance(result, Err)
        assert isinstance(result.error, ValueError)

    def test_try_result_with_lambda(self):
        """try_result should work with lambda."""
        result = try_result(lambda: 2 + 3)
        assert isinstance(result, Ok)
        assert result.unwrap() == 5

    def test_try_result_catches_specific_exception(self):
        """try_result should catch specific exception type."""
        def divide():
            return 1 / 0
        
        result = try_result(divide, ZeroDivisionError)
        assert isinstance(result, Err)
        assert isinstance(result.error, ZeroDivisionError)

    def test_try_result_default_catches_all(self):
        """try_result with default should catch any Exception."""
        def fail_type():
            raise TypeError("type error")
        
        result = try_result(fail_type)
        assert isinstance(result, Err)
        assert isinstance(result.error, TypeError)
