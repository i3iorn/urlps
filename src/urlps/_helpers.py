from __future__ import annotations

from typing import Any

from ._host import is_ascii_digits, port_number
from .exceptions import InvalidURLError


def _check_type(value: Any, expected: type, name: str) -> None:
    """Validate that value is of expected type."""
    if not isinstance(value, expected):
        raise TypeError(f"{name} must be {expected.__name__}, got {type(value).__name__}")


def _normalize_port(value: Any | None) -> int | None:
    """Normalize port value to int or None."""
    if value is None or value == "":
        return None
    if isinstance(value, str) and not is_ascii_digits(value):
        raise InvalidURLError("Port must be numeric.")
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise InvalidURLError("Port must be an integer or numeric string.")
    try:
        return port_number(value)
    except ValueError:
        raise InvalidURLError("Port must be between 1 and 65535.") from None
