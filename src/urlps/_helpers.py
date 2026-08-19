from __future__ import annotations

from typing import Any

from src.urlps import InvalidURLError


def _check_type(value: Any, expected: type, name: str) -> None:
    """Validate that value is of expected type."""
    if not isinstance(value, expected):
        raise TypeError(f"{name} must be {expected.__name__}, got {type(value).__name__}")


def _normalize_port(value: Any | None) -> int | None:
    """Normalize port value to int or None."""
    if value is None or value == "":
        return None
    if isinstance(value, str):
        if not value.isdigit():
            raise InvalidURLError("Port must be numeric.")
        candidate = int(value)
    elif isinstance(value, int):
        candidate = value
    else:
        raise InvalidURLError("Port must be an integer or numeric string.")
    if not 0 < candidate < 65536:
        raise InvalidURLError("Port must be between 1 and 65535.")
    return candidate
