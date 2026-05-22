"""Thread-safe audit callback for URL parsing security logging."""
from __future__ import annotations

import threading
import time
from typing import Optional, Callable, TYPE_CHECKING, Dict, Any

from ._security import redact_url_for_logs

if TYPE_CHECKING:
    from .url import URL

_audit_callback_lock = threading.Lock()
_audit_callback: Optional[Callable[[str, Optional['URL'], Optional[Exception]], None]] = None
_audit_event_callback: Optional[Callable[[Dict[str, Any]], None]] = None
_audit_callback_redact_urls: bool = True

_callback_failure_count: int = 0
_last_callback_error: Optional[Exception] = None


def set_audit_callback(
    callback: Optional[Callable[[str, Optional['URL'], Optional[Exception]], None]],
    *,
    redact_urls: bool = True,
) -> None:
    """Set a callback function for URL parsing audit logging.

    Thread Safety:
        This function is thread-safe. The callback reference is protected by a lock.
        The callback itself should be thread-safe if used in multi-threaded environments.

    Args:
        callback: The callback function, or None to disable auditing.
    """
    global _audit_callback, _audit_callback_redact_urls
    with _audit_callback_lock:
        _audit_callback = callback
        _audit_callback_redact_urls = redact_urls


def set_audit_event_callback(callback: Optional[Callable[[Dict[str, Any]], None]]) -> None:
    """Set a structured audit event callback receiving event dictionaries."""
    global _audit_event_callback
    with _audit_callback_lock:
        _audit_event_callback = callback


def get_audit_event_callback() -> Optional[Callable[[Dict[str, Any]], None]]:
    """Get the current structured audit event callback."""
    with _audit_callback_lock:
        return _audit_event_callback


def get_audit_callback() -> Optional[Callable[[str, Optional['URL'], Optional[Exception]], None]]:
    """Get the current audit callback function (thread-safe)."""
    with _audit_callback_lock:
        return _audit_callback


def invoke_audit_callback(
    raw_url: str,
    parsed_url: Optional['URL'],
    exception: Optional[Exception],
    *,
    correlation_id: Optional[str] = None,
) -> None:
    """Invoke the audit callback if set, in a thread-safe manner."""
    global _callback_failure_count, _last_callback_error

    with _audit_callback_lock:
        callback = _audit_callback
        event_callback = _audit_event_callback
        redact_urls = _audit_callback_redact_urls

    # Fast path for the common case where auditing is disabled.
    if callback is None and event_callback is None:
        return

    logged_url = redact_url_for_logs(raw_url) if redact_urls else raw_url

    if callback is not None:
        assert callback is not None
        try:
            callback(logged_url, parsed_url, exception)
        except Exception as e:
            with _audit_callback_lock:
                _callback_failure_count += 1
                _last_callback_error = e

    if event_callback is not None:
        assert event_callback is not None
        exception_code = getattr(exception, "code", None) if exception is not None else None
        event: Dict[str, Any] = {
            "timestamp": time.time(),
            "level": "error" if exception is not None else "info",
            "operation": "url_parse",
            "raw_url": logged_url,
            "host": parsed_url.host if parsed_url is not None else None,
            "error_type": type(exception).__name__ if exception is not None else None,
            "error_code": exception_code.value if exception_code is not None else None,
            "correlation_id": correlation_id,
        }
        try:
            event_callback(event)
        except Exception as e:
            with _audit_callback_lock:
                _callback_failure_count += 1
                _last_callback_error = e


def get_callback_failure_metrics() -> Dict[str, Any]:
    """Get metrics about audit callback failures.

    Returns:
        Dict containing:
            - failure_count: Total number of callback invocation failures
            - last_error: The last exception raised by a callback, or None
    """
    with _audit_callback_lock:
        return {
            "failure_count": _callback_failure_count,
            "last_error": _last_callback_error,
        }


def reset_callback_failure_metrics() -> Dict[str, Any]:
    """Reset callback failure metrics and return previous values.

    Returns:
        Dict containing the metrics before reset.
    """
    global _callback_failure_count, _last_callback_error

    with _audit_callback_lock:
        previous = {
            "failure_count": _callback_failure_count,
            "last_error": _last_callback_error,
        }
        _callback_failure_count = 0
        _last_callback_error = None
        return previous


__all__ = [
    "set_audit_callback",
    "set_audit_event_callback",
    "get_audit_callback",
    "get_audit_event_callback",
    "invoke_audit_callback",
    "get_callback_failure_metrics",
    "reset_callback_failure_metrics",
]
