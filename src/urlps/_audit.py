"""Thread-safe audit callback for URL parsing security logging."""
from __future__ import annotations

from dataclasses import dataclass
import threading
import time
from typing import TYPE_CHECKING, Any, Callable, Dict, Optional, cast

from ._security import redact_url_for_logs

if TYPE_CHECKING:
    from .url import URL

AuditCallback = Callable[[str, Optional["URL"], Optional[Exception]], None]
AuditEventCallback = Callable[[Dict[str, Any]], None]


@dataclass(frozen=True)
class _AuditConfig:
    """Immutable audit callback configuration for lock-free reads."""

    callback: Optional[AuditCallback] = None
    event_callback: Optional[AuditEventCallback] = None
    redact_urls: bool = True


_audit_callback_lock = threading.Lock()
_audit_config = _AuditConfig()

_callback_failure_count: int = 0
_last_callback_error: Optional[Exception] = None
_time_now = time.time


def _record_callback_failure(error: Exception) -> None:
    """Record callback failures without leaking exceptions to callers."""
    global _callback_failure_count, _last_callback_error

    with _audit_callback_lock:
        _callback_failure_count += 1
        _last_callback_error = error


def set_audit_callback(
    callback: Optional[AuditCallback],
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
    global _audit_config

    with _audit_callback_lock:
        _audit_config = _AuditConfig(
            callback=callback,
            event_callback=_audit_config.event_callback,
            redact_urls=redact_urls,
        )


def set_audit_event_callback(callback: Optional[AuditEventCallback]) -> None:
    """Set a structured audit event callback receiving event dictionaries."""
    global _audit_config

    with _audit_callback_lock:
        _audit_config = _AuditConfig(
            callback=_audit_config.callback,
            event_callback=callback,
            redact_urls=_audit_config.redact_urls,
        )


def get_audit_event_callback() -> Optional[AuditEventCallback]:
    """Get the current structured audit event callback."""
    return _audit_config.event_callback


def get_audit_callback() -> Optional[AuditCallback]:
    """Get the current audit callback function (thread-safe)."""
    return _audit_config.callback


def invoke_audit_callback(
    raw_url: str,
    parsed_url: Optional['URL'],
    exception: Optional[Exception],
    *,
    correlation_id: Optional[str] = None,
) -> None:
    """Invoke the audit callback if set, in a thread-safe manner."""
    config = _audit_config
    callback = config.callback
    event_callback = config.event_callback

    # Fast path for the common case where auditing is disabled.
    if callback is None and event_callback is None:
        return

    logged_url = redact_url_for_logs(raw_url) if config.redact_urls else raw_url

    if callback is not None:
        callback_fn = cast(AuditCallback, callback)
        try:
            callback_fn(logged_url, parsed_url, exception)
        except Exception as e:
            _record_callback_failure(e)

    if event_callback is not None:
        event_callback_fn = cast(AuditEventCallback, event_callback)
        exception_code_value: Optional[str] = None
        error_type: Optional[str] = None
        if exception is not None:
            error_type = type(exception).__name__
            exception_code = getattr(exception, "code", None)
            exception_code_value = exception_code.value if exception_code is not None else None

        event: Dict[str, Any] = {
            "timestamp": _time_now(),
            "level": "error" if exception is not None else "info",
            "operation": "url_parse",
            "raw_url": logged_url,
            "host": parsed_url.host if parsed_url is not None else None,
            "error_type": error_type,
            "error_code": exception_code_value,
            "correlation_id": correlation_id,
        }
        try:
            event_callback_fn(event)
        except Exception as e:
            _record_callback_failure(e)


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
