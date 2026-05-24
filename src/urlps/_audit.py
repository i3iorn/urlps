"""
Thread‑safe audit manager for URL parsing security logging.

This module provides a dependency‑injected, zero‑global‑state
audit manager with strict input validation and deterministic behavior.
"""

from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
from time import time
from typing import Any, Callable, Dict, Optional, Protocol, TYPE_CHECKING

from ._security import redact_url_for_logs

if TYPE_CHECKING:
    from .url import URL


class AuditCallback(Protocol):
    """Protocol for simple audit callbacks."""

    def __call__(
        self,
        logged_url: str,
        parsed_url: Optional["URL"],
        exception: Optional[Exception],
    ) -> None:
        ...


class AuditEventCallback(Protocol):
    """Protocol for structured audit event callbacks."""

    def __call__(self, event: Dict[str, Any]) -> None:
        ...


@dataclass(frozen=True)
class AuditConfig:
    """
    Immutable audit configuration.

    Attributes:
        callback: Optional simple audit callback.
        event_callback: Optional structured event callback.
        redact_urls: Whether URLs must be redacted before logging.
    """

    callback: Optional[AuditCallback] = None
    event_callback: Optional[AuditEventCallback] = None
    redact_urls: bool = True


@dataclass(frozen=True)
class CallbackFailureMetrics:
    """
    Immutable metrics snapshot for callback failures.

    Attributes:
        failure_count: Number of callback failures.
        last_error: Last exception raised by a callback.
    """

    failure_count: int
    last_error: Optional[Exception]


class AuditManager:
    """
    Thread‑safe audit manager with no global state.

    Responsibilities:
        - Store immutable audit configuration
        - Invoke callbacks safely
        - Track callback failure metrics
    """

    def __init__(self, config: Optional[AuditConfig] = None) -> None:
        self._config: AuditConfig = config or AuditConfig()
        self._lock: Lock = Lock()
        self._failure_count: int = 0
        self._last_error: Optional[Exception] = None

    # ------------------------------------------------------------------
    # Configuration Management
    # ------------------------------------------------------------------

    def update_config(self, new_config: AuditConfig) -> None:
        """
        Replace the audit configuration atomically.

        Args:
            new_config: New immutable configuration.
        """
        if not isinstance(new_config, AuditConfig):
            raise TypeError("new_config must be an AuditConfig instance")

        with self._lock:
            self._config = new_config

    def get_config(self) -> AuditConfig:
        """Return the current immutable configuration."""
        return self._config

    # ------------------------------------------------------------------
    # Callback Failure Tracking
    # ------------------------------------------------------------------

    def _record_failure(self, error: Exception) -> None:
        """Record callback failures without leaking exceptions."""
        with self._lock:
            self._failure_count += 1
            self._last_error = error

    def get_failure_metrics(self) -> CallbackFailureMetrics:
        """Return a snapshot of failure metrics."""
        with self._lock:
            return CallbackFailureMetrics(
                failure_count=self._failure_count,
                last_error=self._last_error,
            )

    def reset_failure_metrics(self) -> CallbackFailureMetrics:
        """Reset metrics and return the previous snapshot."""
        with self._lock:
            previous = CallbackFailureMetrics(
                failure_count=self._failure_count,
                last_error=self._last_error,
            )
            self._failure_count = 0
            self._last_error = None
            return previous

    # ------------------------------------------------------------------
    # Callback Invocation
    # ------------------------------------------------------------------

    def invoke(
        self,
        raw_url: str,
        parsed_url: Optional["URL"],
        exception: Optional[Exception],
        *,
        correlation_id: Optional[str] = None,
    ) -> None:
        """
        Invoke configured callbacks safely.

        Args:
            raw_url: Raw URL string.
            parsed_url: Parsed URL object or None.
            exception: Exception raised during parsing, if any.
            correlation_id: Optional correlation identifier.
        """
        config = self._config

        if config.callback is None and config.event_callback is None:
            return

        logged_url = (
            redact_url_for_logs(raw_url) if config.redact_urls else raw_url
        )

        # Simple callback
        if config.callback is not None:
            try:
                config.callback(logged_url, parsed_url, exception)
            except Exception as error:
                self._record_failure(error)

        # Structured event callback
        if config.event_callback is not None:
            event = self._build_event(
                logged_url=logged_url,
                parsed_url=parsed_url,
                exception=exception,
                correlation_id=correlation_id,
            )
            try:
                config.event_callback(event)
            except Exception as error:
                self._record_failure(error)

    # ------------------------------------------------------------------
    # Event Construction
    # ------------------------------------------------------------------

    @staticmethod
    def _build_event(
        *,
        logged_url: str,
        parsed_url: Optional["URL"],
        exception: Optional[Exception],
        correlation_id: Optional[str],
    ) -> Dict[str, Any]:
        """Build a structured audit event dictionary."""
        error_type: Optional[str] = None
        error_code: Optional[str] = None

        if exception is not None:
            error_type = type(exception).__name__
            code = getattr(exception, "code", None)
            error_code = getattr(code, "value", None)

        return {
            "timestamp": time(),
            "level": "error" if exception else "info",
            "operation": "url_parse",
            "raw_url": logged_url,
            "host": parsed_url.host if parsed_url else None,
            "error_type": error_type,
            "error_code": error_code,
            "correlation_id": correlation_id,
        }
