"""Tests for AuditManager and related audit configuration."""

from __future__ import annotations

import pytest

from urlps._audit import (
    AuditConfig,
    AuditManager,
    CallbackFailureMetrics,
)


def test_audit_callback_protocol_signature() -> None:
    """A simple callback receives logged_url, parsed_url, exception."""
    seen = []

    def callback(logged_url, parsed_url, exception):
        seen.append((logged_url, parsed_url, exception))

    manager = AuditManager(AuditConfig(callback=callback))
    manager.invoke(raw_url="https://example.com/", parsed_url=None, exception=None)
    assert seen == [("https://example.com/", None, None)]


def test_audit_event_callback_protocol_signature() -> None:
    """A structured event callback receives a single event dict."""
    events = []

    def event_callback(event: dict) -> None:
        events.append(event)

    manager = AuditManager(AuditConfig(event_callback=event_callback))
    manager.invoke(raw_url="https://example.com/", parsed_url=None, exception=None)
    assert len(events) == 1
    assert events[0]["operation"] == "url_parse"


def test_update_config_rejects_non_audit_config() -> None:
    manager = AuditManager()
    with pytest.raises(TypeError, match="AuditConfig instance"):
        manager.update_config("not a config")  # type: ignore[arg-type]


def test_update_config_replaces_config() -> None:
    manager = AuditManager()
    new_config = AuditConfig(redact_urls=False)
    manager.update_config(new_config)
    assert manager.get_config() is new_config


def test_get_config_returns_current_config() -> None:
    config = AuditConfig(redact_urls=False)
    manager = AuditManager(config)
    assert manager.get_config() is config


def test_get_failure_metrics_returns_snapshot() -> None:
    def failing_callback(logged_url, parsed_url, exception):
        raise RuntimeError("boom")

    manager = AuditManager(AuditConfig(callback=failing_callback))
    manager.invoke(raw_url="https://example.com/", parsed_url=None, exception=None)

    metrics = manager.get_failure_metrics()
    assert isinstance(metrics, CallbackFailureMetrics)
    assert metrics.failure_count == 1
    assert isinstance(metrics.last_error, RuntimeError)


def test_reset_failure_metrics_clears_state_and_returns_previous() -> None:
    def failing_callback(logged_url, parsed_url, exception):
        raise RuntimeError("boom")

    manager = AuditManager(AuditConfig(callback=failing_callback))
    manager.invoke(raw_url="https://example.com/", parsed_url=None, exception=None)

    previous = manager.reset_failure_metrics()
    assert previous.failure_count == 1

    current = manager.get_failure_metrics()
    assert current.failure_count == 0
    assert current.last_error is None


def test_event_callback_failure_is_recorded_without_raising() -> None:
    def failing_event_callback(event: dict) -> None:
        raise RuntimeError("event callback boom")

    manager = AuditManager(AuditConfig(event_callback=failing_event_callback))
    manager.invoke(raw_url="https://example.com/", parsed_url=None, exception=None)

    metrics = manager.get_failure_metrics()
    assert metrics.failure_count == 1
    assert isinstance(metrics.last_error, RuntimeError)


def test_invoke_is_noop_when_no_callbacks_configured() -> None:
    manager = AuditManager(AuditConfig())
    # Should not raise, and failure metrics should remain untouched.
    manager.invoke(raw_url="https://example.com/", parsed_url=None, exception=None)
    assert manager.get_failure_metrics().failure_count == 0


def test_event_callback_records_exception_type_and_code() -> None:
    from urlps.exceptions import InvalidURLError

    events = []

    def event_callback(event: dict) -> None:
        events.append(event)

    manager = AuditManager(AuditConfig(event_callback=event_callback))
    exc = InvalidURLError("bad url", code=None)
    manager.invoke(raw_url="https://example.com/", parsed_url=None, exception=exc, correlation_id="abc")

    assert events[0]["level"] == "error"
    assert events[0]["error_type"] == "InvalidURLError"
    assert events[0]["correlation_id"] == "abc"

    from urlps import ErrorCode

    exc_with_code = InvalidURLError("bad url", code=ErrorCode.SSRF_RISK)
    events.clear()
    manager.invoke(raw_url="https://example.com/", parsed_url=None, exception=exc_with_code)
    assert events[0]["error_code"] == ErrorCode.SSRF_RISK.value


def test_event_callback_records_parsed_url_host() -> None:
    from urlps import parse_url

    events = []

    def event_callback(event: dict) -> None:
        events.append(event)

    manager = AuditManager(AuditConfig(event_callback=event_callback))
    parsed = parse_url("https://example.com/path")
    manager.invoke(raw_url="https://example.com/path", parsed_url=parsed, exception=None)

    assert events[0]["host"] == "example.com"


def test_invoke_both_callbacks_run_independently_on_failure() -> None:
    """A failing simple callback must not prevent the event callback from running."""
    events = []

    def failing_callback(logged_url, parsed_url, exception):
        raise RuntimeError("boom")

    def event_callback(event: dict) -> None:
        events.append(event)

    manager = AuditManager(AuditConfig(callback=failing_callback, event_callback=event_callback))
    manager.invoke(raw_url="https://example.com/", parsed_url=None, exception=None)

    assert manager.get_failure_metrics().failure_count == 1
    assert len(events) == 1
