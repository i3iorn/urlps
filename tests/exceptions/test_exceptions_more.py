"""Additional coverage for exceptions.py: the unrepresentable-value fallback."""

from __future__ import annotations

from urlps.exceptions import InvalidURLError, _safe_truncated_repr


class _UnrepresentableValue:
    def __repr__(self) -> str:
        raise RuntimeError("cannot repr this")


def test_safe_truncated_repr_handles_repr_failure():
    assert _safe_truncated_repr(_UnrepresentableValue()) == "<unrepresentable>"


def test_exception_message_survives_unrepresentable_value():
    error = InvalidURLError("bad value", value=_UnrepresentableValue())
    assert "<unrepresentable>" in str(error)
