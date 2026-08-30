"""Additional coverage for _validation.py edge cases."""

from __future__ import annotations

import pytest

from urlps import parse_url
from urlps._validation import Validator, _URLValidation
from urlps.exceptions import InvalidURLError


def test_is_valid_host_rejects_oversized_ascii_form(monkeypatch):
    """Line 126: host with a valid Unicode form but an oversized ASCII encoding."""
    monkeypatch.setattr(Validator, "_to_ascii_host", staticmethod(lambda host: "a" * 300))
    assert Validator.is_valid_host("short-input.example") is False


def test_is_valid_ipv4_rejects_wrong_regex_shape():
    """Line 141->142 (regex-level rejection before octet validation)."""
    assert Validator.is_valid_ipv4("999.999.999.999.extra") is False


def test_with_fragment_override_rejects_invalid_fragment():
    url = parse_url("https://example.com/")
    with pytest.raises(InvalidURLError, match="Invalid fragment"):
        url.with_fragment("bad fragment with spaces and \x00 control char")


def test_empty_host_override_is_valid():
    """Clearing the host is allowed at the validation level; compose() enforces the rest."""
    assert _URLValidation._is_valid_host_override("") is True
