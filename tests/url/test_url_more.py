"""Additional coverage for url.py: unfrozen __delattr__, aliasing, and
backward-compat wrapper methods.
"""

from __future__ import annotations

import pytest

from urlps import parse_url
from urlps.url import URL


def test_delattr_succeeds_while_unfrozen():
    """__delattr__ deletes normally before the immutability guard is armed."""
    instance = object.__new__(URL)
    object.__setattr__(instance, "_frozen", False)
    object.__setattr__(instance, "_scheme", "https")
    del instance._scheme
    assert "_scheme" not in instance.__dict__ if hasattr(instance, "__dict__") else True
    with pytest.raises(AttributeError):
        instance._scheme  # noqa: B018


def test_query_pairs_is_alias_for_query_params():
    url = parse_url("https://example.com/?a=1&b=2")
    assert url.query_pairs == url.query_params
