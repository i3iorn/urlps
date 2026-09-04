"""Tests for URLComponents validation helpers."""

from __future__ import annotations

import pytest

from urlps._components import URLComponentError, URLComponents


def test_with_updates_rejects_non_string_text_field() -> None:
    components = URLComponents()
    with pytest.raises(URLComponentError, match="Expected string or None"):
        components.with_updates(host=123)


def test_with_updates_rejects_empty_string_when_not_allowed() -> None:
    components = URLComponents()
    with pytest.raises(URLComponentError, match="Empty string not allowed"):
        components.with_updates(host="")


def test_with_updates_allows_empty_path() -> None:
    components = URLComponents()
    updated = components.with_updates(path="")
    assert updated.path == ""


def test_with_updates_rejects_invalid_port() -> None:
    components = URLComponents()
    with pytest.raises(URLComponentError, match="Port must be an integer"):
        components.with_updates(port=70000)


def test_with_updates_rejects_non_integer_port() -> None:
    components = URLComponents()
    with pytest.raises(URLComponentError, match="Port must be an integer"):
        components.with_updates(port="8080")


def test_with_updates_accepts_none_port() -> None:
    components = URLComponents(port=80)
    updated = components.with_updates(port=None)
    assert updated.port is None


def test_with_updates_rejects_non_list_query_pairs() -> None:
    components = URLComponents()
    with pytest.raises(URLComponentError, match="query_pairs must be a list"):
        components.with_updates(query_pairs="not-a-list")


@pytest.mark.parametrize(
    "bad_pair",
    [
        "not-a-tuple",
        ("only-one",),
        ("a", "b", "c"),
        (1, "value"),
        ("key", 2),
    ],
)
def test_with_updates_rejects_malformed_query_pair(bad_pair) -> None:
    components = URLComponents()
    with pytest.raises(URLComponentError, match="Invalid query pair structure"):
        components.with_updates(query_pairs=[bad_pair])


def test_with_updates_accepts_valid_query_pairs() -> None:
    components = URLComponents()
    updated = components.with_updates(query_pairs=[("a", "1"), ("b", None)])
    assert updated.query_pairs == [("a", "1"), ("b", None)]
