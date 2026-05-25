import pytest

from urlps._builder import Builder
from urlps.exceptions import InvalidURLError


def test_compose_infers_root_path_when_host_present() -> None:
    builder = Builder()
    result = builder.compose({"scheme": "https", "host": "example.com", "path": ""})
    assert result == "https://example.com/"


def test_compose_requires_host_for_network_schemes() -> None:
    builder = Builder()
    with pytest.raises(InvalidURLError):
        builder.compose({"scheme": "http", "path": "/"})


def test_compose_allows_file_scheme_without_host() -> None:
    builder = Builder()
    result = builder.compose({"scheme": "file", "path": "/tmp/data"})
    assert result == "file:///tmp/data"


def test_build_netloc_hides_default_port() -> None:
    builder = Builder()
    assert builder.build_netloc(None, "example.com", 443, "https") == "example.com"


def test_build_netloc_raises_when_port_without_host() -> None:
    builder = Builder()
    with pytest.raises(InvalidURLError):
        builder.build_netloc(None, None, 443, "https")


def test_parse_query_rejects_empty_key() -> None:
    builder = Builder()
    with pytest.raises(InvalidURLError):
        builder.parse_query("=value")


def test_query_mutators_round_trip() -> None:
    builder = Builder()
    query = builder.add_param(None, "foo", "bar")
    assert query == "foo=bar"
    query = builder.add_param(query, "flag", None)
    assert query == "foo=bar&flag"
    query = builder.remove_param(query, "foo")
    assert query == "flag"
    query = builder.merge_params(query, {"multi": [1, 2], "plain": "x"})
    assert query == "flag&multi=1&multi=2&plain=x"


def test_normalize_path_collapses_dot_segments() -> None:
    builder = Builder()
    assert builder.normalize_path("/a/./b/../c/") == "/a/c/"


def test_percent_encode_preserves_safe_chars() -> None:
    builder = Builder()
    assert builder.percent_encode("abc-._~", safe=builder.PATH_SAFE) == "abc-._~"


def test_compose_prefers_query_pairs_over_query() -> None:
    builder = Builder()
    result = builder.compose(
        {
            "scheme": "https",
            "host": "example.com",
            "query": "ignored=1",
            "query_pairs": [("bar", "2"), ("flag", None)],
        }
    )
    assert result == "https://example.com/?bar=2&flag"


def test_compose_uses_pre_serialized_query_when_no_pairs() -> None:
    builder = Builder()
    result = builder.compose(
        {
            "scheme": "https",
            "host": "example.com",
            "query": "already=encoded",
            "query_pairs": [],
        }
    )
    assert result == "https://example.com/?already=encoded"


def test_compose_encodes_fragment_characters() -> None:
    builder = Builder()
    result = builder.compose(
        {
            "scheme": "https",
            "host": "example.com",
            "fragment": "frag value/%",
        }
    )
    assert result == "https://example.com/#frag%20value/%25"


def test_parse_query_skips_empty_chunks() -> None:
    builder = Builder()
    assert builder.parse_query("a=1&&b&") == [("a", "1"), ("b", None)]


def test_serialize_query_returns_empty_string_for_empty_input() -> None:
    builder = Builder()
    assert builder.serialize_query([]) == ""
