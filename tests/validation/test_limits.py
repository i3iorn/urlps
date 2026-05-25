import pytest

from urlps import parse_url, parse_url_unsafe
from urlps.exceptions import InvalidURLError
from urlps import URL

from urlps.constants import (
    MAX_URL_LENGTH,
    MAX_SCHEME_LENGTH,
    MAX_HOST_LENGTH,
    MAX_PATH_LENGTH,
    MAX_QUERY_LENGTH,
    MAX_FRAGMENT_LENGTH,
    MAX_USERINFO_LENGTH,
)


def make_long_path(n):
    return "/" + "a" * n


def make_long_query(n):
    # produce key=val pairs joined by & to hit roughly n chars
    pair = "k=" + "v" * 10
    pairs = []
    # ensure we always produce at least something when n is small
    if n <= len(pair):
        return pair[:n]
    while sum(len(p) for p in pairs) + len(pairs) + len(pair) <= n:
        pairs.append(pair)
    if not pairs:
        return pair
    return "&".join(pairs)


def test_path_length_boundary():
    path_ok = make_long_path(MAX_PATH_LENGTH - 1)
    # compose a URL and ensure parse_url_unsafe accepts it (unsafe allows longer internals)
    u = parse_url_unsafe("http://example.com" + path_ok)
    assert u.path == path_ok
    # one over
    path_bad = make_long_path(MAX_PATH_LENGTH + 1)
    with pytest.raises(InvalidURLError):
        parse_url("http://example.com" + path_bad)


def test_query_length_boundary():
    query_ok = make_long_query(MAX_QUERY_LENGTH - 10)
    u = parse_url_unsafe("http://example.com/" + "?" + query_ok)
    assert u.query is not None
    query_bad = make_long_query(MAX_QUERY_LENGTH + 10)
    with pytest.raises(InvalidURLError):
        parse_url("http://example.com/" + "?" + query_bad)


def test_fragment_length_boundary():
    frag_ok = "a" * (MAX_FRAGMENT_LENGTH - 1)
    u = parse_url_unsafe(f"http://example.com/path#{frag_ok}")
    assert u.fragment == frag_ok
    frag_bad = "a" * (MAX_FRAGMENT_LENGTH + 1)
    with pytest.raises(InvalidURLError):
        parse_url(f"http://example.com/path#{frag_bad}")


def test_userinfo_length_boundary():
    user_ok = "u" * (MAX_USERINFO_LENGTH - 1)
    # build a URL with userinfo
    url_ok = f"http://{user_ok}@example.com/"
    u = parse_url_unsafe(url_ok)
    assert u.userinfo == user_ok
    user_bad = "u" * (MAX_USERINFO_LENGTH + 1)
    url_bad = f"http://{user_bad}@example.com/"
    with pytest.raises(InvalidURLError):
        parse_url(url_bad)


def test_total_url_length_boundary():
    # create a long query to reach total length
    base = "http://example.com/"
    remaining = MAX_URL_LENGTH - len(base) - 10
    q = make_long_query(min(remaining, MAX_QUERY_LENGTH))
    ok = base + "?" + q
    u = parse_url_unsafe(ok)
    assert isinstance(u, URL)
    # one over
    remaining = MAX_URL_LENGTH - len(base) + 10
    q = make_long_query(remaining)
    bad = base + "?" + q
    with pytest.raises(InvalidURLError):
        parse_url(bad)
