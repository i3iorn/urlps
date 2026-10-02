"""Python object-model contracts a URL must keep.

``a == b`` must imply ``hash(a) == hash(b)`` (otherwise sets and dict keys
silently hold duplicates), and a URL's components must come from its own
parse even when the Parser instance is shared.
"""

from __future__ import annotations

import base64
import pickle

import pytest

from urlps import URL, parse_url
from urlps._parser import Parser


@pytest.mark.parametrize(
    ("left", "right"),
    [
        # Same serialization, different stored port (443 vs None).
        (lambda: parse_url("https://example.com/"), lambda: parse_url("https://example.com/").with_port(None)),
        # with_path() stores the path as given; the string is normalized.
        (
            lambda: parse_url("https://example.com/b", policy="internal"),
            lambda: parse_url("https://example.com/", policy="internal").with_path("/a/../b"),
        ),
    ],
    ids=["default-port-vs-none", "unnormalized-path"],
)
def test_equal_urls_hash_equal(left, right) -> None:
    a, b = left(), right()
    assert a == b
    assert hash(a) == hash(b)
    assert len({a, b}) == 1


def test_url_hashes_like_the_string_it_equals() -> None:
    url = parse_url("https://example.com/p?q=1#f")
    assert url == str(url)
    assert hash(url) == hash(str(url))
    assert {str(url): "hit"}[url] == "hit"


class _ReusedParser(Parser):
    """Simulates another caller using the same Parser before URL reads its state."""

    def parse(self, maybe_url: str) -> dict:
        result = super().parse(maybe_url)
        super().parse("foo+bar://other.example/?stale=1")
        return result


def test_components_come_from_this_parse_not_the_parsers_last_state() -> None:
    parser = _ReusedParser()
    parser.custom_scheme = True
    with pytest.warns(DeprecationWarning):
        url = URL("https://example.com/?k=v", parser=parser)
    assert url.query_params == [("k", "v")]
    assert url.recognized_scheme is True


#: A URL pickled by urlps 1.1.4: parse_url("https://user:pw@example.com:8443/a/b?q=1&flag#frag",
#: policy="balanced"), protocol 4. 1.1 stored one attribute per component.
LEGACY_1_1_4_PICKLE = (
    "gASVSQUAAAAAAACMCXVybHBzLnVybJSMA1VSTJSTlCmBlH2UKIwKX2NoZWNrX2Ruc5SJjA9fY2hlY2tfcGhpc2hpbmeUiYwPX2Nv"
    "cnJlbGF0aW9uX2lklE6MBl9kZWJ1Z5SJjAlfZnJhZ21lbnSUjARmcmFnlIwHX2Zyb3plbpSIjAVfaG9zdJSMC2V4YW1wbGUuY29t"
    "lIwFX3BhdGiUjAQvYS9ilIwFX3BvcnSUTfsgjAZfcXVlcnmUjAhxPTEmZmxhZ5SMDF9xdWVyeV9wYWlyc5RdlCiMAXGUjAExlIaU"
    "jARmbGFnlE6GlGWMB19zY2hlbWWUjAVodHRwc5SMEl9zZWN1cml0eV9maW5kaW5nc5RdlIwRdXJscHMuX2NvbXBvbmVudHOUjA9T"
    "ZWN1cml0eUZpbmRpbmeUk5QpgZRdlCiMB3dhcm5pbmeUjBJjcmVkZW50aWFsc19pbl91cmyUjMJVUkwgY29udGFpbnMgY3JlZGVu"
    "dGlhbHMgaW4gdGhlIGF1dGhvcml0eS4gVGhlIGhvc3QgcmVzb2x2ZXMgdG8gdGhlIHBhcnQgYWZ0ZXIgdGhlIGxhc3QgJ0AnOyB2"
    "ZXJpZnkgaXQgaXMgdGhlIGhvc3QgeW91IGV4cGVjdC4gVXNlIFVSTC5yZWRhY3RlZCgpIG9yIGFzX3N0cmluZyhtYXNrX3Bhc3N3"
    "b3JkPVRydWUpIGJlZm9yZSBsb2dnaW5nLpSMCHVzZXJpbmZvlIyaQ3JlZGVudGlhbHMgaW4gYSBVUkwgYXJlIGxlZ2FsIGJ1dCBk"
    "aXNjb3VyYWdlZC4gVXNlIHBvbGljeT0iYmFsYW5jZWQiIHRvIGFsbG93IHRoZW0sIGFuZCBVUkwucmVkYWN0ZWQoKSBvciBVUkwu"
    "YXNfc3RyaW5nKG1hc2tfcGFzc3dvcmQ9VHJ1ZSkgd2hlbiBsb2dnaW5nLpRlYmGMEF9zZWN1cml0eV9wb2xpY3mUjBZ1cmxwcy5f"
    "c2VjdXJpdHkucG9saWN5lIwOU2VjdXJpdHlQb2xpY3mUk5QpgZR9lCiMBG5hbWWUjAhiYWxhbmNlZJSMDGVuZm9yY2Vfc3NyZpSI"
    "jBNhbGxvd19wcml2YXRlX2hvc3RzlImMFmVuZm9yY2VfcGF0aF90cmF2ZXJzYWyUiIwVZW5mb3JjZV9vcGVuX3JlZGlyZWN0lIiM"
    "FWVuZm9yY2VfbWl4ZWRfc2NyaXB0c5SIjBhlbmZvcmNlX3BhcnNlcl9jb25mdXNpb26UiIwXZW5mb3JjZV9kb3VibGVfZW5jb2Rp"
    "bmeUiIwVYmxvY2tfZGFuZ2Vyb3VzX3BvcnRzlImMEnJlamVjdF9jcmVkZW50aWFsc5SJjBtlbmZvcmNlX3N1c3BpY2lvdXNfcHVu"
    "eWNvZGWUiYwXZW5mb3JjZV9jb25mdXNhYmxlX2hvc3SUiIwbZW5mb3JjZV9ob3N0X3VuaWNvZGVfc2FmZXR5lIiMCWNoZWNrX2Ru"
    "c5SJjA5jaGVja19waGlzaGluZ5SJjBZlbmZvcmNlX2Ruc19yYXRlX2xpbWl0lIiMHmRuc19mYWlsX29wZW5fb25fY29ubmVjdF9l"
    "cnJvcpSIjAtkbnNfcmV0cmllc5RLAowYZG5zX2JhY2tvZmZfYmFzZV9zZWNvbmRzlEc/qZmZmZmZmowaZG5zX2JhY2tvZmZfaml0"
    "dGVyX3NlY29uZHOURz+UeuFHrhR7jBBkbnNfcmF0ZV9saW1pdGVylE51YowJX3VzZXJpbmZvlIwHdXNlcjpwd5SMEXJlY29nbml6"
    "ZWRfc2NoZW1llIh1Yi4="
)


def test_a_pickle_made_by_urlps_1_1_still_loads() -> None:
    restored = pickle.loads(base64.b64decode(LEGACY_1_1_4_PICKLE))
    assert str(restored) == "https://user:pw@example.com:8443/a/b?q=1&flag#frag"
    assert restored.query_params == [("q", "1"), ("flag", None)]
    assert restored.security_policy.name == "balanced"
    assert restored.with_path("/c").host == "example.com"
    with pytest.raises(AttributeError, match="immutable"):
        restored._parts = None


def test_str_is_cached_but_not_pickled() -> None:
    url = parse_url("https://example.com/p")
    assert url.as_string() is url.as_string()
    state = url.__getstate__()
    assert "serialized" not in state and "_serialized" not in state
    assert pickle.loads(pickle.dumps(url)) == url
