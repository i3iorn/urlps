import pytest

from urlps import URL, InvalidURLError, compose_url, parse_url, parse_url_unsafe


def test_parse_url_returns_URL() -> None:
    u = parse_url("https://example.com:8080/path?x=1&x=2#f")
    assert isinstance(u, URL)
    assert u.host == "example.com"
    assert u.query_params == [("x", "1"), ("x", "2")]


def test_parse_url_warns_on_credentials_but_does_not_block() -> None:
    # Credentials are legal RFC 3986 and are advisory by default; the host
    # still resolves to the part after the last '@', which is what matters.
    url = parse_url("https://user:pw@example.com:8080/path?x=1", policy="strict")
    assert url.host == "example.com"
    assert any(f.code == "credentials_in_url" and f.severity == "warning" for f in url.security_findings)


def test_parse_url_blocks_credentials_when_opted_in() -> None:
    from urlps import SecurityPolicy

    with pytest.raises(InvalidURLError):
        parse_url(
            "https://user:pw@example.com:8080/path?x=1",
            policy=SecurityPolicy(name="creds", reject_credentials=True),
        )


def test_parse_url_unsafe_allows_credentials_for_internal_policy() -> None:
    u = parse_url_unsafe("https://user:pw@example.com:8080/path?x=1")
    assert u.userinfo == "user:pw"


def test_compose_url_matches_builder_compose() -> None:
    u = parse_url("https://example.com:8443/a/b?c=1#z")
    components = {
        "scheme": u.scheme,
        "host": u.host,
        "port": u.port,
        "path": u.path,
        "query_pairs": u.query_params,
        "fragment": "z",
    }
    composed = compose_url(components)
    assert "example.com" in composed
    assert "8443" in composed


def test_URL_direct_construction() -> None:
    u = URL("https://example.com/foo")
    assert u.as_string() == "https://example.com/foo"
