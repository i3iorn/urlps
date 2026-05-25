"""Additional public facade tests grouped by package entry points."""

from __future__ import annotations

import pytest

class TestInitBuild:
    def test_build_single_arg_host_only(self):
        """Lines 273-274: build() with a single positional arg (host only)."""
        from src.urlps import build
        result = build("example.com")
        assert "example.com" in result

    def test_build_no_args_raises(self):
        """Lines 278-279: build() with zero args raises URLBuildError."""
        from src.urlps import build
        from src.urlps.exceptions import URLBuildError
        with pytest.raises(URLBuildError):
            build()

    def test_build_secure_returns_string(self):
        """Line 333: build_secure() returns validated URL string."""
        from src.urlps import build_secure
        result = build_secure("https", "example.com", path="/api")
        assert "example.com" in result
        assert result.startswith("https://")

    def test_build_secure_with_policy(self):
        """build_secure() with a custom policy."""
        from src.urlps import build_secure
        from src.urlps._security import SecurityPolicy
        policy = SecurityPolicy.balanced()
        result = build_secure("https", "example.com", path="/v1", policy=policy)
        assert "https://example.com/v1" in result

    def test_get_cache_info_structure(self):
        """Lines 354-356: get_cache_info() returns expected keys."""
        from src.urlps import get_cache_info
        info = get_cache_info()
        assert "parser" in info
        assert "validation" in info
        assert "security" in info
        assert "builder" in info

    def test_get_cache_info_builder_keys(self):
        """Lines 354-356: builder cache info has expected keys."""
        from src.urlps import get_cache_info
        info = get_cache_info()
        builder_info = info["builder"]
        assert "percent_encode" in builder_info
        assert "encode_for_query" in builder_info

    def test_clear_all_caches_returns_dict(self):
        """Lines 385-402: clear_all_caches() returns previous cache sizes."""
        from src.urlps import clear_all_caches
        result = clear_all_caches()
        assert "parser" in result
        assert "validation" in result
        assert "security" in result
        assert "builder" in result

    def test_clear_all_caches_builder_keys(self):
        """Lines 394-400: builder entries populated after use."""
        from src.urlps import parse_url, clear_all_caches
        # Warm up caches
        parse_url("https://example.com/path")
        result = clear_all_caches()
        assert "builder" in result

    def test_parse_url_with_policy_instance(self):
        """parse_url() passing a SecurityPolicy instance directly."""
        from src.urlps import parse_url
        from src.urlps._security import SecurityPolicy
        policy = SecurityPolicy.balanced()
        url = parse_url("https://example.com/", policy=policy)
        assert url.host == "example.com"

    def test_parse_url_unsafe_with_policy(self):
        """parse_url_unsafe() with explicit policy uses resolve_security_policy."""
        from src.urlps import parse_url_unsafe
        from src.urlps._security import SecurityPolicy
        policy = SecurityPolicy.internal()
        url = parse_url_unsafe("http://localhost/test", policy=policy)
        assert url.host == "localhost"

class TestInitAdditional:
    """Cover remaining __init__.py lines."""

    def test_parse_url_unsafe_with_security_policy_object(self):
        """parse_url_unsafe with SecurityPolicy object routes via resolve."""
        from src.urlps import parse_url_unsafe
        from src.urlps._security.policy import SecurityPolicy
        p = SecurityPolicy.internal()
        url = parse_url_unsafe("http://localhost/test", policy=p)
        assert url.host == "localhost"

    def test_compose_url_with_query_pairs_dict(self):
        """compose_url with query_pairs builds properly."""
        from src.urlps import compose_url
        result = compose_url({
            "scheme": "https",
            "host": "api.example.com",
            "path": "/v1",
            "query_pairs": [("page", "1"), ("size", "50")],
        })
        assert "api.example.com" in result
        assert "page=1" in result

    def test_get_cache_info_full_structure(self):
        """get_cache_info() returns all expected sub-keys."""
        from src.urlps import get_cache_info, parse_url
        parse_url("https://example.com/warm")
        info = get_cache_info()
        assert "parser" in info
        assert "normalize_path" in info["parser"]
        assert "validation" in info
        assert "security" in info
        assert "builder" in info

    def test_clear_all_caches_includes_builder(self):
        """clear_all_caches() populates builder sub-dict after cache warmup."""
        from src.urlps import clear_all_caches, parse_url
        parse_url("https://example.com/")
        result = clear_all_caches()
        assert "builder" in result
        # builder may have percent_encode and/or encode_for_query
        assert isinstance(result["builder"], dict)

    def test_parse_url_blocks_scheme_relative_localhost(self):
        """Secure parsing must reject SSRF targets in scheme-relative URLs."""
        from src.urlps import parse_url
        from src.urlps.exceptions import InvalidURLError

        with pytest.raises(InvalidURLError):
            parse_url("//localhost/admin")

    def test_parse_url_unsafe_allows_scheme_relative_localhost(self):
        """Unsafe parsing keeps scheme-relative localhost support for trusted inputs."""
        from src.urlps import parse_url_unsafe

        parsed = parse_url_unsafe("//localhost/admin")
        assert parsed.host == "localhost"
        assert parsed.path == "/admin"

