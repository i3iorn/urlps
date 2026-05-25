"""Additional builder tests grouped by builder behavior."""

from __future__ import annotations

import pytest

class TestBuilder:
    def test_compose_secure(self):
        """Lines 123-133: compose_secure() builds and validates URL."""
        from urlps._builder import Builder
        builder = Builder()
        result = builder.compose_secure(
            {"scheme": "https", "host": "example.com", "path": "/secure"}
        )
        assert "example.com" in result

    def test_compose_scheme_none_no_host_raises(self):
        """Lines 97->99 / 102-103: compose() with scheme but no valid netloc raises."""
        from urlps._builder import Builder
        from urlps.exceptions import URLBuildError
        builder = Builder()
        with pytest.raises(URLBuildError):
            builder.compose({"scheme": "https"})

    def test_normalize_path_dotdot_at_start(self):
        """Lines 219->215: path starts with '..' on empty segment list."""
        from urlps._builder import Builder
        builder = Builder()
        result = builder.normalize_path("/../foo")
        assert result == "/foo"

    def test_normalize_path_relative_path(self):
        """Lines 228->231: relative path skips absolute re-prefix."""
        from urlps._builder import Builder
        builder = Builder()
        result = builder.normalize_path("a/b/../c")
        assert result == "a/c"

    def test_normalize_path_relative_with_trailing_slash(self):
        """Lines 228->231: relative path with trailing slash preserved."""
        from urlps._builder import Builder
        builder = Builder()
        result = builder.normalize_path("a/b/")
        assert result.endswith("/")

    def test_fast_unquote_plus_with_plus(self):
        """Line 255: _fast_unquote_plus with '+' decodes to space."""
        from urlps._builder import Builder
        result = Builder._fast_unquote_plus("hello+world")
        assert result == "hello world"

    def test_fast_unquote_plus_with_percent_encoding(self):
        """Line 255: _fast_unquote_plus with '%20' decodes to space."""
        from urlps._builder import Builder
        result = Builder._fast_unquote_plus("hello%20world")
        assert result == "hello world"

    def test_compose_with_file_scheme_no_host(self):
        """compose() with file:// scheme allows no host."""
        from urlps._builder import Builder
        builder = Builder()
        result = builder.compose({"scheme": "file", "path": "/tmp/file.txt"})
        assert "file://" in result

    def test_build_netloc_port_without_host_raises(self):
        """PortValidationError when port without host."""
        from urlps._builder import Builder
        from urlps.exceptions import PortValidationError
        builder = Builder()
        with pytest.raises(PortValidationError):
            builder.build_netloc(None, None, 8080, "https")
