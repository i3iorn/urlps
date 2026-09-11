"""Tests for URL comparison operators and sorting."""

from urlps import parse_url_local


class TestURLComparison:
    """Tests for URL comparison operators."""

    def test_equality(self):
        """URLs with same string representation should be equal."""
        url1 = parse_url_local("https://example.com/path")
        url2 = parse_url_local("https://example.com/path")
        assert url1 == url2

    def test_inequality(self):
        """URLs with different string representation should not be equal."""
        url1 = parse_url_local("https://example.com/path1")
        url2 = parse_url_local("https://example.com/path2")
        assert url1 != url2

    def test_less_than(self):
        """URLs should compare lexicographically."""
        url_a = parse_url_local("https://aaa.com/")
        url_b = parse_url_local("https://bbb.com/")
        assert url_a < url_b
        assert not url_b < url_a

    def test_less_than_or_equal(self):
        """URLs should compare with less than or equal."""
        url_a = parse_url_local("https://aaa.com/")
        url_b = parse_url_local("https://bbb.com/")
        url_a2 = parse_url_local("https://aaa.com/")

        assert url_a <= url_b
        assert url_a <= url_a2
        assert not url_b <= url_a

    def test_greater_than(self):
        """URLs should compare with greater than."""
        url_a = parse_url_local("https://aaa.com/")
        url_b = parse_url_local("https://bbb.com/")

        assert url_b > url_a
        assert not url_a > url_b

    def test_greater_than_or_equal(self):
        """URLs should compare with greater than or equal."""
        url_a = parse_url_local("https://aaa.com/")
        url_b = parse_url_local("https://bbb.com/")
        url_b2 = parse_url_local("https://bbb.com/")

        assert url_b >= url_a
        assert url_b >= url_b2
        assert not url_a >= url_b

    def test_comparison_with_unrelated_type_returns_not_implemented(self):
        """Comparison with a type that is neither URL nor str should return NotImplemented.

        A plain string *is* a supported comparison target (see
        TestURLStringComparison below) -- it's compared against
        ``as_string()`` directly, which is what makes ``url == "https://..."``
        work.
        """
        url = parse_url_local("https://example.com/")

        assert url.__lt__(42) == NotImplemented
        assert url.__le__(42) == NotImplemented
        assert url.__gt__(42) == NotImplemented
        assert url.__ge__(42) == NotImplemented
        assert url.__eq__(42) == NotImplemented


class TestURLSorting:
    """Tests for sorting lists of URLs."""

    def test_sort_urls(self):
        """URLs should be sortable."""
        urls = [
            parse_url_local("https://zzz.com/"),
            parse_url_local("https://aaa.com/"),
            parse_url_local("https://mmm.com/"),
        ]

        sorted_urls = sorted(urls)

        assert sorted_urls[0].host == "aaa.com"
        assert sorted_urls[1].host == "mmm.com"
        assert sorted_urls[2].host == "zzz.com"

    def test_sort_urls_by_path(self):
        """URLs with same host should sort by path."""
        urls = [
            parse_url_local("https://example.com/z"),
            parse_url_local("https://example.com/a"),
            parse_url_local("https://example.com/m"),
        ]

        sorted_urls = sorted(urls)

        assert sorted_urls[0].path == "/a"
        assert sorted_urls[1].path == "/m"
        assert sorted_urls[2].path == "/z"

    def test_sort_urls_reverse(self):
        """URLs should be sortable in reverse order."""
        urls = [
            parse_url_local("https://aaa.com/"),
            parse_url_local("https://zzz.com/"),
        ]

        sorted_urls = sorted(urls, reverse=True)

        assert sorted_urls[0].host == "zzz.com"
        assert sorted_urls[1].host == "aaa.com"

    def test_min_max_urls(self):
        """min() and max() should work with URLs."""
        urls = [
            parse_url_local("https://bbb.com/"),
            parse_url_local("https://aaa.com/"),
            parse_url_local("https://ccc.com/"),
        ]

        assert min(urls).host == "aaa.com"
        assert max(urls).host == "ccc.com"

    def test_sort_mixed_schemes(self):
        """URLs with different schemes should sort correctly."""
        urls = [
            parse_url_local("https://example.com/"),
            parse_url_local("http://example.com/"),
            parse_url_local("ftp://example.com/"),
        ]

        sorted_urls = sorted(urls)

        # ftp < http < https (lexicographic)
        assert sorted_urls[0].scheme == "ftp"
        assert sorted_urls[1].scheme == "http"
        assert sorted_urls[2].scheme == "https"

    def test_sort_preserves_duplicates(self):
        """Sorting should preserve duplicate URLs."""
        urls = [
            parse_url_local("https://example.com/"),
            parse_url_local("https://example.com/"),
            parse_url_local("https://aaa.com/"),
        ]

        sorted_urls = sorted(urls)

        assert len(sorted_urls) == 3
        assert sorted_urls[0].host == "aaa.com"
        assert sorted_urls[1].host == "example.com"
        assert sorted_urls[2].host == "example.com"


class TestURLStringComparison:
    """Regression tests: a URL must compare directly against a plain string.

    This worked once (the __lt__/__le__/__gt__/__ge__/__eq__ operators had an
    explicit ``isinstance(other, str)`` branch) but was silently dropped when
    those operators were moved into _comparison.py's _URLComparison during
    the url.py/__init__.py decomposition -- every comparison there only
    checked ``isinstance(other, type(url))``, so a URL no longer compared
    equal (or orderable) to the exact string it was parsed from.
    """

    def test_url_equals_its_own_string(self):
        url = parse_url_local("https://example.com/path")
        assert url == "https://example.com/path"
        assert "https://example.com/path" == url

    def test_url_not_equal_to_different_string(self):
        url = parse_url_local("https://example.com/path")
        assert url != "https://example.com/other"

    def test_url_ordering_against_string(self):
        url = parse_url_local("https://bbb.com/")
        assert url > "https://aaa.com/"
        assert url < "https://ccc.com/"
        assert url >= "https://bbb.com/"
        assert url <= "https://bbb.com/"
