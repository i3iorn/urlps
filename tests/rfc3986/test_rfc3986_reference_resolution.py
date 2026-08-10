"""RFC 3986 Section 5 reference resolution conformance.

The Section 5.4 example tables are reproduced verbatim and driven as data.
They are the canonical conformance suite for reference resolution, and the
abnormal set in particular is where implementations usually diverge.
"""
import pytest

from urlps import InvalidURLError, join, parse_url
from urlps._resolve import (
    merge_paths,
    recompose,
    remove_dot_segments,
    resolve_reference,
    split_uri_reference,
)

# RFC 3986 Section 5.4
RFC_BASE = "http://a/b/c/d;p?q"

# Section 5.4.1 -- Normal Examples
NORMAL_EXAMPLES = [
    ("g:h", "g:h"),
    ("g", "http://a/b/c/g"),
    ("./g", "http://a/b/c/g"),
    ("g/", "http://a/b/c/g/"),
    ("/g", "http://a/g"),
    ("//g", "http://g"),
    ("?y", "http://a/b/c/d;p?y"),
    ("g?y", "http://a/b/c/g?y"),
    ("#s", "http://a/b/c/d;p?q#s"),
    ("g#s", "http://a/b/c/g#s"),
    ("g?y#s", "http://a/b/c/g?y#s"),
    (";x", "http://a/b/c/;x"),
    ("g;x", "http://a/b/c/g;x"),
    ("g;x?y#s", "http://a/b/c/g;x?y#s"),
    ("", "http://a/b/c/d;p?q"),
    (".", "http://a/b/c/"),
    ("./", "http://a/b/c/"),
    ("..", "http://a/b/"),
    ("../", "http://a/b/"),
    ("../g", "http://a/b/g"),
    ("../..", "http://a/"),
    ("../../", "http://a/"),
    ("../../g", "http://a/g"),
]

# Section 5.4.2 -- Abnormal Examples
ABNORMAL_EXAMPLES = [
    # Excess ".." segments are discarded rather than escaping the root.
    ("../../../g", "http://a/g"),
    ("../../../../g", "http://a/g"),
    # "." and ".." only count as complete path segments.
    ("/./g", "http://a/g"),
    ("/../g", "http://a/g"),
    ("g.", "http://a/b/c/g."),
    (".g", "http://a/b/c/.g"),
    ("g..", "http://a/b/c/g.."),
    ("..g", "http://a/b/c/..g"),
    # Nonsensical but legal dot-segment combinations.
    ("./../g", "http://a/b/g"),
    ("./g/.", "http://a/b/c/g/"),
    ("g/./h", "http://a/b/c/g/h"),
    ("g/../h", "http://a/b/c/h"),
    ("g;x=1/./y", "http://a/b/c/g;x=1/y"),
    ("g;x=1/../y", "http://a/b/c/y"),
    # Dot segments in query or fragment are data, not path syntax.
    ("g?y/./x", "http://a/b/c/g?y/./x"),
    ("g?y/../x", "http://a/b/c/g?y/../x"),
    ("g#s/./x", "http://a/b/c/g#s/./x"),
    ("g#s/../x", "http://a/b/c/g#s/../x"),
]


class TestRFC5241NormalExamples:
    @pytest.mark.parametrize(("reference", "expected"), NORMAL_EXAMPLES)
    def test_normal_example(self, reference, expected):
        assert resolve_reference(RFC_BASE, reference) == expected


class TestRFC5242AbnormalExamples:
    @pytest.mark.parametrize(("reference", "expected"), ABNORMAL_EXAMPLES)
    def test_abnormal_example(self, reference, expected):
        assert resolve_reference(RFC_BASE, reference) == expected

    def test_same_scheme_reference_strict_vs_non_strict(self):
        """RFC 3986 5.4.2: `http:g` differs between strict and legacy parsers."""
        assert resolve_reference(RFC_BASE, "http:g") == "http:g"
        assert resolve_reference(RFC_BASE, "http:g", strict=False) == "http://a/b/c/g"


class TestRemoveDotSegments:
    """RFC 3986 Section 5.2.4, including the worked examples in the RFC text."""

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("/a/b/c/./../../g", "/a/g"),      # RFC 5.2.4 example 1
            ("mid/content=5/../6", "mid/6"),   # RFC 5.2.4 example 2
            ("", ""),
            ("/", "/"),
            (".", ""),
            ("..", ""),
            ("/.", "/"),
            ("/..", "/"),
            ("./", ""),
            ("../", ""),
            ("/a/b/", "/a/b/"),
            ("/a/./b", "/a/b"),
            ("/a/../b", "/b"),
            # Rootless path where '..' consumes a segment: step C replaces the
            # "/../" prefix with "/", so a leading slash appears. This differs
            # from posixpath.normpath (which gives "c") and is correct per the
            # literal algorithm -- verified to agree with urllib.urljoin once
            # used in a real resolution.
            ("a/b/../../c", "/c"),
        ],
    )
    def test_remove_dot_segments(self, path, expected):
        assert remove_dot_segments(path) == expected

    @pytest.mark.parametrize(
        "reference",
        ["a/b/../../c", "a/b/../c", "mid/content=5/../6"],
    )
    def test_agrees_with_stdlib_on_rootless_references(self, reference):
        """Cross-check against urllib, an independent RFC 3986 implementation."""
        from urllib.parse import urljoin

        base = "http://h/base/x"
        assert resolve_reference(base, reference) == urljoin(base, reference)

    @pytest.mark.parametrize(
        "path",
        ["/../../../etc/passwd", "/a/../../../../etc/passwd", "../../../../.."],
    )
    def test_dot_segments_cannot_escape_the_root(self, path):
        """Excess '..' is discarded, so traversal cannot climb above root."""
        result = remove_dot_segments(path)
        assert ".." not in result
        assert not result.startswith("/..")


class TestMergePaths:
    """RFC 3986 Section 5.2.3."""

    def test_authority_with_empty_base_path_gets_root(self):
        assert merge_paths("example.com", "", "g") == "/g"

    def test_replaces_last_segment_of_base(self):
        assert merge_paths("example.com", "/b/c/d;p", "g") == "/b/c/g"

    def test_base_path_without_slash(self):
        assert merge_paths(None, "b", "g") == "g"


class TestSplitAndRecompose:
    """The undefined-vs-empty distinction is load-bearing (Sections 5.2.2/5.3)."""

    def test_undefined_query_differs_from_empty_query(self):
        assert split_uri_reference("http://a/b").query is None
        assert split_uri_reference("http://a/b?").query == ""

    def test_undefined_fragment_differs_from_empty_fragment(self):
        assert split_uri_reference("http://a/b").fragment is None
        assert split_uri_reference("http://a/b#").fragment == ""

    def test_undefined_authority_differs_from_empty_authority(self):
        assert split_uri_reference("mailto:x@y").authority is None
        assert split_uri_reference("file:///tmp").authority == ""

    @pytest.mark.parametrize(
        "uri",
        [
            "http://a/b/c/d;p?q",
            "http://a/b?",
            "http://a/b#",
            "mailto:user@example.com",
            "//example.com/path",
            "/absolute/path",
            "relative/path",
            "?query-only",
            "#fragment-only",
            "",
        ],
    )
    def test_split_recompose_round_trip(self, uri):
        assert recompose(split_uri_reference(uri)) == uri

    def test_empty_reference_inherits_base_query(self):
        """RFC 5.2.2: an empty reference keeps the base query; '?' clears it."""
        assert resolve_reference(RFC_BASE, "") == "http://a/b/c/d;p?q"
        assert resolve_reference(RFC_BASE, "?") == "http://a/b/c/d;p?"


class TestJoinPublicAPI:
    """`join()` resolves and then validates, keeping the security perimeter."""

    def test_returns_validated_url_object(self):
        result = join("https://example.com/a/b", "../c")
        assert isinstance(result, type(parse_url("https://example.com/")))
        assert str(result) == "https://example.com/c"

    def test_accepts_url_objects_for_both_arguments(self):
        base = parse_url("https://example.com/a/b")
        assert str(join(base, "c")) == "https://example.com/a/c"

    def test_fragment_only_reference(self):
        assert str(join("https://example.com/a", "#s")) == "https://example.com/a#s"

    def test_query_only_reference(self):
        assert str(join("https://example.com/a", "?q=1")) == "https://example.com/a?q=1"

    def test_protocol_relative_reference_replaces_authority(self):
        """A '//host' reference legitimately swaps the host.

        This is precisely why the *result* must be re-validated rather than
        trusted because the base was trusted.
        """
        assert str(join("https://example.com/a/", "//other.example/x")) == "https://other.example/x"

    def test_resolved_target_is_security_validated(self):
        """Resolution must not be an escape hatch around parse_url's checks."""
        with pytest.raises(InvalidURLError):
            join("https://example.com/a/", "//localhost/admin")

    def test_resolved_target_respects_policy(self):
        with pytest.raises(InvalidURLError):
            join("https://example.com/a/", "//192.168.1.1/x")

    def test_traversal_reference_cannot_escape_authority(self):
        result = join("https://example.com/a/b", "../../../../etc/passwd")
        assert result.host == "example.com"
        assert str(result) == "https://example.com/etc/passwd"

    def test_query_is_preserved_through_join(self):
        """Resolution must not reintroduce the query-encoding corruption."""
        result = join("https://example.com/a/b", "c?q=a+%26+b")
        assert result.query == "q=a+%26+b"
        assert result.query_params == [("q", "a & b")]

    def test_relative_base_is_rejected(self):
        with pytest.raises(ValueError, match="absolute"):
            join("/not/absolute", "x")

    def test_non_string_arguments_rejected(self):
        with pytest.raises(TypeError):
            join(123, "x")
        with pytest.raises(TypeError):
            join("https://example.com/", 123)
