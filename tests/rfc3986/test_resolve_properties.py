"""Property-based coverage for RFC 3986 Section 5 path arithmetic.

Property-based testing has already caught two real bugs in this project
(the `QUERY_SAFE` mutation-path corruption and a hypothesis-collection
`NameError`, both in the query round-trip tests), but until now it only
covered query strings and the fixed RFC 5.4 example tables. This extends it
to `remove_dot_segments`/`merge_paths`, the other place doing non-trivial
parsing logic with a lot of edge cases (a trailing `/.`, a `..` that would
try to escape the root, a bare `..`) that a fixed example table can miss.
"""

import string

import pytest

from urlps._resolve import merge_paths, remove_dot_segments

try:
    from hypothesis import given, settings
    from hypothesis import strategies as st

    _PATH_ALPHABET = string.ascii_lowercase[:4] + "./"

    class TestRemoveDotSegmentsProperties:
        """Property-based coverage of RFC 3986 Section 5.2.4."""

        @staticmethod
        def _paths():
            return st.text(alphabet=_PATH_ALPHABET, min_size=0, max_size=20)

        @given(path=_paths.__func__())
        @settings(max_examples=300, deadline=None)
        def test_output_never_contains_a_dot_segment(self, path):
            """The whole point of the algorithm: no output segment is
            literally '.' or '..' -- those are always consumed, never
            passed through. (A segment that merely *contains* dots, like
            '..a', is untouched -- only exact '.'/'..' segments are
            special per the RFC.)"""
            result = remove_dot_segments(path)
            segments = result.split("/")
            assert "." not in segments
            assert ".." not in segments

        @given(path=_paths.__func__())
        @settings(max_examples=300, deadline=None)
        def test_idempotent(self, path):
            """A path with no dot segments left should be a fixed point."""
            once = remove_dot_segments(path)
            twice = remove_dot_segments(once)
            assert once == twice

        @given(path=_paths.__func__())
        @settings(max_examples=300, deadline=None)
        def test_never_lengthens_the_path(self, path):
            """Removing segments can only shrink or preserve length, never
            grow it -- a cheap sanity bound distinct from the dot-segment
            property above."""
            result = remove_dot_segments(path)
            assert len(result) <= len(path)

    class TestMergePathsProperties:
        """Property-based coverage of RFC 3986 Section 5.2.3."""

        @staticmethod
        def _base_paths():
            return st.text(alphabet=_PATH_ALPHABET, min_size=0, max_size=15)

        @staticmethod
        def _reference_paths():
            return st.text(alphabet=_PATH_ALPHABET, min_size=0, max_size=15)

        @given(
            base_path=_base_paths.__func__(),
            reference_path=_reference_paths.__func__(),
        )
        @settings(max_examples=300, deadline=None)
        def test_with_authority_and_empty_base_path_prefixes_with_slash(self, base_path, reference_path):
            """RFC 3986 5.2.3: if the base URI has authority and an empty
            path, the merge result is '/' + reference, regardless of what
            the (unused, per this branch) base_path text was."""
            result = merge_paths("example.com", "", reference_path)
            assert result == "/" + reference_path

        @given(
            base_path=_base_paths.__func__(),
            reference_path=_reference_paths.__func__(),
        )
        @settings(max_examples=300, deadline=None)
        def test_result_always_ends_with_the_reference_path(self, base_path, reference_path):
            """Merging only ever prepends base-path directory segments; the
            reference path itself is never truncated or rewritten."""
            result = merge_paths(None, base_path, reference_path)
            assert result.endswith(reference_path)

except ImportError:
    pytest.skip("hypothesis not installed", allow_module_level=True)
