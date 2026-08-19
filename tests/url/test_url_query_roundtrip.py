"""Query round-trip fidelity and mutation correctness.

Regression coverage for two defects fixed in 0.7.0:

* Query mutators (``with_query``, ``with_query_param``,
  ``without_query_param``) were silent no-ops.
* Parsing re-serialized the query from decoded pairs, which corrupted data.
  ``quote_plus`` treats ``+``, ``&`` and ``=`` as safe, so a decoded literal
  ``+`` came back bare (decoding as a space next pass) and a decoded literal
  ``&`` came back as a *delimiter*, turning one parameter into two.
"""

from urllib.parse import parse_qsl

import pytest

from urlps import parse_url

BASE = "https://example.com/p"

try:
    from hypothesis import given, settings
    from hypothesis import strategies as st

    class TestQueryRoundTripProperties:
        """Property-based coverage of the round-trip invariant."""

        @staticmethod
        def _queries():
            safe_key = st.text(
                alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd")),
                min_size=1,
                max_size=8,
            )
            safe_value = st.text(
                alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd")),
                min_size=0,
                max_size=8,
            )
            pair = st.tuples(safe_key, safe_value).map(lambda kv: f"{kv[0]}={kv[1]}")
            return st.lists(pair, min_size=1, max_size=5).map("&".join)

        @given(query=_queries.__func__())
        @settings(max_examples=200, deadline=None)
        def test_parse_preserves_query_exactly(self, query):
            url = parse_url(f"{BASE}?{query}")
            assert url.query == query
            assert str(url) == f"{BASE}?{query}"

        @given(query=_queries.__func__())
        @settings(max_examples=200, deadline=None)
        def test_stringification_is_idempotent(self, query):
            once = str(parse_url(f"{BASE}?{query}"))
            assert str(parse_url(once)) == once

        @given(
            value=st.text(
                # Printable ASCII excluding '%': a literal '%' encodes to '%25',
                # which the double-encoding check rejects by design, so it is not
                # a valid input for a round-trip property.
                alphabet=st.characters(min_codepoint=32, max_codepoint=126, blacklist_characters="%"),
                min_size=1,
                max_size=20,
            )
        )
        @settings(max_examples=200, deadline=None)
        def test_percent_encoded_value_never_gains_a_parameter(self, value):
            """However a value is encoded, it must decode back to one parameter.

            This is the general form of the smuggling regression: no matter what a
            value contains -- '&', '=', '+' included -- encoding it must yield
            exactly one parameter that decodes back to the original.
            """
            from urllib.parse import quote

            encoded = quote(value, safe="")
            url = parse_url(f"{BASE}?q={encoded}", policy="balanced")
            assert len(url.query_params) == 1
            assert url.query_params[0] == ("q", value)
            # And it must survive a full string round trip.
            assert parse_url(str(url), policy="balanced").query_params == [("q", value)]

        @given(
            value=st.text(
                alphabet=st.characters(min_codepoint=32, max_codepoint=126, blacklist_characters="%"),
                min_size=1,
                max_size=20,
            )
        )
        @settings(max_examples=200, deadline=None)
        def test_mutation_never_gains_a_parameter(self, value):
            """Re-serialization on the mutation path must also stay injective."""
            from urllib.parse import quote

            url = parse_url(f"{BASE}?q={quote(value, safe='')}", policy="balanced")
            mutated = url.with_query_param("extra", "1")
            assert parse_url(str(mutated), policy="balanced").query_params == [("q", value), ("extra", "1")]

except ImportError:
    pass


class TestQueryRoundTrip:
    """Parsing must not rewrite the query string."""

    @pytest.mark.parametrize(
        "query",
        [
            "a=hello%20world",  # %20 must not become '+'
            "sig=aGVsbG8%3D&x=1",  # base64 padding must survive verbatim
            "q=C%2B%2B",  # encoded '+' must not become a bare '+'
            "q=a+%26+b",  # encoded '&' must not become a delimiter
            "a=1&b=2",
            "flag",
            "a=1&&b=2",  # semantically empty chunk is still preserved
            "empty=",
            "k=%E2%9C%93",
            "a%5Bb%5D=c",  # encoded brackets
        ],
    )
    def test_query_survives_parse_unchanged(self, query):
        url = parse_url(f"{BASE}?{query}", policy="balanced")
        assert url.query == query
        assert str(url) == f"{BASE}?{query}"

    @pytest.mark.parametrize(
        "query",
        ["a=hello%20world", "q=C%2B%2B", "q=a+%26+b", "sig=aGVsbG8%3D&x=1"],
    )
    def test_stringification_is_idempotent(self, query):
        """str(parse(str(parse(x)))) must equal str(parse(x))."""
        once = str(parse_url(f"{BASE}?{query}"))
        twice = str(parse_url(once))
        assert once == twice

    def test_encoded_ampersand_does_not_smuggle_a_parameter(self):
        """The parameter-smuggling regression.

        `?q=a+%26+b` is one parameter whose value contains '&'. Re-serializing
        it emitted a bare '&', so re-parsing produced two parameters and an
        attacker could inject one through a proxy that echoed str(url).
        """
        url = parse_url(f"{BASE}?q=a+%26+b")
        assert url.query_params == [("q", "a & b")]

        reparsed = parse_url(str(url))
        assert reparsed.query_params == [("q", "a & b")]
        assert len(reparsed.query_params) == 1

    def test_encoded_plus_is_not_downgraded_to_space(self):
        url = parse_url(f"{BASE}?q=C%2B%2B")
        assert url.query_params == [("q", "C++")]
        assert parse_url(str(url)).query_params == [("q", "C++")]

    def test_base64_signature_survives_round_trip(self):
        """A signature over the raw query must still verify after a round trip."""
        raw = "sig=aGVsbG8%3D&x=1"
        url = parse_url(f"{BASE}?{raw}")
        assert url.query == raw

    def test_decoded_pairs_match_stdlib(self):
        """Decoded pairs should agree with urllib for ordinary queries."""
        query = "a=hello%20world&b=x+y&c=%26"
        url = parse_url(f"{BASE}?{query}")
        assert url.query_params == parse_qsl(query, keep_blank_values=True)


class TestQueryMutators:
    """Mutators must actually produce a changed URL, not return self unchanged."""

    def test_without_query_param_removes_it(self):
        url = parse_url(f"{BASE}?a=1&b=2")
        result = url.without_query_param("a")
        assert result.query_params == [("b", "2")]
        assert str(result) == f"{BASE}?b=2"

    def test_without_query_param_removes_all_occurrences(self):
        url = parse_url(f"{BASE}?a=1&b=2&a=3")
        assert url.without_query_param("a").query_params == [("b", "2")]

    def test_with_query_param_appends(self):
        url = parse_url(f"{BASE}?a=1")
        result = url.with_query_param("b", "2")
        assert result.query_params == [("a", "1"), ("b", "2")]
        assert str(result) == f"{BASE}?a=1&b=2"

    def test_with_query_param_on_url_without_query(self):
        url = parse_url(BASE)
        assert url.with_query_param("a", "1").query_params == [("a", "1")]

    def test_with_query_replaces_wholesale(self):
        url = parse_url(f"{BASE}?a=1&b=2")
        result = url.with_query("c=3")
        assert result.query == "c=3"
        assert result.query_params == [("c", "3")]
        assert str(result) == f"{BASE}?c=3"

    def test_without_query_clears_query_and_fragment(self):
        url = parse_url(f"{BASE}?a=1#frag")
        result = url.without_query()
        assert result.query is None
        assert result.query_params == []
        assert str(result) == BASE

    def test_mutators_do_not_affect_the_original(self):
        url = parse_url(f"{BASE}?a=1")
        url.with_query_param("b", "2")
        url.without_query_param("a")
        assert url.query_params == [("a", "1")]

    def test_mutation_re_encodes_but_preserves_meaning(self):
        """Explicit mutation may canonicalise encoding; it must not lose data."""
        url = parse_url(f"{BASE}?q=a+%26+b")
        result = url.with_query_param("x", "1")
        # The '&'-containing value must still be a single parameter.
        assert result.query_params[0] == ("q", "a & b")
        assert ("x", "1") in result.query_params
        assert parse_url(str(result)).query_params == result.query_params


class TestCopyQueryCoherence:
    """`query` and `query_pairs` are one value; copy() must not let them drift."""

    def test_overriding_query_rederives_pairs(self):
        url = parse_url(f"{BASE}?a=1&b=2")
        result = url.copy(query="c=3")
        assert result.query == "c=3"
        assert result.query_params == [("c", "3")]

    def test_overriding_pairs_rederives_query(self):
        url = parse_url(f"{BASE}?a=1&b=2")
        result = url.copy(query_pairs=[("c", "3")])
        assert result.query_params == [("c", "3")]
        assert result.query == "c=3"

    def test_copy_without_query_override_preserves_both(self):
        url = parse_url(f"{BASE}?q=C%2B%2B")
        result = url.copy(host="other.example.com")
        assert result.query == "q=C%2B%2B"
        assert result.query_params == [("q", "C++")]

    def test_copy_initialises_audit_manager(self):
        """copy() left _audit_manager unset, so touching it raised AttributeError."""
        url = parse_url(f"{BASE}?a=1")
        assert hasattr(url.copy(), "_audit_manager")
        assert hasattr(url.with_query_param("b", "2"), "_audit_manager")
