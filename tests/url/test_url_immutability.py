"""URL objects must actually be immutable, not immutable by convention.

The README has always advertised immutable URL objects, but before 1.0
``u._host = "evil.com"`` worked and changed ``str(u)``. That is a security
problem, not just a documentation one: a URL validated by ``parse_url()``
could be pointed somewhere else afterwards while still presenting itself as
validated.

The slot list is read from ``URL.__slots__`` rather than hardcoded, so a slot
added later is covered automatically instead of quietly escaping these tests.
"""

from __future__ import annotations

import copy
import pickle

import pytest

import urlps
from urlps import URL, SecurityPolicy, parse_url

BASE = "https://user:pw@example.com/a/b?z=1&a=2#frag"

ALL_SLOTS = list(URL.__slots__)


@pytest.fixture
def url() -> URL:
    return parse_url(BASE)


# ---------------------------------------------------------------------------
# The guard itself
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("slot", ALL_SLOTS)
def test_every_slot_rejects_assignment(url: URL, slot: str) -> None:
    with pytest.raises(AttributeError, match="immutable"):
        setattr(url, slot, "mutated")


@pytest.mark.parametrize("slot", ALL_SLOTS)
def test_every_slot_rejects_deletion(url: URL, slot: str) -> None:
    """``del u._host`` would otherwise be a trivial way around __setattr__."""
    with pytest.raises(AttributeError, match="immutable"):
        delattr(url, slot)


def test_unknown_attribute_also_rejected(url: URL) -> None:
    with pytest.raises(AttributeError, match="immutable"):
        url.some_new_attribute = 1


def test_mutation_attempt_leaves_the_url_intact(url: URL) -> None:
    """The point of the guard: the URL must not be re-pointable after validation."""
    before = str(url)
    with pytest.raises(AttributeError):
        url._host = "evil.com"
    assert str(url) == before
    assert url.host == "example.com"


def test_error_message_names_the_alternative(url: URL) -> None:
    with pytest.raises(AttributeError) as excinfo:
        url._host = "evil.com"
    message = str(excinfo.value)
    assert "with_*()" in message
    assert "_host" in message


# ---------------------------------------------------------------------------
# Derivation must still work -- a freeze that breaks with_*() is useless
# ---------------------------------------------------------------------------


def test_with_methods_return_new_objects(url: URL) -> None:
    derived = [
        url.with_scheme("http"),
        url.with_host("other.example"),
        url.with_port(8443),
        url.with_path("/z"),
        url.with_query("q=1"),
        url.with_fragment("other"),
        url.with_userinfo("someone"),
        url.with_query_param("extra", "1"),
        url.without_query_param("z"),
        url.without_query(),
    ]
    for new_url in derived:
        assert isinstance(new_url, URL)
        assert new_url is not url
    assert str(url) == BASE, "deriving must not disturb the original"


def test_copy_and_canonicalize_still_work(url: URL) -> None:
    assert url.copy(path="/other").path == "/other"
    # canonicalize() used to write _query_pairs after construction; it now
    # passes query and query_pairs together through copy().
    canonical = url.canonicalize()
    assert canonical.query == "a=2&z=1"
    assert canonical.query_params == [("a", "2"), ("z", "1")]


def test_derived_urls_are_themselves_frozen(url: URL) -> None:
    for new_url in (url.with_path("/z"), url.copy(path="/y"), url.canonicalize()):
        with pytest.raises(AttributeError, match="immutable"):
            new_url._host = "evil.com"


# ---------------------------------------------------------------------------
# copy / deepcopy / pickle
# ---------------------------------------------------------------------------


def test_shallow_copy_is_safe(url: URL) -> None:
    assert copy.copy(url) is url


def test_deep_copy_is_safe(url: URL) -> None:
    """Default deepcopy reconstructs slot-by-slot via __setattr__ and would trip the guard."""
    assert copy.deepcopy(url) is url


def test_pickle_round_trip(url: URL) -> None:
    restored = pickle.loads(pickle.dumps(url))
    assert str(restored) == str(url)
    assert restored == url
    assert hash(restored) == hash(url)


def test_unpickled_url_is_still_frozen(url: URL) -> None:
    restored = pickle.loads(pickle.dumps(url))
    with pytest.raises(AttributeError, match="immutable"):
        restored._host = "evil.com"


def test_unpickled_url_can_still_derive(url: URL) -> None:
    """Collaborators are rebuilt on unpickle, so the object stays fully usable."""
    restored = pickle.loads(pickle.dumps(url))
    assert restored.with_path("/q").path == "/q"
    assert restored.canonicalize().host == "example.com"


def test_pickle_works_for_a_policy_holding_a_lock() -> None:
    """The DNS rate limiter holds a thread lock; it must not break serialization."""
    url = parse_url("https://example.com/", policy=SecurityPolicy.strict())
    assert str(pickle.loads(pickle.dumps(url))) == str(url)


# ---------------------------------------------------------------------------
# validate() is pure
# ---------------------------------------------------------------------------


def test_validate_does_not_rewrite_recorded_findings() -> None:
    """Asking a hypothetical must not overwrite the URL's own verdict."""
    url = parse_url("https://example.com/", policy="balanced")
    before = url.security_findings

    url.validate(policy=SecurityPolicy.strict(), raise_on_error=False)

    assert url.security_findings == before


def test_validate_still_returns_findings() -> None:
    url = parse_url(
        "http://169.254.169.254/latest/meta-data/",
        policy=SecurityPolicy.internal(enforce_ssrf=False),
    )
    findings = url.validate(policy=SecurityPolicy.strict(), raise_on_error=False)
    assert any(f.code == urlps.ErrorCode.SSRF_RISK.value for f in findings)


def test_security_findings_property_returns_a_defensive_copy(url: URL) -> None:
    findings = url.security_findings
    findings.append("not a finding")  # type: ignore[arg-type]
    assert url.security_findings != findings


# ---------------------------------------------------------------------------
# Identity invariants
# ---------------------------------------------------------------------------


def test_hash_is_stable_across_derivation_and_serialization(url: URL) -> None:
    original = hash(url)
    url.with_path("/z")
    url.canonicalize()
    pickle.loads(pickle.dumps(url))
    assert hash(url) == original


def test_url_is_usable_as_a_dict_key_and_set_member() -> None:
    a, b = parse_url(BASE), parse_url(BASE)
    assert len({a, b}) == 1
    assert {a: "value"}[b] == "value"
