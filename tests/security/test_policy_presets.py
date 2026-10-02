"""Presets are derived, not hand-listed (M1).

internal and local used to repeat every heuristic flag as False, so a new
heuristic defaulting to True would silently turn on in both; and the preset
keyword lists covered only some fields.
"""

from __future__ import annotations

import warnings
from dataclasses import fields

import pytest

from urlps import SecurityPolicy
from urlps._security.policy import _heuristics_off

#: Fields named enforce_* that are not heuristics the trusted presets drop.
NOT_HEURISTICS = {"enforce_ssrf", "enforce_dns_rate_limit", "enforce_suspicious_punycode"}


def test_every_on_by_default_enforce_flag_is_marked_as_a_heuristic() -> None:
    """Guards the marker itself: a new enforce_* check must say what it is."""
    unmarked = [
        f.name
        for f in fields(SecurityPolicy)
        if f.name.startswith("enforce_")
        and f.default is True
        and f.name not in NOT_HEURISTICS
        and not f.metadata.get("heuristic")
    ]
    assert unmarked == []


@pytest.mark.parametrize("preset", [SecurityPolicy.internal, SecurityPolicy.local])
def test_trusted_presets_turn_every_heuristic_off(preset) -> None:
    policy = preset()
    assert all(getattr(policy, name) is False for name in _heuristics_off())
    assert policy.enforce_ssrf is True


def test_presets_accept_any_field_as_an_override() -> None:
    assert SecurityPolicy.strict(dns_deadline_seconds=2.0).dns_deadline_seconds == 2.0
    assert SecurityPolicy.local(allowed_schemes={"http", "https", "ws"}).allowed_schemes == {"http", "https", "ws"}
    assert SecurityPolicy.internal(enforce_ssrf=False).enforce_ssrf is False
    assert SecurityPolicy.local(enforce_path_traversal=True).enforce_path_traversal is True


def test_unknown_or_name_overrides_are_rejected() -> None:
    with pytest.raises(TypeError):
        SecurityPolicy.strict(no_such_field=True)
    with pytest.raises(TypeError):
        SecurityPolicy.strict(name="other")


def test_deprecated_fail_open_warning_points_at_the_caller() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        SecurityPolicy.strict(dns_fail_open_on_connect_error=True)
    assert caught and caught[0].category is DeprecationWarning
    assert caught[0].filename == __file__
