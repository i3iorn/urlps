"""``_apply_overrides`` must preserve every policy field.

A field forgotten during an override silently reverts to its default, which
in a security policy means silently *disabling a check*.

These tests are driven by ``dataclasses.fields(SecurityPolicy)`` rather than a
hardcoded list, so adding a field to the policy automatically extends the
coverage instead of quietly escaping it.
"""

from __future__ import annotations

import dataclasses

import pytest

from urlps import SecurityPolicy
from urlps._security.policy import _apply_overrides, resolve_security_policy

POLICY_NAMES = ["strict", "balanced", "internal", "local"]

#: Fields the override path is *supposed* to change.
OVERRIDDEN = {"check_dns", "check_phishing", "dns_rate_limiter"}

PRESERVED_FIELDS = [f.name for f in dataclasses.fields(SecurityPolicy) if f.name not in OVERRIDDEN]


@pytest.mark.parametrize("name", POLICY_NAMES)
@pytest.mark.parametrize("field_name", PRESERVED_FIELDS)
def test_override_preserves_every_other_field(name: str, field_name: str) -> None:
    base = resolve_security_policy(name)
    overridden = _apply_overrides(base, check_dns=True, check_phishing=True)

    assert getattr(overridden, field_name) == getattr(base, field_name), (
        f"{name}.{field_name} was not preserved through _apply_overrides"
    )


@pytest.mark.parametrize("name", POLICY_NAMES)
def test_override_actually_applies(name: str) -> None:
    base = resolve_security_policy(name)
    overridden = _apply_overrides(base, check_dns=True, check_phishing=True)
    assert overridden.check_dns is True
    assert overridden.check_phishing is True


@pytest.mark.parametrize("name", POLICY_NAMES)
def test_no_op_override_returns_the_same_object(name: str) -> None:
    """Identity, not just equality -- the fast path must avoid rebuilding."""
    base = resolve_security_policy(name)
    assert _apply_overrides(base, check_dns=None, check_phishing=None) is base


@pytest.mark.parametrize("name", POLICY_NAMES)
def test_resolve_via_public_api_preserves_enforcement_flags(name: str) -> None:
    """The same guarantee through the public entry point callers actually use."""
    base = resolve_security_policy(name)
    resolved = resolve_security_policy(name, check_dns=True)

    for field_name in PRESERVED_FIELDS:
        assert getattr(resolved, field_name) == getattr(base, field_name)


def test_every_enforcement_flag_is_covered_by_this_module() -> None:
    """Guard the guard: if a new enforce_*/block_*/allow_* flag appears, it is checked above."""
    flags = {
        f.name
        for f in dataclasses.fields(SecurityPolicy)
        if f.name.startswith(("enforce_", "block_", "allow_", "reject_", "require_"))
    }
    assert flags, "expected at least one enforcement flag"
    assert flags <= set(PRESERVED_FIELDS)


def test_ssrf_is_enforced_by_every_named_policy() -> None:
    """No preset may silently disable SSRF -- that must be an explicit opt-out."""
    for name in POLICY_NAMES:
        assert resolve_security_policy(name).enforce_ssrf is True, name
    assert SecurityPolicy.internal(enforce_ssrf=False).enforce_ssrf is False


def test_only_local_widens_to_private_hosts() -> None:
    for name in POLICY_NAMES:
        expected = name == "local"
        assert resolve_security_policy(name).allow_private_hosts is expected, name
