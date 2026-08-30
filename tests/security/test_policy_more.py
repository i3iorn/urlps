"""Additional coverage for _security/policy.py: __str__ and unknown policy name."""

from __future__ import annotations

import pytest

from urlps import SecurityPolicy
from urlps._security.policy import resolve_security_policy
from urlps.exceptions import SecurityPolicyError


def test_str_reports_policy_name():
    assert str(SecurityPolicy.strict()) == "SecurityPolicy(name='strict')"


def test_resolve_unknown_named_policy_raises():
    with pytest.raises(SecurityPolicyError, match="Unsupported security policy"):
        resolve_security_policy("not-a-real-policy")


def test_enforce_suspicious_punycode_true_warns_deprecated():
    """The field gates nothing; explicitly enabling it should warn, not silently no-op."""
    with pytest.warns(DeprecationWarning, match="enforce_suspicious_punycode"):
        SecurityPolicy(name="strict", enforce_suspicious_punycode=True)


def test_enforce_suspicious_punycode_default_false_does_not_warn():
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        SecurityPolicy(name="strict")
