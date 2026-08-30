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
