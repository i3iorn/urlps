"""Regression guard against the fail-open pattern reappearing in `_security/`.

Phase 4 (0.7.0) found and fixed several security predicates that failed
*open* on unparseable/unverifiable input (`except ...: return True` where
`True` meant "safe", or an implicit fall-through with the same effect) --
most notably the obfuscated-IPv4 SSRF bypass in `ip_utils.py`. Nothing
stopped that pattern from being reintroduced in a new check, or in a new
`except` branch added to an existing one, since the fix was applied ad hoc
case by case rather than backed by a standing test.

This test statically scans every `_security/*.py` module for security
predicates (`is_*`, `has_*`, `check_*`, `_check_*`, `_verify_*`) that return
a bare `True`/`False`/`None` literal from inside an `except` block, and
compares the result against `_ALLOWLIST` below. Two failure modes:

- A new exception literal shows up that isn't allowlisted: either the new
  code fails open and needs fixing, or it's a deliberate, reviewed choice
  (e.g. a policy-controlled fallback) that belongs in `_ALLOWLIST` with a
  comment explaining why it's safe.
- An allowlisted entry no longer exists in the code: the allowlist is stale
  and should be trimmed, so it can't hide a *different* regression later.
"""

from __future__ import annotations

import ast
import pathlib

SECURITY_DIR = pathlib.Path(__file__).parent.parent.parent / "src" / "urlps" / "_security"

_PREDICATE_PREFIXES = ("is_", "has_", "check_", "_check_", "_verify_")

# (filename, function_name, literal) -> why this is safe, not a fail-open bug.
#
# Each entry here was reviewed by hand. If you're adding a new one, state
# explicitly what makes it safe (fails closed despite the literal, or is a
# documented/policy-gated tradeoff), not just "it's fine".
_ALLOWLIST = {
    (
        "ip_utils.py",
        "is_malicious_ipv6_zone_id",
        True,
    ): (
        "Fails CLOSED, not open: True here means 'treat as malicious'. An "
        "ambiguous/unparseable zone ID is the one case this function is "
        "supposed to flag, so returning True on a parse error is correct."
    ),
    (
        "ip_utils.py",
        "_check_ipv4_private",
        False,
    ): (
        "Not the terminal verdict: this is one of several OR'd sub-checks "
        "in is_private_ip()/is_ssrf_risk(). 'Not parseable as plain IPv4' "
        "just means this particular representation doesn't match -- it does "
        "not mean the host is declared safe overall."
    ),
    (
        "ip_utils.py",
        "_check_ipv6_private",
        False,
    ): ("Same shape as _check_ipv4_private: one OR'd sub-check, not a terminal safe/unsafe verdict."),
    (
        "ip_utils.py",
        "_check_direct_ip_safe",
        None,
    ): (
        "Returns None (not False) on ValueError, meaning 'not an IP "
        "literal at all' -- explicitly not a safety verdict. Callers "
        "branch on None to fall through to hostname-based checks instead "
        "of treating it as safe."
    ),
    (
        "ip_utils.py",
        "_check_resolved_ips_safe",
        False,
    ): (
        "This IS the fail-closed fix from Phase 4: False on an unparseable "
        "resolved address is deliberately 'unsafe', replacing a prior "
        "`continue` that let unparseable-only results read as safe."
    ),
    (
        "ip_utils.py",
        "_verify_connection_safe",
        False,
    ): (
        "The non-fail_open_on_error except branch (getpeername() "
        "unparseable) is fail-closed by design -- see the function's own "
        "docstring: 'Being unable to determine the peer... always fails "
        "closed.' The other except branch in this same function already "
        "routes through fail_open_on_error explicitly and isn't a bare "
        "literal, so it doesn't appear in this scan."
    ),
    (
        "url_checks.py",
        "has_suspicious_punycode",
        True,
    ): (
        "Fails CLOSED: True means 'suspicious'. A Punycode label that can't "
        "be IDNA-decoded is exactly the ambiguous case this check exists to "
        "flag. (Also currently dead code per docs/design/heuristics.md, but "
        "the fail-closed behavior itself is correct.)"
    ),
    (
        "url_checks.py",
        "has_mixed_scripts",
        False,
    ): (
        "Empty/malformed script-category lookup input can't exhibit mixed "
        "scripts by definition -- False here is 'no finding produced by "
        "this detector', not 'the URL was verified safe'. Detector-style "
        "has_* checks (as opposed to connection/IP safety verdicts) already "
        "default to False when they have nothing to flag; that's their "
        "normal not-applicable return, not a fail-open regression."
    ),
    (
        "url_checks.py",
        "has_path_traversal",
        False,
    ): (
        "Same detector shape as has_mixed_scripts: False means 'this "
        "specific decode attempt found nothing', not 'declared safe'."
    ),
    (
        "url_checks.py",
        "has_credentials",
        False,
    ): (
        "Same detector shape: an unparseable netloc has no extractable "
        "credentials to find, so False ('none found') is correct, not a "
        "safety verdict being widened."
    ),
    (
        "url_checks.py",
        "is_non_canonical_url",
        False,
    ): (
        "Canonicalization-comparison helper, not an SSRF/connection safety "
        "check -- an unparseable URL can't be shown non-canonical against "
        "itself, so False is the correct 'nothing to compare' answer."
    ),
}


def _predicate_except_literals() -> dict[tuple[str, str, object], int]:
    """Map (filename, function, literal) -> line number for every bare
    True/False/None literal returned from an except block inside a
    security-predicate-named function."""
    found: dict[tuple[str, str, object], int] = {}

    for path in sorted(SECURITY_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for func in ast.walk(tree):
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not func.name.startswith(_PREDICATE_PREFIXES):
                continue
            for node in ast.walk(func):
                if not isinstance(node, ast.ExceptHandler):
                    continue
                for stmt in ast.walk(node):
                    if not isinstance(stmt, ast.Return):
                        continue
                    val = stmt.value
                    if isinstance(val, ast.Constant) and val.value in (True, False, None):
                        found[(path.name, func.name, val.value)] = stmt.lineno

    return found


def test_no_unreviewed_fail_open_literals_in_security_predicates():
    found = _predicate_except_literals()

    unreviewed = {key: line for key, line in found.items() if key not in _ALLOWLIST}
    assert not unreviewed, (
        "New except-block literal return(s) found in security predicate "
        f"function(s), not covered by _ALLOWLIST: {unreviewed}. If this is a "
        "genuine fail-open (an unparseable/unverifiable input is treated as "
        "safe), fix it to fail closed instead. If it's deliberate and "
        "reviewed, add it to _ALLOWLIST with a justification comment."
    )


def test_fail_open_allowlist_has_no_stale_entries():
    found = _predicate_except_literals()

    stale = [key for key in _ALLOWLIST if key not in found]
    assert not stale, (
        f"_ALLOWLIST entries no longer found in the code: {stale}. Remove "
        "them so the allowlist can't accidentally cover a future, unrelated "
        "regression at the same (file, function) pair."
    )
