# Architecture

This is a map of the module layering, verified against the actual import
graph rather than assumed. It exists to reduce two specific risks that have
already caused real bugs in this project:

1. **Duplicated logic across modules that don't know about each other.** The
   `"://"` substring-matching bug (fixed for 0.6.1) was independently
   reintroduced in `_relative.py` and only caught later, because nothing
   documented that both modules were doing the same kind of parsing.
2. **New logic landing in the wrong layer.** In particular: parsing and
   security validation are deliberately separate passes (see below) — a
   change that "fixes" a security gap by adding a check inside the parser
   itself would be fighting that design rather than following it.

## Layers

Each layer only imports from layers above it in this list (verified via the
actual `from .` import statements, not inferred):

```
constants.py, exceptions.py, _patterns.py, _components.py, _resolve.py
        |  (no dependencies on the rest of the package)
        v
_validation.py, _builder.py, _relative.py
_security/ip_utils.py, _security/policy.py, _security/url_checks.py
        |
        v
_security/dns_guard.py, _security/phishing_db.py
        |
        v
_security/__init__.py            (aggregates every _security/* submodule)
        |
        v
_parser.py                       (pure syntax; does NOT import _security)
        |
        v
_audit.py                        (imports _security, for redact_url_for_logs)
        |
        v
url.py                           (the URL class; ties parser + security + audit together)
        |
        v
__init__.py                      (public API: parse_url, parse_url_unsafe, join, build, ...)
```

## The parse/validate split (the important part)

**`_parser.py` knows nothing about security.** It resolves the grammar of a
URL — scheme, authority, path, query, fragment, percent-encoding,
`.`/`..` normalization — and rejects only what's structurally invalid
(malformed IPv6 literals, control characters, oversized components). It does
not know what SSRF is, does not check for private IP ranges, and does not
import anything from `_security/`.

**`url.py` runs security validation as a separate pass after parsing
succeeds.** `URL.__init__` calls `self._parser.parse(url)` first, then
`self.validate(...)`, which delegates to `_security.validate_url_security`.
A syntactically valid URL can still be rejected at that second step (e.g.
`http://127.0.0.1/` parses fine and is rejected only by the SSRF check).

This split is why `parse_url_unsafe()` and `parse_url()` can share the exact
same parser: the difference between them is entirely which `SecurityPolicy`
gets applied in the second pass, not a different parsing codepath. If you're
adding a new check, it belongs in `_security/`, not `_parser.py` — a check
added to the parser runs unconditionally for both functions and can't be
gated by policy the way everything else is.

## Where "relative URL" logic lives

Three modules touch this and it's easy to reach for the wrong one:

- **`_resolve.py`** — RFC 3986 §5 reference resolution (`remove_dot_segments`,
  `merge_paths`, `transform_reference`). This is the only module that knows
  how to resolve a reference *against a base URI*. If you're adding
  anything involving a base URL, it belongs here.
- **`_relative.py`** — splits a bare reference (no base) into
  path/query/fragment and rejoins it. It uses `_resolve.py`'s
  `split_uri_reference` internally to reject references that turn out to be
  absolute, but it does not do resolution itself.
- **`url.py`** — re-exports both (`parse_relative_reference`,
  `build_relative_reference`, `round_trip_relative` from `_relative.py`) and
  additionally exposes `join()` (in `__init__.py`) as the validated,
  public-facing wrapper around `_resolve.py`.

If you find yourself writing a third implementation of dot-segment removal
or reference splitting, one of the two existing ones is very likely already
doing what you need.

## `_security/` internals

`_security/__init__.py` is the aggregation point — nothing outside
`_security/` should import a submodule directly (with the historical
exception of `dns_guard.DNSRateLimiter`/`DNSRateLimiterConfig`, which are
also re-exported from the top-level `urlps` package for dependency
injection). The submodules:

- **`ip_utils.py`** — SSRF-relevant IP classification: private-range checks,
  the obfuscated-IPv4 grammar (`_parse_inet_aton_ipv4`), IPv6 zone-ID
  validation. Every predicate here is expected to **fail closed**: an
  address that can't be parsed or verified is treated as unsafe, never as
  safe-by-default. If you add a new check here, preserve that invariant.
- **`url_checks.py`** — the largest submodule (~700 lines) and doing the
  most unrelated things: canonicalization, credential detection,
  homograph/mixed-script detection, parser-confusion detection, and the
  query-injection heuristic. See `docs/design/heuristics.md` for why two of
  these checks (`has_query_injection`, `has_suspicious_punycode`) are
  known-weak and left deliberately undecided rather than trusted.
- **`dns_guard.py`** — DNS rebinding checks and the `DNSRateLimiter`.
  Performs real network I/O (resolution + a verification connect) when
  `check_dns=True`; see its module docstring for the timeout/thread-pool
  design.
- **`phishing_db.py`** — the phishing-domain database: lazy download,
  cooldown-gated retry, thread-safe refresh.
- **`policy.py`** — `SecurityPolicy` and the `"strict"`/`"balanced"`/
  `"internal"` presets. This is the single place that decides which checks
  in `url_checks.py`/`ip_utils.py`/`dns_guard.py`/`phishing_db.py` actually
  run for a given parse.

## Public API surface

`__init__.py` is intentionally thin: it resolves a policy, builds a
`Parser`, and constructs a `URL`. The actual work happens in `url.py` and
`_security/`. If a new top-level function is warranted, it should follow
that same shape rather than reimplementing parsing or validation inline.
