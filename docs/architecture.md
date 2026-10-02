# Architecture

A map of the module layering, and the few rules that keep it honest. The
layering is not aspirational: it is a contract in `pyproject.toml`
(`[tool.importlinter]`) that CI enforces with `lint-imports`, so a lower
layer importing a higher one -- even inside a function body, which is how
import cycles used to be hidden -- fails the build.

It exists to reduce two specific risks that have already caused real bugs in
this project:

1. **Duplicated logic across modules that don't know about each other.**
   The `"://"` substring bug was reintroduced in `_relative.py` after being
   fixed elsewhere; four dot-segment implementations, four "IDNA then
   normalize" copies and three port grammars had drifted apart by 1.1.4.
   Each rule now has exactly one home (see "One definition per rule").
2. **New logic landing in the wrong layer.** Parsing and security
   validation are deliberately separate passes (see below) -- a check about
   *where a URL goes* added inside the parser would be fighting that design.

## Layers

Higher layers may import lower ones, never the reverse. Modules on the same
line must not import each other.

```
_cli
_entrypoints | _egress          public functions; connect-time SSRF guard
url                             the URL class: parts + context
_mutations | _serialization | _audit
_security                       policy, checks, DNS, phishing, services
_parser                         grammar -> URLParts (normalize_components)
_builder                        URLParts -> string
_validation                     component predicates; the scheme rule
_unicode | _relative | _diagnostics
_normalize | _resolve | _redaction | _helpers
_host | _components | _cache_config | _patterns
constants | exceptions
```

`__init__.py` sits above all of them and only re-exports.

## The parse/validate split (the important part)

**`_parser.py` resolves grammar, not policy.** It splits scheme, authority,
path, query and fragment, and hands the pieces to `normalize_components()`,
which applies RFC 3986 §6.2.2 normalization and IDNA/UTS-46 host encoding and
rejects only what is structurally invalid. The one policy input it takes is
the scheme rule (`allowed_schemes` / `allow_custom_scheme`), applied while
splitting so a dangerous scheme is refused before anything after it is read;
the same rule (`_validation.scheme_rejection`) runs again in the security
pass.

**`url.py` runs security validation as a separate pass after parsing
succeeds.** `URL.__init__` parses, then calls `self.validate(...)`, which
delegates to `_security.validate_url_security`. A syntactically valid URL
can still be rejected at that second step (`http://127.0.0.1/` parses fine
and is rejected only by the SSRF check).

**The second pass validates the parser's output, not a re-parse of the
input.** `validate()` hands `_security` the components the parser produced
(`ParsedComponents`: host, port, userinfo, path, scheme), and every check
about where the URL goes -- SSRF, address rules, IPv6 zone IDs, Unicode host
analysis, dangerous ports, DNS, phishing -- runs on those. The heuristics
that look for things the parser normalizes away (traversal, open redirect,
double encoding, parser confusion) read the raw string *as well*; a finding
on either spelling rejects, so the raw text can only add findings.

This was learned the hard way. `_security` used to extract the host from the
raw string with its own splitter, and wherever that splitter and the parser
disagreed the checks approved one host while `URL.host` was another
(`http://169.254.169.254?`, `127。0。0。1`). The path joined the set once
empty segments were kept: `/.//evil.com` has no leading `//` as written but
normalizes to one. If you add a check about *where the URL goes*, read it from
`ParsedComponents`, never from the raw string.

`parse_url_local()` and `parse_url()` share the same parser; the difference
between them is entirely which `SecurityPolicy` the second pass applies.

## One construction path

A `URL` holds two values: `_parts` (a frozen `URLParts`) and `_context` (the
policy, check flags, debug, audit manager, builder and `SecurityServices`).
Nothing outside `url.py` touches its other state.

Every URL's components come from `_parser.normalize_components()`: parsing
calls it after splitting a string, and every derivation (`copy()`,
`with_*()`) calls it with the overridden and carried-over components. So a
derived URL is exactly what parsing its own string would give --
`with_path("/a/../b").path` is `/b`, `with_port(None)` leaves the scheme's
default port. `_mutations.assert_round_trip` stays as defence in depth for
the authority.

## One definition per rule

| Rule | Home |
|---|---|
| Dot segments (RFC 3986 §5.2.4) | `_resolve.remove_dot_segments` / `normalize_dot_segments` |
| Host form (IDNA, then §6.2.2) | `_unicode.uts46.canonical_host` |
| Brackets, zone IDs, port grammar, IPv4 shape | `_host` |
| Query pair decoding | `_builder.decode_query_pairs` |
| Scheme allowlist | `_validation.scheme_rejection` |
| Whether an address may be connected to | `SecurityPolicy.permits_address` (DNS check and connect guard) |
| Redaction | `_redaction` |

If you find yourself writing a second implementation of any of these, use
the existing one.

## Where "relative URL" logic lives

- **`_resolve.py`** -- RFC 3986 §5 reference resolution. The only module
  that resolves a reference *against a base URI*, and the home of the
  dot-segment algorithm everything uses.
- **`_relative.py`** -- splits and rejoins a bare reference (no base); uses
  `_resolve.split_uri_reference` to reject references that are absolute.
- **`join()`** (in `_entrypoints.py`) -- the validated, public-facing
  wrapper around `_resolve.py`.

## `_security/` internals

`_security/__init__.py` aggregates the package and runs the checks:
`collect_security_findings()` builds one `_CheckContext` and runs a fixed
sequence of per-concern functions (scheme, encoding, host identity, path,
structure, credentials, port, DNS, phishing). Order matters: the first
blocking finding decides the exception, and a test pins it.

- **`policy.py`** -- `SecurityPolicy` (frozen data) and the presets. Fields
  marked as heuristics are what the `internal`/`local` presets turn off, so
  a new heuristic cannot silently stay on in them; every preset takes any
  field as an override. `permits_address()` and `host_is_*()` combine the
  caller's address rules with the built-in classification.
- **`services.py`** -- `SecurityServices`: the resolver, resolution cache,
  DNS rate limiter and phishing feed. Every entry point takes `services=`;
  the default is the process-global set. This is the seam for per-tenant
  budgets, mirrors, and tests (which inject fakes instead of patching
  module globals).
- **`dns_guard.py`** -- `check_host_resolution()` (resolver, cache, limiter
  and clocks injected; returns a `DNSCheckResult`), `DNSRateLimiter` (rate
  limiting only) and `DNSResolutionCache` (raw answers, not verdicts, so
  one cache serves every policy).
- **`phishing_db.py`** -- `PhishingDatabaseManager`: source (`fetch`),
  clock and limits (`PhishingFeedConfig`) are arguments; it implements the
  `PhishingFeed` protocol.
- **`ip_utils.py`** -- address classification. Every predicate fails
  closed: unparseable or unverifiable means unsafe. A regression test scans
  the package for `except` branches that return a literal from a predicate.
- **`address_rules.py`** -- `allowed_addresses`/`denied_addresses`, matched
  on what a host *is* (every IP spelling, embedded IPv4, IDNA/case/dot).
- **`host_analysis.py`** (over `urlps._unicode`) -- Unicode host findings:
  mixed scripts, whole-script confusables, invisible characters, decoded
  from Punycode first. Pure: the policy decides which findings apply.
- **`url_checks.py`** -- the raw-string heuristics, plus deprecated legacy
  helpers. Redaction moved to `urlps._redaction`.

`_egress.py` sits above `url.py` because it is not part of parsing at all:
it validates the address actually connected to, which is the only defence
against DNS rebinding. Parse-time checks, including `check_dns`, run before
the client resolves the host again.

## Caches

Every cache is declared with `_cache_config.bounded_lru_cache` /
`lru_cache` and a group, and registers itself; `get_cache_info()` and
`clear_all_caches()` read the registry, so a new cache is reported without
anyone listing it.

## Public API surface

`__init__.py` is intentionally thin: it re-exports. The entry points in
`_entrypoints.py` resolve a policy and construct a `URL` through one helper;
the work happens in `url.py`, `_parser.py` and `_security/`. A new top-level
function should follow that shape rather than reimplementing parsing or
validation inline.
