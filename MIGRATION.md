# Migration Guide

## 1.1.x → 1.2.0

A security release. Several checks now do what the documentation always
said they did, which means some input that used to be accepted is now
rejected. Each row says how to get the old behaviour back on purpose.

### You will notice these

| Change | Who it affects | What to do |
|---|---|---|
| Non-standard schemes (`smb://`, `redis://`, `mailto:`, `ms-msdt:`, `x-custom://`, ...) now raise `UnsupportedSchemeError` unless `allow_custom_scheme=True` | Anyone parsing non-`http(s)`/`ftp(s)`/`sftp`/`ws(s)` URLs | Pass `allow_custom_scheme=True`, as the parameter's documentation always said was required. `with_scheme()` follows the same rule, based on how the URL was parsed. |
| `100.64.0.0/10` (shared address space / CGNAT, which includes Alibaba Cloud's metadata endpoint `100.100.100.200`), IPv6 site-local `fec0::/10`, and the rest of `NON_PUBLIC_NETWORKS` are now SSRF risks | Anyone fetching Tailscale (`100.x`) or CGNAT-range hosts | Add them to `SecurityPolicy(..., allowed_addresses=["100.64.0.0/10"])` (every preset accepts it). |
| The `local` policy never permits a cloud metadata address, in any spelling, including the AWS IPv6 endpoint `fd00:ec2::254` (otherwise an ordinary ULA) | Nobody legitimate | Nothing. |
| `parse_url(url, policy=SecurityPolicy.strict(check_dns=True))` now actually runs the DNS check (it silently did not), and a `dns_rate_limiter` set on the policy is now actually used | Anyone who configured DNS checks on the policy | Nothing, unless your tests relied on no lookups happening. Pass `check_dns=False` explicitly to override a policy. |
| The DNS check no longer makes a "verification connection" to the resolved address | Nobody legitimate | Use `create_guarded_connection()` / `resolve_and_validate()` for connect-time protection; see the README. |
| DNS lookups are cached (30s positive, 5s negative) and the per-host limit counts only real lookups | Anyone relying on every `check_dns=True` parse hitting the resolver | Pass `services=SecurityServices(resolution_cache=DNSResolutionCache(DNSCacheConfig(ttl_seconds=0, negative_ttl_seconds=0)))` to disable caching. |
| Exception `value` (and so `str(exc)`) has credentials and query/fragment values redacted | Anyone parsing `str(exc)` for the original input | Pass `debug=True` (now also accepted by `parse_url()`) to keep the raw input. |
| Userinfo is percent-encoded to the RFC 3986 grammar on parse, `with_userinfo()`/`with_netloc()` and `build()`: `a\b` becomes `a%5Cb`, a password `p#ss` becomes `p%23ss` | Anyone comparing `url.userinfo` to a raw string | Compare against the encoded form, or `urllib.parse.unquote()` it. Previously such characters were emitted raw and could move the host for other parsers. |
| `with_scheme()` resets a *default* port (`https://h/` -> `with_scheme("http")` -> `http://h/`, not `http://h:443/`) and lowercases the scheme | Anyone relying on the old port carry-over | Pass `port=` explicitly via `copy(scheme=..., port=...)`. |
| `with_query("a#b")` raises | Anyone putting a raw `#` in a query override | Encode it as `%23`, or use `with_query_param()`. |
| Escaped fragments are no longer double-encoded on output (`#a%2Fb` stays `#a%2Fb`, not `#a%252Fb`) | Anyone who worked around the double encoding | Remove the workaround. |
| Path, fragment and userinfo length limits count *decoded* characters | Nobody legitimate | Nothing; a parsed URL's own `str()` now always re-parses. |
| C1 control characters (`\x80`-`\x9F`) are rejected like other control characters | Anyone with raw C1 bytes in URLs | Percent-encode them. |
| `check_phishing=True` also flags subdomains of listed domains, refreshes the list daily, and keeps the previous list when a refresh fails | Anyone relying on exact-match only | Nothing, unless a listed parent domain covers hosts you trust. `phishing_fail_closed=True` on the policy rejects when the feed is unavailable. |
| Caches do not retain keys longer than `URLPS_CACHE_MAX_KEY_LENGTH` (1024) / `URLPS_CACHE_MAX_VALUE_KEY_LENGTH` (128) | Nobody (results are identical) | Raise them if profiling shows misses on long, repeated URLs. |
| `urlps check` escapes non-printable characters in its output | Scripts parsing raw control characters out of the CLI's stderr | Nothing reasonable depends on this. |
| Paths are normalized exactly as RFC 3986 says: empty segments are kept (`/a//b` is no longer `/a/b`), `/a/b/..` is `/a/` (was `/a`), and `%2E%2E` is decoded *before* dot segments are removed (`/a/%2e%2e/b` is `/b`, where `.path` used to say `/a/../b` while `str()` said `/b`) | Anyone relying on `//` being collapsed | Collapse it yourself if your server treats `//` as `/`. Keeping it is what signed URLs and S3-style keys need. A path that normalizes to a leading `//` is reported as an open redirect under `strict`/`balanced`. |
| Derived URLs are normalized exactly like a parse: `with_path("/a/../b").path` is `/b`, and `with_port(None)` leaves the scheme's default port (`.port == 443` for https, as for `parse_url("https://h/")`), not `None` | Anyone reading `.path`/`.port` back after `with_*()` | `str(url)` is unchanged. Use `effective_port` if you need the port either way. |
| A relative path after an authority gets its leading `/`: `with_path("x")` on `https://h/` is `https://h/x`; `build("https", "h", path="api")` is `https://h/api` | Nobody legitimate | Nothing. Before, the path ran into the authority (`https://hx`) and changed the host. |
| Clearing the host of an absolute URL (`with_host("")`) raises `MissingHostError`, as a parse does; `with_port()` on a scheme that takes no port (`file`) raises | Anyone relying on the later serialization error | Catch `InvalidURLError` as before. |
| `with_port()`/`Validator.is_valid_port()` reject `True`, fullwidth digits, `" 80"` and `80.0` | Nobody legitimate | Pass an `int`. |
| `UnsupportedSchemeError` is now a `URLParseError` too, and is what a disallowed scheme raises everywhere (`javascript:` raised a plain `URLParseError` in 1.1) | Nobody: `except URLParseError` still catches it | Tell the cases apart with `exc.code` (`unsafe_scheme`, `unsupported_scheme`). |
| A custom scheme must be well-formed RFC 3986 even with `allow_custom_scheme=True` (`a_b://` is rejected) | Anyone using non-RFC schemes | Use a well-formed scheme. |
| Under `local` (and `enforce_ssrf=False`), the `check_dns=True` check accepts a host that resolves to a private address, as `create_guarded_connection()` already did and as a private literal already was; metadata and link-local stay rejected | Anyone using `local` + `check_dns` to keep internal names out | Use `strict`, or `denied_addresses=[...]`. |
| `parse_url_local(..., policy=..., check_dns=...)` honours `check_dns` (it was ignored whenever a policy was passed) | Anyone passing both | Drop the argument if you relied on it being ignored. |
| The query length limit counts decoded characters, like the path's | Nobody (a re-serialized query must still parse) | Nothing. |
| `hash(url)` hashes the serialized URL, so equal URLs hash equal (two URLs serializing identically used to hash apart) and a URL hashes like its string | Anyone persisting `hash(url)` | Hashes were never stable across processes. |

### Renamed and deprecated

| Old | New | Status |
|---|---|---|
| `dns_fail_open_on_connect_error=` on the policy presets | nothing (it governed the removed verification connect) | Passing it emits `DeprecationWarning` and has no effect. Removed in 2.0. |
| `URL(..., parser=Parser())` | `URL(..., allow_custom_scheme=...)` (all a parser was ever used for) | Emits `DeprecationWarning`; still works. Removed in 2.0. |
| `URL(..., builder=Builder())` | nothing | Emits `DeprecationWarning`; still works. Removed in 2.0. |
| `urlps._security.has_mixed_scripts()`, `get_canonical_url()` | `host_analysis.analyze_host()`; `str(parse_url(url).canonicalize())` | Emit `DeprecationWarning`. Removed in 2.0. |
| `Builder.compose_secure()`, `Builder.merge_params()`, `Validator.is_valid_path()`/`is_valid_query_param()`/`is_standard_port()`, `_components.URLComponents` | `build_secure()`; nothing | Removed: unused internals of private modules. |
| `urlps.constants.STANDARD_PORTS` | `DEFAULT_PORTS` | Unused by urlps. Emits `DeprecationWarning`; still works. Removed in 2.0. |
| The redaction helpers in `urlps._security.url_checks` | `urlps._redaction` | Re-exported from the old place. |
| `urlps._security._unicode` | `urlps._unicode` | Private module, moved. |

### New

| API | What it is for |
|---|---|
| `SecurityPolicy(allowed_addresses=..., denied_addresses=...)` (and on every preset) | Your own IP/CIDR/hostname/`.domain` rules, applied to every spelling of a host and every resolved address. |
| `create_guarded_connection()` | Connect-time SSRF protection; a drop-in for `socket.create_connection` and urllib3's. |
| `resolve_and_validate()` | The vetted addresses for a URL, to pin a connection to. |
| `DNSResolutionCache`/`DNSCacheConfig(ttl_seconds=, negative_ttl_seconds=, max_hosts=)`, `SecurityPolicy.dns_deadline_seconds`, `DNSRateLimitError.retry_after` | DNS check tuning. |
| `SecurityPolicy.phishing_fail_closed`, `URLPS_PHISHING_DATABASE_REFRESH_SECONDS`, `URLPS_PHISHING_DATABASE_SHA256` | Phishing feed behaviour. |
| `AuditConfig(sensitive_keys=...)` | Extra query-key fragments to redact in audit logs. |
| `SecurityServices(resolver=, resolution_cache=, dns_rate_limiter=, phishing_feed=)`, accepted as `services=` by every entry point and by `URL()` | Your own resolver, cache, limiter or phishing feed -- per tenant, a mirror, or fakes in tests -- instead of the process-global ones. |
| `PhishingDatabaseManager(PhishingFeedConfig(url=, sha256=, refresh_seconds=, ...), fetch=, clock=)`, the `PhishingFeed` protocol (`lookup(host) -> bool \| None`) | A configurable or custom phishing feed. |
| `SecurityPolicy(allowed_schemes={...}, allow_custom_scheme=...)` | The scheme allowlist as policy: narrow it (`{"https"}`), widen it, and have `validate(policy=...)` and derived URLs follow it. |
| Every preset takes any field as an override: `SecurityPolicy.strict(dns_deadline_seconds=2.0)` | Tuning a preset without constructing the whole policy. |
| `audit=AuditManager(...)` on every entry point | Share one manager and read its `get_failure_metrics()`. |
| `URL(..., allow_custom_scheme=True)`, `URL.security_policy`, `build_secure(..., allow_custom_scheme=True)` | Parity with `parse_url()`. |
| `SecurityPolicy.permits_address(ip)` | The one rule both the DNS check and `create_guarded_connection()` apply to an address. |

## 1.0.x → 1.1.0

No breaking changes. Two things are worth knowing about before you upgrade.

### You will notice these

| Change | Who it affects | What to do |
|---|---|---|
| `build()`/`compose_url()` now raise `HostValidationError` for a host that isn't a syntactically valid hostname or IPv4/IPv6 literal | Anyone building URLs from an unvalidated/untrusted host component | Validate or sanitize the host first, or catch `HostValidationError`. Previously an invalid host silently produced a string that `parse_url()` then failed to re-parse. |
| `is_ssrf_risk("10.0.0.5.")` (and other trailing-dot numeric hosts) now correctly returns `True` | Anyone calling `is_ssrf_risk()` directly (not through `parse_url()`, which was never affected) | Nothing, unless you were relying on the bypass. |
| `url == "https://example.com/"` (and `<`, `<=`, `>`, `>=` against a plain string) works again | Anyone comparing a `URL` to a string | Nothing — this restores behavior that briefly regressed in 1.0.1's internal refactor. |

### Renamed and deprecated (now enforced at runtime)

These were already listed as deprecated in the 1.0.0 section below, but
nothing actually warned until 1.1.0:

| Old | New | Status |
|---|---|---|
| `parse_url_unsafe()` | `parse_url_local()` | Now emits `DeprecationWarning`. Still works identically. Removed in 2.0. |
| `SecurityPolicy(enforce_suspicious_punycode=True)` | `enforce_mixed_scripts` / `enforce_confusable_host` (already on by default) | Passing `True` now emits `DeprecationWarning`. The default (`False`) is silent. Removed in 2.0. |
| `has_suspicious_punycode()` | `urlps._security.host_analysis.analyze_host()` | Now emits `DeprecationWarning`. Removed in 2.0. |

## 0.8.x → 1.0.0

1.0 makes the library behave the way its documentation always claimed:
cosmetic differences are normalized instead of rejected, every entry point
enforces the same policy, and `URL` is genuinely immutable.

Most code needs no changes. Read the first table if you parse URLs; read the
second only if you touched internals.

### You will notice these

| Change | Who it affects | What to do |
|---|---|---|
| URLs that used to be rejected now parse: `HTTP://EXAMPLE.COM/`, `https://example.com:443/`, `https://example.com/%7Euser`, `http://example.com/a/./b`, `?q=WAITFOR` | Anyone relying on those raising | Nothing. If you depended on rejection, add your own check — none of these were security failures. |
| `url.host` is now always lowercase with any trailing root dot stripped | Anyone comparing `.host` to a raw string | Nothing; comparisons get *more* correct. This closes a real bypass — `parse_url('http://EVIL.COM./', policy='balanced').host` used to return `'EVIL.COM.'` and slip past a `host in BLOCKLIST` check. |
| `URL(...)` now defaults to `strict`, matching `parse_url()` | Anyone constructing `URL` directly | Pass `security_policy=SecurityPolicy.local()` for development URLs, or use `parse_url_local()`. Previously the class silently applied a near-no-op policy. |
| `SecurityPolicy.internal()` now enforces SSRF | Anyone using `policy="internal"` with private hosts | Use `policy="local"` (permits loopback/RFC1918, still blocks metadata endpoints) or `SecurityPolicy.internal(enforce_ssrf=False)` to opt out explicitly. |
| Punycode homographs are now caught: `xn--pypal-4ve.com` and friends are rejected under `strict` *and* `balanced` | Anyone parsing IDN hosts | Nothing, unless you were relying on them being accepted. Legitimate IDNs (`例え.com`, `한국.com`, `münchen.de`, `онлайн.com`) still parse. |
| Internationalized hosts now encode per UTS-46/IDNA 2008 | Anyone parsing non-ASCII hosts | Nothing, but note `https://straße.de/` now yields `xn--strae-oqa.de` (what browsers resolve) rather than `strasse.de`. The old answer was a parser differential. |
| `URL` rejects attribute assignment | Anyone doing `u._host = ...` | Use `with_host()` / `copy()`. `copy.copy`, `copy.deepcopy` and `pickle` all still work. |
| `validate()` no longer stores its result on the instance | Anyone calling `validate(policy=other)` and then reading `security_findings` | Use the returned list. `security_findings` now consistently reports the construction-time verdict. |

### Renamed and deprecated

| Old | New | Status |
|---|---|---|
| `parse_url_unsafe()` | `parse_url_local()` | Alias retained, still works, but now emits `DeprecationWarning` (as of 1.1.0). "Unsafe" was the wrong signal for parsing your own dev URL — and under the `local` policy it is not even unsafe. Removed in 2.0. |
| `enforce_query_injection` | *(removed)* | Passing it is accepted and ignored; removed in 2.0. |
| `require_canonical` | *(removed)* | Superseded by normalization. |
| `enforce_suspicious_punycode` | `enforce_confusable_host` + `enforce_mixed_scripts` | Old flag accepted as a no-op; passing `True` now emits `DeprecationWarning` (as of 1.1.0); removed in 2.0. |
| `ErrorCode.QUERY_INJECTION`, `.NON_CANONICAL_URL`, `.MIXED_SCRIPTS`, `.SUSPICIOUS_PUNYCODE` | `.MIXED_SCRIPT_LABEL`, `.CONFUSABLE_HOST` | Old members remain importable but are never emitted; removed in 2.0. |

### Why the query-injection check was removed

It was a substring blocklist over the raw query string. Whether `?q=DROP TABLE`
is an attack depends entirely on what the consuming application does with the
decoded value — which a URL parser cannot see. It produced false positives on
ordinary input (`?q=WAITFOR`, `?filter=a--b`) while being trivially bypassed by
re-encoding, so it provided no security floor, only noise. Escaping belongs at
the SQL/HTML boundary, not the URL boundary.

## 0.7.x → 0.8.0

`parse_url()` without an explicit `policy=` argument now uses `"strict"`
instead of `"balanced"`. This is a real behavior change if you parse any of:

- URLs with credentials in userinfo (`http://user:pass@host/`)
- Non-canonical URLs (`HTTP://EXAMPLE.COM/`, `http://example.com:80/`)
- Query strings matching injection-like patterns (`<script>`, `javascript:`, ...)
- URLs targeting commonly-exploited ports (22, 25, 3306, 6379, ...)
- Punycode-encoded hosts (`xn--...`), including entirely legitimate ones —
  the new check is deliberately aggressive (see
  [changelogs/0.8.0.md](changelogs/0.8.0.md))

**Action required:** if any of the above previously parsed successfully in
your code without you passing `policy=`, pass `policy="balanced"` explicitly
to keep the old behavior:

```python
# 0.7.x behaviour, now explicit
url = parse_url("http://user:pass@example.com:8080/path", policy="balanced")
```

`parse_url_unsafe()` is unaffected.

---

## 0.6.x → 0.7.0

0.7.0 fixes two data-correctness bugs and removes a redundant parameter. Most
code needs no changes; the exceptions are listed below.

---

### 1. Query strings are no longer re-encoded on parse

**What changed:** parsing preserves the query string exactly as supplied.
Previously the parser decoded the query into pairs and re-serialized it, which
altered the output — sometimes changing its meaning.

| Input | 0.6.x `str(url)` | 0.7.0 `str(url)` |
|---|---|---|
| `?a=hello%20world` | `?a=hello+world` | `?a=hello%20world` |
| `?sig=aGVsbG8%3D&x=1` | `?sig=aGVsbG8=&x=1` | `?sig=aGVsbG8%3D&x=1` |
| `?q=C%2B%2B` | `?q=C++` | `?q=C%2B%2B` |
| `?q=a+%26+b` | `?q=a+&+b` (two params!) | `?q=a+%26+b` (one param) |

**Why:** the old behaviour was lossy and, in the last case, a
parameter-smuggling vector — `?q=a+%26+b` is a single parameter whose value
contains `&`, but the emitted form re-parsed as two parameters. Anything
echoing `str(url)` onward could forward an attacker-injected parameter.
`str()` was also not idempotent.

**Action required:** if you relied on the old normalisation (for example, to
compare URLs), use `canonicalize()` explicitly:

```python
# 0.6.x behaviour, now explicit
normalized = url.canonicalize().as_string()

# Comparing two URLs by meaning
a.is_semantically_equal(b)
```

`url.query_params` is unchanged — decoded pairs behave exactly as before.

---

### 2. Query mutators now actually work

**What changed:** `with_query()`, `with_query_param()` and
`without_query_param()` previously returned an unchanged URL. They now apply
the change.

```python
url = parse_url("https://example.com/p?a=1&b=2")

url.without_query_param("a")
# 0.6.x: https://example.com/p?a=1&b=2   (unchanged — silent no-op)
# 0.7.0: https://example.com/p?b=2
```

**Action required:** none, unless you added a workaround for the no-op (for
example calling `copy(query=..., query_pairs=[...])` yourself). Remove it.

---

### 3. `strict=` removed — use `policy=`

**What changed:** the `strict` parameter is gone from `parse_url_unsafe()` and
`URL()`.

**Why:** it duplicated `policy` and was silently ignored whenever a policy was
also supplied — `parse_url_unsafe(url, strict=True, policy="internal")` quietly
dropped `strict`. Its own docstring described it as negating the function's
name. `policy=` is now the single control for security behaviour.

```python
# Before
parse_url_unsafe(url, strict=True)
URL(url, strict=True)

# After
parse_url_unsafe(url, policy="strict")
parse_url(url, policy="strict")          # usually what you actually want
```

Passing `strict=` now raises `TypeError` rather than being ignored.

---

### 4. `copy()` and `with_*` validate components properly

**What changed:** overrides are checked against the same validators the parser
uses. Previously only the *type* was checked, so `copy()` could build a `URL`
that `parse_url()` would have rejected:

```python
url.with_host("not a valid host!")
# 0.6.x: succeeded, producing an invalid URL object
# 0.7.0: raises InvalidURLError
```

**Action required:** none, unless you were relying on constructing invalid
URLs. Note this is *component format* validation; policy checks (SSRF and
friends) applied on this path already and still do.

---

### 5. Audit callbacks are attached per call

**What changed:** the README documented `set_audit_callback()` and
`set_audit_event_callback()`. **Neither function ever existed** — the examples
raised `ImportError`. The exported `AuditManager` / `AuditConfig` types were
also unreachable, because `URL.__init__` hardcoded a default manager.

Audit configuration is now passed per call:

```python
from urlps import AuditConfig, parse_url

url = parse_url(
    "https://api.example.com/data",
    audit=AuditConfig(callback=my_callback),
)
```

`audit=` is accepted by `parse_url()`, `parse_url_unsafe()`, `join()` and
`build_secure()`.

---

### 6. New: `join()` for RFC 3986 reference resolution

Previously there was no reference resolution at all, so users fell back to
`urllib.parse.urljoin` — which bypasses every security check this library
provides.

```python
from urlps import join

join("https://example.com/a/b", "../c")   # https://example.com/c
```

The resolved target is parsed and validated, so resolution stays inside the
security perimeter.

---

### 7. New: types importable from the package root

These no longer require reaching into private modules:

```python
# Before
from urlps._security.dns_guard import DNSRateLimiter, DNSRateLimiterConfig
from urlps._components import SecurityFinding
from urlps.exceptions import ErrorCode

# After
from urlps import DNSRateLimiter, DNSRateLimiterConfig, SecurityFinding, ErrorCode
```

The old paths still work, but the public names are now the supported ones.

---

### 8. Type checking now works for downstream users

The package declared the `Typing :: Typed` classifier but shipped no
`py.typed` marker, so mypy and pyright ignored its annotations entirely. The
marker now ships. If you previously had `ignore_missing_imports` or a
`# type: ignore` on `import urlps`, you can remove it — and you may see *new*
type errors in your own code that were previously suppressed.
