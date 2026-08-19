# urlps

Lightweight, secure URL parsing and building library with RFC 3986 compliance. Features comprehensive security protections including SSRF prevention, DNS rebinding detection, path traversal protection, and homograph attack detection.

## Installation

```bash
pip install urlps
```

Development setup:
```bash
python -m venv .venv
. .venv/Scripts/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Search cleanup: repository searches can use `.rgignore` to skip local/IDE/build artifacts.

## Quick Start

```python
from urlps import parse_url, build

# Secure by default - blocks SSRF, private IPs, localhost
url = parse_url("https://api.example.com/data?token=abc#section")
print(url.host)  # api.example.com
print(url.query_params)  # [("token", "abc")]

# Build URLs
url_str = build("https", "example.com", port=8443, path="/api", query="x=1")
# https://example.com:8443/api?x=1

# Immutable with functional updates
url = parse_url("https://example.com/path")
new_url = url.with_host("other.com").with_port(8080)
print(new_url)  # https://other.com:8080/path

# Policy-based validation (policy="strict" is the default; shown explicitly
# here -- see "Security" below for what it blocks and when to relax it)
strict_url = parse_url("https://example.com", policy="strict")
```

### Security

`parse_url()` defaults to `policy="strict"` -- the strongest built-in preset.
It blocks:
- Private IPs (192.168.x.x, 10.x.x.x, 172.16.x.x)
- Localhost and loopback addresses
- Link-local addresses (169.254.x.x)
- `.local` and `.internal` domains
- Path traversal patterns (`../`)
- Double-encoded characters
- Open redirect patterns (leading `//`, backslashes, raw or percent-encoded)
- Mixed Unicode scripts (homograph attacks)
- URL parser confusion attacks
- Query parameter injection
- Dangerous ports (commonly exploited)
- Non-canonical URL forms (filter bypass prevention)
- Credentials in URL userinfo (`user:pass@host`)
- Suspicious Punycode/IDN domains (confusable characters, excessive
  hyphens, brand-like names combined with non-ASCII)

The last five are the ones `policy="balanced"` relaxes -- it's meant for
parsing URLs you intend to inspect/canonicalize/reconstruct yourself rather
than reject outright, and it trades some protection for fewer false
positives (the Punycode heuristic in particular flags some plain ASCII
domains too, e.g. `carnival.com` for containing "rn"):

```python
from urlps import parse_url

balanced_url = parse_url("HTTP://EXAMPLE.com", policy="balanced")
```

Use `parse_url_local()` for development and internal URLs. It turns the
heuristic checks off and permits loopback/RFC1918 hosts, but **narrows SSRF
enforcement rather than disabling it** -- cloud metadata endpoints, the
link-local range, `.internal` and kubernetes service names stay blocked:

```python
from urlps import SecurityPolicy, parse_url_local

dev_url = parse_url_local("http://localhost:3000/api")
internal = parse_url_local("http://192.168.1.100/metrics")

# If policy is passed, parse_url_local uses it exactly.
trusted_policy = SecurityPolicy.local(check_dns=True)
internal_checked = parse_url_local("http://intranet.local/service", policy=trusted_policy)
```

`parse_url_unsafe()` is the former name for the same function and still works.

Need to adjust the tradeoff? Use policy presets:
- `policy="strict"` (default): maximum protections, DNS connect checks fail-closed by default
- `policy="balanced"`: fewer false positives, DNS connect checks fail-open by default
- `policy="internal"`: trusted traffic -- heuristics off, **SSRF still enforced**
- `policy="local"`: development -- heuristics off, loopback/private hosts allowed,
  metadata endpoints still blocked

To genuinely disable SSRF enforcement you must say so explicitly:
`SecurityPolicy.internal(enforce_ssrf=False)`.

DNS connect behavior can be customized per policy:

```python
from urlps import SecurityPolicy, parse_url

policy = SecurityPolicy.strict(check_dns=True, dns_fail_open_on_connect_error=True)
url = parse_url("https://api.example.com", policy=policy)
```

Recommended for multi-tenant or concurrent applications: inject a dedicated DNS limiter.

```python
from urlps import DNSRateLimiter, DNSRateLimiterConfig, parse_url

limiter = DNSRateLimiter(
    DNSRateLimiterConfig(max_lookups_per_second=20, max_lookups_per_host=50)
)

url = parse_url(
    "https://api.example.com",
    policy="strict",
    check_dns=True,
    dns_rate_limiter=limiter,
)
```

## Core Features

### Immutable URL Objects

```python
from urlps import parse_url

url = parse_url("https://user:pass@example.com:8080/path?token=abc", policy="balanced")
print(url.netloc)         # user:pass@example.com:8080
print(url.effective_port) # 8080

# with_* methods return new URL objects
url2 = url.with_netloc("admin@example.com")
url3 = url.with_host("other.com").with_port(443).with_path("/api")
url4 = url.with_query_param("new", "value")
url5 = url.without_query_param("token")
```

### Query strings round-trip exactly

Parsing never rewrites the query. This matters if you verify signatures over a
raw query string, or proxy URLs onward:

```python
from urlps import parse_url

url = parse_url("https://api.example.com/search?sig=aGVsbG8%3D&q=a+%26+b")
print(url.query)         # sig=aGVsbG8%3D&q=a+%26+b   (byte-for-byte)
print(str(url) )         # ...unchanged...
print(url.query_params)  # [('sig', 'aGVsbG8='), ('q', 'a & b')]
```

`q=a+%26+b` is **one** parameter whose value contains `&`. Re-encoding is only
performed when you explicitly change the query (`with_query_param()`,
`canonicalize()`), and never turns one parameter into two.

### Reference resolution (RFC 3986 §5)

`join()` is the security-preserving equivalent of `urllib.parse.urljoin` — the
resolved target is validated, so resolution can't be used to slip past the
checks `parse_url()` applies:

```python
from urlps import join

join("https://example.com/a/b", "../c")     # https://example.com/c
join("https://example.com/a/b", "?q=1")     # https://example.com/a/b?q=1
join("https://example.com/a/b", "#frag")    # https://example.com/a/b#frag

# '..' can never escape the authority
join("https://example.com/a/b", "../../../../etc/passwd")
# https://example.com/etc/passwd

# A protocol-relative reference legitimately replaces the host, which is
# exactly why the *result* is re-validated rather than trusted:
join("https://example.com/a/", "//localhost/admin")   # raises InvalidURLError
```

### Security Checks

```python
from urlps import parse_url, InvalidURLError

# SSRF protection (enabled by default)
try:
    parse_url("http://localhost/admin")  # Blocked
except InvalidURLError as e:
    print(f"Rejected: {e}")

# DNS rebinding detection (optional - rate-limited to prevent DoS)
url_dns = parse_url("https://api.example.com/", check_dns=True)

# URL canonicalization (policy="balanced": the raw non-canonical/credentialed
# forms below are exactly what strict's require_canonical/reject_credentials
# would block -- use balanced when you want to parse first and canonicalize
# after, rather than reject upfront)
url_raw = parse_url("HTTP://EXAMPLE.COM:80/path?z=1&a=2", policy="balanced")
canonical = url_raw.canonicalize()
print(canonical.scheme)  # "http"
print(canonical.host)    # "example.com"
print(canonical.port)    # None (default port removed)
print(canonical.query)   # "a=2&z=1" (sorted)

# Password masking
url = parse_url("https://admin:secret123@api.example.com/", policy="balanced")
print(url.as_string(mask_password=True))  # https://admin:***@api.example.com/
```

### Audit Logging

Audit callbacks are supplied per call via `AuditConfig`, so different callers
can log differently without sharing global state:

```python
import logging
from urlps import AuditConfig, parse_url

def audit_url_parsing(logged_url, parsed_url, exception):
    if exception:
        logging.warning(f"Failed to parse URL: {exception}")
    else:
        logging.info(f"Parsed URL to host: {parsed_url.host}")

url = parse_url(
    "https://api.example.com/data",
    audit=AuditConfig(callback=audit_url_parsing),
)
```

Structured event callback:

```python
from urlps import AuditConfig, parse_url

def on_event(event):
    # event includes: timestamp, level, operation, raw_url, host,
    # error_type, error_code, correlation_id
    print(event)

url = parse_url(
    "https://api.example.com/data",
    correlation_id="request-42",
    audit=AuditConfig(event_callback=on_event),
)
```

URLs are redacted before being passed to callbacks (credentials and sensitive
query values are masked). Pass `AuditConfig(..., redact_urls=False)` to opt out.
A callback that raises is recorded as a failure and never breaks the parse.

The same `audit=` parameter is accepted by `parse_url_unsafe()`, `join()` and
`build_secure()`.

### Component Length Limits

Conservative limits to prevent DoS attacks:

| Component | Max Length |
|-----------|------------|
| URL (total) | 32 KB |
| Scheme | 16 chars |
| Host | 253 chars |
| Path | 4 KB |
| Query | 8 KB |
| Fragment | 1 KB |
| Userinfo | 128 chars |

## Environment Variables

Override length limits via environment variables:

```bash
# PowerShell
$env:URLPS_MAX_URL_LENGTH = "65536"
python -c "import urlps.constants as c; print(c.MAX_URL_LENGTH)"

# Bash
export URLPS_MAX_URL_LENGTH=65536
python -c 'import urlps.constants as c; print(c.MAX_URL_LENGTH)'
```

Supported variables:
- `URLPS_MAX_URL_LENGTH`
- `URLPS_MAX_SCHEME_LENGTH`
- `URLPS_MAX_HOST_LENGTH`
- `URLPS_MAX_PATH_LENGTH`
- `URLPS_MAX_QUERY_LENGTH`
- `URLPS_MAX_FRAGMENT_LENGTH`
- `URLPS_MAX_USERINFO_LENGTH`
- `URLPS_MAX_IPV6_STRING_LENGTH`

Internal `@lru_cache` sizes are also overridable this way -- see [Cache Sizing](#cache-sizing) below.

## API Reference

### Main Functions

| Function | Description |
| --- | --- |
| `parse_url(url, *, allow_custom_scheme=False, check_dns=False, check_phishing=False, dns_rate_limiter=None, policy=None, correlation_id=None, audit=None)` | Parse URL with policy-aware security checks (recommended) |
| `parse_url_unsafe(url, *, allow_custom_scheme=False, debug=False, check_dns=False, dns_rate_limiter=None, policy=None, correlation_id=None, audit=None)` | Parse URL for trusted/internal input with optional policy overrides |
| `join(base, reference, *, policy=None, strict_resolution=True, ...)` | Resolve a reference against a base URI (RFC 3986 §5), then validate |
| `build(*scheme_and_host, port=None, path="/", query=None, fragment=None, userinfo=None)` | Build URL string from components |
| `build_secure(*scheme_and_host, policy=None, check_dns=False, check_phishing=False, dns_rate_limiter=None, correlation_id=None, audit=None, ...)` | Build and then validate a URL under a selected security policy |
| `compose_url(components)` | Build URL from components dict |

Note: `get_dns_rate_limiter()` and `reset_dns_rate_limiter()` remain available for compatibility, but explicit `dns_rate_limiter=` injection is preferred.

### URL Methods

| Method | Description |
| --- | --- |
| `url.as_string(mask_password=False)` | Convert to string, optionally masking password |
| `url.canonicalize()` | Return canonicalized copy |
| `url.is_semantically_equal(other)` | Compare URLs by meaning after canonicalization |
| `url.same_origin(other)` | Check if URLs have same origin |
| `url.origin` | Return origin string (e.g., `https://example.com`) |
| `url.copy(**overrides)` | Create copy with optional component overrides |
| `url.with_*()` | Functional updates: `with_scheme`, `with_host`, `with_port`, `with_path`, `with_fragment`, `with_userinfo`, `with_netloc`, `with_query_param`, `without_query_param` |

### Cache Management

```python
from urlps import get_cache_info, clear_all_caches

# Get cache statistics
stats = get_cache_info()
print(stats['parser']['normalize_path']['hits'])

# Clear all caches (useful for long-running apps)
previous = clear_all_caches()
```

### Cache Sizing

Every internal `@lru_cache` (security/host checks, validation predicates, path
normalization, percent-encoding, policy resolution) is sized from a small set
of environment variables, all read **once, at import time**. Python's
`functools.lru_cache` bakes `maxsize` in when the decorated function is
defined, so these must be set *before* `import urlps` runs -- setting them
afterwards, or after the first `parse_url()` call, has no effect:

```python
import os
os.environ["URLPS_CACHE_SIZE_SECURITY"] = "8192"
import urlps  # cache sizes are now locked in for this process
```

| Variable | Default | Covers |
| --- | --- | --- |
| `URLPS_CACHE_SIZE_SECURITY` | 512 | `is_ssrf_risk`, `is_private_ip`, `has_parser_confusion`, `has_mixed_scripts`, `find_authority_marker` -- keyed on host or full URL |
| `URLPS_CACHE_SIZE_VALIDATION` | 512 | `is_valid_host`, `is_valid_scheme`, `is_url_safe_string`, `is_valid_fragment`, etc. |
| `URLPS_CACHE_SIZE_PARSER` | 1024 | `normalize_path` |
| `URLPS_CACHE_SIZE_BUILDER_QUERY_ENCODE` | 8192 | percent-encoding of query keys/values |
| `URLPS_CACHE_SIZE_BUILDER_PATH_ENCODE` | 1024 | percent-encoding of path segments |
| `URLPS_CACHE_SIZE_POLICY` | 16 | resolved named policies (`strict`/`balanced`/`internal` x overrides) -- rarely worth changing, the working set is inherently tiny |

**Which value fits your workload?** A cache only helps when the *same* input
(same host, same URL shape) is seen again within the cache's window --
otherwise every lookup is a miss and the cache is pure overhead with no
benefit. Use `get_cache_info()` after a representative burst of real traffic
to check hit rates before guessing:

- **Short-lived script/CLI** (parses a handful of URLs and exits): defaults
  are fine either way -- there's rarely enough repetition for cache size to
  matter, and the downside of an "oversized" cache here is negligible.
- **Long-running service with a bounded set of upstream hosts** (an internal
  proxy, a service validating callback URLs from a fixed partner list):
  keep the defaults, or size `URLPS_CACHE_SIZE_SECURITY`/`_VALIDATION` to
  comfortably exceed your distinct-host count. A cache that fits your whole
  working set converges to a near-100% hit rate and stays there.
- **High-diversity, public-facing workload** (a crawler, a webhook receiver
  from many tenants, a link-checker over arbitrary user-submitted URLs):
  the default 512 is easy to blow through in a single request burst, at
  which point the cache is being evicted before it's ever reused --
  raise `URLPS_CACHE_SIZE_SECURITY`/`_VALIDATION` substantially (several
  thousand), or accept that there may be little to gain from caching this
  workload at all if hosts are effectively unique per request.
- **Memory-constrained environment**: lower the values, especially the
  builder encode caches (8192/1024 by default) if you build many large,
  distinct query strings -- each cache entry holds a copy of the encoded
  string, and eviction under memory pressure is not automatic the way it
  is for cache-key diversity.

## Comparison with urllib.parse

| Feature | urllib.parse | urlps |
| --- | --- | --- |
| Basic URL parsing | ✓ | ✓ |
| RFC 3986 strict compliance | Partial | ✓ |
| SSRF protection | ✗ | ✓ |
| DNS rebinding detection | ✗ | ✓ (with rate limiting) |
| Path traversal detection | ✗ | ✓ |
| Homograph detection | ✗ | ✓ |
| URL parser confusion protection | ✗ | ✓ |
| Query parameter injection detection | ✗ | ✓ |
| Dangerous port validation | ✗ | ✓ |
| Canonical form validation | ✗ | ✓ |
| Immutable URL objects | ✗ | ✓ |
| URL canonicalization | ✗ | ✓ |
| Password masking | ✗ | ✓ |
| Audit logging | ✗ | ✓ |
| Component length limits | ✗ | ✓ |

**Use urllib.parse when:** You need zero dependencies and basic parsing is sufficient.

**Use urlps when:** Security matters, you need RFC 3986 strict compliance, or you want immutable URL objects with ergonomic manipulation methods.

## Exceptions

```python
from urlps import InvalidURLError, URLParseError, parse_url

user_input = "https://example.com"

try:
    url = parse_url(user_input)
except URLParseError:
    print("Malformed URL")
except InvalidURLError:
    print("Rejected by security policy")
```

Exception hierarchy:
- `InvalidURLError` — Base exception for all URL errors
- `URLParseError` — Parsing errors
- `URLBuildError` — Building errors
- `HostValidationError` / `PortValidationError` — Component validation errors
- `QueryParsingError`, `FragmentEncodingError`, `UserInfoParsingError`, `UnsupportedSchemeError` — Specific errors

## Running Tests

```bash
pytest
pytest -v -k "test_parse"     # Run specific tests
pytest -m ipv6                # Run IPv6 tests
pytest -m idna                # Run IDNA tests
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a summary of every release, and [changelogs/](changelogs/) for detailed per-release notes.

## License

MIT
