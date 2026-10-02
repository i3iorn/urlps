# urlps

Lightweight, secure URL parsing and building library with RFC 3986 compliance. Features comprehensive security protections including SSRF prevention (with a connect-time guard against DNS rebinding), path traversal protection, and homograph attack detection.

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

# Strict by default: internal addresses, dangerous schemes, traversal,
# homographs and more are rejected. See "What SSRF protection covers" below
# for where parse-time checks stop and connect-time protection starts.
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

`parse_url()` defaults to `policy="strict"`. Rejection is reserved for input
that is genuinely malformed or genuinely dangerous -- **cosmetic differences
are normalized, not rejected**, so `HTTP://EXAMPLE.COM./`,
`https://example.com:443/`, `/a/./b` and `%7E` all parse fine and resolve to
one canonical form. That is what makes `url.host` safe to compare against an
allowlist directly.

The security checks validate **the host the parser actually produced** --
the one `url.host` returns and `str(url)` serializes -- not a re-reading of
the raw string, so spellings such as `http://169.254.169.254?` or `127.0.0.1`
written with ideographic full stops (`127。0。0。1`) cannot slip past them.

Blocked under **both** `strict` and `balanced`:

- **SSRF** -- every address that is not public, globally routable unicast:
  private IPs (10.x, 172.16-31.x, 192.168.x), loopback, link-local
  (169.254.x), shared address space / CGNAT (100.64.0.0/10), IPv6 ULA,
  site-local and link-local, multicast, reserved and documentation ranges;
  `.local`/`.internal`; cloud metadata endpoints *by address*
  (`169.254.169.254`, `169.254.170.2`, Alibaba's `100.100.100.200`, AWS's
  `fd00:ec2::254`) and by name (`metadata.google.internal`); kubernetes
  service names; and every obfuscated spelling of those (decimal
  `2130706433`, octal, hex, IPv4-mapped IPv6, NAT64, 6to4, Teredo)
- **Path traversal** -- `../`, null bytes, and encoded variants
- **Open redirect** -- leading `//`, backslashes, raw or percent-encoded
- **Double-encoded characters** -- `%25xx` filter bypass
- **Parser confusion** -- URLs that different parsers disagree about
- **Homograph attacks** -- mixed scripts *and* whole-script confusables,
  evaluated per label on the Punycode-*decoded* host
- **Invisible characters** -- bidi controls, zero-width, malformed Punycode
- **Non-standard schemes** -- only `http`, `https`, `ftp`, `ftps`, `sftp`,
  `ws` and `wss` are accepted unless you pass `allow_custom_scheme=True`
  (so a vetted link can't be `ms-msdt:`, `search-ms:` or `smb://`);
  `javascript:`, `data:`, `file:`, `gopher:` and friends need it too

Opt-in (off by default; enable via `SecurityPolicy`):

- `block_dangerous_ports` -- SSRF already covers the internal-service case,
  and blocking port 22 on a *public* host prevents nothing
- `reject_credentials` -- `user:pass@host` is legal RFC 3986; a non-blocking
  advisory finding is emitted regardless

`policy="balanced"` differs from `strict` only in those two opt-in checks, so
in practice the two are very close. Use `balanced` when you intend to inspect
and canonicalize URLs yourself rather than reject them outright:

```python
from urlps import parse_url

balanced_url = parse_url("HTTP://EXAMPLE.com", policy="balanced")
```

Use `parse_url_local()` for development and internal URLs. It turns the
heuristic checks off and permits loopback/RFC1918 hosts, but **narrows SSRF
enforcement rather than disabling it** -- cloud metadata endpoints (in every
spelling), the link-local range, CGNAT, `.internal` and kubernetes service
names stay blocked:

```python
from urlps import SecurityPolicy, parse_url_local

dev_url = parse_url_local("http://localhost:3000/api")
internal = parse_url_local("http://192.168.1.100/metrics")

# If policy is passed, parse_url_local uses it exactly.
trusted_policy = SecurityPolicy.local(check_dns=True)
internal_checked = parse_url_local("http://intranet.local/service", policy=trusted_policy)
```

`parse_url_unsafe()` is the former name for the same function. It still
works but is deprecated -- it emits a `DeprecationWarning` and will be
removed in a future major release; use `parse_url_local()` instead.

Need to adjust the tradeoff? Use policy presets:
- `policy="strict"` (default): maximum protections
- `policy="balanced"`: the same, minus the two opt-in checks above
- `policy="internal"`: trusted traffic -- heuristics off, **SSRF still enforced**
- `policy="local"`: development -- heuristics off, loopback/private hosts allowed,
  metadata endpoints still blocked

To genuinely disable SSRF enforcement you must say so explicitly:
`SecurityPolicy.internal(enforce_ssrf=False)`.

### Allowed and denied addresses

Every preset (and `SecurityPolicy` itself) takes `allowed_addresses` and
`denied_addresses`. A rule is an IP address, a CIDR network, a hostname, or a
`.domain` matching the domain and all its subdomains. Rules match every
spelling of a host (hex/decimal IPs, IPv4-mapped IPv6, case, trailing dot,
IDNA) and every address it resolves to:

```python
from urlps import SecurityPolicy, parse_url

policy = SecurityPolicy.strict(
    allowed_addresses=["100.64.0.0/10", "fd12:3456::/32", "build.internal", ".corp.example"],
    denied_addresses=["hr.corp.example", "203.0.113.0/24"],
)

parse_url("http://100.101.102.103/status", policy=policy)  # a Tailscale address: allowed
parse_url("https://eng.corp.example/", policy=policy)  # allowed by the .corp.example rule
```

A denied match always rejects -- even with `enforce_ssrf=False` -- and wins
over an allowed one. Allowing a *hostname* also trusts what it resolves to,
except cloud metadata addresses, which only an explicit IP/network rule can
allow. An invalid rule (`"10.0.0.0/33"`, `"*.example.com"`) raises
`SecurityPolicyError` when the policy is built, never silently matching
nothing.

### What SSRF protection covers

There are three layers, and only the last one is complete:

1. **The host itself** (always on). Literal internal addresses and known
   internal names are rejected at parse time. A hostname that *resolves* to
   an internal address -- `127.0.0.1.nip.io`, or any domain an attacker
   controls -- passes this layer.
2. **`check_dns=True`** (opt-in). Rejects hosts that resolve to an internal
   address *at parse time*. Your HTTP client resolves the name again when it
   connects, and an attacker's DNS server can answer differently the second
   time (DNS rebinding), so this layer cannot stop a determined attacker.
3. **The connection** (opt-in, robust). `create_guarded_connection()`
   resolves once, refuses the connection if any answer is disallowed,
   connects only to a vetted address and re-checks the peer. It is a
   drop-in for `socket.create_connection` and for urllib3's, which
   `requests` uses:

```python
import functools

import urllib3.util.connection

from urlps import InvalidURLError, SecurityPolicy, create_guarded_connection


def install_ssrf_guard(policy: SecurityPolicy) -> None:
    """Make every urllib3/requests connection in this process go through the guard."""
    urllib3.util.connection.create_connection = functools.partial(create_guarded_connection, policy=policy)


# The guard on its own: refused before any packet is sent.
try:
    create_guarded_connection(("127.0.0.1", 9), timeout=1)
except InvalidURLError as exc:
    print(exc.code)  # ErrorCode.SSRF_RISK
```

If you pin connections yourself, `resolve_and_validate(url)` returns the
vetted addresses to connect to (send the original host in `Host`/SNI):

```python
from urlps import resolve_and_validate

addresses = resolve_and_validate("https://api.example.com/data")
```

Neither can see through an HTTP proxy -- with a proxy configured, the guard
validates the connection to the proxy. For fleet-wide enforcement, an egress
proxy that applies the same rules (e.g. Smokescreen) is the stronger option.

### DNS checks and rate limiting

`check_dns=True` resolutions are cached (30 s for an answer, 5 s for a
failure) and only real lookups count against the rate limits, so checking a
busy host repeatedly costs one lookup per TTL. A rate-limited check raises
`DNSRateLimitError` with `retry_after` set. Each check is bounded by
`SecurityPolicy.dns_deadline_seconds` (default 5 s) across retries.

The default limiter and resolution cache are process-wide. In multi-tenant
or concurrent applications, inject a limiter per tenant so one tenant's
traffic can never spend another's budget. Everything the checks do I/O
through -- the resolver, the resolution cache, the limiter and the phishing
feed -- is one `SecurityServices` value, accepted by every entry point:

```python
from urlps import (
    DNSCacheConfig,
    DNSRateLimiter,
    DNSRateLimiterConfig,
    DNSResolutionCache,
    SecurityServices,
    parse_url,
)

tenant_services = SecurityServices(
    dns_rate_limiter=DNSRateLimiter(DNSRateLimiterConfig(max_lookups_per_second=20, max_lookups_per_host=50)),
    resolution_cache=DNSResolutionCache(DNSCacheConfig(ttl_seconds=60)),
)

url = parse_url(
    "https://api.example.com",
    policy="strict",
    check_dns=True,
    services=tenant_services,
)
```

`SecurityServices(phishing_feed=...)` takes any object with a
`lookup(host) -> bool | None` method (`None` meaning "could not check"), or a
`PhishingDatabaseManager(PhishingFeedConfig(url=...))` pointed at a mirror.

A limiter (or `check_dns=True`) set on the `SecurityPolicy` is honoured by
`parse_url()`, `join()` and `build_secure()`; an explicit `check_dns=`
argument overrides the policy.

### Phishing checks

`check_phishing=True` checks the host -- and its parent domains, so
`login.evil.example` is caught when `evil.example` is listed -- against a
downloaded feed (see `URLPS_PHISHING_DATABASE_*` below). The list is
refreshed daily; a failed refresh keeps the previous list. If the feed cannot
be loaded at all, the URL is accepted with a `phishing_db_unavailable`
warning finding, unless the policy says otherwise:

```python
from urlps import SecurityPolicy

policy = SecurityPolicy.strict(check_phishing=True, phishing_fail_closed=True)
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

# Genuinely immutable, not immutable by convention -- a URL that passed
# validation cannot be re-pointed afterwards.
try:
    url._host = "evil.com"
except AttributeError as exc:
    print(exc)  # URL is immutable; use with_*() or copy() to derive a new URL ...

assert url.host == "example.com"
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

# Parse-time DNS check (optional; cached and rate-limited). This alone cannot
# stop DNS rebinding -- see "What SSRF protection covers" for the connect-time guard.
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

### Using `check_dns`/`check_phishing` from `asyncio` code

`check_dns=True` and `check_phishing=True` both do **blocking** network I/O
(DNS resolution plus a verification connect; a synchronous HTTP download,
respectively). Calling either directly inside an `async def` request handler
blocks the event loop for the duration of that call -- exactly the kind of
mistake that's easy to make in a FastAPI/aiohttp/Starlette handler doing
SSRF-guarded URL validation, which is precisely where this library is most
useful. Run them in an executor instead:

```python
import asyncio
import functools

from urlps import parse_url


async def parse_url_async(url, **kwargs):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, functools.partial(parse_url, url, **kwargs))


async def main():
    url = await parse_url_async("https://api.example.com/data", check_dns=True)
    print(url.host)  # api.example.com


asyncio.run(main())
```

The same pattern applies to `check_phishing=True` and to `build_secure()`.
There is no bundled async wrapper -- `run_in_executor` (or an equivalent from
your framework, e.g. `starlette.concurrency.run_in_threadpool`) is sufficient
and avoids committing this library to a specific async runtime.

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

URLs are redacted before being passed to callbacks: the userinfo password
(or a bare token) is masked; query values are masked when the key *contains*
`token`, `secret`, `key`, `sig`, `pass`, `auth`, `session`, `code`, `jwt`,
`otp`, ... (so `client_secret`, `X-Amz-Signature` and `id_token` are all
caught); every `key=value` value in the fragment is masked (OAuth
implicit-flow tokens live there); and a URL that cannot even be split is
logged as `[unparseable URL redacted]` rather than verbatim. Add your own key
fragments with `AuditConfig(..., sensitive_keys=frozenset({"tenant"}))`, or
opt out entirely with `redact_urls=False`. A callback that raises is recorded
as a failure and never breaks the parse.

The same `audit=` parameter is accepted by `parse_url_local()`, `join()` and
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
- `URLPS_PHISHING_DATABASE_URL` -- overrides the feed `check_phishing=True`
  downloads hostnames from (default: a third-party list at `phish.co.za`).
  Must be an `http://` or `https://` URL; set this to self-host the list or
  point at a mirror you trust instead. Must be set before `import urlps`,
  same as the cache-size variables below.
- `URLPS_PHISHING_DATABASE_REFRESH_SECONDS` -- how old the loaded list may
  get before the next check re-downloads it (default 86400). A failed
  refresh keeps the previous list.
- `URLPS_PHISHING_DATABASE_SHA256` -- optional SHA-256 (hex) the downloaded
  feed must match; for a self-hosted or mirrored snapshot (a live feed
  changes too often to pin). A mismatch counts as a failed download.

Internal `@lru_cache` sizes, and the longest key a cache will retain, are
also overridable this way -- see [Cache Sizing](#cache-sizing) below.

## API Reference

### Main Functions

| Function | Description |
| --- | --- |
| `parse_url(url, *, allow_custom_scheme=False, debug=False, check_dns=None, check_phishing=None, dns_rate_limiter=None, policy=None, correlation_id=None, audit=None)` | Parse URL with policy-aware security checks (recommended). `None` for `check_dns`/`check_phishing` defers to the policy. |
| `parse_url_local(url, *, allow_custom_scheme=False, debug=False, check_dns=False, dns_rate_limiter=None, policy=None, correlation_id=None, audit=None)` | Parse URL for trusted/internal input with optional policy overrides |
| `parse_url_unsafe(...)` | **Deprecated** alias for `parse_url_local()`; emits `DeprecationWarning` |
| `join(base, reference, *, policy=None, strict_resolution=True, ...)` | Resolve a reference against a base URI (RFC 3986 §5), then validate |
| `resolve_and_validate(url, *, policy=None, port=None, dns_timeout=2.0)` | Resolve the host once and return its addresses, all validated under the policy (for pinning connections) |
| `create_guarded_connection(address, timeout=..., source_address=None, socket_options=None, *, policy=None)` | Drop-in for `socket.create_connection` / urllib3's that connects only to policy-permitted addresses |
| `build(*scheme_and_host, port=None, path="/", query=None, fragment=None, userinfo=None)` | Build URL string from components |
| `build_secure(*scheme_and_host, policy=None, check_dns=None, check_phishing=None, dns_rate_limiter=None, correlation_id=None, audit=None, ...)` | Build and then validate a URL under a selected security policy |
| `compose_url(components)` | Build URL from components dict |

`build()`/`compose_url()` validate that `host` is a syntactically valid
hostname, IPv4 literal, or bracketed IPv6 literal (raising
`HostValidationError` otherwise), so their output always round-trips through
`parse_url()`. `userinfo` is percent-encoded to the RFC 3986 grammar
(`build("http", "example.com", userinfo="a@b:p#")` gives
`http://a%40b:p%23@example.com/`), so no character in it can move the host.
This is structural validation only, not security policy -- use
`build_secure()` when the host isn't already trusted.

`with_*()`/`copy()` follow the same rules as `parse_url()`: the scheme
allowlist applies to `with_scheme()` (which also resets a default port),
userinfo is percent-encoded, a raw `#` in `with_query()` is rejected, and
every derived URL is re-parsed to confirm its string names the same scheme
and authority before it is returned.

Note: `get_dns_rate_limiter()` and `reset_dns_rate_limiter()` remain available for compatibility, but explicit `dns_rate_limiter=` injection is preferred.

### URL Methods

| Method | Description |
| --- | --- |
| `url.as_string(mask_password=False)` | Convert to string, optionally masking password |
| `url.canonicalize()` | Return canonicalized copy |
| `url.is_semantically_equal(other)` | Compare URLs by meaning after canonicalization |
| `url.same_origin(other)` | Check if URLs have same origin |
| `url == "https://..."`, `<`, `<=`, `>`, `>=` | Compare a `URL` directly against another `URL` or a plain string, against `as_string()` (no canonicalization) |
| `url.origin` | Return origin string (e.g., `https://example.com`) |
| `url.copy(**overrides)` | Create copy with optional component overrides |
| `url.with_*()` | Functional updates: `with_scheme`, `with_host`, `with_port`, `with_path`, `with_fragment`, `with_userinfo`, `with_netloc`, `with_query_param`, `without_query_param` |
| `url.get_query_param(key, default=None)` | First value for `key`, or `default` if absent (`None` for a present, value-less key like `?flag`) |
| `url.get_query_param_all(key)` | All values for `key`, in order; `[]` if absent |

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
| `URLPS_CACHE_MAX_KEY_LENGTH` | 1024 | longest URL/path/component (in characters) a cache keeps; longer inputs are computed uncached |
| `URLPS_CACHE_MAX_VALUE_KEY_LENGTH` | 128 | the same bound for the per-value query/path encoders |

The key-length bounds exist because a cache keeps its key and result alive
until evicted: without them, maximal-length distinct inputs pinned hundreds
of megabytes for the life of the process. With the defaults, every cache
full of worst-case keys stays around 50 MB in total.

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

## Command Line

`pip install urlps` also installs a `urlps` script for validating URLs from
shell scripts, CI pipelines, or pre-commit hooks, without writing a
throwaway Python file:

```bash
urlps check https://example.com/path 'HTTP://EXAMPLE.COM:80/'
# https://example.com/path
# http://example.com/

urlps check http://localhost/admin
# http://localhost/admin: Host poses SSRF risk and is disallowed. ...  (to stderr)
# exit code 1

urlps check --policy local http://localhost:3000/api   # like parse_url_local()
urlps check --check-dns https://api.example.com/        # also verify DNS resolution

# One URL per line on stdin when no URL arguments are given
# ('#'-prefixed and blank lines are skipped):
cat urls.txt | urlps check
```

Exits `0` and prints the canonical form of every URL if all pass; exits `1`
and prints the rejection reason (to stderr) for each URL that fails,
alongside the canonical form of the ones that passed. `--quiet` suppresses
success output so only failures are printed. `--policy`, `--check-dns` and
`--check-phishing` mirror `parse_url()`'s own options. Non-printable
characters in the output (terminal escape sequences, bidi controls) are
escaped, since the URLs being checked are usually untrusted.

## Comparison with urllib.parse

| Feature | urllib.parse | urlps |
| --- | --- | --- |
| Basic URL parsing | ✓ | ✓ |
| RFC 3986 strict compliance | Partial | ✓ |
| SSRF protection | ✗ | ✓ |
| Connect-time SSRF guard (DNS rebinding) | ✗ | ✓ (`create_guarded_connection`) |
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

Exceptions carry the offending input as `exc.value`, and `str(exc)` includes
it. Credentials and query/fragment values in it are **redacted by default**,
since exception text routinely reaches logs and error responses; pass
`debug=True` to `parse_url()`/`parse_url_local()` to keep the raw input.

Exception hierarchy:
- `InvalidURLError` — Base exception for all URL errors
- `URLParseError` — Parsing errors
- `URLBuildError` — Building errors
- `HostValidationError` / `PortValidationError` — Component validation errors
- `QueryParsingError`, `FragmentEncodingError`, `UserInfoParsingError`, `UnsupportedSchemeError` — Specific errors
- `DNSRateLimitError` (a `DNSRebindingError`) — retryable; `retry_after` says when

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
