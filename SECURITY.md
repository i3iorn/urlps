# Security Policy

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Report privately via
[GitHub Security Advisories](https://github.com/i3iorn/urlps/security/advisories/new).
Include a description, reproduction steps, and impact assessment.

This is a solo-maintained project, so response times are best-effort: expect
an acknowledgement within about a week. Please allow 90 days before public
disclosure, and mention it if you intend to disclose sooner so that can be
coordinated.

## What's protected by default

`parse_url()` defaults to `policy="strict"`. Blocked under both `strict` and
`balanced`:

1. **SSRF** — every address that is not public, globally routable unicast
   (private, loopback, link-local, CGNAT `100.64.0.0/10`, ULA, site-local,
   multicast, reserved, documentation), `.local`/`.internal`, cloud metadata
   endpoints by address and name (`169.254.169.254`, `100.100.100.200`,
   `fd00:ec2::254`, `metadata.google.internal`), and every obfuscated
   spelling (decimal, octal, hex, IPv4-mapped IPv6, NAT64, 6to4, Teredo).
   Checks run on the host the parser produced — the one `url.host` returns —
   not on a re-reading of the raw string. Callers can extend or narrow this
   with `allowed_addresses`/`denied_addresses` on the policy.
2. **Path traversal** — `../`, null bytes, encoded variants
3. **Double-encoding** — `%25xx` filter-bypass patterns
4. **Open redirect** — leading `//`, backslashes, raw or percent-encoded
5. **Homograph attacks** — mixed scripts and whole-script confusables,
   evaluated per label on the Punycode-decoded host
6. **Parser confusion** — URLs different parsers would disagree about
7. **Invisible characters** — bidi controls, zero-width, malformed Punycode
8. **Non-standard schemes** — only `http(s)`, `ftp(s)`, `sftp`, `ws(s)`
   without `allow_custom_scheme=True`

Opt-in via `SecurityPolicy` (off by default — see the README for why):
`block_dangerous_ports`, `reject_credentials`.

Optional, always off by default, and **both do blocking network I/O on the
thread that calls `parse_url()`** — warm them up (or run with expected
latency) rather than first paying it on a live request:

- `check_dns=True` (rejects hosts that resolve to internal addresses at parse
  time; cached and rate-limited). One check is bounded by a ~5s total
  deadline, but a slow or black-holed resolver can leave up to one abandoned
  worker thread per attempt behind it, so per-parse latency is the resolver's
  problem under attack. Prefer `create_guarded_connection()` for the
  connect-time guarantee.
- `check_phishing=True` (downloaded domain blocklist, matched with parent
  domains, refreshed daily). The download is lazy, under a lock: a slow feed
  could otherwise hold every concurrent `check_phishing=True` parse behind
  one in-flight download, so the download is capped (25 MB) and
  wall-clock-bounded (~30s). Call `refresh_phishing_db()` at startup to pay
  the download off the request path.

`check_phishing=True` trusts a single third-party feed (`phish.co.za`) by
default; set `URLPS_PHISHING_DATABASE_URL` to self-host the list or point at a
feed you trust, `URLPS_PHISHING_DATABASE_SHA256` to pin a snapshot, and
`phishing_fail_closed=True` on the policy to reject URLs when the feed is
unavailable. Fail-closed is opt-in here and the default is fail-open: without
it, an unreachable feed means the host was *not* checked — check
`get_phishing_db_info()` for `loaded`/`last_error` when relying on the
feature. A `http://` feed URL is accepted (for unencrypted internal mirrors)
but warned about at import, because the list can be tampered with in transit.

## What parse-time checks cannot do

Parse-time checks — including `check_dns=True` — cannot prevent DNS
rebinding: the HTTP client resolves the host again when it connects, and an
attacker's DNS server can answer differently the second time. Validate the
connection itself with `create_guarded_connection()` (a drop-in for
`socket.create_connection` and urllib3's, which `requests` uses), pin
connections to the addresses `resolve_and_validate()` returns, or route
egress through a proxy that enforces the same rules. See the README's
"What SSRF protection covers".

Cosmetic differences (host case, trailing dot, default port, `%7E`, dot
segments) are normalized rather than rejected — see the README's Security
section for the full account.

## Usage

```python
from urlps import parse_url, InvalidURLError

try:
    url = parse_url(user_input)
except InvalidURLError as e:
    print(f"Rejected: {e}")
```

For URLs you control (local dev, internal config), use `parse_url_local()`
instead of `parse_url()`. It relaxes the heuristic checks and permits
loopback/RFC1918 hosts, but still blocks cloud metadata endpoints and
link-local addresses — it narrows SSRF enforcement, it does not disable it.

```python
from urlps import parse_url_local

dev_url = parse_url_local("http://localhost:3000/api")
```

## Notes

- **IDNA/Unicode.** With the `idna` package installed (`pip install
  urlps[idna]`), hosts are encoded per UTS-46/IDNA 2008, matching browser
  resolution. Without it, urlps falls back to the stdlib IDNA 2003 codec and
  emits a `RuntimeWarning` at import naming what that costs.
- **Fragments** are never transmitted to servers — don't use them for
  sensitive data.
- **Credentials in URLs** are deprecated; `URL.as_string(mask_password=True)`
  or `URL.redacted()` for logging. Exception values and audit callbacks are
  redacted by default (password, sensitive query keys, fragment values);
  `debug=True` keeps the raw input in exceptions — including in anything an
  audit callback receives — and never belongs on a path that can reach
  shared logs.
- **Encoding-unsafe input fails fast.** A URL containing a lone surrogate
  (U+D800-U+DFFF, e.g. from a decoder producing unpaired surrogates) is
  rejected at parse time: such characters cannot be encoded to bytes, so
  they would otherwise crash *consumers'* `str()`/logging paths with a raw
  `UnicodeEncodeError` instead of a `urlps.InvalidURLError`. Similarly,
  `build()`/`compose_url()`/`with_query_param()` raise `URLBuildError` for
  surrogate components.
- **Exception shapes to plan for.** `parse_url()` and the URL methods raise
  `urlps`'s own exception family under `InvalidURLError`. DNS resolution
  failures raised by `create_guarded_connection()` / `resolve_and_validate()`
  are `DNSResolutionError` — both an `InvalidURLError` and an `OSError`, so
  socket-error-family retry logic (urllib3/`requests`, `except OSError`
  handlers) catches them like a native resolution failure would. Calling
  the DNS layer directly with a host no IDNA codec can encode also yields a
  `DNSResolutionError`, not a raw `UnicodeError`.
- **Length limits** are overridable via `URLPS_MAX_*` environment variables.
  Raising them expands attack surface — only do so with a reason. The same
  is true for `URLPS_CACHE_SIZE_*` and `URLPS_CACHE_MAX_KEY_LENGTH`: cache
  sizes and key lengths bound the memory attacker-supplied distinct inputs
  can pin for the life of the process, so oversized values are clamped (with
  a warning) rather than honored.
- **Supply chain.** CI generates a CycloneDX SBOM (`urlps-sbom.json`) for
  every build, uploaded as a build artifact alongside the sdist/wheel. Every
  GitHub Action is pinned to a commit SHA; releases are built from
  hash-pinned tools in a job without publishing credentials, and only a
  command-free job holds the PyPI trusted-publishing token.

## Best practices

- Use `parse_url()` for untrusted input; `parse_url_local()` only for URLs
  you control.
- For outbound requests to untrusted URLs, use `create_guarded_connection()`
  (or an egress proxy); `check_dns=True` alone is an early rejection, not a
  guarantee.
- Don't trust fragments for security decisions.
- Keep urlps updated for security patches.

## Supported versions

| Version | Supported |
|---|---|
| 1.x | Yes |
| 0.x | No |

Always use the latest released version.
