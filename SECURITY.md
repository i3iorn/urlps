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

1. **SSRF** — private IPs, loopback, link-local, `.local`/`.internal`, cloud
   metadata endpoints (`169.254.169.254`, `metadata.google.internal`), and
   obfuscated spellings (decimal, octal, hex, IPv4-mapped IPv6, NAT64)
2. **Path traversal** — `../`, null bytes, encoded variants
3. **Double-encoding** — `%25xx` filter-bypass patterns
4. **Open redirect** — leading `//`, backslashes, raw or percent-encoded
5. **Homograph attacks** — mixed scripts and whole-script confusables,
   evaluated per label on the Punycode-decoded host
6. **Parser confusion** — URLs different parsers would disagree about
7. **Invisible characters** — bidi controls, zero-width, malformed Punycode

Opt-in via `SecurityPolicy` (off by default — see the README for why):
`block_dangerous_ports`, `reject_credentials`.

Optional, always off by default, and both do blocking network I/O:
`check_dns=True` (DNS rebinding, rate-limited), `check_phishing=True`
(downloaded domain blocklist). `check_phishing=True` trusts a single
third-party feed (`phish.co.za`) by default, fetched with no integrity
check beyond a size cap; set `URLPS_PHISHING_DATABASE_URL` (see the
README's Environment Variables section) to self-host the list or point at
a feed you trust instead.

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
  or `URL.redacted()` for logging.
- **Length limits** are overridable via `URLPS_MAX_*` environment variables.
  Raising them expands attack surface — only do so with a reason.

## Best practices

- Use `parse_url()` for untrusted input; `parse_url_local()` only for URLs
  you control.
- Enable `check_dns=True` before making network requests to untrusted
  domains.
- Don't trust fragments for security decisions.
- Keep urlps updated for security patches.

## Supported versions

| Version | Supported |
|---|---|
| 1.x | Yes |
| 0.x | No |

Always use the latest released version.
