# Migration Guide

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
| `parse_url_unsafe()` | `parse_url_local()` | Alias retained, still works. "Unsafe" was the wrong signal for parsing your own dev URL — and under the `local` policy it is not even unsafe. |
| `enforce_query_injection` | *(removed)* | Passing it is accepted and ignored; removed in 2.0. |
| `require_canonical` | *(removed)* | Superseded by normalization. |
| `enforce_suspicious_punycode` | `enforce_confusable_host` + `enforce_mixed_scripts` | Old flag accepted as a no-op; removed in 2.0. |
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
