# Migration Guide

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
