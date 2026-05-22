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

## Quick Start

```python
from src.urlps import parse_url, build

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

# Policy-based validation
strict_url = parse_url("https://example.com", policy="strict")
balanced_url = parse_url("HTTP://EXAMPLE.com", policy="balanced")
```

### Security

`parse_url()` blocks by default:
- Private IPs (192.168.x.x, 10.x.x.x, 172.16.x.x)
- Localhost and loopback addresses
- Link-local addresses (169.254.x.x)
- `.local` and `.internal` domains
- Path traversal patterns (`../`)
- Double-encoded characters
- Mixed Unicode scripts (homograph attacks)
- URL parser confusion attacks

`parse_url(..., policy="strict")` additionally blocks:
- Query parameter injection
- Dangerous ports (commonly exploited)
- Non-canonical URL forms (filter bypass prevention)
- Credentials in URL userinfo by default (`user:pass@host`)

Use `parse_url_unsafe()` for internal/development URLs:
```python
from src.urlps import parse_url_unsafe

dev_url = parse_url_unsafe("http://localhost:3000/api")
internal = parse_url_unsafe("http://192.168.1.100/metrics")
```

Need selective hardening? Use policy presets:
- `policy="strict"`: maximum protections
- `policy="balanced"` (default): fewer false positives
- `policy="internal"`: trusted/internal traffic

## Core Features

### Immutable URL Objects

```python
from src.urlps import parse_url

url = parse_url("https://user:pass@example.com:8080/path?token=abc")
print(url.netloc)         # user:pass@example.com:8080
print(url.effective_port) # 8080

# with_* methods return new URL objects
url2 = url.with_netloc("admin@example.com")
url3 = url.with_host("other.com").with_port(443).with_path("/api")
url4 = url.with_query_param("new", "value")
url5 = url.without_query_param("token")
```

### Security Checks

```python
from src.urlps import parse_url, InvalidURLError

# SSRF protection (enabled by default)
try:
    parse_url("http://localhost/admin")  # Blocked
except InvalidURLError as e:
    print(f"Rejected: {e}")

# DNS rebinding detection (optional - rate-limited to prevent DoS)
url_dns = parse_url("https://api.example.com/", check_dns=True)

# URL canonicalization
url_raw = parse_url("HTTP://EXAMPLE.COM:80/path?z=1&a=2")
canonical = url_raw.canonicalize()
print(canonical.scheme)  # "http"
print(canonical.host)    # "example.com"
print(canonical.port)    # None (default port removed)
print(canonical.query)   # "a=2&z=1" (sorted)

# Password masking
url = parse_url("https://admin:secret123@api.example.com/")
print(url.as_string(mask_password=True))  # https://admin:***@api.example.com/
```

### Audit Logging

```python
from src.urlps import set_audit_callback
import logging

def audit_url_parsing(raw_url, parsed_url, exception):
    if exception:
        logging.warning(f"Failed to parse URL: {exception}")
    else:
        logging.info(f"Parsed URL to host: {parsed_url.host}")

set_audit_callback(audit_url_parsing)
```

Structured event callback:
```python
from src.urlps import set_audit_event_callback

def on_event(event):
    # event includes: timestamp, level, operation, host, error_code, correlation_id
    print(event)

set_audit_event_callback(on_event)
```

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
python -c "import src.urlps.constants as c; print(c.MAX_URL_LENGTH)"

# Bash
export URLPS_MAX_URL_LENGTH=65536
python -c 'import src.urlps.constants as c; print(c.MAX_URL_LENGTH)'
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

## API Reference

### Main Functions

| Function | Description |
| --- | --- |
| `parse_url(url, *, allow_custom_scheme=False, check_dns=False, check_phishing=False, policy=None, correlation_id=None)` | Parse URL with policy-aware security checks (recommended) |
| `parse_url_unsafe(url, *, allow_custom_scheme=False, strict=False, debug=False, check_dns=False, policy=None, correlation_id=None)` | Parse URL for trusted/internal input with optional policy overrides |
| `build(*scheme_and_host, port=None, path="/", query=None, fragment=None, userinfo=None)` | Build URL string from components |
| `build_secure(*scheme_and_host, policy=None, check_dns=False, check_phishing=False, correlation_id=None, ...)` | Build and then validate a URL under a selected security policy |
| `compose_url(components)` | Build URL from components dict |

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
from src.urlps import get_cache_info, clear_all_caches

# Get cache statistics
stats = get_cache_info()
print(stats['parser']['normalize_path']['hits'])

# Clear all caches (useful for long-running apps)
previous = clear_all_caches()
```

## Comparison with urllib.parse

| Feature | urllib.parse | src.urlps |
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

**Use src.urlps when:** Security matters, you need RFC 3986 strict compliance, or you want immutable URL objects with ergonomic manipulation methods.

## Exceptions

```python
from src.urlps import InvalidURLError, URLParseError, parse_url

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

## License

MIT
