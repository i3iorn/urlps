# Security Policy

## Reporting a Vulnerability

**Please do not open a public issue for security vulnerabilities.**

If you discover a security vulnerability in urlps, please report it via GitHub Security Advisories or by opening a private security issue.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if available)

We will acknowledge receipt within 48 hours and provide updates on progress toward a fix.

## Security Features

urlps is designed with security as a priority and includes comprehensive protections:

### Built-in Protections

`parse_url()` uses the `balanced` policy by default for compatibility, and `policy="strict"` enables maximum hardening.

1. **SSRF Protection**: Blocks private IPs, localhost, loopback addresses, link-local addresses, `.local` and `.internal` domains
2. **Path Traversal Detection**: Prevents `../` attacks and path normalization attacks
3. **Double-Encoding Detection**: Identifies malicious double-encoded characters
4. **Homograph Attack Prevention**: Detects mixed Unicode scripts with enhanced Punycode/IDN validation
5. **Open Redirect Detection**: Validates URL structures to prevent redirects
6. **Component Length Limits**: Conservative limits prevent DoS attacks
7. **URL Parser Confusion Detection**: Enhanced security validations to prevent parser inconsistencies
8. **Query Parameter Injection Detection**: Identifies malicious query parameter patterns
9. **Credential Leakage Detection**: Warns about credentials in URLs
10. **Dangerous Port Validation**: Blocks connections to commonly exploited ports
11. **Unicode Normalization**: Prevents Unicode-based security bypasses
12. **IPv6 Zone Identifier Validation**: Validates IPv6 zone identifiers for security
13. **Canonical Form Validation**: Prevents security filter bypasses and cache poisoning via non-canonical URLs

### Optional Security Checks

- **DNS Rebinding Detection**: Enable with `check_dns=True` to verify hostnames don't resolve to private IPs (rate-limited to prevent DoS)
- **DNS Rate Limiting**: Automatic protection against DoS attacks via DNS lookup flooding (10 lookups/second globally, 3 per host per 60 seconds)
- **Phishing Domain Checking**: Enable with `check_phishing=True` to check against known phishing domains
- **Audit Logging**: Use `set_audit_callback()` for security monitoring
- **Structured Audit Events**: Use `set_audit_event_callback()` for machine-readable telemetry

## Usage Guidelines

### Secure Parsing (Recommended)

```python
from urlps import parse_url, InvalidURLError

# Secure by default - automatically blocks malicious patterns
try:
    url = parse_url(user_input)
    # URL is validated and safe to use
except InvalidURLError as e:
    # Handle invalid/malicious URL
    print(f"Rejected: {e}")
```

### Unsafe Parsing (Internal/Trusted URLs Only)

```python
from urlps import parse_url_unsafe

# Use ONLY for internal/development URLs you control
dev_url = parse_url_unsafe("http://localhost:3000/api")
internal = parse_url_unsafe("http://192.168.1.100/metrics")
```

### Additional Security Options

```python
# DNS rebinding protection (performs DNS lookup)
url = parse_url("https://api.example.com/", check_dns=True)

# Policy-based control (strict, balanced, internal)
url = parse_url("https://api.example.com/", policy="strict")

# Password masking for logs
url = parse_url("https://user:pass@example.com/")
safe_string = url.as_string(mask_password=True)  # https://user:***@example.com/

# URL canonicalization for consistent comparisons
url = parse_url("HTTP://EXAMPLE.COM:80/path")
canonical = url.canonicalize()  # Normalized for security checks

# Canonical form validation (prevents filter bypass)
from urlps._security import is_non_canonical_url, get_canonical_url
if is_non_canonical_url("HTTP://EXAMPLE.COM:80/./path"):
    canonical = get_canonical_url("HTTP://EXAMPLE.COM:80/./path")
    # Returns: "http://example.com/path"
```

## Security Considerations

### IDNA/Internationalized Domains

When IDNA support is available (`pip install idna`), hostnames containing non-ASCII characters are automatically normalized to Punycode. This prevents certain homograph attacks but be aware:
- Visually similar characters from different scripts are still possible
- Always use `parse_url()` (not `parse_url_unsafe()`) for untrusted input
- The built-in mixed-script detection helps identify suspicious domains

### URL Components

1. **Fragments**: Not transmitted to servers; don't use for sensitive data
2. **Userinfo**: Credentials in URLs are deprecated; use proper authentication instead
3. **Query Parameters**: Always percent-encode sensitive data in query strings
4. **Relative References**: `parse_relative_reference()` doesn't normalize paths; use with caution for untrusted input

### Environment Variables

Override component length limits via environment variables (e.g., `URLPS_MAX_URL_LENGTH`). Use caution when increasing limits in security-sensitive contexts as this expands attack surface.

## Best Practices

✅ **Do:**
- Use `parse_url()` for all user-supplied URLs
- Use `policy="strict"` (default) for untrusted input
- Enable `check_dns=True` when making network requests to untrusted domains
- Use `mask_password=True` when logging URLs
- Keep urlps updated to receive security patches
- Use audit callbacks for security monitoring in production
- Validate URLs before making network requests

❌ **Don't:**
- Use `parse_url_unsafe()` for untrusted input
- Disable security checks for user-supplied URLs
- Store credentials in URLs (use proper authentication mechanisms)
- Trust fragments for security decisions
- Increase length limits without understanding DoS implications

## Supported Versions

| Version | Supported  | Notes |
| --- |------------| --- |
| 0.4.x | ✅ Yes      | Latest - Enhanced security validations, DNS rate limiting, canonical form validation |
| 0.3.x | ⚠️ Limited | Previous stable - Full security features, upgrade recommended |
| 0.2.x | ❌ No       | Security features added; upgrade required |
| 0.1.x | ❌ No       | Legacy - No security protections |
| 0.0.x | ❌ No       | Legacy |

**Recommendation:** Always use the latest 0.4.x version for complete security protection.

## Security Audit

urlps has been designed with security best practices:
- All user input is validated before processing
- Component length limits prevent DoS attacks
- SSRF protections are enabled by default
- Immutable URL objects prevent accidental modifications
- Comprehensive test coverage including security-focused tests
- Static analysis with Bandit security scanner

For security concerns or questions, please refer to our issue tracker or security advisory system.
