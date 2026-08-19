"""
Hand-written malicious/adversarial URL corpus.

Each section below is tagged with its expected outcome (see
EXPECTATION_* in url_cases/_models.py):

- EXPECTATION_UNSAFE   -- syntactically valid, semantically dangerous
  (SSRF target, path traversal, credential smuggling, ...). Accepting
  it is correct parser behavior; only a security-focused validator is
  expected to flag/reject it.
- EXPECTATION_INVALID  -- malformed under any reasonable interpretation
  of the URI grammar (a raw control character, a non-digit port, a
  truncated IPv6 literal, ...). A correct parser should reject it.
- EXPECTATION_AMBIGUOUS -- genuinely disputed among reasonable,
  spec-compliant parsers (WHATWG vs. RFC 3986 backslash handling,
  out-of-range numeric ports, optional IPv6 zone-ID/IPvFuture support,
  DNS-dependent SSRF that can't be judged statically, ...). Never
  scored either way.
- EXPECTATION_VALID    -- ordinary well-formed URLs included for
  contrast/coverage alongside the adversarial ones above.

These are best-effort classifications, not a formal grammar checker's
output -- edge cases were judged by hand. Where a single hand-written
category mixes outcomes (e.g. some entries percent-encoded and
therefore syntactically valid, others containing a raw control byte
and therefore not), the category is split into sub-sections rather
than forcing one tag on all of it.
"""

from __future__ import annotations

from ._models import (
    EXPECTATION_AMBIGUOUS,
    EXPECTATION_INVALID,
    EXPECTATION_UNSAFE,
    EXPECTATION_VALID,
)

#: (category, expected outcome, urls) -- flattened below into
#: MALICIOUS_URLS/MALICIOUS_EXPECTATIONS, kept structured here so each
#: URL's expectation stays next to the URL itself instead of drifting
#: out of sync in a separate parallel list.
_SECTIONS: list[tuple[str, str, list[str]]] = [
    (
        'SSRF: loopback / private / link-local',
        EXPECTATION_UNSAFE,
        [
            "http://localhost/admin",
            "http://127.0.0.1/admin",
            "http://127.0.0.1:22/",
            "http://0.0.0.0/",
            "http://[::1]/admin",
            "http://10.0.0.1/",
            "http://172.16.0.1/",
            "http://172.31.255.255/",
            "http://192.168.0.1/",
            "http://192.168.1.1/",
            "http://169.254.1.1/",
            "http://[fe80::1]/",
        ],
    ),
    (
        'SSRF: cloud metadata endpoints',
        EXPECTATION_UNSAFE,
        [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.goog/computeMetadata/v1/",
            "http://169.254.170.2/v2/credentials/",
            "http://kubernetes.default.svc.cluster.local/",
        ],
    ),
    (
        'SSRF: obfuscated/encoded IPs (bypass naive string-based blocklists)',
        EXPECTATION_UNSAFE,
        [
            "http://2130706433/",
            "http://017700000001/",
            "http://0x7f000001/",
            "http://0x7f.0x0.0x0.0x1/",
            "http://0177.0.0.1/",
            "http://127.1/",
            "http://127.0.1/",
            "http://[::ffff:127.0.0.1]/",
            "http://[::ffff:169.254.169.254]/",
            "http://[0:0:0:0:0:ffff:a9fe:a9fe]/",
        ],
    ),
    (
        'SSRF: internal-only TLDs',
        EXPECTATION_UNSAFE,
        [
            "http://service.local/",
            "http://internal.corp.internal/",
            "http://box.localhost/",
        ],
    ),
    (
        'SSRF: wildcard-DNS bypass services',
        EXPECTATION_UNSAFE,
        [
            "http://127.0.0.1.nip.io/",
            "http://10.0.0.1.nip.io/",
            "http://127.0.0.1.sslip.io/",
            "http://127.0.0.1.xip.io/",
        ],
    ),
    (
        'Path traversal',
        EXPECTATION_UNSAFE,
        [
            "https://example.com/../../etc/passwd",
            "https://example.com/a/../../../etc/passwd",
            "https://example.com/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "https://example.com/%2e%2e/%2e%2e/etc/passwd",
            "https://example.com/..%2f..%2fetc%2fpasswd",
            "https://example.com/%252e%252e%252fetc%252fpasswd",
            "https://example.com/....//....//etc/passwd",
            "https://example.com/..\\..\\windows\\system32",
            "https://example.com/path/%00.jpg/../../etc/passwd",
        ],
    ),
    (
        'Open redirect / protocol-relative smuggling',
        EXPECTATION_UNSAFE,
        [
            "https://example.com//evil.com/",
            "https://example.com///evil.com/",
            "https://example.com/\\evil.com/",
            "https://example.com/redirect?url=//evil.com",
            "https://example.com/redirect?url=https://evil.com",
            "https://example.com/%5cevil.com",
        ],
    ),
    (
        'Credential smuggling',
        EXPECTATION_UNSAFE,
        [
            "https://paypal.com@evil.com/",
            "https://accounts.google.com@evil.com/login",
            "https://www.bank.com:password@evil.com/",
            "https://evil.com%2523@trusted.com/",
            "https://trusted.com%40evil.com/",
        ],
    ),
    (
        'Homograph / confusable-script and punycode spoofing',
        EXPECTATION_UNSAFE,
        [
            "https://аpple.com/",
            "https://gооgle.com/",
            "https://xn--pple-43d.com/",
            "https://xn--80ak6aa92e.com/",
            "https://xn--e1afmkfd.xn--p1ai/",
            "https://ebay.com.verify-account.evil.com/",
        ],
    ),
    (
        'Double-encoding (filter-bypass via re-encoded percent sequences)',
        EXPECTATION_UNSAFE,
        [
            "https://example.com/?redirect=%252e%252e%252f",
            "https://example.com/%25252e%25252e%25252f",
            "https://example.com/?next=http%253A%252F%252Fevil.com",
        ],
    ),
    (
        'Parser confusion (ambiguous host boundaries)',
        EXPECTATION_AMBIGUOUS,
        [
            "https://trusted.com\\@evil.com/",
            "https://trusted.com#@evil.com/",
            "https://trusted.com?@evil.com/",
            "https://evil.com\\trusted.com/",
            "https:evil.com",
            "https:/\\evil.com",
            "http://foo@evil.com@trusted.com/",
        ],
    ),
    (
        'Query / header injection',
        EXPECTATION_UNSAFE,
        [
            "https://example.com/?q=<script>alert(1)</script>",
            "https://example.com/?redirect=javascript:alert(document.cookie)",
            "https://example.com/?q=\" onmouseover=\"alert(1)",
            "https://example.com/?next=data:text/html,<script>alert(1)</script>",
            "https://example.com/%0d%0aSet-Cookie:%20session=evil",
            "https://example.com/?redirect=%0d%0aLocation:%20https://evil.com",
            "https://example.com/\r\nHost: evil.com",
        ],
    ),
    (
        'Null-byte / control-character smuggling outside the path (unsafe)',
        EXPECTATION_UNSAFE,
        [
            "https://example.com%00.evil.com/",
        ],
    ),
    (
        'Null-byte / control-character smuggling outside the path (invalid)',
        EXPECTATION_INVALID,
        [
            "https://example.com/login\x00.php",
            "https://evil.com\x00.trusted.com/",
        ],
    ),
    (
        'Dangerous ports (plaintext/internal protocols behind an HTTP fetcher)',
        EXPECTATION_UNSAFE,
        [
            "http://example.com:22/",
            "http://example.com:25/",
            "http://example.com:3306/",
            "http://example.com:6379/",
            "http://example.com:11211/",
            "http://example.com:27017/",
        ],
    ),
    (
        'Alternate schemes for SSRF pivoting',
        EXPECTATION_UNSAFE,
        [
            "gopher://127.0.0.1:6379/_SET%20key%20value",
            "dict://127.0.0.1:11211/stat",
            "file:///etc/passwd",
            "file://127.0.0.1/etc/passwd",
            "ftp://127.0.0.1:21/",
        ],
    ),
    (
        'IPv6 zone ID abuse',
        EXPECTATION_AMBIGUOUS,
        [
            "http://[fe80::1%25eth0]/",
            "http://[fe80::1%2500]/",
            "http://[fe80::1%25../../etc/passwd]/",
        ],
    ),
    (
        'Whitespace/control-character smuggling inside the authority (invalid)',
        EXPECTATION_INVALID,
        [
            "http://trusted.com\t.evil.com/",
            "http://trusted.com\n.evil.com/",
        ],
    ),
    (
        'Whitespace/control-character smuggling inside the authority (unsafe)',
        EXPECTATION_UNSAFE,
        [
            "http://trusted.com%0a.evil.com/",
            "http://trusted.com%0d%0a.evil.com/",
        ],
    ),
    (
        'Decoy-URL / substring-allowlist bypass',
        EXPECTATION_UNSAFE,
        [
            "https://evil.com/#https://trusted.com/",
            "https://evil.com/#@trusted.com",
            "https://evil.com/https://trusted.com/",
        ],
    ),
    (
        'Overlong/malformed UTF-8 percent-encoding',
        EXPECTATION_INVALID,
        [
            "https://example.com/%c0%ae%c0%ae/etc/passwd",
            "https://example.com/%e0%80%aeetc/passwd",
            "https://example.com/%c0%afetc%c0%afpasswd",
        ],
    ),
    (
        'Dangerous alternate schemes for SSRF-to-RCE pivoting',
        EXPECTATION_UNSAFE,
        [
            "ldap://evil.com/a",
            "ldaps://evil.com:389/a",
            "php://filter/convert.base64-encode/resource=index.php",
            "expect://id",
            "unix:///var/run/docker.sock:/containers/json",
            "s3://internal-bucket/secret.txt",
            "jar:http://evil.com/x.jar!/",
        ],
    ),
    (
        'UNC path / SMB-relay (unsafe)',
        EXPECTATION_UNSAFE,
        [
            "file://///etc/passwd",
            "file://evil.com/share",
        ],
    ),
    (
        'UNC path / SMB-relay (ambiguous)',
        EXPECTATION_AMBIGUOUS,
        [
            "file:\\\\evil.com\\share\\payload.exe",
        ],
    ),
    (
        'UNC path / SMB-relay (invalid)',
        EXPECTATION_INVALID,
        [
            "\\\\evil.com\\share",
        ],
    ),
    (
        'Case-confusion allowlist bypass',
        EXPECTATION_UNSAFE,
        [
            "HTTP://EVIL.COM/",
            "HttP://Evil.Com/Admin",
        ],
    ),
    (
        'Unicode structural-character spoofing',
        EXPECTATION_UNSAFE,
        [
            "https://example​.com/",
            "https://example.com‍.evil.com/",
            "https://‮example.com/",
            "https://example．com/",
            "https://example.com／admin",
            "https://example.com＠evil.com/",
        ],
    ),
    (
        'IPv4-in-IPv6 embeddings beyond ::ffff:',
        EXPECTATION_UNSAFE,
        [
            "http://[64:ff9b::127.0.0.1]/",
            "http://[::127.0.0.1]/",
        ],
    ),
    (
        'SSRF: additional IPv4 representations',
        EXPECTATION_UNSAFE,
        [
            "http://127.0.0.0/",
            "http://127.0.0.255/",
            "http://127.255.255.255/",
            "http://127.000.000.001/",
            "http://127.00.00.01/",
            "http://2130706432/",
            "http://2130706434/",
            "http://0177.0000.0000.0001/",
            "http://0x7f000000/",
            "http://0x7f000001:80/",
            "http://127.0.0.1:00080/",
            "http://127.0.0.1:00000080/",
        ],
    ),
    (
        'SSRF: private/link-local/reserved IPv6 ranges',
        EXPECTATION_UNSAFE,
        [
            "http://[fc00::1]/",
            "http://[fd00::1]/",
            "http://[fe80::dead:beef]/",
            "http://[::]/",
            "http://[::ffff:10.0.0.1]/",
            "http://[::ffff:192.168.1.1]/",
            "http://[64:ff9b::10.0.0.1]/",
            "http://[64:ff9b::192.168.1.1]/",
        ],
    ),
    (
        'SSRF: localhost / internal hostname variants',
        EXPECTATION_UNSAFE,
        [
            "http://localhost./",
            "http://localhost:80/",
            "http://LOCALHOST/",
            "http://localhost.localdomain/",
            "http://ip6-localhost/",
            "http://ip6-loopback/",
            "http://ip6-allnodes/",
            "http://router.local/",
            "http://docker.internal/",
            "http://host.docker.internal/",
            "http://kubernetes.default/",
            "http://kubernetes.default.svc/",
            "http://kubernetes.default.svc.cluster.local.",
        ],
    ),
    (
        'DNS rebinding / DNS-dependent SSRF',
        EXPECTATION_AMBIGUOUS,
        [
            "http://rebind.example/",
            "http://attacker-controlled.example/",
            "http://127.0.0.1.nip.io/",
            "http://127.0.0.1.sslip.io/",
            "http://127.0.0.1.xip.io.",
            "http://0177.0.0.1.nip.io/",
        ],
    ),
    (
        'Authority parsing: userinfo / @ confusion',
        EXPECTATION_UNSAFE,
        [
            "http://@evil.com/",
            "http://:@evil.com/",
            "http://user:@evil.com/",
            "http://user:pass@evil.com/",
            "http://trusted.com@evil.com/",
            "http://trusted.com:80@evil.com/",
            "http://trusted.com\\@evil.com/",
            "http://trusted.com%40evil.com/",
            "http://trusted.com%2540evil.com/",
            "http://user%40trusted.com@evil.com/",
        ],
    ),
    (
        'Authority parsing: colon / port ambiguity (valid)',
        EXPECTATION_VALID,
        [
            "http://evil.com:/",
            "http://evil.com:80/",
            "http://evil.com:080/",
            "http://evil.com:00080/",
            "http://evil.com:65535/",
        ],
    ),
    (
        'Authority parsing: colon / port ambiguity (ambiguous)',
        EXPECTATION_AMBIGUOUS,
        [
            "http://evil.com:65536/",
            "http://evil.com:99999/",
        ],
    ),
    (
        'Authority parsing: colon / port ambiguity (invalid)',
        EXPECTATION_INVALID,
        [
            "http://evil.com:-1/",
            "http://evil.com:+80/",
            "http://evil.com:80:90/",
            "http://evil.com::80/",
            "http://evil.com:abc/",
        ],
    ),
    (
        'Empty / unusual authorities (ambiguous)',
        EXPECTATION_AMBIGUOUS,
        [
            "http:///",
            "http:////evil.com/",
            "http://///evil.com/",
            "http://////evil.com/",
        ],
    ),
    (
        'Empty / unusual authorities (valid)',
        EXPECTATION_VALID,
        [
            "http://?query",
            "http://#fragment",
        ],
    ),
    (
        'Empty / unusual authorities (ambiguous)',
        EXPECTATION_AMBIGUOUS,
        [
            "http:///evil.com/",
            "https:////evil.com/",
            "https:///\\evil.com/",
        ],
    ),
    (
        'Backslash authority confusion',
        EXPECTATION_AMBIGUOUS,
        [
            "http:\\evil.com\\",
            "http:\\\\evil.com\\",
            "http:/\\evil.com/",
            "http://\\evil.com/",
            "http://evil.com\\@trusted.com/",
            "http://trusted.com\\evil.com/",
            "http:\\\\trusted.com@evil.com/",
            "https:\\\\evil.com/",
        ],
    ),
    (
        'Scheme confusion / scheme normalization (valid)',
        EXPECTATION_VALID,
        [
            "HTTP://trusted.com/",
            "HtTp://trusted.com/",
            "httpS://trusted.com/",
        ],
    ),
    (
        'Scheme confusion / scheme normalization (ambiguous)',
        EXPECTATION_AMBIGUOUS,
        [
            "http%3A//evil.com/",
            "h%74tp://evil.com/",
            "http%253A%252F%252Fevil.com/",
        ],
    ),
    (
        'Scheme confusion / scheme normalization (valid)',
        EXPECTATION_VALID,
        [
            "//evil.com/",
        ],
    ),
    (
        'Scheme confusion / scheme normalization (ambiguous)',
        EXPECTATION_AMBIGUOUS,
        [
            "///evil.com/",
            "////evil.com/",
            "/////evil.com/",
        ],
    ),
    (
        'Scheme smuggling / ambiguous schemes',
        EXPECTATION_UNSAFE,
        [
            "javascript:alert(1)",
            "JAVASCRIPT:alert(1)",
            "java%73cript:alert(1)",
            "java%2573cript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "DATA:text/html,<script>alert(1)</script>",
            "vbscript:alert(1)",
            "about:blank",
            "blob:https://evil.com/",
            "filesystem:https://evil.com/",
            "ws://evil.com/",
            "wss://evil.com/",
        ],
    ),
    (
        'Path normalization discrepancies',
        EXPECTATION_VALID,
        [
            "https://trusted.com/a/./b",
            "https://trusted.com/a/../b",
            "https://trusted.com/a//../b",
            "https://trusted.com/a/%2e/b",
            "https://trusted.com/a/%2E/b",
            "https://trusted.com/a/%2e%2e/b",
            "https://trusted.com/a/%2E%2E/b",
            "https://trusted.com/a/%252e/b",
            "https://trusted.com/a/%252e%252e/b",
            "https://trusted.com/a/%2f/b",
            "https://trusted.com/a/%2F/b",
            "https://trusted.com/a/%5c/b",
            "https://trusted.com/a/%5C/b",
        ],
    ),
    (
        'Dot-segment / trailing-dot host confusion (valid)',
        EXPECTATION_VALID,
        [
            "https://trusted.com./",
        ],
    ),
    (
        'Dot-segment / trailing-dot host confusion (ambiguous)',
        EXPECTATION_AMBIGUOUS,
        [
            "https://trusted.com../",
            "https://trusted..com/",
            "https://.trusted.com/",
            "https://trusted.com.../",
        ],
    ),
    (
        'Dot-segment / trailing-dot host confusion (valid)',
        EXPECTATION_VALID,
        [
            "https://evil.com./",
            "https://evil.com./trusted.com/",
        ],
    ),
    (
        'Percent encoding in authority',
        EXPECTATION_UNSAFE,
        [
            "https://%65vil.com/",
            "https://%2565vil.com/",
            "https://evil%2ecom/",
            "https://evil%2Ecom/",
            "https://evil%252ecom/",
            "https://user%3Apass@evil.com/",
            "https://evil.com%2f@trusted.com/",
            "https://evil.com%5c@trusted.com/",
        ],
    ),
    (
        'Query delimiter confusion',
        EXPECTATION_UNSAFE,
        [
            "https://evil.com?https://trusted.com/",
            "https://evil.com?url=https://trusted.com/",
            "https://evil.com#?https://trusted.com/",
            "https://evil.com?x#https://trusted.com/",
            "https://evil.com/?@trusted.com",
            "https://evil.com/?//trusted.com/",
            "https://evil.com/?\\trusted.com/",
        ],
    ),
    (
        'Fragment confusion',
        EXPECTATION_UNSAFE,
        [
            "https://evil.com#trusted.com",
            "https://evil.com/#trusted.com",
            "https://evil.com/#https://trusted.com/",
            "https://evil.com/%23https://trusted.com/",
        ],
    ),
    (
        'CR/LF and ASCII control characters (unsafe)',
        EXPECTATION_UNSAFE,
        [
            "http://evil.com%09trusted.com/",
            "http://evil.com%0btrusted.com/",
            "http://evil.com%0ctrusted.com/",
            "http://evil.com%0dtrusted.com/",
            "http://evil.com%0atrusted.com/",
            "http://evil.com%00trusted.com/",
        ],
    ),
    (
        'CR/LF and ASCII control characters (invalid)',
        EXPECTATION_INVALID,
        [
            "http://evil.com\x00trusted.com/",
            "http://evil.com\rtrusted.com/",
            "http://evil.com\ntrusted.com/",
            "http://evil.com\ttrusted.com/",
        ],
    ),
    (
        'Unicode whitespace (invalid)',
        EXPECTATION_INVALID,
        [
            "https://trusted.com\u0000.evil.com/",
            "https://trusted.com\u0009.evil.com/",
            "https://trusted.com\u000a.evil.com/",
            "https://trusted.com\u000d.evil.com/",
            "https://trusted.com\u0020.evil.com/",
        ],
    ),
    (
        'Unicode whitespace (unsafe)',
        EXPECTATION_UNSAFE,
        [
            "https://trusted.com\u00a0.evil.com/",
            "https://trusted.com\u2003.evil.com/",
            "https://trusted.com\u200b.evil.com/",
        ],
    ),
    (
        'Unicode normalization / IDNA edge cases',
        EXPECTATION_UNSAFE,
        [
            "https://ｅxample.com/",
            "https://example．com/",
            "https://example。com/",
            "https://example｡com/",
            "https://xn--e1awd7f.com/",
            "https://xn--80ak6aa92e.com/",
            "https://xn--pple-43d.com/",
            "https://xn--80asehdb.com/",
            "https://ß.example/",
            "https://ẞ.example/",
            "https://K.example/",
            "https://ſ.example/",
        ],
    ),
    (
        'Bidi / invisible Unicode',
        EXPECTATION_UNSAFE,
        [
            "https://evil.com\u202e.gnihtemos/",
            "https://evil.com\u202dtrusted.com/",
            "https://evil.com\u202c.trusted.com/",
            "https://evil.com\u2066trusted.com\u2069/",
            "https://evil.com\u200b.trusted.com/",
            "https://evil.com\u200c.trusted.com/",
            "https://evil.com\u200d.trusted.com/",
        ],
    ),
    (
        'Invalid percent escapes',
        EXPECTATION_INVALID,
        [
            "https://example.com/%",
            "https://example.com/%0",
            "https://example.com/%GG",
            "https://example.com/%2",
            "https://example.com/%zz",
            "https://example.com/%u002e%u002e/",
            "https://example.com/%C0%AF",
            "https://example.com/%E0%80%AF",
            "https://example.com/%F0%80%80%AF",
        ],
    ),
    (
        'Double / triple decoding',
        EXPECTATION_UNSAFE,
        [
            "https://example.com/%252Fetc%252Fpasswd",
            "https://example.com/%252E%252E%252F",
            "https://example.com/%25252E%25252E%25252F",
            "https://example.com/%255c%255cserver%255cshare",
            "https://example.com/?next=%2525252F%2525252Fevil.com",
        ],
    ),
    (
        'Encoded authority delimiters',
        EXPECTATION_UNSAFE,
        [
            "https://trusted.com%2f%2fevil.com/",
            "https://trusted.com%5c%5cevil.com/",
            "https://trusted.com%23@evil.com/",
            "https://trusted.com%3f@evil.com/",
            "https://trusted.com%40evil.com/",
            "https://trusted.com%3a80@evil.com/",
        ],
    ),
    (
        'Malformed / truncated IPv6',
        EXPECTATION_INVALID,
        [
            "http://[::",
            "http://[:::1]/",
            "http://[::1",
            "http://[]/",
            "http://[127.0.0.1]/",
            "http://[::ffff:127.0.0.1",
            "http://[v1.fe80::1]/",
            "http://[fe80::1::2]/",
            "http://[1:2:3:4:5:6:7:8:9]/",
        ],
    ),
    (
        'IPvFuture syntax / parser differential',
        EXPECTATION_AMBIGUOUS,
        [
            "http://[v1.fe80]/",
            "http://[vF.foo]/",
            "http://[v1]/",
            "http://[v1.]/",
        ],
    ),
    (
        'Empty / repeated delimiters',
        EXPECTATION_VALID,
        [
            "https://evil.com///",
            "https://evil.com////",
            "https://evil.com??",
            "https://evil.com##",
            "https://evil.com?#",
            "https://evil.com#?",
            "https://evil.com?&&&&",
            "https://evil.com?a=1&&b=2",
        ],
    ),
    (
        'Credentials containing delimiters',
        EXPECTATION_UNSAFE,
        [
            "https://user@example.com@evil.com/",
            "https://user:pass@example.com@evil.com/",
            "https://user%40example.com@evil.com/",
            "https://user%3Apass@evil.com/",
            "https://user:pa%40ss@evil.com/",
        ],
    ),
    (
        'File / local filesystem variants',
        EXPECTATION_UNSAFE,
        [
            "file:/etc/passwd",
            "file://localhost/etc/passwd",
            "file://127.0.0.1/etc/passwd",
            "file:///C:/Windows/System32/",
            "file:///C:\\Windows\\System32\\",
            "file://C:/Windows/System32/",
            "file://server/share/file.txt",
            "file:////server/share/file.txt",
        ],
    ),
    (
        'SSRF-capable protocols commonly encountered by URL consumers',
        EXPECTATION_UNSAFE,
        [
            "gopher://127.0.0.1:6379/",
            "gopher://127.0.0.1:11211/",
            "dict://127.0.0.1:11211/",
            "ftp://127.0.0.1/",
            "ldap://127.0.0.1/",
            "ldaps://127.0.0.1/",
            "telnet://127.0.0.1/",
            "ssh://127.0.0.1/",
            "sftp://127.0.0.1/",
            "nfs://127.0.0.1/",
            "smtp://127.0.0.1/",
            "imap://127.0.0.1/",
            "pop3://127.0.0.1/",
        ],
    ),
    (
        'Scheme prefix confusion',
        EXPECTATION_UNSAFE,
        [
            "http+unix://evil.com/",
            "http+unix://%2Fvar%2Frun%2Fdocker.sock/",
            "http+unix://%2Fvar%2Frun%2Fsocket.sock:/",
            "httpx://evil.com/",
            "httpss://evil.com/",
            "http-eval://evil.com/",
            "http://evil.com/",
        ],
    ),
    (
        'Trusted-domain substring / suffix bypasses',
        EXPECTATION_UNSAFE,
        [
            "https://trusted.com.evil.com/",
            "https://eviltrusted.com/",
            "https://trusted.com@evil.com/",
            "https://evil.com/trusted.com/",
            "https://evil.com/?trusted.com",
            "https://evil.com/#trusted.com",
            "https://trusted.com%2eevil.com/",
            "https://trusted%2ecom.evil.com/",
        ],
    ),
    (
        'Port-based allowlist confusion',
        EXPECTATION_UNSAFE,
        [
            "https://trusted.com:443.evil.com/",
            "https://trusted.com:443@evil.com/",
            "https://trusted.com:@evil.com/",
            "https://trusted.com:80@evil.com/",
            "https://evil.com:443/",
            "http://evil.com:443/",
            "https://evil.com:80/",
        ],
    ),
    (
        'Extremely long components',
        EXPECTATION_VALID,
        [
            "https://" + "a" * 4096 + ".com/",
            "https://example.com/" + "a" * 10000,
            "https://example.com/?" + "a=" * 5000,
            "https://" + ("a." * 1000) + "com/",
        ],
    ),
]

MALICIOUS_URLS: list[str] = [url for _, _, urls in _SECTIONS for url in urls]

MALICIOUS_EXPECTATIONS: tuple[str, ...] = tuple(
    expectation for _, expectation, urls in _SECTIONS for _ in urls
)
