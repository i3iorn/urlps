"""Connect-time SSRF protection: resolve_and_validate() and create_guarded_connection().

Parse-time checks cannot stop DNS rebinding: the client resolves again when it
connects. These tests pin the properties that make the connect-time guard
robust -- one resolution, every address validated, connect only to a vetted
address, peer re-checked -- and exercise the documented urllib3 integration
against a real local server.
"""

from __future__ import annotations

import functools
import http.server
import ipaddress
import socket
import threading
from collections.abc import Iterator
from unittest.mock import MagicMock, patch

import pytest

from urlps import (
    DNSRateLimiter,
    DNSResolutionError,
    InvalidURLError,
    SecurityPolicy,
    create_guarded_connection,
    parse_url,
    parse_url_local,
    resolve_and_validate,
)

RESOLVER = "urlps._security.dns_guard._resolve_addr_info"


def _addrinfo(*addresses: str, port: int = 80) -> list[tuple]:
    entries = []
    for address in addresses:
        if ":" in address:
            entries.append((socket.AF_INET6, socket.SOCK_STREAM, 6, "", (address, port, 0, 0)))
        else:
            entries.append((socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port)))
    return entries


def _ssrf_code(excinfo: pytest.ExceptionInfo) -> str | None:
    code = excinfo.value.code
    return code.value if code is not None else None


@pytest.fixture
def local_server() -> Iterator[int]:
    """A real TCP server on 127.0.0.1 that answers every connection with a byte."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    # Short timeout so the accept loop notices `stop` promptly on teardown.
    listener.settimeout(0.05)
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with conn:
                conn.sendall(b"!")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield listener.getsockname()[1]
    stop.set()
    listener.close()
    thread.join(timeout=5)


# ---------------------------------------------------------------------------
# resolve_and_validate()
# ---------------------------------------------------------------------------


def test_resolve_and_validate_returns_vetted_addresses() -> None:
    with patch(RESOLVER, return_value=_addrinfo("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946")) as resolver:
        addresses = resolve_and_validate("https://example.com/path")
    assert addresses == [
        ipaddress.ip_address("93.184.216.34"),
        ipaddress.ip_address("2606:2800:220:1:248:1893:25c8:1946"),
    ]
    assert resolver.call_args.kwargs["port"] == 443


@pytest.mark.parametrize(
    "answers",
    [
        ("127.0.0.1",),
        ("169.254.169.254",),
        ("100.100.100.200",),
        ("93.184.216.34", "10.0.0.1"),  # one bad answer poisons the whole lookup
        ("::ffff:127.0.0.1",),
        ("fd00:ec2::254",),
    ],
)
def test_resolve_and_validate_rejects_any_internal_answer(answers: tuple[str, ...]) -> None:
    with patch(RESOLVER, return_value=_addrinfo(*answers)), pytest.raises(InvalidURLError) as excinfo:
        resolve_and_validate("https://rebind.example/")
    assert _ssrf_code(excinfo) == "ssrf_risk"


def test_resolve_and_validate_reports_resolution_failure() -> None:
    with patch(RESOLVER, side_effect=socket.gaierror(-2, "Name or service not known")):
        with pytest.raises(DNSResolutionError):
            resolve_and_validate("https://does-not-exist.example/")
    with patch(RESOLVER, side_effect=TimeoutError("slow")):
        with pytest.raises(DNSResolutionError):
            resolve_and_validate("https://slow.example/")


def test_resolve_and_validate_uses_the_url_policy_or_an_override() -> None:
    local_url = parse_url_local("http://dev.localhost:8080/")
    with patch(RESOLVER, return_value=_addrinfo("127.0.0.1")):
        assert resolve_and_validate(local_url) == [ipaddress.ip_address("127.0.0.1")]
        with pytest.raises(InvalidURLError):
            resolve_and_validate(local_url, policy="strict")
        allowed = SecurityPolicy.strict(allowed_addresses=["127.0.0.0/8"])
        assert resolve_and_validate("http://build.example/", policy=allowed) == [ipaddress.ip_address("127.0.0.1")]


def test_resolve_and_validate_rejects_invalid_urls_before_resolving() -> None:
    with patch(RESOLVER) as resolver:
        with pytest.raises(InvalidURLError):
            resolve_and_validate("http://169.254.169.254?")
        with pytest.raises(InvalidURLError):
            resolve_and_validate("mailto:someone@example.com", policy="strict")
    resolver.assert_not_called()


# ---------------------------------------------------------------------------
# create_guarded_connection(): unit behaviour
# ---------------------------------------------------------------------------


def _fake_socket(peer: str = "93.184.216.34") -> MagicMock:
    sock = MagicMock(spec=socket.socket)
    sock.getpeername.return_value = (peer, 443)
    return sock


def test_guard_resolves_once_and_connects_only_to_the_vetted_address() -> None:
    """Rebinding: a second resolution would say 127.0.0.1, but there is none."""
    resolver = MagicMock(side_effect=[_addrinfo("93.184.216.34", port=443), _addrinfo("127.0.0.1", port=443)])
    sock = _fake_socket()
    with patch(RESOLVER, resolver), patch("socket.socket", return_value=sock):
        assert create_guarded_connection(("rebind.example", 443), timeout=3) is sock
    assert resolver.call_count == 1
    sock.connect.assert_called_once_with(("93.184.216.34", 443))
    sock.settimeout.assert_called_once_with(3)


def test_guard_rejects_before_connecting_when_any_answer_is_internal() -> None:
    with (
        patch(RESOLVER, return_value=_addrinfo("93.184.216.34", "127.0.0.1", port=443)),
        patch("socket.socket", side_effect=AssertionError("must not connect")),
        pytest.raises(InvalidURLError) as excinfo,
    ):
        create_guarded_connection(("rebind.example", 443))
    assert _ssrf_code(excinfo) == "ssrf_risk"


def test_guard_rechecks_the_peer_after_connecting() -> None:
    """Defence in depth: whatever sits between us and the network, the peer must be permitted."""
    sock = _fake_socket(peer="10.0.0.1")
    with (
        patch(RESOLVER, return_value=_addrinfo("93.184.216.34", port=443)),
        patch("socket.socket", return_value=sock),
        pytest.raises(InvalidURLError),
    ):
        create_guarded_connection(("example.com", 443))
    sock.close.assert_called()


@pytest.mark.parametrize(
    "host",
    ["127.0.0.1", "::1", "localhost", "169.254.169.254", "metadata.google.internal", "ｌｏｃａｌｈｏｓｔ"],
)
def test_guard_rejects_internal_hosts_without_resolving(host: str) -> None:
    with patch(RESOLVER) as resolver, pytest.raises(InvalidURLError):
        create_guarded_connection((host, 80))
    resolver.assert_not_called()


def test_guard_tries_the_next_vetted_address_on_connection_failure() -> None:
    first, second = _fake_socket(), _fake_socket(peer="93.184.216.35")
    first.connect.side_effect = ConnectionRefusedError()
    with (
        patch(RESOLVER, return_value=_addrinfo("93.184.216.34", "93.184.216.35", port=443)),
        patch("socket.socket", side_effect=[first, second]),
    ):
        assert create_guarded_connection(("example.com", 443)) is second
    first.close.assert_called_once()


def test_guard_ignores_timeout_sentinels() -> None:
    """socket's and urllib3's "default timeout" sentinels are not numbers."""
    sock = _fake_socket()
    with patch(RESOLVER, return_value=_addrinfo("93.184.216.34", port=443)), patch("socket.socket", return_value=sock):
        create_guarded_connection(("example.com", 443), timeout=object())
    sock.settimeout.assert_not_called()


def test_guard_without_ssrf_enforcement_still_honours_deny_rules() -> None:
    policy = SecurityPolicy.internal(enforce_ssrf=False, denied_addresses=["10.0.0.0/8"])
    with (
        patch(RESOLVER, return_value=_addrinfo("192.168.1.1")),
        patch("socket.socket", return_value=_fake_socket("192.168.1.1")),
    ):
        create_guarded_connection(("intranet.example", 80), policy=policy)
    with patch(RESOLVER, return_value=_addrinfo("10.1.1.1")), pytest.raises(InvalidURLError):
        create_guarded_connection(("intranet.example", 80), policy=policy)


# ---------------------------------------------------------------------------
# create_guarded_connection(): real sockets
# ---------------------------------------------------------------------------


def test_guard_refuses_a_real_loopback_server(local_server: int) -> None:
    with pytest.raises(InvalidURLError):
        create_guarded_connection(("127.0.0.1", local_server), timeout=5)


def test_guard_connects_when_policy_permits_it(local_server: int) -> None:
    for policy in (SecurityPolicy.strict(allowed_addresses=["127.0.0.1"]), SecurityPolicy.local()):
        sock = create_guarded_connection(("127.0.0.1", local_server), timeout=5, policy=policy)
        with sock:
            assert sock.recv(1) == b"!"


def test_parse_time_check_passes_but_guard_stops_the_rebind() -> None:
    """The attack F-03 describes, end to end: public at parse time, loopback at connect time."""
    answers = MagicMock(side_effect=[_addrinfo("93.184.216.34"), _addrinfo("127.0.0.1")])
    with patch(RESOLVER, answers):
        url = parse_url("http://rebind.example/", check_dns=True, dns_rate_limiter=DNSRateLimiter())
        assert url.host == "rebind.example"  # the parse-time check was fooled
        with pytest.raises(InvalidURLError):
            create_guarded_connection((url.host, url.effective_port), policy=url._security_policy)


# ---------------------------------------------------------------------------
# The documented urllib3 / requests integration
# ---------------------------------------------------------------------------


class _QuietHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def http_server() -> Iterator[int]:
    server = http.server.HTTPServer(("127.0.0.1", 0), _QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def test_urllib3_recipe_blocks_internal_targets(http_server: int, monkeypatch: pytest.MonkeyPatch) -> None:
    urllib3 = pytest.importorskip("urllib3")
    connection = pytest.importorskip("urllib3.util.connection")

    monkeypatch.setattr(
        connection,
        "create_connection",
        functools.partial(create_guarded_connection, policy=SecurityPolicy.strict()),
    )
    with urllib3.PoolManager(retries=False) as pool:
        with pytest.raises(InvalidURLError):
            pool.request("GET", f"http://127.0.0.1:{http_server}/")


def test_urllib3_recipe_allows_permitted_targets(http_server: int, monkeypatch: pytest.MonkeyPatch) -> None:
    urllib3 = pytest.importorskip("urllib3")
    connection = pytest.importorskip("urllib3.util.connection")

    monkeypatch.setattr(
        connection,
        "create_connection",
        functools.partial(create_guarded_connection, policy=SecurityPolicy.strict(allowed_addresses=["127.0.0.1"])),
    )
    with urllib3.PoolManager(retries=False) as pool:
        response = pool.request("GET", f"http://127.0.0.1:{http_server}/")
    assert response.status == 200
    assert response.data == b"ok"


# ---------------------------------------------------------------------------
# Remaining branches
# ---------------------------------------------------------------------------


def test_resolve_and_validate_strips_ipv6_brackets_and_zone_for_the_resolver() -> None:
    with patch(RESOLVER, return_value=_addrinfo("2001:4860:4860::8888", port=443)) as resolver:
        addresses = resolve_and_validate("https://[2001:4860:4860::8888]/")
    assert addresses == [ipaddress.ip_address("2001:4860:4860::8888")]
    assert resolver.call_args.args[0] == "2001:4860:4860::8888"


def test_unverifiable_resolver_answer_fails_closed() -> None:
    bogus = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("not-an-ip", 80))]
    with patch(RESOLVER, return_value=bogus), pytest.raises(InvalidURLError) as excinfo:
        resolve_and_validate("http://odd.example/")
    assert _ssrf_code(excinfo) == "ssrf_risk"


def test_empty_resolution_is_a_resolution_error() -> None:
    with patch(RESOLVER, return_value=[]), pytest.raises(DNSResolutionError):
        resolve_and_validate("http://empty.example/")


def test_url_without_host_cannot_be_resolved() -> None:
    url = parse_url("file:///etc/hosts", allow_custom_scheme=True, policy="local")
    with pytest.raises(InvalidURLError):
        resolve_and_validate(url)


def test_guard_applies_socket_options_and_source_address() -> None:
    sock = _fake_socket()
    options = [(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)]
    with patch(RESOLVER, return_value=_addrinfo("93.184.216.34", port=443)), patch("socket.socket", return_value=sock):
        create_guarded_connection(("example.com", 443), 2.5, ("0.0.0.0", 0), options)
    sock.setsockopt.assert_called_once_with(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.bind.assert_called_once_with(("0.0.0.0", 0))
    sock.settimeout.assert_called_once_with(2.5)


def test_guard_raises_the_last_network_error_when_every_address_fails() -> None:
    sock = _fake_socket()
    sock.connect.side_effect = ConnectionRefusedError("refused")
    with (
        patch(RESOLVER, return_value=_addrinfo("93.184.216.34", port=443)),
        patch("socket.socket", return_value=sock),
        pytest.raises(ConnectionRefusedError),
    ):
        create_guarded_connection(("example.com", 443))
