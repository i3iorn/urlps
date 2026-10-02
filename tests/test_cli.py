"""Tests for the urlps CLI (urlps._cli)."""

from __future__ import annotations

import io

import pytest

from urlps import __version__
from urlps._cli import build_parser, main


class TestCheckCommand:
    def test_valid_url_exits_zero_and_prints_canonical_form(self, capsys):
        code = main(["check", "HTTP://EXAMPLE.COM:80/path"])
        out = capsys.readouterr().out
        assert code == 0
        assert out.strip() == "http://example.com/path"

    def test_multiple_valid_urls_all_printed(self, capsys):
        code = main(["check", "https://a.example.com/", "https://b.example.com/"])
        out = capsys.readouterr().out.splitlines()
        assert code == 0
        assert out == ["https://a.example.com/", "https://b.example.com/"]

    def test_rejected_url_exits_nonzero_and_prints_reason_to_stderr(self, capsys):
        code = main(["check", "http://localhost/admin"])
        captured = capsys.readouterr()
        assert code == 1
        assert captured.out == ""
        assert "http://localhost/admin:" in captured.err
        assert "ssrf" in captured.err.lower()

    def test_mixed_valid_and_invalid_urls_exits_nonzero(self, capsys):
        code = main(["check", "https://example.com/", "http://169.254.169.254/"])
        captured = capsys.readouterr()
        assert code == 1
        assert "https://example.com/" in captured.out
        assert "169.254.169.254" in captured.err

    def test_policy_local_permits_localhost(self, capsys):
        code = main(["check", "--policy", "local", "http://localhost:3000/api"])
        out = capsys.readouterr().out
        assert code == 0
        assert "localhost" in out

    def test_default_policy_rejects_localhost(self, capsys):
        code = main(["check", "http://localhost:3000/api"])
        assert code == 1

    def test_quiet_suppresses_success_output(self, capsys):
        code = main(["check", "--quiet", "https://example.com/"])
        captured = capsys.readouterr()
        assert code == 0
        assert captured.out == ""

    def test_quiet_still_prints_failures(self, capsys):
        code = main(["check", "--quiet", "http://localhost/admin"])
        captured = capsys.readouterr()
        assert code == 1
        assert "http://localhost/admin:" in captured.err

    def test_reads_urls_from_stdin_when_none_given(self, capsys, monkeypatch):
        monkeypatch.setattr("sys.stdin", io.StringIO("https://example.com/\nhttps://example.org/\n"))
        code = main(["check"])
        out = capsys.readouterr().out.splitlines()
        assert code == 0
        assert out == ["https://example.com/", "https://example.org/"]

    def test_stdin_skips_blank_lines_and_comments(self, capsys, monkeypatch):
        monkeypatch.setattr("sys.stdin", io.StringIO("\n# a comment\nhttps://example.com/\n\n"))
        code = main(["check"])
        out = capsys.readouterr().out.splitlines()
        assert code == 0
        assert out == ["https://example.com/"]

    def test_no_urls_anywhere_is_a_usage_error(self, capsys, monkeypatch):
        monkeypatch.setattr("sys.stdin", io.StringIO(""))
        with pytest.raises(SystemExit) as exc_info:
            main(["check"])
        assert exc_info.value.code == 2
        assert "no URLs given" in capsys.readouterr().err


class TestTopLevel:
    def test_version_flag_prints_version_and_exits_zero(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            main(["--version"])
        assert exc_info.value.code == 0
        assert __version__ in capsys.readouterr().out

    def test_no_command_is_a_usage_error(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            main([])
        assert exc_info.value.code == 2

    def test_build_parser_returns_argparse_parser(self):
        parser = build_parser()
        assert parser.prog == "urlps"


class TestTerminalSafety:
    """URL lists checked in CI are untrusted; nothing raw may reach the terminal."""

    @pytest.mark.parametrize(
        "url",
        [
            "http://evil\x1b]0;pwned\x07.example/",  # OSC title-set sequence
            "http://example.com/\x1b[2J",  # clear screen
            "http://example.com/\x9b31m",  # C1 CSI: now also rejected as a control character
            "\x1b[1A\x1b[2Khttps://looks-fine.example/",  # rewrite the previous line
        ],
    )
    def test_rejected_input_is_escaped_when_echoed(self, capsys, url):
        code = main(["check", url])
        captured = capsys.readouterr()
        assert code == 1
        for control in ("\x1b", "\x07", "\x9b"):
            assert control not in captured.err
        assert "\\x1b" in captured.err or "\\x9b" in captured.err

    def test_bidi_control_in_an_accepted_url_never_reaches_the_terminal_raw(self, capsys):
        code = main(["check", "https://example.com/?q=\u202egnp.exe"])
        out = capsys.readouterr().out
        assert code == 0
        assert "\u202e" not in out

    def test_printable_escapes_only_what_it_must(self):
        from urlps._cli import _printable

        assert _printable("https://example.com/caf\u00e9") == "https://example.com/caf\u00e9"
        assert _printable("a\x1bb\u202ec\x9bd") == "a\\x1bb\\u202ec\\x9bd"

    def test_ordinary_unicode_is_printed_as_is(self, capsys):
        code = main(["check", "https://example.com/caf\u00e9?q=\u00fcber"])
        out = capsys.readouterr().out
        assert code == 0
        assert "\\x" not in out and "\\u" not in out
