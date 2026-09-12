"""Command-line interface: ``urlps check <url> [...]``.

A thin wrapper around :func:`urlps.parse_url` for shell scripts, CI
pipelines, and pre-commit hooks -- "is this URL safe under policy X" as a
process exit code, without writing a throwaway Python script.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterable, Sequence

from . import InvalidURLError, PolicyInput, URLParseError, __version__, parse_url


def _read_stdin_urls() -> list[str]:
    """One URL per line from stdin; blank lines and '#'-comments are skipped."""
    urls = []
    for line in sys.stdin:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            urls.append(stripped)
    return urls


def _check_one(url: str, *, policy: PolicyInput, check_dns: bool, check_phishing: bool) -> tuple[bool, str]:
    """Return (ok, message) for a single URL.

    ``message`` is the canonical form on success, or the rejection reason
    on failure -- never both, so callers can print it directly either way.
    """
    try:
        parsed = parse_url(url, policy=policy, check_dns=check_dns, check_phishing=check_phishing)
    except (InvalidURLError, URLParseError) as exc:
        return False, str(exc)
    return True, parsed.canonicalize().as_string()


def _run_check(urls: Iterable[str], *, policy: PolicyInput, check_dns: bool, check_phishing: bool, quiet: bool) -> int:
    """Check every URL, printing per-URL results; return the process exit code."""
    all_ok = True
    for url in urls:
        ok, message = _check_one(url, policy=policy, check_dns=check_dns, check_phishing=check_phishing)
        all_ok = all_ok and ok
        if ok:
            if not quiet:
                print(message)
        else:
            print(f"{url}: {message}", file=sys.stderr)
    return 0 if all_ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="urlps",
        description="Secure, RFC 3986-compliant URL parsing and validation.",
    )
    parser.add_argument("--version", action="version", version=f"urlps {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser(
        "check",
        help="Validate one or more URLs under a security policy.",
        description=(
            "Validate each URL with parse_url(). Exits 0 and prints the canonical "
            "form of every URL if all pass; exits 1 and prints the rejection reason "
            "(to stderr) for each URL that fails, otherwise. With no URL arguments, "
            "reads one URL per line from stdin ('#'-prefixed and blank lines skipped)."
        ),
    )
    check.add_argument("urls", nargs="*", metavar="URL", help="URL(s) to validate. Omit to read from stdin.")
    check.add_argument(
        "--policy",
        choices=["strict", "balanced", "internal", "local"],
        default="strict",
        help="Security policy to validate under (default: strict).",
    )
    check.add_argument(
        "--check-dns",
        action="store_true",
        help="Also verify DNS resolution and block private/reserved resolved targets.",
    )
    check.add_argument(
        "--check-phishing",
        action="store_true",
        help="Also check the host against the phishing domain database.",
    )
    check.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress canonical-form output for URLs that pass; only failures are printed.",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "check":
        urls = args.urls if args.urls else _read_stdin_urls()
        if not urls:
            parser.error("no URLs given as arguments or on stdin")
        return _run_check(
            urls,
            policy=args.policy,
            check_dns=args.check_dns,
            check_phishing=args.check_phishing,
            quiet=args.quiet,
        )

    parser.error(f"unknown command: {args.command!r}")  # pragma: no cover - argparse already validates `command`
    return 2  # pragma: no cover - unreachable; parser.error() above always calls sys.exit()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
