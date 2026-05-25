# Changelog

All notable changes to `urlps` are documented here.

## 0.6.0 - 2026-05-25

- Standardized public imports on `urlps` across docs, tests, performance tooling, and package metadata.
- Added configurable DNS connect error behavior via `dns_fail_open_on_connect_error`.
- Updated policy defaults for DNS connect checks: strict fail-closed, balanced fail-open.
- Updated `parse_url_unsafe(policy=...)` to honor explicit policy values exactly.
- Refined audit, phishing database, DNS rate limiting, IP safety, and policy-resolution internals.
- Added search hygiene support via `.rgignore`.
- Added release notes in `changelogs/0.6.0.md`, including the full commit history since `v0.5.1`.

## 0.5.1 - 2026-06-22

- Added focused coverage suites (`tests/test_coverage_gaps.py`, `tests/test_coverage_gaps2.py`) for parser, security, validation, URL helpers, and facade flows.
- Added regression tests for defensive error-handling paths (IDNA failures, query parsing errors, DNS failures/rate limiting, parser-confusion and canonicalization branches).
- Improved confidence in secure defaults and fallback behavior without introducing breaking API changes.

## 0.5.0 - 2026-05-22

- Added policy-based security controls via `SecurityPolicy` (`strict`, `balanced`, `internal`).
- Added structured security findings, typed error codes, and richer URL validation interfaces.
- Added structured audit event callbacks with correlation-id support and safer URL redaction.
- Added secure composition helpers (`build_secure`, secure builder flow).
- Strengthened mutation-time validation for `URL.copy()` and `with_*` methods.

## 0.4.0

- Introduced major security hardening across parsing and validation.
- Added DNS rebinding checks, rate-limiting controls, and phishing-database integration.
- Expanded parser-confusion, canonicalization, and injection-related protections.
- Improved cache management and performance observability.

## 0.3

- Stabilized core parser/builder behavior and immutable `URL` workflows.
- Improved RFC 3986 alignment and expanded test coverage.

## 0.2

- Added foundational security checks and stricter validation paths.
- Improved host/IP handling and URL normalization behavior.

## 0.1

- Initial public releases of URL parsing/building APIs.
- Core immutable URL representation and component helpers.

