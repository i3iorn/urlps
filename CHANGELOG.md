# Changelog

All notable changes to `urlps` are documented here.

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

