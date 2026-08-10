## What changed

<!-- What this does and why. Link any related issue. -->

## Security impact

<!-- Required for anything touching parsing, validation, or _security/.
     Does this make the library reject more, reject less, or fail differently?
     Write "None — no change to what is accepted or rejected" if that is true. -->

## Checklist

- [ ] `pytest -q --cov=urlps --cov-report=term-missing` passes (coverage floor met)
- [ ] `ruff check src/ tests/` passes
- [ ] `mypy src/urlps --ignore-missing-imports` passes
- [ ] `bandit -r src/urlps -ll` passes (any `# nosec` carries a real justification)
- [ ] Tests cover the new behaviour, and assert on specific exception types
- [ ] No new network calls in tests
- [ ] `CHANGELOG.md` updated if user-visible
- [ ] README updated if documented behaviour changed
- [ ] Mechanical changes (formatting/import sorting) kept in separate commits
