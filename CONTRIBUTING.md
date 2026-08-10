# Contributing to urlps

Thanks for your interest in contributing.

`urlps` is a security library. That shapes what "done" means here: a change is
not finished when it works, it is finished when it is demonstrably correct,
covered by tests, and honest about what it does and does not protect against.

## Development setup

```bash
git clone https://github.com/i3iorn/urlps.git
cd urlps
python -m venv .venv
. .venv/Scripts/activate      # Windows
# source .venv/bin/activate   # Linux/macOS
pip install -e ".[dev]"
```

Install the git hooks so the same checks CI runs happen locally:

```bash
pre-commit install
```

## The checks

CI runs exactly these, and all of them are blocking:

```bash
pytest -q --cov=urlps --cov-report=term-missing   # tests + coverage gate
ruff check src/ tests/                            # lint
mypy src/urlps --ignore-missing-imports           # types
bandit -r src/urlps -ll                           # static security analysis
```

Notes:

- **Coverage has a floor** (`fail_under` in `pyproject.toml`). Ratchet it up when
  coverage improves; never lower it to turn a red build green.
- **`hypothesis` is a required dev dependency.** The property-based security
  tests in `tests/security/test_security_fuzzing.py` skip silently without it,
  so CI explicitly asserts they ran.
- **`bandit` findings must be fixed or annotated.** If a finding is a genuine
  false positive, add `# nosec <RULE> -- <reason>` on the offending line with a
  real justification. Make sure the comment is on the line bandit flags — a
  misplaced `nosec` silently suppresses nothing.

## Tests

- Put tests under the `tests/<area>/` directory matching the module you changed.
- **Assert on behaviour, not line numbers.** Some older tests have docstrings
  like `"""Line 1084: ..."""`; those references are stale and should not be
  copied. Name the behaviour instead.
- **Never assert on a bare `Exception`.** Use the specific exception type, so
  the test cannot pass on an unrelated failure.
- **Do not hit the network.** Mock `socket.getaddrinfo` and
  `urllib.request.urlopen`. Tests must pass offline.
- A test that assigns a result and never asserts on it is not a test.

## Security-affecting changes

If your change touches parsing, validation, or any check under `_security/`:

1. State in the PR what the change means for the threat model — does it make
   the library reject more, reject less, or fail differently?
2. Prefer **failing closed**. If a check cannot reach a verdict (unparseable
   input, resolution failure), the safe answer is "unsafe", not "safe".
3. Do not add a protection that cannot be honestly described. A check that only
   catches naive cases should say so, rather than implying full coverage.

## Pull requests

- Branch from `master`.
- Keep mechanical changes (formatting, import sorting, annotation
  modernisation) in their own commits so behavioural review isn't buried.
- Update `CHANGELOG.md` for anything user-visible.
- Update the README if you change documented behaviour — the README is
  expected to be executable truth, not aspiration.

## Reporting security vulnerabilities

Do not open a public issue. See [SECURITY.md](SECURITY.md).
