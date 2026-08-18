# Mirrors the CI jobs in .github/workflows/ci.yml so the exact checks CI
# runs are reachable as one command instead of four separate copy-pastes.
# All targets are safe to run repeatedly and touch nothing outside the repo.

.PHONY: help install test lint format format-check typecheck security check clean

help:
	@echo "Targets:"
	@echo "  install       Install the package with dev dependencies (pip install -e .[dev])"
	@echo "  test          Run the test suite with coverage"
	@echo "  lint          Run ruff check"
	@echo "  format        Apply ruff format"
	@echo "  format-check  Check formatting without modifying files (what CI runs)"
	@echo "  typecheck     Run mypy"
	@echo "  security      Run bandit"
	@echo "  check         Run everything CI runs: test + lint + format-check + typecheck + security"
	@echo "  clean         Remove build artifacts and caches"

install:
	pip install -e ".[dev]"

test:
	pytest -q --cov=urlps --cov-report=term-missing

lint:
	ruff check src/ tests/

format:
	ruff format src/ tests/

format-check:
	ruff format --check src/ tests/

typecheck:
	mypy src/urlps --ignore-missing-imports

security:
	bandit -r src/urlps -ll

check: test lint format-check typecheck security
	@echo "All checks passed."

clean:
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov
	find . -type d -name __pycache__ -exec rm -rf {} +
