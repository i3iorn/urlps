"""Pytest test configuration for import paths."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


def _ensure_src_on_path() -> None:
    """Add repository paths so `urlps` and legacy `urlps` imports both resolve."""
    repo_root = Path(__file__).resolve().parents[1]
    src_dir = repo_root / "src"
    repo_root_str = str(repo_root)
    src_dir_str = str(src_dir)
    if repo_root_str not in sys.path:
        sys.path.insert(0, repo_root_str)
    if src_dir_str not in sys.path:
        sys.path.insert(0, src_dir_str)


_ensure_src_on_path()


@pytest.fixture(autouse=True)
def _fresh_global_dns_limiter():
    """The process-global DNS limiter caches resolutions; never share them between tests."""
    from urlps._security.dns_guard import reset_dns_rate_limiter

    reset_dns_rate_limiter()
    yield
    reset_dns_rate_limiter()
