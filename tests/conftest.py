"""Pytest test configuration for import paths."""

from __future__ import annotations

import sys
from pathlib import Path


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

