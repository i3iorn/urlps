import sys
import importlib
import pytest
import os
from pathlib import Path

# Ensure tests can import the local `urlp` package when running under pytest
def _ensure_project_in_path():
    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

# Default as declared in constants.py
DEFAULT_MAX_URL_LENGTH = 32 * 1024


def _import_constants_fresh():
    # Make sure local package is importable and re-import module to run import-time overrides
    _ensure_project_in_path()
    sys.modules.pop('src.urlps.constants', None)
    return importlib.import_module('src.urlps.constants')


def test_valid_override(monkeypatch):
    monkeypatch.setenv('URLPS_MAX_URL_LENGTH', '12345')
    const = _import_constants_fresh()
    assert const.MAX_URL_LENGTH == 12345


def test_non_integer_warns_and_ignores(monkeypatch):
    monkeypatch.setenv('URLPS_MAX_URL_LENGTH', 'not-an-int')
    sys.modules.pop('src.urlps.constants', None)
    with pytest.warns(UserWarning, match="not an integer"):
        const = importlib.import_module('src.urlps.constants')
    assert const.MAX_URL_LENGTH == DEFAULT_MAX_URL_LENGTH


def test_non_positive_warns_and_ignores(monkeypatch):
    monkeypatch.setenv('URLPS_MAX_URL_LENGTH', '0')
    sys.modules.pop('src.urlps.constants', None)
    with pytest.warns(UserWarning, match="must be a positive integer"):
        const = importlib.import_module('src.urlps.constants')
    assert const.MAX_URL_LENGTH == DEFAULT_MAX_URL_LENGTH


def test_multiple_overrides(monkeypatch):
    monkeypatch.setenv('URLPS_MAX_PATH_LENGTH', '9999')
    monkeypatch.setenv('URLPS_MAX_QUERY_LENGTH', '8888')
    const = _import_constants_fresh()
    assert const.MAX_PATH_LENGTH == 9999
    assert const.MAX_QUERY_LENGTH == 8888
