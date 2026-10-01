"""Guards for the release pipeline's supply-chain hardening.

A compromised action tag or build dependency in a job that can mint a PyPI
OIDC token can publish a malicious release of a security library. These
tests keep three properties from regressing: every action is pinned to a
commit SHA, no job holding ``id-token: write`` runs shell commands (it only
uploads an artifact built elsewhere), and release builds use the hash-pinned
toolchain without build isolation.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
RELEASE_WORKFLOWS = ["publish_to_pypi.yml", "publish_to_test_pypi.yml"]

pytestmark = pytest.mark.skipif(not WORKFLOWS.is_dir(), reason="workflows are not part of an sdist")


def _jobs(text: str) -> dict[str, str]:
    """Split a workflow into {job_id: job_block} by its two-space job indentation."""
    body = text.split("\njobs:\n", 1)[1]
    jobs: dict[str, str] = {}
    current = None
    for line in body.splitlines():
        match = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if match:
            current = match.group(1)
            jobs[current] = ""
        elif current is not None:
            jobs[current] += line + "\n"
    return jobs


@pytest.mark.parametrize("workflow", sorted(p.name for p in WORKFLOWS.glob("*.yml")))
def test_every_action_is_pinned_to_a_commit_sha(workflow: str) -> None:
    text = (WORKFLOWS / workflow).read_text()
    uses = re.findall(r"uses:\s*(\S+)", text)
    assert uses, workflow
    unpinned = [ref for ref in uses if not re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", ref)]
    assert not unpinned, f"{workflow}: {unpinned}"


@pytest.mark.parametrize("workflow", RELEASE_WORKFLOWS)
def test_only_a_command_free_job_holds_the_oidc_token(workflow: str) -> None:
    jobs = _jobs((WORKFLOWS / workflow).read_text())
    token_jobs = [name for name, block in jobs.items() if re.search(r"id-token:\s*write", block)]
    assert token_jobs == ["publish"], token_jobs
    assert "run:" not in jobs["publish"]
    assert "download-artifact@" in jobs["publish"]


@pytest.mark.parametrize("workflow", [*RELEASE_WORKFLOWS, "ci.yml"])
def test_builds_use_the_hash_pinned_toolchain(workflow: str) -> None:
    text = (WORKFLOWS / workflow).read_text()
    assert "pip install --require-hashes -r .github/requirements/release.txt" in text
    assert "python -m build --no-isolation" in text
    assert not re.search(r"python -m build\s*$", text, re.MULTILINE)


def test_release_requirements_are_fully_hashed() -> None:
    requirements = (WORKFLOWS.parent / "requirements" / "release.txt").read_text()
    pinned = re.findall(r"^([A-Za-z0-9_.-]+)==\S+", requirements, re.MULTILINE)
    assert {"build", "twine", "setuptools", "wheel"} <= {name.lower() for name in pinned}
    for block in re.split(r"\n(?=[A-Za-z0-9_.-]+==)", requirements.split("\n", 2)[2]):
        assert "--hash=sha256:" in block, block.splitlines()[0]
