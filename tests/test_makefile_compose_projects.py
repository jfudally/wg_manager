"""Tests that the dev and prod stacks use separate compose projects.

Both stacks are built from ``docker-compose.yml``. Without ``-p``,
compose names the project after the checkout directory, and the prod
(``~/prod/wg_manager``) and dev (``~/workspace/wg_manager``) checkouts
are both called ``wg_manager``. On a host that runs prod (rv), dev
targets such as ``make vault-up`` or ``make db-down`` therefore acted
on the **prod** project: they could recreate prod's Vault in dev mode or
stop prod's containers.

- Every dev target runs ``docker compose -p wg_manager_dev``.
- Every prod target pins ``-p wg_manager``, the name prod has always had,
  so its containers and ``wg_manager_wg_manager_*`` volumes keep their
  names whatever the checkout directory is called.

The checks use ``make -n``, so they read the commands each target would
run without running them.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

DEV_PROJECT = "wg_manager_dev"
PROD_PROJECT = "wg_manager"

DEV_TARGETS = [
    "db-up",
    "db-down",
    "db-logs",
    "ha-up",
    "ha-down",
    "ha-logs",
    "vault-up",
    "vault-down",
    "vault-logs",
    "backup-vault",
    "e2e-up",
    "e2e-down",
    "e2e-logs",
]
PROD_TARGETS = ["prod-config", "prod-up", "prod-down", "prod-logs"]


def _dry_run(target: str) -> str:
    """Return the commands ``make -n <target>`` prints, without running them."""
    proc = subprocess.run(
        ["make", "-n", "-s", target],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def _compose_projects(commands: str) -> list[str | None]:
    """Return the ``-p`` value of each ``docker compose`` call (None if absent)."""
    projects: list[str | None] = []
    for call in re.findall(r"docker compose\b[^\n;&|]*", commands):
        match = re.search(r"(?:-p|--project-name)[ =](\S+)", call)
        projects.append(match.group(1) if match else None)
    return projects


@pytest.mark.parametrize("target", DEV_TARGETS)
def test_dev_target_uses_the_dev_project(target: str) -> None:
    projects = _compose_projects(_dry_run(target))
    assert projects, f"{target} runs no docker compose command"
    assert set(projects) == {DEV_PROJECT}, (target, projects)


@pytest.mark.parametrize("target", PROD_TARGETS)
def test_prod_target_pins_the_prod_project(target: str) -> None:
    projects = _compose_projects(_dry_run(target))
    assert projects, f"{target} runs no docker compose command"
    assert set(projects) == {PROD_PROJECT}, (target, projects)


def test_every_compose_call_in_the_makefile_names_a_project() -> None:
    # A new target written as a bare `docker compose ...` would quietly
    # pick up the directory name again, which on rv is prod's project.
    bare = [
        line.strip()
        for line in (REPO_ROOT / "Makefile").read_text().splitlines()
        if re.search(r"\bdocker compose\b", line)
        and not line.lstrip().startswith("#")
        and "@echo" not in line
    ]
    assert bare, "expected the compose command variables in the Makefile"
    for line in bare:
        assert re.search(r"(?:-p|--project-name) ", line), line


def test_e2e_conftest_brings_sshd_up_in_the_dev_project() -> None:
    # The e2e fixture starts sshd-e2e itself; outside the dev project it
    # would land in the directory-named one, which on rv is prod's.
    text = (REPO_ROOT / "tests" / "e2e" / "conftest.py").read_text()
    match = re.search(r'\[\s*"docker",\s*"compose",(.*?)\]', text, re.S)
    assert match, "no docker compose call found in tests/e2e/conftest.py"
    args = re.findall(r'"([^"]+)"', match.group(1))
    assert args[:2] == ["-p", DEV_PROJECT], args
