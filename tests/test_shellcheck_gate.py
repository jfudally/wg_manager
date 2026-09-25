"""Shape tests for the shellcheck gate.

Mirrors the ruff gate (``tests/test_lint_gate.py``): ``make shellcheck``
is the one entrypoint humans and CI share, and shellcheck is pinned
exactly (via the ``shellcheck-py`` wheel in the dev extra) so the gate
only moves when the pin does. The target lints every tracked ``*.sh``
file, so a new script is covered without touching the Makefile.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]


def _makefile() -> str:
    return (REPO_ROOT / "Makefile").read_text()


def _recipe(target: str) -> str:
    """Recipe lines of ``target`` in the Makefile."""
    lines = _makefile().splitlines()
    start = lines.index(f"{target}:") + 1
    body: list[str] = []
    for line in lines[start:]:
        if not line.startswith("\t"):
            break
        body.append(line)
    return "\n".join(body)


class TestMakefile:
    def test_target_is_phony_and_in_help(self) -> None:
        body = _makefile()
        phony = " ".join(
            line for line in body.splitlines() if line.startswith(".PHONY:")
        ).split()
        assert "shellcheck" in phony
        assert re.search(r'@echo\s+"\s*shellcheck\b', body)

    def test_var_points_at_the_venv_shellcheck(self) -> None:
        assert re.search(
            r"^SHELLCHECK := \.venv/bin/shellcheck$", _makefile(), re.M
        )

    def test_lints_every_tracked_shell_script(self) -> None:
        recipe = _recipe("shellcheck")
        assert "git ls-files" in recipe and "*.sh" in recipe
        assert "$(SHELLCHECK)" in recipe


class TestCI:
    def test_ci_has_a_shellcheck_job_running_make_shellcheck(self) -> None:
        ci = yaml.safe_load((REPO_ROOT / ".github/workflows/ci.yml").read_text())
        job = ci["jobs"]["shellcheck"]
        runs = [step.get("run", "") for step in job["steps"]]
        assert any("uv sync" in r and "--frozen" in r for r in runs)
        assert "make shellcheck" in runs


class TestPyproject:
    def test_shellcheck_is_pinned_exactly_in_dev_extra(self) -> None:
        data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
        dev = data["project"]["optional-dependencies"]["dev"]
        assert any(
            re.fullmatch(r"shellcheck-py==\d+\.\d+\.\d+\.\d+", d) for d in dev
        )
