"""Shape tests for the ruff lint gate.

``make lint`` is the one entrypoint humans and CI share; the CI job
must call it (not an ad-hoc ruff invocation) so the two can't drift,
and ruff must be pinned exactly so the gate only moves when the pin
does. ``[tool.ruff]`` in ``pyproject.toml`` holds the rule selection.
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
    def test_lint_and_fmt_are_phony_and_in_help(self) -> None:
        body = _makefile()
        phony = " ".join(
            line for line in body.splitlines() if line.startswith(".PHONY:")
        ).split()
        for target in ("lint", "fmt"):
            assert target in phony
            assert re.search(rf'@echo\s+"\s*{target}\b', body)

    def test_ruff_var_points_at_the_venv_ruff(self) -> None:
        assert re.search(r"^RUFF := \.venv/bin/ruff$", _makefile(), re.M)

    def test_lint_checks_without_modifying(self) -> None:
        recipe = _recipe("lint")
        assert "$(RUFF) check" in recipe
        assert "--fix" not in recipe

    def test_fmt_applies_fixes(self) -> None:
        assert "$(RUFF) check --fix" in _recipe("fmt")


class TestCI:
    def test_ci_has_a_lint_job_running_make_lint(self) -> None:
        ci = yaml.safe_load((REPO_ROOT / ".github/workflows/ci.yml").read_text())
        job = ci["jobs"]["lint"]
        runs = [step.get("run", "") for step in job["steps"]]
        assert any("uv sync" in r and "--frozen" in r for r in runs)
        assert "make lint" in runs


class TestPyproject:
    def test_ruff_is_pinned_exactly_in_dev_extra(self) -> None:
        data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
        dev = data["project"]["optional-dependencies"]["dev"]
        assert any(re.fullmatch(r"ruff==\d+\.\d+\.\d+", d) for d in dev)

    def test_rule_selection_is_configured(self) -> None:
        data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
        assert data["tool"]["ruff"]["lint"]["select"]
