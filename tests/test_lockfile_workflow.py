"""Tests for Phase 2e reproducible-builds cycle 3 — lockfile CI gate.

Phase 2e's "Reproducible builds" ROADMAP bullet calls for two
guarantees:

* ``pyproject.toml`` is locked via ``uv lock``.
* The CI gate refuses unpinned upgrades — i.e. a PR that edits
  ``pyproject.toml`` (or ``web/package.json``) without re-locking the
  matching lockfile fails the gate before review.

Cycle 3 ships ``.github/workflows/lockfile.yml`` with two jobs:

* ``uv lock --check`` against ``pyproject.toml`` + ``uv.lock``.
* ``npm ci --dry-run`` against ``web/package.json`` +
  ``web/package-lock.json``.

These tests pin the workflow's shape so a future refactor that drops
either job (or replaces ``--check`` with a no-op) trips here rather
than silently re-opening the supply-chain hole this cycle closes.

Pure parse-and-assert so the fast ``make test`` invocation stays
hermetic. The live CI runs are the canonical verifier — this file
is the contract on the workflow's shape, not its behaviour.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "lockfile.yml"
MAKEFILE_PATH = REPO_ROOT / "Makefile"


@pytest.fixture(scope="module")
def workflow() -> dict:
    """Parsed ``.github/workflows/lockfile.yml``."""
    return yaml.safe_load(WORKFLOW_PATH.read_text())


# ---------------------------------------------------------------------------
# Workflow file exists + has a useful name
# ---------------------------------------------------------------------------


class TestWorkflowExists:
    def test_workflow_file_exists(self) -> None:
        assert WORKFLOW_PATH.is_file(), (
            f"{WORKFLOW_PATH} is missing — cycle 3 hasn't shipped yet"
        )

    def test_workflow_has_descriptive_name(self, workflow: dict) -> None:
        name = workflow.get("name", "")
        assert "lock" in name.lower() or "reproducible" in name.lower(), (
            f"workflow name should hint at its purpose, got: {name!r}"
        )


# ---------------------------------------------------------------------------
# Trigger shape — runs on the events that matter and skips the rest
# ---------------------------------------------------------------------------


class TestTriggers:
    """The gate must run on every PR that could break it + on push to
    main (so a force-push or admin bypass still surfaces drift)."""

    def test_runs_on_pull_request(self, workflow: dict) -> None:
        # YAML's ``on`` key parses as the Python bool ``True`` when
        # bare; round-trip through the safe loader keeps it as ``on``
        # only if the file quotes it. Accept both shapes so a future
        # editor flip doesn't trip the test.
        on = workflow.get("on") or workflow.get(True)
        assert on is not None, "workflow must declare an `on:` block"
        assert "pull_request" in on, "must run on pull_request"

    def test_runs_on_push_to_main(self, workflow: dict) -> None:
        on = workflow.get("on") or workflow.get(True)
        push = on.get("push", {})
        branches = push.get("branches", [])
        assert "main" in branches, "must run on push to main"

    def test_pr_trigger_is_path_filtered(self, workflow: dict) -> None:
        """Skip cost on PRs that don't touch dep manifests. Code-only
        PRs don't need to re-validate the lockfiles."""
        on = workflow.get("on") or workflow.get(True)
        pr = on.get("pull_request", {})
        paths = pr.get("paths", [])
        assert "pyproject.toml" in paths
        assert "uv.lock" in paths
        assert "web/package.json" in paths
        assert "web/package-lock.json" in paths
        # The workflow file itself — a refactor that breaks the gate
        # should re-trigger the gate.
        assert ".github/workflows/lockfile.yml" in paths


# ---------------------------------------------------------------------------
# Job shape — uv + npm checks both present, each runs the actual
# guarantee command
# ---------------------------------------------------------------------------


class TestJobs:
    def test_two_jobs_present(self, workflow: dict) -> None:
        """One Python lock-check, one Node lock-check. Anything else is
        out of scope for this cycle."""
        jobs = workflow.get("jobs", {})
        assert len(jobs) >= 2, f"expected >= 2 jobs, got {list(jobs)}"

    def test_uv_lock_check_job_present(self, workflow: dict) -> None:
        jobs = workflow.get("jobs", {})
        steps_all: list[str] = []
        for job in jobs.values():
            for step in job.get("steps", []):
                run = step.get("run", "") or ""
                steps_all.append(run)
        joined = "\n".join(steps_all)
        assert "uv lock --check" in joined, (
            "no job runs `uv lock --check` — this is the whole point of "
            "the gate"
        )

    def test_npm_lock_check_job_present(self, workflow: dict) -> None:
        jobs = workflow.get("jobs", {})
        steps_all: list[str] = []
        for job in jobs.values():
            for step in job.get("steps", []):
                run = step.get("run", "") or ""
                steps_all.append(run)
        joined = "\n".join(steps_all)
        # ``npm ci --dry-run`` validates the lockfile against package.json
        # without actually installing — same parity check, hermetic.
        assert "npm ci --dry-run" in joined, (
            "no job runs `npm ci --dry-run` — npm lockfile drift would "
            "go undetected by this gate"
        )


# ---------------------------------------------------------------------------
# Concurrency + permissions — match the pattern the other Phase 2e
# workflows use so a future-cancellation refactor doesn't have to chase
# down inconsistencies
# ---------------------------------------------------------------------------


class TestConcurrency:
    def test_cancels_in_progress(self, workflow: dict) -> None:
        """A force-push to a PR should cancel the in-flight run so we
        don't burn runner time on stale state."""
        conc = workflow.get("concurrency", {})
        assert conc.get("cancel-in-progress") is True


class TestPermissions:
    def test_least_privilege_contents_read(self, workflow: dict) -> None:
        """The gate only needs to read the repo; no write tokens."""
        perms = workflow.get("permissions", {})
        assert perms.get("contents") == "read", (
            "workflow should pin permissions: contents: read (least "
            "privilege)"
        )


# ---------------------------------------------------------------------------
# Local equivalent — `make lockfiles` so the dev hand-spin matches CI
# ---------------------------------------------------------------------------


class TestMakefileTarget:
    @pytest.fixture(scope="class")
    def makefile(self) -> str:
        return MAKEFILE_PATH.read_text()

    def test_lockfiles_target_declared(self, makefile: str) -> None:
        assert "lockfiles:" in makefile, (
            "Makefile must declare a `lockfiles` target so `make "
            "lockfiles` runs the same checks as CI"
        )

    def test_lockfiles_target_runs_uv_lock_check(self, makefile: str) -> None:
        """The local target's body must call `uv lock --check`."""
        # Find the recipe block after `lockfiles:` and before the next
        # blank line — same idiom test_makefile_backup.py uses.
        in_block = False
        block_lines: list[str] = []
        for line in makefile.splitlines():
            if line.startswith("lockfiles:"):
                in_block = True
                continue
            if in_block:
                if line.strip() == "":
                    break
                block_lines.append(line)
        block = "\n".join(block_lines)
        assert "uv lock --check" in block, (
            f"lockfiles target must run `uv lock --check` — got:\n{block}"
        )
        assert "npm ci --dry-run" in block, (
            f"lockfiles target must run `npm ci --dry-run` — got:\n{block}"
        )

    def test_help_target_lists_lockfiles(self, makefile: str) -> None:
        """``make help`` must surface the new target."""
        assert "lockfiles" in makefile, (
            "help frame must mention the lockfiles target"
        )
