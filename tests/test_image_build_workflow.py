"""Tests for Phase 2f cycle 1 — image-build CI workflow.

The image-build workflow runs ``docker buildx build`` against both
Dockerfiles on every PR + push to main, *without pushing*. It is the
CI-side guarantee that a future commit doesn't silently break the
Dockerfiles before cycles 2-4 wire up the actual publish flow.

These tests pin the workflow's shape — the live build itself is what
CI runs.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "image-build.yml"


@pytest.fixture(scope="module")
def workflow() -> dict:
    return yaml.safe_load(WORKFLOW_PATH.read_text())


class TestWorkflowExists:
    def test_workflow_file_exists(self) -> None:
        assert WORKFLOW_PATH.is_file(), (
            f"{WORKFLOW_PATH} is missing — Phase 2f cycle 1 ships the "
            "build-on-PR gate"
        )

    def test_workflow_has_descriptive_name(self, workflow: dict) -> None:
        name = workflow.get("name", "")
        assert "build" in name.lower() or "image" in name.lower()


class TestTriggers:
    def test_runs_on_pull_request(self, workflow: dict) -> None:
        on = workflow.get("on") or workflow.get(True)
        assert "pull_request" in on

    def test_runs_on_push_to_main(self, workflow: dict) -> None:
        on = workflow.get("on") or workflow.get(True)
        push = on.get("push", {})
        branches = push.get("branches", [])
        assert "main" in branches

    def test_pr_trigger_is_path_filtered(self, workflow: dict) -> None:
        """Only re-run the build when something that could break it
        changes — Dockerfile, lockfiles, source dirs, the workflow
        itself."""
        on = workflow.get("on") or workflow.get(True)
        pr = on.get("pull_request", {})
        paths = pr.get("paths", [])
        # The two Dockerfiles and the workflow itself.
        assert "Dockerfile" in paths
        assert "web/Dockerfile" in paths
        assert ".github/workflows/image-build.yml" in paths


class TestJobs:
    """Build-step assertions. Inspecting per-step keys misses the
    ``with:`` block where docker/build-push-action takes its
    ``file:``/``context:`` inputs, so these tests look at the raw
    workflow body — same idiom the deps-audit/sast workflow tests
    elsewhere in this repo use."""

    @pytest.fixture(scope="class")
    def body(self) -> str:
        return WORKFLOW_PATH.read_text()

    def test_uses_docker_build_push_action(self, body: str) -> None:
        """The canonical actions/build-push-action is the only step in
        the workflow that should drive ``docker build``. A future
        refactor to a hand-rolled ``run: docker build ...`` step would
        bypass the buildx + GHA cache integration."""
        assert "docker/build-push-action" in body

    def test_builds_root_dockerfile(self, body: str) -> None:
        """The API job must reference the repo-root ``Dockerfile``."""
        assert "file: Dockerfile" in body, (
            "no docker/build-push-action step appears to point at the "
            "root Dockerfile"
        )

    def test_builds_web_dockerfile(self, body: str) -> None:
        """The web job must reference ``web/Dockerfile``."""
        assert "file: web/Dockerfile" in body, (
            "no docker/build-push-action step appears to point at "
            "web/Dockerfile"
        )

    def test_does_not_push(self, workflow: dict) -> None:
        """Cycle 1 builds but does NOT publish — that lands in cycle 2.
        A future refactor that flips ``push: true`` slips a publish flow
        into a non-release context, which would also break the cosign +
        SBOM cycles' design."""
        body = WORKFLOW_PATH.read_text()
        # The docker/build-push-action push input defaults to false; we
        # pin it explicitly to make the design intent unambiguous.
        assert "push: false" in body or "push: 'false'" in body, (
            "workflow must explicitly set push: false — cycle 1 does NOT "
            "publish images"
        )


class TestConcurrency:
    def test_cancels_in_progress(self, workflow: dict) -> None:
        conc = workflow.get("concurrency", {})
        assert conc.get("cancel-in-progress") is True


class TestPermissions:
    def test_contents_read(self, workflow: dict) -> None:
        perms = workflow.get("permissions", {})
        assert perms.get("contents") == "read"
