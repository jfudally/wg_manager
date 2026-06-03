"""Tests for ``.github/workflows/release.yml`` (Phase 2f cycle 2).

The release workflow is what turns a ``git push origin v0.1.0`` into a
published, tagged Docker image on GHCR + a GitHub release with notes
extracted from the matching CHANGELOG section. Cycle 1 shipped the
Dockerfiles + the build-on-PR gate; this cycle layers the actual
publish on top.

These tests pin the workflow's shape. The live publish is what the
workflow itself runs — we don't shell out to docker here.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "release.yml"


@pytest.fixture(scope="module")
def workflow() -> dict:
    return yaml.safe_load(WORKFLOW_PATH.read_text())


@pytest.fixture(scope="module")
def body() -> str:
    return WORKFLOW_PATH.read_text()


class TestWorkflowExists:
    def test_workflow_file_exists(self) -> None:
        assert WORKFLOW_PATH.is_file(), (
            f"{WORKFLOW_PATH} is missing — Phase 2f cycle 2 ships the "
            "tagged-release publish workflow"
        )

    def test_workflow_has_descriptive_name(self, workflow: dict) -> None:
        name = workflow.get("name", "")
        assert "release" in name.lower()


class TestTriggers:
    """Fires on tag push only. Branch pushes + PRs must NOT publish."""

    def test_runs_on_tag_push(self, workflow: dict) -> None:
        on = workflow.get("on") or workflow.get(True)
        push = on.get("push", {})
        tags = push.get("tags", [])
        # Accept either the exact pattern or a more permissive one,
        # so a future bump to e.g. ``v*`` doesn't trip the test.
        assert any("v" in t for t in tags), (
            f"workflow must trigger on v-prefixed tag pushes — got tags={tags}"
        )

    def test_does_not_run_on_branch_push(self, workflow: dict) -> None:
        """The push trigger must not list branches — a release on every
        merge to main would burn the version namespace and publish
        unsigned untagged artefacts."""
        on = workflow.get("on") or workflow.get(True)
        push = on.get("push", {})
        # Either no branches key at all, or empty list.
        branches = push.get("branches")
        assert not branches, (
            f"workflow must not trigger on branch pushes — got "
            f"branches={branches}"
        )

    def test_does_not_run_on_pull_request(self, workflow: dict) -> None:
        on = workflow.get("on") or workflow.get(True)
        assert "pull_request" not in on


class TestPermissions:
    """The release job needs write tokens. ``contents: write`` for the
    GitHub release, ``packages: write`` for GHCR, and ``id-token:
    write`` so cycle 3 can layer cosign keyless signing on top without
    a workflow-level perms refactor."""

    def test_contents_write(self, workflow: dict) -> None:
        perms = workflow.get("permissions", {})
        assert perms.get("contents") == "write", (
            "release workflow needs contents: write for the GitHub "
            "release"
        )

    def test_packages_write(self, workflow: dict) -> None:
        perms = workflow.get("permissions", {})
        assert perms.get("packages") == "write", (
            "release workflow needs packages: write for GHCR publish"
        )

    def test_id_token_write_for_cosign(self, workflow: dict) -> None:
        perms = workflow.get("permissions", {})
        assert perms.get("id-token") == "write", (
            "release workflow needs id-token: write so cycle 3 can "
            "layer cosign keyless signing without a perms refactor"
        )


class TestGhcrPublish:
    """The publish target is GHCR."""

    def test_logs_into_ghcr(self, body: str) -> None:
        """Use ``docker/login-action`` against ``ghcr.io`` — the GHCR
        registry tied to the repo's GitHub identity."""
        assert "ghcr.io" in body, "workflow must reference ghcr.io"
        assert "docker/login-action" in body

    def test_uses_docker_build_push_action(self, body: str) -> None:
        assert "docker/build-push-action" in body

    def test_pushes_both_images(self, body: str) -> None:
        """One push for the API/worker image (root Dockerfile), one
        for the dashboard (web/Dockerfile)."""
        assert "file: Dockerfile" in body
        assert "file: web/Dockerfile" in body

    def test_push_is_true(self, body: str) -> None:
        """Cycle 1 pinned ``push: false`` on the build gate. The
        release workflow flips it — pin so a refactor doesn't lose it."""
        # docker/build-push-action's push input — we look for the
        # ``push: true`` literal anywhere in the file.
        assert "push: true" in body, (
            "release workflow's build-push step must set push: true"
        )


class TestTagging:
    """Images get semver + sha + latest tags so consumers can pin."""

    def test_uses_docker_metadata_action(self, body: str) -> None:
        """``docker/metadata-action`` derives semver / sha / latest tags
        from the git ref — the canonical pattern. A hand-rolled tag
        list would skew between API and web images."""
        assert "docker/metadata-action" in body, (
            "release workflow should use docker/metadata-action to "
            "derive image tags from the git ref"
        )


class TestChangelogExtraction:
    """The release notes come from the matching CHANGELOG section."""

    def test_uses_extract_changelog_script(self, body: str) -> None:
        assert "extract_changelog.py" in body, (
            "release workflow must shell out to scripts/extract_changelog.py "
            "to source release notes from CHANGELOG"
        )

    def test_creates_github_release(self, body: str) -> None:
        """``gh release create`` (or the equivalent action) wires the
        extracted notes into a GitHub release."""
        assert "gh release create" in body or "softprops/action-gh-release" in body, (
            "workflow must create a GitHub release (gh release create or "
            "softprops/action-gh-release)"
        )


class TestConcurrency:
    """A release job in flight must not be cancelled — but two
    concurrent releases of the same tag is illegal."""

    def test_does_not_cancel_in_progress(self, workflow: dict) -> None:
        """The opposite of the cycle 1 / lockfile pattern. Letting a
        partially-pushed release get cancelled mid-flight leaves GHCR
        in an inconsistent state."""
        conc = workflow.get("concurrency", {})
        # Either no concurrency block (default cancel=false) or
        # explicit cancel-in-progress=false.
        if conc:
            assert conc.get("cancel-in-progress") is not True, (
                "release workflow must not cancel-in-progress — a "
                "partial push leaves GHCR in an inconsistent state"
            )


# ---------------------------------------------------------------------------
# Cosign keyless signing (Phase 2f cycle 3)
# ---------------------------------------------------------------------------


class TestCosignSigning:
    """Each pushed image must be signed via cosign keyless OIDC. The
    signature lands in the OCI registry as a sibling artefact; the
    cycle 3 image-verify workflow consumes it.

    Keyless signing requires:
      * ``sigstore/cosign-installer`` action in each build job.
      * A ``cosign sign --yes`` step that signs the image digest after
        push (signing the digest lets all tags pointing at it inherit
        the signature — a re-tag doesn't invalidate verification).
      * ``id-token: write`` workflow permission (cycle 2 already pins
        this).
    """

    def test_installs_cosign(self, body: str) -> None:
        assert "sigstore/cosign-installer" in body, (
            "release workflow must install cosign via "
            "sigstore/cosign-installer in each build job"
        )

    def test_signs_pushed_images(self, body: str) -> None:
        """``cosign sign`` must run after each ``build-push-action``
        push step. The canonical idiom is signing the digest the push
        emits as an output."""
        assert "cosign sign" in body, (
            "release workflow must call `cosign sign` against each "
            "pushed image"
        )

    def test_sign_uses_yes_flag(self, body: str) -> None:
        """The ``--yes`` flag tells cosign to skip the interactive
        confirmation (which would block the workflow forever in CI)."""
        assert "--yes" in body, (
            "cosign sign must pass --yes — interactive confirmation "
            "would block the workflow"
        )

    def test_signs_by_digest_not_tag(self, body: str) -> None:
        """Signing by digest (``image@sha256:...``) is the correct
        idiom: it pins the signature to the immutable artefact rather
        than the floating tag. Pin the ``@`` reference."""
        assert "@${{ steps." in body or "@$" in body or "DIGEST" in body, (
            "cosign sign must sign the digest reference "
            "(image@sha256:...) not the tag — tags are mutable"
        )
