"""Tests for ``.github/workflows/image-verify.yml`` (Phase 2f cycle 3).

The verify workflow is the consumer-side gate: it runs
``cosign verify`` against the GHCR-published images to detect
either (a) supply-chain tampering with a published image or (b) a
broken signing step in the release workflow.

Trigger shape:
  * ``workflow_dispatch`` — operator can verify a specific tag on
    demand (input: ``tag``, default: ``latest``).
  * Scheduled daily cron — periodic re-verification catches
    supply-chain attacks against already-published images.
  * **Not** on push/PR — verification before the first release would
    always fail (no signed image to verify), which is noise. The
    schedule + dispatch shape works from v0.1.0 onwards.

Verification uses sigstore's Fulcio-issued certificate identity:
  * ``--certificate-identity-regexp`` matches the workflow path
    (release.yml) inside the repo.
  * ``--certificate-oidc-issuer`` pins
    ``https://token.actions.githubusercontent.com`` so a Fulcio
    cert signed by a different OIDC issuer (e.g. a malicious mirror)
    fails verification.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "image-verify.yml"


@pytest.fixture(scope="module")
def workflow() -> dict:
    return yaml.safe_load(WORKFLOW_PATH.read_text())


@pytest.fixture(scope="module")
def body() -> str:
    return WORKFLOW_PATH.read_text()


class TestWorkflowExists:
    def test_workflow_file_exists(self) -> None:
        assert WORKFLOW_PATH.is_file(), (
            f"{WORKFLOW_PATH} is missing — Phase 2f cycle 3 ships the "
            "image-verify consumer gate"
        )

    def test_workflow_has_descriptive_name(self, workflow: dict) -> None:
        name = workflow.get("name", "")
        assert "verify" in name.lower() or "cosign" in name.lower()


class TestTriggers:
    """Dispatch + schedule, NOT push/PR."""

    def test_runs_on_workflow_dispatch(self, workflow: dict) -> None:
        on = workflow.get("on") or workflow.get(True)
        assert "workflow_dispatch" in on, (
            "verify workflow must support workflow_dispatch so an "
            "operator can verify a specific tag on demand"
        )

    def test_dispatch_takes_tag_input(self, workflow: dict) -> None:
        on = workflow.get("on") or workflow.get(True)
        dispatch = on.get("workflow_dispatch", {}) or {}
        inputs = dispatch.get("inputs", {})
        assert "tag" in inputs, (
            "workflow_dispatch must take a `tag` input so an operator "
            "can verify a specific version"
        )

    def test_runs_on_schedule(self, workflow: dict) -> None:
        on = workflow.get("on") or workflow.get(True)
        assert "schedule" in on, (
            "verify workflow must run on schedule to catch supply-"
            "chain attacks against published images"
        )

    def test_does_not_run_on_push_or_pr(self, workflow: dict) -> None:
        """Push/PR would fail until the first release exists — noise."""
        on = workflow.get("on") or workflow.get(True)
        assert "push" not in on, (
            "verify workflow must not run on push — fails until first "
            "release tag exists"
        )
        assert "pull_request" not in on


class TestPermissions:
    def test_contents_read(self, workflow: dict) -> None:
        """Verify is read-only — no write tokens needed."""
        perms = workflow.get("permissions", {})
        assert perms.get("contents") == "read"


class TestCosignVerify:
    def test_installs_cosign(self, body: str) -> None:
        assert "sigstore/cosign-installer" in body

    def test_calls_cosign_verify(self, body: str) -> None:
        assert "cosign verify" in body

    def test_pins_certificate_identity_regexp(self, body: str) -> None:
        """The identity is what proves the signature came from the
        release workflow, not from some random keyless signer. Pin
        the regexp form so a missing identity binding trips here."""
        assert "--certificate-identity-regexp" in body, (
            "cosign verify must pin --certificate-identity-regexp to "
            "the release workflow path — bare verify accepts any "
            "Fulcio-signed cert"
        )

    def test_pins_certificate_oidc_issuer(self, body: str) -> None:
        """OIDC issuer must be GitHub Actions — accepting any issuer
        would let a Google / GitLab / etc. signed cert pass."""
        assert "--certificate-oidc-issuer" in body, (
            "cosign verify must pin --certificate-oidc-issuer to "
            "Fulcio's GitHub Actions issuer"
        )
        assert "token.actions.githubusercontent.com" in body, (
            "OIDC issuer must be https://token.actions.githubusercontent.com"
        )

    def test_verifies_both_images(self, body: str) -> None:
        """Both the API and the dashboard images must be verified —
        cycle 2 publishes both, cycle 3 must verify both."""
        # The image identifiers are derived from github.repository, so
        # look for the ``wg-manager`` and ``wg-manager-web`` shapes.
        assert "wg-manager-web" in body or "-web" in body, (
            "verify workflow must cover the -web (dashboard) image too"
        )
