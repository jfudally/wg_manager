"""Tests for Phase 2f cycle 1 — Dockerfile + image build.

Phase 2f opens the release-engineering work-stream that Phase 2e
deferred: signed Docker image publish, cosign verify, SBOM
attachment. Cycle 1 lays the foundation — Dockerfiles for the API +
worker and the dashboard — so cycles 2-4 have an artefact to publish,
sign, and SBOM.

These tests pin the **shape** of the Dockerfiles: multi-stage so the
final image doesn't carry uv / build tools, ``uv sync --frozen`` so
the image build uses the locked deps (reproducible with cycle 3's
lockfile gate), non-root user in the runtime stage so a container
escape doesn't immediately have root inside the namespace, and a
slim base image so the surface area for CVEs stays bounded.

Pure parse-and-assert — the tests do NOT shell out to ``docker
build``. CI runs the live build in a dedicated workflow; here we
pin the source-of-truth shape so a refactor that drops one of the
above invariants trips the test rather than silently regressing the
deploy security posture.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
API_DOCKERFILE = REPO_ROOT / "Dockerfile"
WEB_DOCKERFILE = REPO_ROOT / "web" / "Dockerfile"
NEXT_CONFIG = REPO_ROOT / "web" / "next.config.ts"


def _stages(body: str) -> list[str]:
    """Return the alias of every ``FROM ... AS <alias>`` stage."""
    aliases: list[str] = []
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.upper().startswith("FROM ") and " AS " in stripped.upper():
            # ``FROM image AS alias`` — split on AS, last token is alias.
            parts = stripped.split()
            try:
                idx = [p.upper() for p in parts].index("AS")
                aliases.append(parts[idx + 1])
            except (ValueError, IndexError):
                pass
    return aliases


# ---------------------------------------------------------------------------
# API + worker Dockerfile (repo-root ``Dockerfile``)
# ---------------------------------------------------------------------------


class TestApiDockerfileExists:
    def test_dockerfile_exists(self) -> None:
        assert API_DOCKERFILE.is_file(), (
            f"{API_DOCKERFILE} is missing — Phase 2f cycle 1 ships the "
            "Dockerfile that cycles 2-4 publish/sign/SBOM"
        )


class TestApiDockerfileStructure:
    @pytest.fixture(scope="class")
    def body(self) -> str:
        return API_DOCKERFILE.read_text(encoding="utf-8")

    def test_uses_python_3_13(self, body: str) -> None:
        """pyproject.toml requires Python >= 3.13 — the image must match."""
        assert "python:3.13" in body, (
            "base image must be python:3.13-* to match pyproject.toml's "
            "requires-python >= 3.13"
        )

    def test_base_is_slim(self, body: str) -> None:
        """Slim cuts CVE surface — full debian/python images carry tools
        the runtime doesn't need."""
        assert "slim" in body.lower(), (
            "base image should use a *-slim variant — full python images "
            "ship build-essential, perl, etc."
        )

    def test_is_multi_stage(self, body: str) -> None:
        """Multi-stage so the final image doesn't carry uv / build deps."""
        aliases = _stages(body)
        assert len(aliases) >= 2, (
            f"Dockerfile must declare at least 2 ``FROM ... AS`` stages — "
            f"got {aliases}. Single-stage builds carry uv + build tools "
            f"into the runtime image."
        )

    def test_uv_frozen_install(self, body: str) -> None:
        """``uv sync --frozen`` (or ``--locked``) so the build uses the
        cycle-3-gated lockfile, not a fresh resolution."""
        assert "--frozen" in body or "--locked" in body, (
            "uv sync must use --frozen (or --locked) so the image build "
            "consumes the lockfile that cycle 3's CI gate enforces"
        )

    def test_runtime_stage_drops_to_non_root_user(self, body: str) -> None:
        """Container escape inside a non-root user namespace is a far
        smaller blast radius than escape from root."""
        lower = body.lower()
        # The runtime stage must declare a non-root USER. Accept either
        # an explicit numeric UID or a named user (we create one).
        assert "user " in lower, (
            "Dockerfile must include a USER directive — the runtime "
            "stage must NOT run as root"
        )
        # Sanity: it must not be the literal `USER root` as the last
        # USER directive (a refactor that left root for debugging would
        # otherwise sneak through).
        user_directives = [
            line.strip().lower()
            for line in body.splitlines()
            if line.strip().lower().startswith("user ")
        ]
        assert user_directives, "no USER directive found"
        last = user_directives[-1]
        assert last not in {"user root", "user 0"}, (
            f"final USER directive is {last!r} — runtime stage must not "
            f"end as root"
        )

    def test_workdir_set(self, body: str) -> None:
        """A WORKDIR keeps relative paths in CMD / ENTRYPOINT predictable."""
        assert "workdir " in body.lower(), "Dockerfile must set WORKDIR"

    def test_default_cmd_runs_api(self, body: str) -> None:
        """Default CMD runs the API entrypoint. The worker compose
        service overrides CMD; the CLI overrides ENTRYPOINT."""
        # ``python -m wg_manager`` is the canonical API runner. Pin that
        # phrase appears in a CMD or ENTRYPOINT line.
        assert "wg_manager" in body or "wg-manager" in body, (
            "Dockerfile CMD/ENTRYPOINT must reference wg_manager"
        )


# ---------------------------------------------------------------------------
# Dashboard Dockerfile (web/Dockerfile)
# ---------------------------------------------------------------------------


class TestWebDockerfileExists:
    def test_dockerfile_exists(self) -> None:
        assert WEB_DOCKERFILE.is_file(), (
            f"{WEB_DOCKERFILE} is missing — Phase 2f cycle 1 ships the "
            "dashboard image alongside the API/worker image"
        )


class TestWebDockerfileStructure:
    @pytest.fixture(scope="class")
    def body(self) -> str:
        return WEB_DOCKERFILE.read_text(encoding="utf-8")

    def test_uses_node_22(self, body: str) -> None:
        """Match the CI workflow's Node 22 pin."""
        assert "node:22" in body, "base must be node:22-*"

    def test_is_multi_stage(self, body: str) -> None:
        aliases = _stages(body)
        assert len(aliases) >= 2, (
            f"web/Dockerfile must declare at least 2 stages — got {aliases}"
        )

    def test_uses_npm_ci(self, body: str) -> None:
        """``npm ci`` (not ``npm install``) so the image build consumes
        the locked deps that cycle 3's CI gate enforces."""
        assert "npm ci" in body, (
            "web/Dockerfile must use npm ci so the image build matches "
            "the cycle-3 lockfile parity gate"
        )

    def test_uses_next_standalone_output(self, body: str) -> None:
        """The standalone output trims node_modules to runtime-only and
        is the recommended next-in-container shape."""
        assert "standalone" in body.lower(), (
            "web/Dockerfile should copy from .next/standalone — the "
            "non-standalone shape ships dev/build dependencies"
        )

    def test_runtime_stage_drops_to_non_root_user(self, body: str) -> None:
        lower = body.lower()
        assert "user " in lower
        user_directives = [
            line.strip().lower()
            for line in body.splitlines()
            if line.strip().lower().startswith("user ")
        ]
        assert user_directives
        last = user_directives[-1]
        assert last not in {"user root", "user 0"}, (
            f"final USER is {last!r} — runtime must not end as root"
        )


class TestNextStandaloneEnabled:
    """The web Dockerfile's standalone copy only works if next.config has
    ``output: 'standalone'`` — pin it at the source of truth."""

    def test_next_config_has_standalone_output(self) -> None:
        body = NEXT_CONFIG.read_text(encoding="utf-8")
        assert "standalone" in body, (
            "web/next.config.ts must set output: 'standalone' so the "
            "Dockerfile's standalone copy has something to copy"
        )
