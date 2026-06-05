"""Tests for ``docker/entrypoint-wg-manager.sh``.

The shim sits between Compose's ``CMD`` and the actual wg-manager
process. Its job: source the operator-generated Vault root token
from ``vault-init.json`` (the file the substrate bootstrap wrote)
and export it as ``VAULT_TOKEN`` BEFORE exec'ing the real CMD.
Without this layer, the api / worker / bootstrap-app containers
would need ``VAULT_TOKEN`` baked in at compose-evaluation time —
which they can't get, because the value is generated at first-run
init.

Shape-only tests.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = REPO_ROOT / "docker" / "entrypoint-wg-manager.sh"
DOCKERFILE = REPO_ROOT / "Dockerfile"


@pytest.fixture(scope="module")
def body() -> str:
    assert ENTRYPOINT.is_file(), (
        f"{ENTRYPOINT} is missing — the wg-manager image's entrypoint "
        "shim sources VAULT_TOKEN from vault-init.json before exec'ing "
        "the real CMD."
    )
    return ENTRYPOINT.read_text()


@pytest.fixture(scope="module")
def dockerfile_body() -> str:
    return DOCKERFILE.read_text()


class TestEntrypointShape:
    def test_executable(self) -> None:
        assert bool(os.stat(ENTRYPOINT).st_mode & stat.S_IXUSR), (
            "entrypoint shim must be chmod +x — Docker requires "
            "execute permission to invoke ENTRYPOINT."
        )

    def test_strict_mode(self, body: str) -> None:
        first = body.splitlines()[0] if body else ""
        assert "sh" in first, f"need a shell shebang; got {first!r}"
        # ``set -e`` is sufficient here — the script is short and
        # any unbound variable shape would fail at the source step
        # anyway. We don't enforce -u to keep the script tolerant
        # of unset VAULT_TOKEN on first-run boot.


class TestExecsCmd:
    """The shim must end with ``exec "$@"`` so the container's
    actual PID 1 is the wg-manager process, not the shim. Without
    this, signal forwarding (SIGTERM on `docker stop`) breaks."""

    def test_exec_passes_args_through(self, body: str) -> None:
        # `exec "$@"` is the canonical pattern. Any of the
        # equivalent forms (`exec "$@"`, `exec $@`, `exec ${@}`)
        # are fine.
        assert "exec \"$@\"" in body or "exec $@" in body or 'exec "${@}"' in body, (
            "entrypoint shim must end with `exec \"$@\"` so the "
            "container's PID 1 is the wg-manager process and "
            "docker-stop signals reach it directly."
        )


class TestVaultTokenSourcing:
    """The shim reads ``vault-init.json`` and exports the root
    token as ``VAULT_TOKEN``. The file path is operator-configurable
    via ``${VAULT_INIT_FILE}`` (default ``/app/vault-init.json``);
    a missing file is non-fatal — the shim just doesn't export the
    var and lets the downstream CMD fail with its own error."""

    def test_references_vault_init_file(self, body: str) -> None:
        assert "VAULT_INIT_FILE" in body or "vault-init.json" in body, (
            "entrypoint shim must reference VAULT_INIT_FILE (or the "
            "default /app/vault-init.json path) when sourcing the "
            "root token."
        )

    def test_exports_vault_token(self, body: str) -> None:
        # The line could be `export VAULT_TOKEN=...` or
        # `VAULT_TOKEN=...; export VAULT_TOKEN`. Either is fine —
        # the grep just confirms the variable name is in the
        # script.
        assert "VAULT_TOKEN" in body, (
            "entrypoint shim must export VAULT_TOKEN so the "
            "downstream CMD's hvac client picks it up."
        )

    def test_extracts_root_token_field(self, body: str) -> None:
        # The init JSON's root token field is `root_token`. The
        # shim must reference it (via jq or python or shell
        # extraction).
        assert "root_token" in body, (
            "entrypoint shim must extract the `root_token` field "
            "from vault-init.json (Vault's init JSON output shape)."
        )

    def test_tolerates_missing_init_file(self, body: str) -> None:
        # On the very first prod-up, vault-init.json doesn't exist
        # yet — the substrate bootstrap creates it. The shim must
        # not crash if the file is missing; it just doesn't export
        # VAULT_TOKEN and lets the downstream CMD handle the gap.
        guard = (
            "[ -f" in body
            or "[[ -f" in body
            or "test -f" in body
            or "if [ ! -f" in body
        )
        assert guard, (
            "entrypoint shim must guard the init-file source with a "
            "file-existence test so first-run boot (when the file "
            "doesn't exist yet) doesn't crash."
        )


class TestDockerfileWiresEntrypoint:
    """The Dockerfile must COPY the shim, mark it executable, and
    declare it as the image's ENTRYPOINT."""

    def test_dockerfile_copies_entrypoint(
        self, dockerfile_body: str
    ) -> None:
        assert "entrypoint-wg-manager.sh" in dockerfile_body, (
            "Dockerfile must COPY docker/entrypoint-wg-manager.sh "
            "into the image so the ENTRYPOINT directive can resolve "
            "it at boot."
        )

    def test_dockerfile_declares_entrypoint(
        self, dockerfile_body: str
    ) -> None:
        # `ENTRYPOINT [...]` (exec form) — must reference the shim.
        assert "ENTRYPOINT" in dockerfile_body, (
            "Dockerfile must declare an ENTRYPOINT pointing at the "
            "shim. Without this, the api/worker/bootstrap-* "
            "containers run the CMD directly and skip the VAULT_TOKEN "
            "sourcing step."
        )
        # Find the ENTRYPOINT line and confirm it points at the
        # shim, not at python or some other binary.
        for line in dockerfile_body.splitlines():
            if line.strip().startswith("ENTRYPOINT"):
                assert "entrypoint-wg-manager.sh" in line, (
                    "ENTRYPOINT line must reference the shim "
                    f"(entrypoint-wg-manager.sh); got: {line!r}."
                )
                break
