"""Tests for the ``make certs-rotate`` target.

The Vault-issued leaves on ``tls/`` and ``tls/mysql/`` are short-TTL
(30-day for MySQL server + client, longer for API/CLI). The prod
overlay's ``bootstrap-app`` script skips minting when the files
already exist — good for boot idempotence, bad for rotation. Without
a dedicated rotate path the operator would have to manually
``docker compose run`` the mint scripts and remember which files to
delete, which is exactly the drill that bit us in cycle 2 of the
Sep '26 prod-up incident.

``make certs-rotate`` is the single entrypoint: it wraps the
``prod_rotate_certs.sh`` orchestrator inside a compose ``run --rm``
so the Vault entrypoint shim sources ``VAULT_TOKEN``, then restarts
``mysql`` + ``api`` on the host so the newly-minted server certs
actually get loaded.

Shape tests — pinning the target so a future refactor can't quietly
drop the restart step (a common regression class: cert on disk is
fresh, but the running process is still holding the old one).
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MAKEFILE_PATH = REPO_ROOT / "Makefile"


def _block_for_target(target: str) -> str:
    """Return the recipe lines between ``<target>:`` and the next
    top-level target. Preserves blank/comment lines inside the block."""
    body = MAKEFILE_PATH.read_text()
    in_block = False
    block_lines: list[str] = []
    for line in body.splitlines():
        if line.startswith(f"{target}:"):
            in_block = True
            continue
        if in_block:
            if line and not line[0].isspace() and re.match(r"[A-Za-z0-9_.-]+:", line):
                break
            block_lines.append(line)
    return "\n".join(block_lines)


class TestCertsRotateTarget:
    def test_target_declared(self) -> None:
        body = MAKEFILE_PATH.read_text()
        assert "certs-rotate:" in body, (
            "Makefile must declare a certs-rotate target — see the "
            "cert-rotation followup from the Sep '26 prod-up incident"
        )

    def test_target_listed_in_phony(self) -> None:
        """`.PHONY:` prevents make from getting confused by a file
        named ``certs-rotate`` in the working tree."""
        body = MAKEFILE_PATH.read_text()
        # First non-comment, non-blank line usually holds .PHONY.
        phony_lines = [
            line for line in body.splitlines()
            if line.startswith(".PHONY:")
        ]
        assert phony_lines, "Makefile must have a .PHONY declaration"
        joined = " ".join(phony_lines)
        assert "certs-rotate" in joined, (
            f"certs-rotate must appear in .PHONY — got:\n{joined}"
        )

    def test_target_listed_in_help(self) -> None:
        """Operators discover this via `make help`."""
        body = MAKEFILE_PATH.read_text()
        assert re.search(r'@echo\s+"\s*certs-rotate\b', body), (
            "make help must mention certs-rotate so operators discover "
            "it without grepping the Makefile"
        )

    def test_target_invokes_rotate_script(self) -> None:
        block = _block_for_target("certs-rotate")
        assert "prod_rotate_certs.sh" in block, (
            "certs-rotate must invoke scripts/prod_rotate_certs.sh — "
            f"got:\n{block}"
        )

    def test_target_runs_script_via_compose(self) -> None:
        """The script mints via Vault's PKI backend, which needs the
        VAULT_TOKEN the wg-manager entrypoint shim sources from
        ``/app/vault-init.json``. Only the compose containers have
        that wiring, so the target must ``docker compose run --rm``
        (or use the pinned ``$(PROD_COMPOSE)`` variable)."""
        block = _block_for_target("certs-rotate")
        assert "$(PROD_COMPOSE)" in block or "docker compose" in block, (
            "certs-rotate must run the script inside a compose "
            f"container — got:\n{block}"
        )
        assert "run --rm" in block, (
            f"certs-rotate must use `run --rm` — got:\n{block}"
        )

    def test_target_restarts_mysql(self) -> None:
        """MySQL loads its server cert at process start. A fresh cert
        on disk is invisible to the running mysqld until we restart."""
        block = _block_for_target("certs-rotate")
        assert "restart" in block and "mysql" in block, (
            "certs-rotate must `docker compose restart mysql` after "
            f"minting so mysqld reloads the fresh server cert — got:\n{block}"
        )

    def test_target_restarts_api(self) -> None:
        """Uvicorn loads tls/server.crt at bind time. Same story as
        mysqld — the running process is still holding the old cert
        until we bounce it."""
        block = _block_for_target("certs-rotate")
        assert "restart" in block and "api" in block, (
            "certs-rotate must restart the api service after minting "
            f"so uvicorn reloads tls/server.crt — got:\n{block}"
        )

    def test_target_guards_on_env_prod(self) -> None:
        """Same failure-mode as prod-up: without .env.prod the compose
        stack has no MYSQL_APP_PASSWORD etc, so the run --rm call
        would fail with a confusing interpolation error. Fail loudly."""
        block = _block_for_target("certs-rotate")
        assert ".env.prod" in block, (
            "certs-rotate must guard on .env.prod's presence so it "
            "fails with a helpful message instead of a compose "
            f"interpolation error — got:\n{block}"
        )
