"""Tests for ``scripts/prod_rotate_certs.sh``.

The rotate orchestrator runs inside ``bootstrap-app``'s image (so the
wg-manager entrypoint shim sources ``VAULT_TOKEN`` from the bind-
mounted ``vault-init.json``) and re-mints the three cert families
that Vault issues short-TTL leaves for:

* ``tls/mysql/{server,client}.{crt,key}`` — via the direct-to-Vault
  bootstrap script (no DB dependency; the mint path we get unstuck
  with when MySQL TLS itself has expired).
* ``tls/{server,ca-bundle}.{crt,key}`` — the API server cert, minted
  through the ``wg-manager certs issue --type api`` CLI so an audit
  row lands in the ``certificate`` table.
* ``tls/{client,client.chain}.{crt,key}`` — the operator CLI client
  cert, minted the same way with ``--type cli``.

Shape-only tests — the live rotation happens against a real Vault +
DB via ``make certs-rotate`` (covered separately by the Makefile
shape tests and the operator's manual smoke).
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "prod_rotate_certs.sh"


@pytest.fixture(scope="module")
def body() -> str:
    assert SCRIPT_PATH.is_file(), (
        f"{SCRIPT_PATH} is missing — `make certs-rotate` has "
        "nothing to exec."
    )
    return SCRIPT_PATH.read_text()


class TestScriptExecutable:
    def test_script_is_executable(self) -> None:
        assert bool(os.stat(SCRIPT_PATH).st_mode & stat.S_IXUSR), (
            f"{SCRIPT_PATH} must have the owner-executable bit set — "
            "compose invokes it as an argv entry, so exec() will "
            "otherwise ENOEXEC out."
        )

    def test_script_uses_strict_mode(self, body: str) -> None:
        assert "set -euo pipefail" in body, (
            "the rotate script handles cert material — a silently-"
            "swallowed failure would leave the operator with a "
            "half-rotated stack. `set -euo pipefail` is mandatory."
        )


class TestMysqlRotation:
    def test_invokes_bootstrap_mysql_tls_files(self, body: str) -> None:
        """The MySQL leaves are rotated by the direct-to-Vault
        bootstrap script (no DB dependency — same one the operator
        reaches for when MySQL TLS itself has expired)."""
        assert "bootstrap_mysql_tls_files.py" in body, (
            "rotate script must call scripts/bootstrap_mysql_tls_files.py "
            "for the MySQL server + client cert pair"
        )


class TestApiCertRotation:
    def test_reissues_api_server_cert(self, body: str) -> None:
        assert "--type api" in body, (
            "rotate script must reissue the API server cert with "
            "`wg-manager certs issue --type api`"
        )

    def test_writes_expected_api_outputs(self, body: str) -> None:
        """Uvicorn is wired to read these three paths — the rotate
        script must overwrite the same filenames prod_bootstrap_app.sh
        writes on first-run."""
        for path_fragment in (
            "server.crt",
            "server.key",
            "ca-bundle.crt",
        ):
            assert path_fragment in body, (
                f"rotate script must write {path_fragment} — "
                "compose points uvicorn at that filename"
            )


class TestCliCertRotation:
    def test_reissues_cli_client_cert(self, body: str) -> None:
        assert "--type cli" in body, (
            "rotate script must reissue the operator CLI client cert "
            "with `wg-manager certs issue --type cli`"
        )

    def test_writes_expected_cli_outputs(self, body: str) -> None:
        for path_fragment in (
            "client.crt",
            "client.key",
            "client.chain.crt",
        ):
            assert path_fragment in body, (
                f"rotate script must write {path_fragment} — the "
                "operator + dashboard BFF present that cert to the API"
            )


class TestPostMintOwnership:
    def test_chowns_tls_dir_back_to_wgmanager(self, body: str) -> None:
        """Same rationale as prod_bootstrap_app.sh: the container runs
        as root for portable bind-mount write access, so the outputs
        would land as UID 0 on the host. The runtime tier reads as
        UID 1001 (wgmanager)."""
        assert "chown -R 1001:1001" in body, (
            "rotate script must chown the tls tree back to 1001:1001 "
            "so the api/worker/web containers can read the fresh keys"
        )

    def test_key_files_get_group_readable_mode(self, body: str) -> None:
        """Same rationale as prod_bootstrap_app.sh line 116: MySQL's
        container runs as UID 999, so 0600 on the keys locks it out.
        The rotate script must widen key modes to 0644."""
        assert "chmod 0644" in body and "*.key" in body, (
            "rotate script must chmod 0644 on the .key files so "
            "non-1001 container UIDs (mysql's 999) can read them"
        )

    def test_operator_cn_required(self, body: str) -> None:
        """CLI cert CN comes from BOOTSTRAP_OPERATOR_CN — the same
        env the bootstrap script requires. Fail loudly if unset
        rather than mint an anonymous cert."""
        assert "BOOTSTRAP_OPERATOR_CN" in body, (
            "rotate script must read BOOTSTRAP_OPERATOR_CN for the "
            "CLI cert subject — see prod_bootstrap_app.sh for the "
            "matching first-run behaviour"
        )
