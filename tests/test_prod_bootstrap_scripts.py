"""Tests for the self-bootstrap shell scripts.

``scripts/prod_bootstrap_substrate.sh`` and
``scripts/prod_bootstrap_app.sh`` are the two scripts the
self-bootstrapping prod overlay invokes via the `bootstrap-substrate`
and `bootstrap-app` compose services. The scripts must be present,
executable, and call the expected sub-commands — these tests pin the
contract so a future edit that drops the alembic call (for example)
breaks at test time rather than silently making the prod stack
half-bootstrapped.

Shape-only tests. Live execution lives in the operator's
end-to-end smoke (``make prod-up``).
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SUBSTRATE_SCRIPT = REPO_ROOT / "scripts" / "prod_bootstrap_substrate.sh"
APP_SCRIPT = REPO_ROOT / "scripts" / "prod_bootstrap_app.sh"


@pytest.fixture(scope="module")
def substrate_body() -> str:
    assert SUBSTRATE_SCRIPT.is_file(), (
        f"{SUBSTRATE_SCRIPT} is missing — Phase 1 bootstrap container "
        "has nothing to exec."
    )
    return SUBSTRATE_SCRIPT.read_text()


@pytest.fixture(scope="module")
def app_body() -> str:
    assert APP_SCRIPT.is_file(), (
        f"{APP_SCRIPT} is missing — Phase 2 bootstrap container has "
        "nothing to exec."
    )
    return APP_SCRIPT.read_text()


def _is_executable(path: Path) -> bool:
    """Owner-executable bit is set."""
    return bool(os.stat(path).st_mode & stat.S_IXUSR)


# ---------------------------------------------------------------------------
# Both scripts present + executable
# ---------------------------------------------------------------------------


class TestScriptsExecutable:
    @pytest.mark.parametrize("script", [SUBSTRATE_SCRIPT, APP_SCRIPT])
    def test_script_is_executable(self, script: Path) -> None:
        assert _is_executable(script), (
            f"{script.name} must be `chmod +x` so the compose service "
            "can exec it directly. Otherwise compose has to invoke "
            "`bash <path>` which is fragile."
        )


class TestScriptShebangs:
    """Both scripts must declare a bash shebang and `set -euo pipefail`
    so a failure stops the bootstrap rather than continuing with
    partial state."""

    @pytest.mark.parametrize("body_fixture", ["substrate_body", "app_body"])
    def test_has_bash_shebang(
        self, request: pytest.FixtureRequest, body_fixture: str
    ) -> None:
        body = request.getfixturevalue(body_fixture)
        first = body.splitlines()[0] if body else ""
        assert first.startswith("#!"), (
            f"{body_fixture} must declare a shebang on line 1; got "
            f"{first!r}."
        )
        assert "bash" in first, (
            f"{body_fixture} must use bash so `set -euo pipefail` and "
            f"`[[ ]]` work. Got shebang {first!r}."
        )

    @pytest.mark.parametrize("body_fixture", ["substrate_body", "app_body"])
    def test_uses_strict_mode(
        self, request: pytest.FixtureRequest, body_fixture: str
    ) -> None:
        body = request.getfixturevalue(body_fixture)
        # `set -euo pipefail` makes the script fail loud — without it,
        # a half-bootstrapped stack would continue silently past the
        # first error.
        assert "set -euo pipefail" in body, (
            f"{body_fixture} must declare `set -euo pipefail` so a "
            "failure halts bootstrap rather than continuing into a "
            "half-applied state."
        )


# ---------------------------------------------------------------------------
# Substrate script content
# ---------------------------------------------------------------------------


class TestSubstrateScript:
    """Phase 1 — Vault bootstraps + MySQL cert mints."""

    @pytest.mark.parametrize(
        "marker",
        [
            "pki_bootstrap",       # python script the Vault PKI bootstrap calls
            "ssh_ca_bootstrap",    # SSH CA bootstrap
            "vault_audit_bootstrap",  # audit device bootstrap
        ],
    )
    def test_invokes_vault_bootstrap_script(
        self, substrate_body: str, marker: str
    ) -> None:
        assert marker in substrate_body, (
            f"Phase 1 script must invoke `scripts/{marker}.py` so the "
            "Vault substrate (PKI / SSH CA / audit) is ready before "
            f"any cert mint runs. Marker {marker!r} not found."
        )

    def test_mints_mysql_server_cert(
        self, substrate_body: str
    ) -> None:
        # The MySQL server cert is what mysqld presents. mysql-tls-issue
        # is the existing Make target; the script can either invoke
        # that target or shell out to `wg-manager certs issue --type
        # mysql` directly.
        has_target = "mysql-tls-issue" in substrate_body
        has_direct = (
            "--type mysql" in substrate_body
            and "tls/mysql/server" in substrate_body
        )
        assert has_target or has_direct, (
            "Phase 1 script must mint the MySQL server cert "
            "(`--type mysql`) into tls/mysql/server.{crt,key}. Without "
            "it, MySQL refuses to start."
        )

    def test_mints_mysql_client_cert(
        self, substrate_body: str
    ) -> None:
        # `--type mysql-client` is the clientAuth EKU profile — using
        # `--type mysql` here would mint a serverAuth cert that mysqld
        # rejects on client handshake (the bug the prod-overlay
        # verification surfaced).
        assert "--type mysql-client" in substrate_body, (
            "Phase 1 script must mint the MySQL client cert with "
            "`--type mysql-client` (clientAuth EKU). `--type mysql` "
            "would produce serverAuth which mysqld rejects as a client "
            "cert."
        )


# ---------------------------------------------------------------------------
# App script content
# ---------------------------------------------------------------------------


class TestAppScript:
    """Phase 2 — migrate + register operator + mint app certs."""

    def test_runs_alembic_upgrade_head(self, app_body: str) -> None:
        # `alembic upgrade head` is the idempotent apply-all-migrations
        # call. Skipping it leaves the schema empty and every API call
        # would 5xx.
        assert "alembic upgrade head" in app_body, (
            "Phase 2 script must run `alembic upgrade head` to apply "
            "migrations against the running MySQL."
        )

    def test_registers_bootstrap_operator(self, app_body: str) -> None:
        # `wg-manager operators add` is what populates the operator
        # registry. Without a registered operator with a matching CN,
        # every mTLS request to the API would 401.
        assert "operators add" in app_body, (
            "Phase 2 script must register the bootstrap operator via "
            "`wg-manager operators add`. Without it, the API rejects "
            "every mTLS request with `operator not registered`."
        )

    def test_references_bootstrap_operator_cn_env(
        self, app_body: str
    ) -> None:
        # The operator's CN should come from the `BOOTSTRAP_OPERATOR_CN`
        # env var (which compose passes through from .env.prod).
        # Hard-coding the CN would defeat the whole point.
        assert "BOOTSTRAP_OPERATOR_CN" in app_body, (
            "Phase 2 script must reference $BOOTSTRAP_OPERATOR_CN so "
            "the operator's CN is operator-configurable via .env.prod, "
            "not baked into the script."
        )

    def test_mints_api_server_cert(self, app_body: str) -> None:
        # The api container needs the server cert to start; it's
        # delivered by Phase 2 because that's the first phase where
        # the cert audit row can be written.
        assert "--type api" in app_body, (
            "Phase 2 script must mint the API server cert with "
            "`--type api` into tls/server.{crt,key}."
        )

    def test_mints_operator_cli_cert(self, app_body: str) -> None:
        # The cli client cert is what an operator presents on every
        # API call, and what the dashboard's BFF proxy reuses.
        assert "--type cli" in app_body, (
            "Phase 2 script must mint the operator CLI client cert "
            "with `--type cli` into tls/client.{crt,key}. The dashboard "
            "and the operator's own curl invocations share this cert."
        )


# ---------------------------------------------------------------------------
# Re-run safety
# ---------------------------------------------------------------------------


class TestReRunSafety:
    """`make prod-down && make prod-up` against the same volume +
    tls/ state must be a clean no-op, not a re-mint or re-register
    that breaks existing credentials. Both scripts should guard each
    mutating step behind an existence check."""

    def test_substrate_guards_existing_cert_mints(
        self, substrate_body: str
    ) -> None:
        # Either `[ -f tls/...crt ]` or `[[ -f tls/...crt ]]`. The grep
        # is loose — what matters is that an `if` test gates the mint.
        assert "[ -f" in substrate_body or "[[ -f" in substrate_body, (
            "Phase 1 script must guard cert mints behind file-existence "
            "tests so re-running `make prod-up` against persistent tls/ "
            "doesn't overwrite valid certs."
        )

    def test_app_guards_existing_cert_mints(
        self, app_body: str
    ) -> None:
        assert "[ -f" in app_body or "[[ -f" in app_body, (
            "Phase 2 script must guard cert mints behind file-existence "
            "tests so re-running `make prod-up` is idempotent."
        )
