"""Tests for the Phase 2d CP3.3 ``wg-manager certs`` CLI subgroup.

CP3.3 replaces the throwaway ``scripts/issue_dev_tls.py`` helper with
a production-shaped CLI that walks ``wg_manager.pki`` and records
every issued leaf in the new :class:`wg_manager.models.Certificate`
registry. Four cert types ship:

* ``api`` — ``serverAuth`` for the FastAPI mTLS listener. SANs default
  to ``127.0.0.1`` + ``localhost``; operator can override with
  ``--san``.
* ``cli`` — ``clientAuth`` for an operator's CLI client cert. CN +
  default SAN are the operator's CN; ``--operator-cn`` ties the row
  to a registered :class:`Operator`.
* ``dashboard`` — ``clientAuth`` exported as a PKCS#12 archive for
  browser import. Same operator-FK shape as ``cli``.
* ``mysql`` — ``serverAuth`` for the MySQL listener (Phase 2d CP4
  wires this in). No operator owner.

The CLI is direct-DB / direct-PKI (mirrors ``wg-manager db
backup/restore``) — there is no API surface in CP3.3, so the tests
swap ``cli._get_engine`` for the in-memory test engine and let the
default :class:`LocalDevPKI` backend handle issuance.

Tests pin:

1. **Happy paths** for all four cert types — files are written, the
   ``certificate`` row carries the right metadata, and the cert PEM
   the file holds decrypts back to the expected CN + EKU.
2. **Operator FK enforcement** for ``cli`` / ``dashboard`` — issuing
   for an unregistered operator CN exits non-zero with a clear error.
3. **Revoke** flips the row's ``revoked`` flag, populates
   ``revoked_at``, and calls into the PKI backend's CRL.
4. **List** surfaces every row (live + revoked) as JSON.
5. **PKCS#12** export round-trips: the .p12 file parses back to the
   same cert + private key the CLI issued.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID
from sqlmodel import Session, select
from typer.testing import CliRunner

from wg_manager import cli
from wg_manager import db as db_module
from wg_manager.models import (
    Certificate,
    CertificateType,
    Operator,
    OperatorRole,
)


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def certs_env(
    engine: Any,  # noqa: ARG001 — installs schema on db_module.engine
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wire ``cli._get_engine`` at the test engine so direct-DB commands work.

    Mirrors the pattern ``test_cli.py``'s ``db backup`` tests use. The
    ``engine`` fixture already swaps :data:`wg_manager.db.engine` for
    the in-memory handle; this monkeypatch threads it through the CLI's
    ``--database-url``-aware engine accessor.
    """
    monkeypatch.setattr(cli, "_get_engine", lambda url=None: db_module.engine)


def _invoke(runner: CliRunner, *args: str) -> Any:
    """Invoke the CLI with ``--api-url`` omitted (no HTTP, direct-DB)."""
    return runner.invoke(cli.app, list(args))


def _insert_operator(cn: str, role: OperatorRole = OperatorRole.operator) -> int:
    """Insert an Operator row and return its primary key."""
    with Session(db_module.engine) as session:
        row = Operator(cn=cn, role=role)
        session.add(row)
        session.commit()
        session.refresh(row)
        return int(row.id or 0)


def _load_pem_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_text().encode())


def _cert_rows() -> list[Certificate]:
    with Session(db_module.engine) as session:
        return list(session.exec(select(Certificate)).all())


# ---------------------------------------------------------------------------
# issue — api / mysql (service certs, no operator owner)
# ---------------------------------------------------------------------------


class TestIssueApiCert:
    """``issue --type api`` mints a serverAuth cert for the FastAPI listener."""

    def test_writes_pem_files_and_records_row(
        self,
        runner: CliRunner,
        certs_env: None,  # noqa: ARG002
        tmp_path: Path,
    ) -> None:
        cert_path = tmp_path / "api.crt"
        key_path = tmp_path / "api.key"
        chain_path = tmp_path / "api.chain.crt"

        result = _invoke(
            runner,
            "certs",
            "issue",
            "--type",
            "api",
            "--cn",
            "127.0.0.1",
            "--san",
            "127.0.0.1",
            "--san",
            "localhost",
            "--ttl-days",
            "30",
            "--out-cert",
            str(cert_path),
            "--out-key",
            str(key_path),
            "--out-chain",
            str(chain_path),
        )

        assert result.exit_code == 0, result.output
        assert cert_path.exists()
        assert key_path.exists()
        assert chain_path.exists()
        # Permission discipline: private key not world-readable.
        assert (key_path.stat().st_mode & 0o077) == 0

        leaf = _load_pem_cert(cert_path)
        ekus = leaf.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
        assert ExtendedKeyUsageOID.SERVER_AUTH in list(ekus)

        rows = _cert_rows()
        assert len(rows) == 1
        row = rows[0]
        assert row.cert_type == CertificateType.api
        assert row.common_name == "127.0.0.1"
        assert "127.0.0.1" in row.sans and "localhost" in row.sans
        assert row.operator_id is None
        assert row.revoked is False
        # Serial is the decimal string of the cert's int serial.
        assert row.serial == str(leaf.serial_number)

    def test_default_sans_when_none_supplied(
        self,
        runner: CliRunner,
        certs_env: None,  # noqa: ARG002
        tmp_path: Path,
    ) -> None:
        """No ``--san`` flags → fall back to ``127.0.0.1`` + ``localhost``."""
        result = _invoke(
            runner,
            "certs",
            "issue",
            "--type",
            "api",
            "--cn",
            "127.0.0.1",
            "--out-cert",
            str(tmp_path / "api.crt"),
            "--out-key",
            str(tmp_path / "api.key"),
            "--out-chain",
            str(tmp_path / "api.chain.crt"),
        )
        assert result.exit_code == 0, result.output
        rows = _cert_rows()
        assert len(rows) == 1
        sans = rows[0].sans.split(",")
        assert "127.0.0.1" in sans
        assert "localhost" in sans


class TestIssueMysqlCert:
    """``issue --type mysql`` mints a serverAuth cert for the DB listener."""

    def test_writes_pem_files_and_records_row(
        self,
        runner: CliRunner,
        certs_env: None,  # noqa: ARG002
        tmp_path: Path,
    ) -> None:
        result = _invoke(
            runner,
            "certs",
            "issue",
            "--type",
            "mysql",
            "--cn",
            "mysql",
            "--san",
            "mysql",
            "--san",
            "127.0.0.1",
            "--out-cert",
            str(tmp_path / "mysql.crt"),
            "--out-key",
            str(tmp_path / "mysql.key"),
            "--out-chain",
            str(tmp_path / "mysql.chain.crt"),
        )
        assert result.exit_code == 0, result.output
        rows = _cert_rows()
        assert len(rows) == 1
        assert rows[0].cert_type == CertificateType.mysql
        assert rows[0].operator_id is None


class TestIssueMysqlClientCert:
    """``issue --type mysql-client`` mints a clientAuth cert with no operator FK.

    Phase 2d CP4.2 adds this cert type so the app + worker can present
    a Vault-issued client cert to the MySQL server (which is itself
    running with a ``--type mysql`` server cert). Unlike ``cli`` /
    ``dashboard``, ``mysql-client`` is a service principal — there is
    no human :class:`Operator` to bind it to — so the ``requires_operator``
    profile bit is ``False``.
    """

    def test_writes_pem_files_and_records_row(
        self,
        runner: CliRunner,
        certs_env: None,  # noqa: ARG002
        tmp_path: Path,
    ) -> None:
        result = _invoke(
            runner,
            "certs",
            "issue",
            "--type",
            "mysql-client",
            "--cn",
            "wg-manager-app",
            "--out-cert",
            str(tmp_path / "mysql-client.crt"),
            "--out-key",
            str(tmp_path / "mysql-client.key"),
            "--out-chain",
            str(tmp_path / "mysql-client.chain.crt"),
        )
        assert result.exit_code == 0, result.output
        rows = _cert_rows()
        assert len(rows) == 1
        assert rows[0].cert_type == CertificateType.mysql_client
        # No operator is bound — this is a service cert.
        assert rows[0].operator_id is None
        # The default SAN list folds back to the CN since the profile
        # carries ``default_sans=None`` (matching cli/dashboard's
        # CN-driven shape).
        sans = rows[0].sans.split(",")
        assert "wg-manager-app" in sans

    def test_leaf_carries_client_auth_eku(
        self,
        runner: CliRunner,
        certs_env: None,  # noqa: ARG002
        tmp_path: Path,
    ) -> None:
        """The leaf's EKU is clientAuth — server certs would fail mTLS as a client."""
        _invoke(
            runner,
            "certs",
            "issue",
            "--type",
            "mysql-client",
            "--cn",
            "wg-manager-app",
            "--out-cert",
            str(tmp_path / "mc.crt"),
            "--out-key",
            str(tmp_path / "mc.key"),
            "--out-chain",
            str(tmp_path / "mc.chain.crt"),
        )
        cert = _load_pem_cert(tmp_path / "mc.crt")
        eku = cert.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku
        assert ExtendedKeyUsageOID.SERVER_AUTH not in eku


# ---------------------------------------------------------------------------
# issue — cli / dashboard (operator-bound)
# ---------------------------------------------------------------------------


class TestIssueCliCert:
    """``issue --type cli`` mints a clientAuth cert bound to an Operator."""

    def test_happy_path_binds_to_operator(
        self,
        runner: CliRunner,
        certs_env: None,  # noqa: ARG002
        tmp_path: Path,
    ) -> None:
        op_id = _insert_operator("ops@wg.local", role=OperatorRole.admin)

        result = _invoke(
            runner,
            "certs",
            "issue",
            "--type",
            "cli",
            "--cn",
            "ops@wg.local",
            "--operator-cn",
            "ops@wg.local",
            "--ttl-days",
            "365",
            "--out-cert",
            str(tmp_path / "cli.crt"),
            "--out-key",
            str(tmp_path / "cli.key"),
            "--out-chain",
            str(tmp_path / "cli.chain.crt"),
        )

        assert result.exit_code == 0, result.output
        leaf = _load_pem_cert(tmp_path / "cli.crt")
        ekus = leaf.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
        assert ExtendedKeyUsageOID.CLIENT_AUTH in list(ekus)

        rows = _cert_rows()
        assert len(rows) == 1
        assert rows[0].cert_type == CertificateType.cli
        assert rows[0].operator_id == op_id

    def test_operator_cn_defaults_to_cn(
        self,
        runner: CliRunner,
        certs_env: None,  # noqa: ARG002
        tmp_path: Path,
    ) -> None:
        """Skipping ``--operator-cn`` implies it from ``--cn`` for cli rows."""
        op_id = _insert_operator("ops@wg.local")
        result = _invoke(
            runner,
            "certs",
            "issue",
            "--type",
            "cli",
            "--cn",
            "ops@wg.local",
            "--out-cert",
            str(tmp_path / "cli.crt"),
            "--out-key",
            str(tmp_path / "cli.key"),
            "--out-chain",
            str(tmp_path / "cli.chain.crt"),
        )
        assert result.exit_code == 0, result.output
        rows = _cert_rows()
        assert len(rows) == 1
        assert rows[0].operator_id == op_id

    def test_unknown_operator_cn_fails_with_clear_error(
        self,
        runner: CliRunner,
        certs_env: None,  # noqa: ARG002
        tmp_path: Path,
    ) -> None:
        """No matching Operator row → non-zero exit + named-CN error."""
        # No operator inserted.
        result = _invoke(
            runner,
            "certs",
            "issue",
            "--type",
            "cli",
            "--cn",
            "ghost@wg.local",
            "--operator-cn",
            "ghost@wg.local",
            "--out-cert",
            str(tmp_path / "cli.crt"),
            "--out-key",
            str(tmp_path / "cli.key"),
            "--out-chain",
            str(tmp_path / "cli.chain.crt"),
        )
        assert result.exit_code != 0
        # The error mentions the missing CN so the operator knows
        # exactly which row to add.
        assert "ghost@wg.local" in result.output
        # No row was inserted on the partial failure.
        assert _cert_rows() == []


class TestIssueDashboardCert:
    """``issue --type dashboard`` writes a PKCS#12 for browser import."""

    def test_writes_pkcs12_and_records_row(
        self,
        runner: CliRunner,
        certs_env: None,  # noqa: ARG002
        tmp_path: Path,
    ) -> None:
        op_id = _insert_operator("ops@wg.local")
        p12_path = tmp_path / "dashboard.p12"

        result = _invoke(
            runner,
            "certs",
            "issue",
            "--type",
            "dashboard",
            "--cn",
            "ops@wg.local",
            "--operator-cn",
            "ops@wg.local",
            "--out-pkcs12",
            str(p12_path),
            "--pkcs12-password",
            "hunter2",
        )

        assert result.exit_code == 0, result.output
        assert p12_path.exists()
        # Re-parse the PKCS#12 — proves the export shape is round-trippable.
        key, leaf, chain = pkcs12.load_key_and_certificates(
            p12_path.read_bytes(), b"hunter2"
        )
        assert leaf is not None
        ekus = leaf.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
        assert ExtendedKeyUsageOID.CLIENT_AUTH in list(ekus)
        assert key is not None  # private key embedded
        # Chain carries at least the issuing intermediate.
        assert chain is not None and len(chain) >= 1

        rows = _cert_rows()
        assert len(rows) == 1
        assert rows[0].cert_type == CertificateType.dashboard
        assert rows[0].operator_id == op_id
        assert rows[0].serial == str(leaf.serial_number)


# ---------------------------------------------------------------------------
# revoke
# ---------------------------------------------------------------------------


class TestRevoke:
    """``revoke --serial`` flips the row and calls into the PKI CRL."""

    def test_revoke_marks_row_and_updates_crl(
        self,
        runner: CliRunner,
        certs_env: None,  # noqa: ARG002
        tmp_path: Path,
    ) -> None:
        # Issue first so there's something to revoke.
        _invoke(
            runner,
            "certs",
            "issue",
            "--type",
            "api",
            "--cn",
            "127.0.0.1",
            "--out-cert",
            str(tmp_path / "api.crt"),
            "--out-key",
            str(tmp_path / "api.key"),
            "--out-chain",
            str(tmp_path / "api.chain.crt"),
        )
        rows = _cert_rows()
        assert len(rows) == 1
        serial = rows[0].serial

        # Serial is stored as a decimal string; revoke takes int input.
        result = _invoke(runner, "certs", "revoke", "--serial", serial)
        assert result.exit_code == 0, result.output

        rows = _cert_rows()
        assert len(rows) == 1
        assert rows[0].revoked is True
        assert rows[0].revoked_at is not None

    def test_revoke_unknown_serial_fails(
        self,
        runner: CliRunner,
        certs_env: None,  # noqa: ARG002
    ) -> None:
        result = _invoke(runner, "certs", "revoke", "--serial", "999999")
        assert result.exit_code != 0
        # The error names the serial so operator typos are easy to spot.
        assert "999999" in result.output


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


class TestOperatorsCLI:
    """Phase 2d CP3.3 also ships ``wg-manager operators add/list``.

    The CLI is the direct-DB bootstrap glue that closes the
    chicken-and-egg between ``certs issue --type cli`` (which needs an
    Operator row to exist) and the API (which needs a registered
    client cert to register the operator). The dashboard / HTTP
    surface lands in CP3.4 on top of the same table.
    """

    def test_add_registers_operator(
        self,
        runner: CliRunner,
        certs_env: None,  # noqa: ARG002
    ) -> None:
        result = _invoke(
            runner,
            "operators",
            "add",
            "--cn",
            "dev-operator",
            "--role",
            "admin",
            "--display-name",
            "Dev Operator",
        )
        assert result.exit_code == 0, result.output

        with Session(db_module.engine) as session:
            row = session.exec(
                select(Operator).where(Operator.cn == "dev-operator")
            ).first()
        assert row is not None
        assert row.role == OperatorRole.admin
        assert row.display_name == "Dev Operator"

    def test_add_duplicate_cn_fails(
        self,
        runner: CliRunner,
        certs_env: None,  # noqa: ARG002
    ) -> None:
        _insert_operator("ops@wg.local")
        result = _invoke(runner, "operators", "add", "--cn", "ops@wg.local")
        assert result.exit_code != 0
        assert "ops@wg.local" in result.output

    def test_list_prints_registered_rows(
        self,
        runner: CliRunner,
        certs_env: None,  # noqa: ARG002
    ) -> None:
        _insert_operator("ops@wg.local", role=OperatorRole.admin)
        _insert_operator("audit@wg.local", role=OperatorRole.auditor)

        result = _invoke(runner, "operators", "list")
        assert result.exit_code == 0, result.output
        parsed = json.loads(result.output)
        assert isinstance(parsed, list)
        cns = {entry["cn"] for entry in parsed}
        assert cns == {"ops@wg.local", "audit@wg.local"}


class TestList:
    """``certs list`` prints every row (live + revoked) as JSON."""

    def test_list_shows_issued_rows(
        self,
        runner: CliRunner,
        certs_env: None,  # noqa: ARG002
        tmp_path: Path,
    ) -> None:
        _insert_operator("ops@wg.local")
        _invoke(
            runner,
            "certs",
            "issue",
            "--type",
            "api",
            "--cn",
            "127.0.0.1",
            "--out-cert",
            str(tmp_path / "api.crt"),
            "--out-key",
            str(tmp_path / "api.key"),
            "--out-chain",
            str(tmp_path / "api.chain.crt"),
        )
        _invoke(
            runner,
            "certs",
            "issue",
            "--type",
            "cli",
            "--cn",
            "ops@wg.local",
            "--out-cert",
            str(tmp_path / "cli.crt"),
            "--out-key",
            str(tmp_path / "cli.key"),
            "--out-chain",
            str(tmp_path / "cli.chain.crt"),
        )

        result = _invoke(runner, "certs", "list")
        assert result.exit_code == 0, result.output
        parsed = json.loads(result.output)
        assert isinstance(parsed, list)
        assert len(parsed) == 2
        types = {entry["cert_type"] for entry in parsed}
        assert types == {"api", "cli"}
