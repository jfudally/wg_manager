"""Phase 3b cycle 5 — tenant SAN convention on cli/dashboard certs.

Cycle 3 added per-operator scope from the registry; cycle 5 lets
**non-operator service identities** also carry a tenant binding.
The convention: when ``wg-manager certs issue --type {cli,dashboard}``
is invoked with ``--tenant <slug>``, a SAN of the form
``tenant:<slug>`` is baked into the leaf, and the resulting
:class:`Certificate` row's ``tenant_id`` is populated.

The dashboard / API can later parse the SAN back out at handshake
time to decide which tenant the cert represents — useful for the
``cli`` cert types that a CI runner or automation account might
carry (where there's no operator registry row to consult).

Contract pinned here:

1. ``wg-manager certs issue --type cli --tenant acme`` mints a leaf
   whose SAN list includes ``tenant:acme``. The audit row's
   ``tenant_id`` mirrors the resolved tenant.
2. Same for ``--type dashboard``.
3. ``--tenant`` against a server-EKU type (``api``, ``mysql``,
   ``mysql-client``) is rejected with a clear error — the
   convention is operator-/service-client-only.
4. ``--tenant <unknown-slug>`` is rejected with a clear error
   naming the missing slug.
5. The API mirror (``POST /certs``) accepts ``tenant_slug`` with
   the same shape.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

import pytest
from cryptography import x509
from fastapi.testclient import TestClient
from sqlmodel import Session, select
from typer.testing import CliRunner

from wg_manager import cli
from wg_manager import db as db_module
from wg_manager.auth import CertSubject
from wg_manager.main import app
from wg_manager.models import (
    Certificate,
    CertificateType,
    Operator,
    OperatorRole,
    OperatorStatus,
    Tenant,
)


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def certs_env(
    engine: Any,  # noqa: ARG001
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wire ``cli._get_engine`` at the test engine."""
    monkeypatch.setattr(cli, "_get_engine", lambda url=None: db_module.engine)


def _invoke(runner: CliRunner, *args: str) -> Any:
    return runner.invoke(cli.app, list(args))


def _insert_operator(cn: str, role: OperatorRole = OperatorRole.operator) -> Operator:
    with Session(db_module.engine) as session:
        row = Operator(cn=cn, role=role)
        session.add(row)
        session.commit()
        session.refresh(row)
        return Operator(
            id=row.id, cn=row.cn, role=row.role,
            status=row.status, display_name=row.display_name,
            created_at=row.created_at,
        )


def _seed_tenant(slug: str, pool: str = "10.0.0.0/8") -> Tenant:
    with Session(db_module.engine) as session:
        existing = session.exec(
            select(Tenant).where(Tenant.slug == slug)
        ).first()
        if existing is not None:
            return Tenant(
                id=existing.id, name=existing.name, slug=existing.slug,
                subnet_pool=existing.subnet_pool,
                created_at=existing.created_at,
            )
        row = Tenant(name=slug.title(), slug=slug, subnet_pool=pool)
        session.add(row)
        session.commit()
        session.refresh(row)
        return Tenant(
            id=row.id, name=row.name, slug=row.slug,
            subnet_pool=row.subnet_pool, created_at=row.created_at,
        )


def _sans_on_cert(cert_pem: str) -> list[str]:
    """Pull SAN strings out of a leaf cert PEM."""
    leaf = x509.load_pem_x509_certificate(cert_pem.encode())
    try:
        ext = leaf.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
    except x509.ExtensionNotFound:
        return []
    out: list[str] = []
    for entry in ext.value:
        if isinstance(entry, x509.DNSName):
            out.append(entry.value)
        elif isinstance(entry, x509.IPAddress):
            out.append(str(entry.value))
    return out


# ---------------------------------------------------------------------------
# CLI — `wg-manager certs issue --type cli --tenant acme`
# ---------------------------------------------------------------------------


class TestCLICertTenantSAN:
    def test_cli_cert_with_tenant_flag_bakes_san(
        self,
        runner: CliRunner,
        certs_env: None,  # noqa: ARG002
        tmp_path: Any,
    ) -> None:
        _insert_operator("automation@wg.local", role=OperatorRole.operator)
        acme = _seed_tenant("acme")

        cert_path = tmp_path / "auto.crt"
        key_path = tmp_path / "auto.key"
        chain_path = tmp_path / "auto.chain.crt"

        result = _invoke(
            runner,
            "certs",
            "issue",
            "--type",
            "cli",
            "--cn",
            "automation@wg.local",
            "--tenant",
            "acme",
            "--out-cert",
            str(cert_path),
            "--out-key",
            str(key_path),
            "--out-chain",
            str(chain_path),
        )
        assert result.exit_code == 0, result.output

        sans = _sans_on_cert(cert_path.read_text())
        assert "tenant:acme" in sans

        with Session(db_module.engine) as session:
            row = session.exec(
                select(Certificate).where(Certificate.cert_type == CertificateType.cli)
            ).first()
        assert row is not None
        assert row.tenant_id == acme.id
        # The stored SAN string mirrors the cert.
        assert "tenant:acme" in row.sans

    def test_dashboard_cert_with_tenant_flag_bakes_san(
        self,
        runner: CliRunner,
        certs_env: None,  # noqa: ARG002
        tmp_path: Any,
    ) -> None:
        _insert_operator("ui@wg.local", role=OperatorRole.operator)
        _seed_tenant("acme")

        p12_path = tmp_path / "ui.p12"

        result = _invoke(
            runner,
            "certs",
            "issue",
            "--type",
            "dashboard",
            "--cn",
            "ui@wg.local",
            "--tenant",
            "acme",
            "--out-pkcs12",
            str(p12_path),
        )
        assert result.exit_code == 0, result.output

        # PKCS#12 round-trip → extract leaf → check SAN.
        from cryptography.hazmat.primitives.serialization import pkcs12

        key, leaf, chain = pkcs12.load_key_and_certificates(
            p12_path.read_bytes(), password=None
        )
        assert leaf is not None
        san_ext = leaf.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        san_strings = []
        for entry in san_ext.value:
            if isinstance(entry, x509.DNSName):
                san_strings.append(entry.value)
        assert "tenant:acme" in san_strings

    def test_tenant_flag_rejected_for_server_type(
        self,
        runner: CliRunner,
        certs_env: None,  # noqa: ARG002
        tmp_path: Any,
    ) -> None:
        _seed_tenant("acme")
        result = _invoke(
            runner,
            "certs",
            "issue",
            "--type",
            "api",
            "--cn",
            "127.0.0.1",
            "--tenant",
            "acme",
            "--out-cert",
            str(tmp_path / "api.crt"),
            "--out-key",
            str(tmp_path / "api.key"),
            "--out-chain",
            str(tmp_path / "api.chain.crt"),
        )
        assert result.exit_code != 0
        assert "tenant" in result.output.lower()

    def test_unknown_tenant_slug_rejected(
        self,
        runner: CliRunner,
        certs_env: None,  # noqa: ARG002
        tmp_path: Any,
    ) -> None:
        _insert_operator("a@wg.local")
        result = _invoke(
            runner,
            "certs",
            "issue",
            "--type",
            "cli",
            "--cn",
            "a@wg.local",
            "--tenant",
            "no-such-tenant",
            "--out-cert",
            str(tmp_path / "x.crt"),
            "--out-key",
            str(tmp_path / "x.key"),
            "--out-chain",
            str(tmp_path / "x.chain.crt"),
        )
        assert result.exit_code != 0
        assert "no-such-tenant" in result.output


# ---------------------------------------------------------------------------
# HTTP — `POST /certs` with tenant_slug
# ---------------------------------------------------------------------------


def _make_admin_subject(cn: str = "ops@wg.local") -> CertSubject:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return CertSubject(
        common_name=cn,
        sans=(cn,),
        serial=4242,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=365),
        cert_pem=f"---fake-pem-for-{cn}---",
    )


@pytest.fixture()
def as_super_admin(client: TestClient) -> Operator:
    """Inject a super-admin operator into the /certs router auth deps."""
    from wg_manager.auth import require_subject
    from wg_manager.routers import certs as certs_router

    with Session(db_module.engine) as session:
        op = Operator(cn="ops@wg.local", role=OperatorRole.admin)
        session.add(op)
        session.commit()
        session.refresh(op)
        op = Operator(
            id=op.id, cn=op.cn, role=op.role,
            status=op.status, display_name=op.display_name,
            created_at=op.created_at,
        )

    canned = _make_admin_subject(op.cn)
    app.dependency_overrides[require_subject] = lambda: canned
    app.dependency_overrides[certs_router._get_operator] = lambda: op
    app.dependency_overrides[certs_router._RequireAdmin] = lambda: canned
    app.dependency_overrides[certs_router._RequireAdminOrAuditor] = (
        lambda: canned
    )
    return op


class TestAPICertTenantSAN:
    def test_post_certs_with_tenant_slug_bakes_san(
        self,
        client: TestClient,
        as_super_admin: Operator,  # noqa: ARG002
    ) -> None:
        _insert_operator("automation@wg.local")
        acme = _seed_tenant("acme")

        resp = client.post(
            "/certs",
            json={
                "cert_type": "cli",
                "common_name": "automation@wg.local",
                "operator_cn": "automation@wg.local",
                "tenant_slug": "acme",
            },
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        # Response surfaces the populated tenant_id.
        assert body["certificate"]["tenant_id"] == acme.id
        # Cert PEM in the body carries the SAN.
        sans = _sans_on_cert(body["cert_pem"])
        assert "tenant:acme" in sans

    def test_post_certs_unknown_tenant_slug_returns_422(
        self,
        client: TestClient,
        as_super_admin: Operator,  # noqa: ARG002
    ) -> None:
        _insert_operator("a@wg.local")
        resp = client.post(
            "/certs",
            json={
                "cert_type": "cli",
                "common_name": "a@wg.local",
                "operator_cn": "a@wg.local",
                "tenant_slug": "no-such-tenant",
            },
        )
        assert resp.status_code == 422, resp.text
        assert "no-such-tenant" in resp.text

    def test_post_certs_tenant_slug_rejected_for_server_type(
        self,
        client: TestClient,
        as_super_admin: Operator,  # noqa: ARG002
    ) -> None:
        _seed_tenant("acme")
        resp = client.post(
            "/certs",
            json={
                "cert_type": "api",
                "common_name": "127.0.0.1",
                "tenant_slug": "acme",
            },
        )
        assert resp.status_code == 422, resp.text
        assert "tenant" in resp.text.lower()
