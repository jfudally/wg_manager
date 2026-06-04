"""Phase 3b cycle 3 — multi-tenant scoping smoke test against live mTLS.

This is the e2e equivalent of the three PR-test-plan checkboxes:

1. A non-super-admin operator attached only to tenant A sees only
   tenant A's resources via ``GET /servers``.
2. An auditor (per-tenant role) gets HTTP 403 on a mutating endpoint
   even when the row is in their tenant.
3. A server mutation by the super-admin produces an audit event
   whose ``tenant_id`` column reflects the resource's tenant.

The harness from ``conftest.py`` spins a real uvicorn subprocess
with ``ssl_cert_reqs=CERT_REQUIRED`` and a fresh ``LocalDevPKI`` as
the trust anchor on both ends. The test process shares the SQLite
file the API serves out of, so we can seed multi-tenant fixtures
(via direct-DB insert) and immediately observe them through the
live API — exercising the *real* :class:`MTLSAuthMiddleware` tenant
resolution + the router's scope filter + the mutation gate, not the
TestClient passthrough.

The router POST path doesn't yet accept ``tenant_id`` in the body
(deferred to cycle 5 alongside the dashboard tenant picker), so
the test seeds the resource rows directly with the desired tenant
binding rather than driving them through ``POST /servers``. The
*read-side* scoping + the mutation *gate* are exactly the cycle 3
behaviour we want pinned end-to-end.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from sqlmodel import Session, SQLModel, create_engine, select

from tests.e2e.tls.conftest import LiveAPIEnv


pytestmark = pytest.mark.e2e_tls


def _shared_engine(env: LiveAPIEnv):
    """Open the SQLite the API subprocess is also writing.

    The harness pins ``DATABASE_URL`` to ``sqlite:///<tmp>/cp5.db``;
    we resolve the same path off the tmp dir + open our own engine
    against it. SQLite handles a single concurrent reader+writer in
    the test+subprocess pair fine for this read-mostly smoke.
    """
    db_path = env.tmp_dir / "cp5.db"
    # Import models to populate metadata for select() below.
    import wg_manager.models  # noqa: F401

    return create_engine(f"sqlite:///{db_path}")


@pytest.fixture(scope="module")
def multi_tenant_fixture(
    live_api_server: LiveAPIEnv,
) -> dict[str, int]:
    """Seed two tenants, a scoped operator, an auditor operator, and
    one server per tenant.

    Module-scoped so the three smoke tests share one fixture against
    the session-scoped SQLite (re-inserting would hit the unique
    constraints on ``tenant.slug`` / ``operator.cn``).

    Returns a label → id map for the test bodies to assert against.
    """
    return _seed_multi_tenant(live_api_server)


def _seed_multi_tenant(env: LiveAPIEnv) -> dict[str, int]:
    """Insert the multi-tenant fixture once. See ``multi_tenant_fixture``."""
    from wg_manager.models import (
        Operator,
        OperatorRole,
        OperatorStatus,
        OperatorTenant,
        SSHKey,
        Server,
        Tenant,
    )

    engine = _shared_engine(env)
    with Session(engine) as session:
        # Tenants.
        acme = Tenant(name="Acme E2E", slug="acme-e2e")
        beta = Tenant(name="Beta E2E", slug="beta-e2e")
        session.add(acme)
        session.add(beta)
        session.flush()

        # SSH key rows — needed for the Server FK. Pin to each tenant.
        acme_key = SSHKey(name="acme-e2e-key", tenant_id=acme.id)
        beta_key = SSHKey(name="beta-e2e-key", tenant_id=beta.id)
        session.add(acme_key)
        session.add(beta_key)
        session.flush()

        # Two servers, one per tenant.
        acme_server = Server(
            hostname="acme-e2e-hub",
            ssh_username="ubuntu",
            ssh_key_id=int(acme_key.id or 0),
            endpoint_host="acme-e2e-hub",
            address="10.10.0.1/24",
            subnet="10.10.0.0/24",
            tenant_id=acme.id,
        )
        beta_server = Server(
            hostname="beta-e2e-hub",
            ssh_username="ubuntu",
            ssh_key_id=int(beta_key.id or 0),
            endpoint_host="beta-e2e-hub",
            address="10.20.0.1/24",
            subnet="10.20.0.0/24",
            tenant_id=beta.id,
        )
        session.add(acme_server)
        session.add(beta_server)
        session.flush()

        # Scoped (non-super-admin) operator. Global role = operator so
        # the super-admin bypass does NOT apply; cycle 3's per-tenant
        # gate is what runs.
        scoped_op = Operator(
            cn="scoped@e2e.wg.local",
            role=OperatorRole.operator,
            status=OperatorStatus.active,
        )
        session.add(scoped_op)
        session.flush()

        # Attach scoped_op to acme as ``operator`` (mutating perms);
        # NOT attached to beta at all so list-scoping leaves beta out.
        session.add(
            OperatorTenant(
                operator_id=int(scoped_op.id or 0),
                tenant_id=int(acme.id or 0),
                role=OperatorRole.operator,
            )
        )

        # Auditor operator: attached to acme with role=auditor so the
        # PR's #2 check (mutation 403 even in-scope) can be exercised
        # against the same fixture.
        auditor_op = Operator(
            cn="auditor@e2e.wg.local",
            role=OperatorRole.operator,
            status=OperatorStatus.active,
        )
        session.add(auditor_op)
        session.flush()
        session.add(
            OperatorTenant(
                operator_id=int(auditor_op.id or 0),
                tenant_id=int(acme.id or 0),
                role=OperatorRole.auditor,
            )
        )
        session.commit()

        return {
            "acme_tenant_id": int(acme.id or 0),
            "beta_tenant_id": int(beta.id or 0),
            "acme_server_id": int(acme_server.id or 0),
            "beta_server_id": int(beta_server.id or 0),
            "scoped_operator_id": int(scoped_op.id or 0),
            "auditor_operator_id": int(auditor_op.id or 0),
        }


def _build_httpx_client(
    env: LiveAPIEnv, cert_path: Path, key_path: Path
) -> httpx.Client:
    """Wire an httpx client at the live API with the operator's cert.

    Uses :meth:`LiveAPIEnv.make_client_ssl_context` so the cert-load
    path matches the CP5 acceptance suite (and disables the OpenSSL
    strict flag — see the docstring there).
    """
    ctx = env.make_client_ssl_context(cert_path, key_path)
    return httpx.Client(
        base_url=env.base_url,
        verify=ctx,
        timeout=10.0,
    )


def test_scoped_operator_sees_only_their_tenants_resources(
    live_api_server: LiveAPIEnv,
    multi_tenant_fixture: dict[str, int],
) -> None:
    """PR test-plan check #1.

    A non-super-admin operator attached only to tenant A hits
    ``GET /servers`` over real mTLS and sees only the acme server.
    """
    fixture = multi_tenant_fixture

    scoped_cert = live_api_server.mint_client_cert(
        "scoped@e2e.wg.local", ttl_seconds=300
    )
    cert_path, key_path = live_api_server.write_pem_files(
        scoped_cert, "scoped"
    )

    with _build_httpx_client(live_api_server, cert_path, key_path) as c:
        resp = c.get("/servers")

    assert resp.status_code == 200, resp.text
    bodies = resp.json()
    ids = {entry["id"] for entry in bodies}
    assert fixture["acme_server_id"] in ids
    assert fixture["beta_server_id"] not in ids
    # The acme row's tenant_id is surfaced on the schema since cycle 3.
    acme_entry = next(
        e for e in bodies if e["id"] == fixture["acme_server_id"]
    )
    assert acme_entry["tenant_id"] == fixture["acme_tenant_id"]


def test_auditor_role_blocks_mutating_endpoint(
    live_api_server: LiveAPIEnv,
    multi_tenant_fixture: dict[str, int],
) -> None:
    """PR test-plan check #2.

    An auditor (per-tenant role) gets HTTP 403 on ``PATCH /servers/{id}``
    for a server in their own tenant — read-side admits but write-side
    rejects via ``require_tenant_role``.
    """
    fixture = multi_tenant_fixture

    auditor_cert = live_api_server.mint_client_cert(
        "auditor@e2e.wg.local", ttl_seconds=300
    )
    cert_path, key_path = live_api_server.write_pem_files(
        auditor_cert, "auditor"
    )

    with _build_httpx_client(live_api_server, cert_path, key_path) as c:
        # Sanity: auditor CAN read.
        list_resp = c.get("/servers")
        assert list_resp.status_code == 200, list_resp.text
        ids = {e["id"] for e in list_resp.json()}
        assert fixture["acme_server_id"] in ids

        # The mutation must 403.
        patch_resp = c.patch(
            f"/servers/{fixture['acme_server_id']}",
            json={"endpoint_port": 51950},
        )

    assert patch_resp.status_code == 403, patch_resp.text
    body = patch_resp.json()
    assert body.get("detail") == "role not permitted"


def test_audit_event_records_tenant_id(
    live_api_server: LiveAPIEnv,
    multi_tenant_fixture: dict[str, int],
) -> None:
    """PR test-plan check #3.

    A super-admin mutating an acme server produces an ``auditevent``
    row whose ``tenant_id`` mirrors the acme tenant.
    """
    fixture = multi_tenant_fixture

    # The bootstrap admin (super-admin) self-registers on first call.
    boot_cert = live_api_server.mint_client_cert(
        live_api_server.bootstrap_operator_cn, ttl_seconds=300
    )
    cert_path, key_path = live_api_server.write_pem_files(
        boot_cert, "boot-admin"
    )

    with _build_httpx_client(live_api_server, cert_path, key_path) as c:
        resp = c.patch(
            f"/servers/{fixture['acme_server_id']}",
            json={"endpoint_port": 51960},
        )

    assert resp.status_code == 200, resp.text

    # Cross-check via the shared SQLite — fewer moving parts than
    # going back through `GET /audit` (which also enforces scope).
    from wg_manager.models import AuditEvent

    engine = _shared_engine(live_api_server)
    with Session(engine) as session:
        row = session.exec(
            select(AuditEvent)
            .where(AuditEvent.event == "server.update")
            .where(AuditEvent.resource_id == fixture["acme_server_id"])
            .order_by(AuditEvent.id.desc())
        ).first()

    assert row is not None
    assert row.tenant_id == fixture["acme_tenant_id"]
