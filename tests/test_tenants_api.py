"""Tests for the Phase 3b cycle 2 ``/tenants`` HTTP surface.

Cycle 2 lifts the CLI's ``wg-manager tenants`` + ``wg-manager
operators attach-tenant`` direct-DB shape into HTTP so the dashboard
(``web/app/tenants``) can manage the multi-tenant registry through
the same mTLS-protected API every other surface goes through.

Endpoints under test:

* ``GET /tenants`` — list every tenant. Any active operator may
  call it; cycle 3 will filter to the operator's tenant set.
* ``GET /tenants/{slug}`` — fetch one tenant by slug. Any active
  operator.
* ``POST /tenants`` — create a new tenant. Admin only.
* ``POST /tenants/{slug}/operators`` — attach an operator to the
  tenant with a per-tenant role. Admin only.
* ``DELETE /tenants/{slug}/operators/{cn}`` — detach. Admin only.
* ``GET /tenants/{slug}/operators`` — list every operator attached
  to the tenant. Admin or auditor.

Role gating mirrors the ``/certs`` router shape: ``_RequireAdmin`` /
``_RequireAdminOrAuditor`` deps composed on top of ``_get_operator``,
each overridable per-test for stable role-mock plumbing.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from wg_manager import db as db_module
from wg_manager.auth import CertSubject, require_subject
from wg_manager.main import app
from wg_manager.models import (
    Operator,
    OperatorRole,
    OperatorStatus,
    OperatorTenant,
    Tenant,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_subject(cn: str) -> CertSubject:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return CertSubject(
        common_name=cn,
        sans=(cn, "127.0.0.1"),
        serial=4242424242,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=365),
        cert_pem=f"---fake-pem-for-{cn}---",
    )


def _insert_operator(
    cn: str,
    role: OperatorRole = OperatorRole.admin,
    status: OperatorStatus = OperatorStatus.active,
) -> Operator:
    with Session(db_module.engine) as session:
        row = Operator(cn=cn, role=role, status=status)
        session.add(row)
        session.commit()
        session.refresh(row)
        return Operator(
            id=row.id,
            cn=row.cn,
            display_name=row.display_name,
            role=row.role,
            status=row.status,
            created_at=row.created_at,
        )


def _insert_tenant(name: str, slug: str) -> Tenant:
    """Upsert a tenant by slug — conftest seeds the default tenant at
    id=1, so a request for ``_insert_tenant('Default', 'default')``
    returns that pre-existing row rather than colliding."""
    with Session(db_module.engine) as session:
        existing = session.exec(
            select(Tenant).where(Tenant.slug == slug)
        ).first()
        if existing is not None:
            return Tenant(
                id=existing.id,
                name=existing.name,
                slug=existing.slug,
                subnet_pool=existing.subnet_pool,
                created_at=existing.created_at,
            )
        row = Tenant(name=name, slug=slug)
        session.add(row)
        session.commit()
        session.refresh(row)
        return Tenant(
            id=row.id,
            name=row.name,
            slug=row.slug,
            subnet_pool=row.subnet_pool,
            created_at=row.created_at,
        )


def _override_auth(
    *,
    operator: Operator,
    role_deps: Iterable[Any] = (),
) -> None:
    canned = _make_subject(operator.cn)
    app.dependency_overrides[require_subject] = lambda: canned
    from wg_manager.routers import tenants as tenants_router

    app.dependency_overrides[tenants_router._get_operator] = lambda: operator
    for dep in role_deps:
        app.dependency_overrides[dep] = lambda: canned


@pytest.fixture()
def as_admin(client: TestClient) -> tuple[TestClient, Operator]:
    from wg_manager.routers import tenants as tenants_router

    operator = _insert_operator("ops@wg.local", role=OperatorRole.admin)
    _override_auth(
        operator=operator,
        role_deps=(
            tenants_router._RequireAdmin,
            tenants_router._RequireAdminOrAuditor,
        ),
    )
    return client, operator


@pytest.fixture()
def as_auditor(client: TestClient) -> tuple[TestClient, Operator]:
    from wg_manager.routers import tenants as tenants_router

    operator = _insert_operator("audit@wg.local", role=OperatorRole.auditor)
    canned = _make_subject(operator.cn)
    app.dependency_overrides[require_subject] = lambda: canned
    app.dependency_overrides[tenants_router._get_operator] = lambda: operator
    app.dependency_overrides[tenants_router._RequireAdminOrAuditor] = (
        lambda: canned
    )
    return client, operator


@pytest.fixture()
def as_operator(client: TestClient) -> tuple[TestClient, Operator]:
    """Plain operator — no admin or auditor privilege.

    Deliberately does NOT override the admin-gated deps so the
    production ``_RequireAdmin`` body 403s the wrong role.
    """
    operator = _insert_operator("user@wg.local", role=OperatorRole.operator)
    canned = _make_subject(operator.cn)
    app.dependency_overrides[require_subject] = lambda: canned
    from wg_manager.routers import tenants as tenants_router

    app.dependency_overrides[tenants_router._get_operator] = lambda: operator
    return client, operator


# ---------------------------------------------------------------------------
# GET /tenants
# ---------------------------------------------------------------------------


class TestListTenants:
    def test_admin_sees_every_tenant(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        _insert_tenant("Acme", "acme")
        _insert_tenant("Default", "default")

        resp = client.get("/tenants")
        assert resp.status_code == 200, resp.text
        slugs = {entry["slug"] for entry in resp.json()}
        assert {"acme", "default"} <= slugs

    def test_auditor_can_list(
        self, as_auditor: tuple[TestClient, Operator]
    ) -> None:
        """List is gated by admin-or-auditor: any read-tier role admits."""
        client, _ = as_auditor
        _insert_tenant("Default", "default")
        resp = client.get("/tenants")
        assert resp.status_code == 200, resp.text


# ---------------------------------------------------------------------------
# GET /tenants/{slug}
# ---------------------------------------------------------------------------


class TestGetTenant:
    def test_admin_can_fetch_by_slug(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        # The conftest seeds the default tenant matching Alembic 0014:
        # name + slug are both "default" (lowercase).
        resp = client.get("/tenants/default")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["slug"] == "default"
        assert body["name"] == "default"

    def test_unknown_slug_returns_404(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        resp = client.get("/tenants/no-such-tenant")
        assert resp.status_code == 404, resp.text
        assert "no-such-tenant" in resp.text


# ---------------------------------------------------------------------------
# POST /tenants
# ---------------------------------------------------------------------------


class TestCreateTenant:
    def test_admin_can_create(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        resp = client.post(
            "/tenants",
            json={"name": "Acme", "slug": "acme"},
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["name"] == "Acme"
        assert body["slug"] == "acme"

        with Session(db_module.engine) as session:
            row = session.exec(
                select(Tenant).where(Tenant.slug == "acme")
            ).first()
        assert row is not None

    def test_auditor_cannot_create(
        self, as_auditor: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_auditor
        resp = client.post(
            "/tenants",
            json={"name": "Acme", "slug": "acme"},
        )
        assert resp.status_code == 403, resp.text

    def test_plain_operator_cannot_create(
        self, as_operator: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_operator
        resp = client.post(
            "/tenants",
            json={"name": "Acme", "slug": "acme"},
        )
        assert resp.status_code == 403, resp.text

    def test_duplicate_slug_returns_409(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        _insert_tenant("Default", "default")
        resp = client.post(
            "/tenants",
            json={"name": "Default Two", "slug": "default"},
        )
        assert resp.status_code == 409, resp.text
        assert "default" in resp.text

    def test_create_derives_slug_when_omitted(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        """Mirrors the CLI: a missing ``slug`` derives from ``name``."""
        client, _ = as_admin
        resp = client.post(
            "/tenants",
            json={"name": "Hello World"},
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["slug"] == "hello-world"


# ---------------------------------------------------------------------------
# POST /tenants/{slug}/operators (attach)
# ---------------------------------------------------------------------------


class TestAttachOperator:
    def test_admin_can_attach(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        tenant = _insert_tenant("Acme", "acme")
        target = _insert_operator(
            "alice@wg.local", role=OperatorRole.operator
        )

        resp = client.post(
            f"/tenants/{tenant.slug}/operators",
            json={"cn": target.cn, "role": "operator"},
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["tenant_slug"] == "acme"
        assert body["operator_cn"] == "alice@wg.local"
        assert body["role"] == "operator"

        with Session(db_module.engine) as session:
            join = session.exec(
                select(OperatorTenant).where(
                    OperatorTenant.operator_id == target.id,
                    OperatorTenant.tenant_id == tenant.id,
                )
            ).first()
        assert join is not None

    def test_attach_unknown_cn_returns_422(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        tenant = _insert_tenant("Acme", "acme")
        resp = client.post(
            f"/tenants/{tenant.slug}/operators",
            json={"cn": "ghost@wg.local", "role": "operator"},
        )
        assert resp.status_code == 422, resp.text
        assert "ghost@wg.local" in resp.text

    def test_attach_unknown_tenant_returns_404(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        _insert_operator("alice@wg.local")
        resp = client.post(
            "/tenants/no-such-tenant/operators",
            json={"cn": "alice@wg.local", "role": "operator"},
        )
        assert resp.status_code == 404, resp.text

    def test_attach_duplicate_returns_409(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        tenant = _insert_tenant("Acme", "acme")
        target = _insert_operator("alice@wg.local")
        client.post(
            f"/tenants/{tenant.slug}/operators",
            json={"cn": target.cn, "role": "operator"},
        )
        resp = client.post(
            f"/tenants/{tenant.slug}/operators",
            json={"cn": target.cn, "role": "admin"},
        )
        assert resp.status_code == 409, resp.text

    def test_attach_defaults_role_to_operator(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        tenant = _insert_tenant("Acme", "acme")
        target = _insert_operator("bob@wg.local")
        resp = client.post(
            f"/tenants/{tenant.slug}/operators",
            json={"cn": target.cn},
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["role"] == "operator"

    def test_auditor_cannot_attach(
        self, as_auditor: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_auditor
        tenant = _insert_tenant("Default", "default")
        _insert_operator("alice@wg.local")
        resp = client.post(
            f"/tenants/{tenant.slug}/operators",
            json={"cn": "alice@wg.local", "role": "operator"},
        )
        assert resp.status_code == 403, resp.text


# ---------------------------------------------------------------------------
# DELETE /tenants/{slug}/operators/{cn}
# ---------------------------------------------------------------------------


class TestDetachOperator:
    def test_admin_can_detach(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        tenant = _insert_tenant("Acme", "acme")
        target = _insert_operator("alice@wg.local")
        client.post(
            f"/tenants/{tenant.slug}/operators",
            json={"cn": target.cn, "role": "operator"},
        )

        resp = client.delete(
            f"/tenants/{tenant.slug}/operators/{target.cn}"
        )
        assert resp.status_code == 204, resp.text

        with Session(db_module.engine) as session:
            join = session.exec(
                select(OperatorTenant).where(
                    OperatorTenant.operator_id == target.id,
                    OperatorTenant.tenant_id == tenant.id,
                )
            ).first()
        assert join is None

    def test_detach_nonexistent_pair_returns_404(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        tenant = _insert_tenant("Acme", "acme")
        _insert_operator("alice@wg.local")
        resp = client.delete(
            f"/tenants/{tenant.slug}/operators/alice@wg.local"
        )
        assert resp.status_code == 404, resp.text

    def test_auditor_cannot_detach(
        self, as_auditor: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_auditor
        tenant = _insert_tenant("Default", "default")
        target = _insert_operator("alice@wg.local")
        # Seed a join the auditor will try (and fail) to remove.
        with Session(db_module.engine) as session:
            session.add(
                OperatorTenant(
                    operator_id=int(target.id or 0),
                    tenant_id=int(tenant.id or 0),
                    role=OperatorRole.operator,
                )
            )
            session.commit()
        resp = client.delete(
            f"/tenants/{tenant.slug}/operators/alice@wg.local"
        )
        assert resp.status_code == 403, resp.text


# ---------------------------------------------------------------------------
# GET /tenants/{slug}/operators
# ---------------------------------------------------------------------------


class TestListOperatorsForTenant:
    def test_list_includes_attached_operators(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        tenant = _insert_tenant("Acme", "acme")
        alice = _insert_operator("alice@wg.local", role=OperatorRole.admin)
        bob = _insert_operator("bob@wg.local", role=OperatorRole.operator)
        with Session(db_module.engine) as session:
            session.add(
                OperatorTenant(
                    operator_id=int(alice.id or 0),
                    tenant_id=int(tenant.id or 0),
                    role=OperatorRole.admin,
                )
            )
            session.add(
                OperatorTenant(
                    operator_id=int(bob.id or 0),
                    tenant_id=int(tenant.id or 0),
                    role=OperatorRole.auditor,
                )
            )
            session.commit()

        resp = client.get(f"/tenants/{tenant.slug}/operators")
        assert resp.status_code == 200, resp.text
        by_cn = {entry["operator_cn"]: entry for entry in resp.json()}
        assert by_cn["alice@wg.local"]["role"] == "admin"
        assert by_cn["bob@wg.local"]["role"] == "auditor"

    def test_unknown_tenant_returns_404(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        resp = client.get("/tenants/no-such-tenant/operators")
        assert resp.status_code == 404, resp.text

    def test_auditor_can_list(
        self, as_auditor: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_auditor
        tenant = _insert_tenant("Acme", "acme")
        resp = client.get(f"/tenants/{tenant.slug}/operators")
        assert resp.status_code == 200, resp.text
