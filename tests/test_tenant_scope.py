"""Phase 3b cycle 3 — tenant scope helper + per-resource list/mutation
enforcement tests.

Cycle 1 (Alembic 0014) added the nullable ``tenant_id`` columns;
cycle 2 (Alembic 0015) added the :class:`OperatorTenant` join. Cycle
3 is where the join finally **enforces** anything: the middleware
resolves the operator's tenant set onto ``request.state``, list
endpoints narrow to that set, and mutating endpoints check per-
tenant role on the resource's tenant.

Design decisions pinned here (from the ROADMAP):

* Global ``Operator.role = admin`` is **super-admin** — bypasses
  per-tenant filtering entirely.
* Non-super-admin operators see only the rows whose
  ``tenant_id`` is in their ``OperatorTenant`` join set.
* Mutating endpoints require per-tenant role ``admin`` or
  ``operator`` on the target row's tenant. ``auditor`` is read-only.
* Resource ``POST`` accepts optional ``tenant_id`` in the body; the
  router resolves it from the operator's context when omitted (the
  one-tenant case) and 422s when ambiguous (the multi-tenant case
  without an explicit choice).

Tests target the shared :mod:`wg_manager.tenant_scope` helper +
the ``/servers`` router as the canonical surface; cycle 3's other
resources (``/clients``, ``/ssh-keys``, ``/certs``, ``/audit``)
re-use the same helper and pick up the same behaviour.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from wg_manager import db as db_module
from wg_manager.auth import CertSubject
from wg_manager.main import app
from wg_manager.models import (
    Operator,
    OperatorRole,
    OperatorStatus,
    OperatorTenant,
    Server,
    SSHKey,
    Tenant,
)
from wg_manager.tenant_scope import (
    TenantScope,
    get_tenant_scope,
    require_tenant_role,
    scope_filter,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _insert_operator(
    cn: str,
    role: OperatorRole = OperatorRole.operator,
    status: OperatorStatus = OperatorStatus.active,
) -> Operator:
    with Session(db_module.engine) as session:
        row = Operator(cn=cn, role=role, status=status)
        session.add(row)
        session.commit()
        session.refresh(row)
        return Operator(
            id=row.id, cn=row.cn, role=row.role, status=row.status,
            display_name=row.display_name, created_at=row.created_at,
        )


def _insert_tenant(name: str, slug: str) -> Tenant:
    with Session(db_module.engine) as session:
        row = Tenant(name=name, slug=slug)
        session.add(row)
        session.commit()
        session.refresh(row)
        return Tenant(
            id=row.id, name=row.name, slug=row.slug,
            created_at=row.created_at,
        )


def _attach(operator: Operator, tenant: Tenant, role: OperatorRole) -> None:
    with Session(db_module.engine) as session:
        session.add(
            OperatorTenant(
                operator_id=int(operator.id or 0),
                tenant_id=int(tenant.id or 0),
                role=role,
            )
        )
        session.commit()


def _insert_ssh_key(name: str, tenant_id: int) -> int:
    with Session(db_module.engine) as session:
        row = SSHKey(name=name, tenant_id=tenant_id)
        session.add(row)
        session.commit()
        session.refresh(row)
        return int(row.id or 0)


def _insert_server(hostname: str, tenant_id: int, ssh_key_id: int) -> int:
    """Insert a Server row pre-bound to ``tenant_id``.

    Bypasses the provisioning task so the test pins the list /
    gating behaviour without going through the SSH path.
    """
    with Session(db_module.engine) as session:
        row = Server(
            hostname=hostname,
            ssh_port=22,
            ssh_username="ubuntu",
            ssh_key_id=ssh_key_id,
            endpoint_host=hostname,
            endpoint_port=51820,
            interface="wg0",
            subnet=f"10.{tenant_id}.0.0/24",
            address=f"10.{tenant_id}.0.1/24",
            public_key=f"PUBKEY::{hostname}",
            tenant_id=tenant_id,
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        return int(row.id or 0)


def _override_scope(scope: TenantScope) -> None:
    """Pin the calling operator's tenant scope for the next request."""
    app.dependency_overrides[get_tenant_scope] = lambda: scope


# ---------------------------------------------------------------------------
# TenantScope value object
# ---------------------------------------------------------------------------


class TestTenantScopeValueObject:
    """The frozen scope captures super-admin + tenant_ids + per-tenant
    roles. ``unscoped`` is the dev / no-auth fallback equivalent to
    super-admin."""

    def test_unscoped_is_super_admin(self) -> None:
        scope = TenantScope.unscoped()
        assert scope.is_super_admin is True
        assert scope.tenant_ids == ()
        assert scope.tenant_roles == {}

    def test_role_in_returns_role_for_attached_tenant(self) -> None:
        scope = TenantScope(
            is_super_admin=False,
            tenant_ids=(7,),
            tenant_roles={7: OperatorRole.admin},
        )
        assert scope.role_in(7) == OperatorRole.admin

    def test_role_in_returns_none_for_unattached_tenant(self) -> None:
        scope = TenantScope(
            is_super_admin=False,
            tenant_ids=(7,),
            tenant_roles={7: OperatorRole.admin},
        )
        assert scope.role_in(99) is None


# ---------------------------------------------------------------------------
# scope_filter helper
# ---------------------------------------------------------------------------


class TestScopeFilter:
    """``scope_filter`` returns either ``None`` (no filter) or a
    SQLAlchemy where-expression that narrows by ``tenant_id``."""

    def test_super_admin_returns_none(self) -> None:
        scope = TenantScope(is_super_admin=True)
        assert scope_filter(scope, Server) is None

    def test_non_super_admin_returns_in_expression(self) -> None:
        scope = TenantScope(
            is_super_admin=False, tenant_ids=(1, 2)
        )
        expr = scope_filter(scope, Server)
        assert expr is not None
        # Compile the expression to SQL text so we can pin the shape
        # rendered into the WHERE clause regardless of dialect.
        compiled = str(expr)
        assert "tenant_id" in compiled


# ---------------------------------------------------------------------------
# require_tenant_role helper
# ---------------------------------------------------------------------------


class TestRequireTenantRole:
    """``require_tenant_role`` 403s unless the scope permits the role
    on ``tenant_id``. Super-admin bypasses every check."""

    def test_super_admin_passes(self) -> None:
        scope = TenantScope(is_super_admin=True)
        # Should not raise.
        require_tenant_role(scope, 1, OperatorRole.admin)

    def test_unattached_operator_403s(self) -> None:
        from fastapi import HTTPException

        scope = TenantScope(
            is_super_admin=False, tenant_ids=(1,),
            tenant_roles={1: OperatorRole.admin},
        )
        with pytest.raises(HTTPException) as exc:
            require_tenant_role(scope, 2, OperatorRole.admin)
        assert exc.value.status_code == 403

    def test_wrong_role_403s(self) -> None:
        from fastapi import HTTPException

        scope = TenantScope(
            is_super_admin=False, tenant_ids=(1,),
            tenant_roles={1: OperatorRole.auditor},
        )
        with pytest.raises(HTTPException) as exc:
            require_tenant_role(
                scope, 1, OperatorRole.admin, OperatorRole.operator
            )
        assert exc.value.status_code == 403

    def test_matching_role_passes(self) -> None:
        scope = TenantScope(
            is_super_admin=False, tenant_ids=(1,),
            tenant_roles={1: OperatorRole.operator},
        )
        # Should not raise.
        require_tenant_role(
            scope, 1, OperatorRole.admin, OperatorRole.operator
        )

    def test_empty_allowed_raises_value_error(self) -> None:
        scope = TenantScope(is_super_admin=True)
        with pytest.raises(ValueError):
            require_tenant_role(scope, 1)

    def test_none_tenant_id_super_admin_passes(self) -> None:
        scope = TenantScope(is_super_admin=True)
        # Super-admin can act on global-scope endpoints.
        require_tenant_role(scope, None, OperatorRole.admin)

    def test_none_tenant_id_non_super_admin_403s(self) -> None:
        from fastapi import HTTPException

        scope = TenantScope(
            is_super_admin=False, tenant_ids=(1,),
            tenant_roles={1: OperatorRole.admin},
        )
        with pytest.raises(HTTPException) as exc:
            require_tenant_role(scope, None, OperatorRole.admin)
        assert exc.value.status_code == 403


# ---------------------------------------------------------------------------
# /servers list — scoped to operator's tenants
# ---------------------------------------------------------------------------


class TestServersListScoping:
    """``GET /servers`` returns only the rows the calling operator
    has visibility into. Super-admin (or no-auth dev mode) sees
    everything; tenant-scoped operator sees only their tenants'
    rows."""

    def _seed_two_tenants_two_servers(self) -> tuple[Tenant, Tenant, int, int]:
        """Insert two tenants + one server in each.

        Returns ``(acme, beta, acme_server_id, beta_server_id)``.
        """
        acme = _insert_tenant("Acme", "acme")
        beta = _insert_tenant("Beta", "beta")
        # SSH key rows must exist for the FK on Server. Cycle 3
        # treats the SSH key's tenant as independent of the server's
        # — they could differ — so pin acme-keys and beta-keys
        # explicitly here.
        acme_key = _insert_ssh_key("acme-key", int(acme.id or 0))
        beta_key = _insert_ssh_key("beta-key", int(beta.id or 0))
        acme_server = _insert_server(
            "acme-hub", int(acme.id or 0), acme_key
        )
        beta_server = _insert_server(
            "beta-hub", int(beta.id or 0), beta_key
        )
        return acme, beta, acme_server, beta_server

    def test_super_admin_sees_every_server(
        self, client: TestClient
    ) -> None:
        _, _, acme_id, beta_id = self._seed_two_tenants_two_servers()
        _override_scope(
            TenantScope(is_super_admin=True)
        )

        resp = client.get("/servers")

        assert resp.status_code == 200, resp.text
        ids = {entry["id"] for entry in resp.json()}
        assert ids >= {acme_id, beta_id}

    def test_tenant_scoped_operator_sees_only_their_tenants_servers(
        self, client: TestClient
    ) -> None:
        acme, _, acme_id, beta_id = self._seed_two_tenants_two_servers()
        _override_scope(
            TenantScope(
                is_super_admin=False,
                tenant_ids=(int(acme.id or 0),),
                tenant_roles={int(acme.id or 0): OperatorRole.operator},
            )
        )

        resp = client.get("/servers")

        assert resp.status_code == 200, resp.text
        ids = {entry["id"] for entry in resp.json()}
        assert acme_id in ids
        assert beta_id not in ids

    def test_operator_with_no_joins_sees_empty_list(
        self, client: TestClient
    ) -> None:
        """A non-super-admin operator with zero
        :class:`OperatorTenant` rows sees no servers — not a 403."""
        self._seed_two_tenants_two_servers()
        _override_scope(
            TenantScope(is_super_admin=False, tenant_ids=())
        )

        resp = client.get("/servers")

        assert resp.status_code == 200, resp.text
        assert resp.json() == []

    def test_no_auth_dev_mode_sees_all(self, client: TestClient) -> None:
        """When the middleware is in passthrough mode (the conftest
        default of ``TLS_REQUIRED=false``) and no operator is on the
        request, the scope falls back to ``unscoped`` (super-admin
        equivalent) and the existing test pattern continues to work
        without any per-test setup."""
        _, _, acme_id, beta_id = self._seed_two_tenants_two_servers()
        # NOTE: do not call _override_scope here — relying on the
        # production fallback path.

        resp = client.get("/servers")

        assert resp.status_code == 200, resp.text
        ids = {entry["id"] for entry in resp.json()}
        assert ids >= {acme_id, beta_id}


# ---------------------------------------------------------------------------
# /servers GET-by-id — scoped lookup
# ---------------------------------------------------------------------------


class TestServerGetByIdScoping:
    """``GET /servers/{id}`` returns 404 to a non-super-admin operator
    who cannot see the row, rather than leaking its existence with a
    403."""

    def test_get_by_id_404s_for_out_of_scope_server(
        self, client: TestClient
    ) -> None:
        acme = _insert_tenant("Acme", "acme")
        beta = _insert_tenant("Beta", "beta")
        beta_key = _insert_ssh_key("beta-key", int(beta.id or 0))
        beta_server_id = _insert_server(
            "beta-hub", int(beta.id or 0), beta_key
        )
        _override_scope(
            TenantScope(
                is_super_admin=False,
                tenant_ids=(int(acme.id or 0),),
                tenant_roles={int(acme.id or 0): OperatorRole.admin},
            )
        )

        resp = client.get(f"/servers/{beta_server_id}")

        assert resp.status_code == 404, resp.text

    def test_get_by_id_returns_in_scope_server(
        self, client: TestClient
    ) -> None:
        acme = _insert_tenant("Acme", "acme")
        acme_key = _insert_ssh_key("acme-key", int(acme.id or 0))
        acme_server_id = _insert_server(
            "acme-hub", int(acme.id or 0), acme_key
        )
        _override_scope(
            TenantScope(
                is_super_admin=False,
                tenant_ids=(int(acme.id or 0),),
                tenant_roles={int(acme.id or 0): OperatorRole.operator},
            )
        )

        resp = client.get(f"/servers/{acme_server_id}")

        assert resp.status_code == 200, resp.text


# ---------------------------------------------------------------------------
# /servers mutation — per-tenant role gate
# ---------------------------------------------------------------------------


class TestServerMutationGate:
    """``PATCH`` / ``DELETE`` on ``/servers/{id}`` enforce the
    per-tenant role of the calling operator on the row's tenant.
    ``admin`` and ``operator`` admit; ``auditor`` 403s; an operator
    not attached to the tenant 404s (same shape as the read-side to
    avoid leaking existence)."""

    def _seed(self) -> tuple[int, int]:
        """Insert an Acme tenant + a server in it. Return
        ``(tenant_id, server_id)``."""
        acme = _insert_tenant("Acme", "acme")
        key = _insert_ssh_key("acme-key", int(acme.id or 0))
        server_id = _insert_server("hub", int(acme.id or 0), key)
        return int(acme.id or 0), server_id

    def test_admin_role_can_patch(self, client: TestClient) -> None:
        tenant_id, server_id = self._seed()
        _override_scope(
            TenantScope(
                is_super_admin=False,
                tenant_ids=(tenant_id,),
                tenant_roles={tenant_id: OperatorRole.admin},
            )
        )

        resp = client.patch(
            f"/servers/{server_id}",
            json={"endpoint_port": 51900},
        )

        assert resp.status_code == 200, resp.text

    def test_operator_role_can_patch(self, client: TestClient) -> None:
        tenant_id, server_id = self._seed()
        _override_scope(
            TenantScope(
                is_super_admin=False,
                tenant_ids=(tenant_id,),
                tenant_roles={tenant_id: OperatorRole.operator},
            )
        )

        resp = client.patch(
            f"/servers/{server_id}",
            json={"endpoint_port": 51901},
        )

        assert resp.status_code == 200, resp.text

    def test_auditor_role_cannot_patch(self, client: TestClient) -> None:
        tenant_id, server_id = self._seed()
        _override_scope(
            TenantScope(
                is_super_admin=False,
                tenant_ids=(tenant_id,),
                tenant_roles={tenant_id: OperatorRole.auditor},
            )
        )

        resp = client.patch(
            f"/servers/{server_id}",
            json={"endpoint_port": 51902},
        )

        assert resp.status_code == 403, resp.text

    def test_operator_outside_tenant_404s(
        self, client: TestClient
    ) -> None:
        tenant_id, server_id = self._seed()
        # Scope to a *different* tenant id than the row's.
        _override_scope(
            TenantScope(
                is_super_admin=False,
                tenant_ids=(tenant_id + 99,),
                tenant_roles={
                    tenant_id + 99: OperatorRole.admin,
                },
            )
        )

        resp = client.patch(
            f"/servers/{server_id}",
            json={"endpoint_port": 51903},
        )

        # 404 (not 403) so the existence of the row in another
        # tenant isn't leaked to a probing operator.
        assert resp.status_code == 404, resp.text

    def test_super_admin_can_delete(self, client: TestClient) -> None:
        tenant_id, server_id = self._seed()
        _override_scope(TenantScope(is_super_admin=True))

        resp = client.delete(f"/servers/{server_id}")

        assert resp.status_code == 204, resp.text


# ---------------------------------------------------------------------------
# Audit event tenant_id population
# ---------------------------------------------------------------------------


class TestAuditEventTenantId:
    """Cycle 1 (Alembic 0014) added the nullable ``tenant_id`` column
    on ``auditevent``. Cycle 3 finally populates it from the affected
    resource's tenant so an auditor reviewing the trail can filter
    per tenant.

    A super-admin acting on a single tenant's resource still produces
    a row tagged with that tenant — the column reflects the affected
    resource, not the actor's scope.
    """

    def test_server_update_records_tenant_id(
        self, client: TestClient
    ) -> None:
        from wg_manager.models import AuditEvent

        acme = _insert_tenant("Acme", "acme")
        key = _insert_ssh_key("acme-key", int(acme.id or 0))
        server_id = _insert_server("hub", int(acme.id or 0), key)

        # Super-admin acts on the row; auditevent should still tag
        # the Acme tenant.
        _override_scope(TenantScope(is_super_admin=True))
        resp = client.patch(
            f"/servers/{server_id}",
            json={"endpoint_port": 51800},
        )
        assert resp.status_code == 200, resp.text

        with Session(db_module.engine) as session:
            from sqlmodel import select

            row = session.exec(
                select(AuditEvent)
                .where(AuditEvent.event == "server.update")
                .where(AuditEvent.resource_id == server_id)
            ).first()
        assert row is not None
        assert row.tenant_id == int(acme.id or 0)

    def test_ssh_key_create_records_tenant_id(
        self, client: TestClient
    ) -> None:
        """``POST /ssh-keys`` records the row's resolved tenant on the
        emitted audit event. Cycle 3 leaves the resolution itself
        deferred to cycle 5; for cycle 3 the audit pulls
        ``tenant_id`` from the inserted row after the insert flushes.
        """
        from wg_manager.models import AuditEvent

        _override_scope(TenantScope(is_super_admin=True))
        resp = client.post("/ssh-keys", json={"name": "tagged"})
        assert resp.status_code == 201, resp.text
        key_id = resp.json()["id"]

        with Session(db_module.engine) as session:
            from sqlmodel import select

            audit_row = session.exec(
                select(AuditEvent)
                .where(AuditEvent.event == "ssh_key.create")
                .where(AuditEvent.resource_id == key_id)
            ).first()
            from wg_manager.models import SSHKey

            ssh_row = session.exec(
                select(SSHKey).where(SSHKey.id == key_id)
            ).first()
        assert audit_row is not None
        assert ssh_row is not None
        # The tenant_id on the audit event mirrors the row's tenant
        # (currently None on the SSH key because cycle 3 doesn't yet
        # demand explicit tenant_id on create; cycle 5 will). The
        # invariant pinned here: audit.tenant_id == row.tenant_id.
        assert audit_row.tenant_id == ssh_row.tenant_id
