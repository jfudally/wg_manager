"""Phase 3b cycle 5 — explicit tenant_id on resource POSTs.

Cycle 3 added per-tenant scoping to list / mutation endpoints but
left resource creation inheriting the SSH key's tenant. Cycle 5
ships the explicit form: ``POST /servers``, ``POST /clients``,
``POST /ssh-keys`` accept an optional ``tenant_id`` in the body.

Resolution rules (matches the ROADMAP design lock):

* **Super-admin** (global ``Operator.role == admin``) — when the
  body omits ``tenant_id``, default to tenant id 1 (the back-filled
  default). Explicit ``tenant_id`` is honoured against any tenant.
* **Single-tenant operator** — when the body omits ``tenant_id``,
  auto-derive from the operator's single ``OperatorTenant`` row.
  Explicit ``tenant_id`` must match the operator's tenant.
* **Multi-tenant operator** — when the body omits ``tenant_id``,
  reject with 422 demanding an explicit choice. Explicit
  ``tenant_id`` must be in the operator's tenant set.
* **No-tenant operator** — when the operator has zero
  ``OperatorTenant`` rows, every resource POST is 403'd. The
  operator must be attached to a tenant before they can create.

In all paths the resolved tenant must permit the operator's
per-tenant role at the ``admin`` / ``operator`` tier (``auditor``
403s). Existing super-admin bypass remains.

The tests target ``/ssh-keys`` first because it's the smallest
surface (no IPAM, no SSH key FK), then re-use the same resolution
helper across ``/servers`` and ``/clients``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from wg_manager import db as db_module
from wg_manager.auth import CertSubject
from wg_manager.main import app
from wg_manager.models import (
    Operator,
    OperatorRole,
    OperatorStatus,
    OperatorTenant,
    SSHKey,
    Tenant,
)
from wg_manager.tenant_scope import TenantScope, get_tenant_scope


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _insert_tenant(slug: str, pool: str = "10.0.0.0/8") -> Tenant:
    """Upsert a tenant by slug — the conftest seeds the default tenant
    at id=1, so an explicit ``_insert_tenant('default')`` here returns
    that pre-existing row rather than colliding on the unique slug."""
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
        row = Tenant(name=slug.title(), slug=slug, subnet_pool=pool)
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


def _override_scope(scope: TenantScope) -> None:
    """Pin the calling operator's scope for the next request."""
    app.dependency_overrides[get_tenant_scope] = lambda: scope


# ---------------------------------------------------------------------------
# /ssh-keys — smallest surface for the resolution contract
# ---------------------------------------------------------------------------


class TestSSHKeysCreateTenantResolution:
    """``POST /ssh-keys`` accepts an optional ``tenant_id``.

    Resolution rules are pinned here once and re-applied uniformly to
    ``/servers`` and ``/clients`` in the next class.
    """

    def test_super_admin_omitting_defaults_to_tenant_1(
        self, client: TestClient
    ) -> None:
        """Super-admin without an explicit ``tenant_id`` — row lands
        in the default tenant."""
        _insert_tenant("default")
        _override_scope(TenantScope(is_super_admin=True))

        resp = client.post("/ssh-keys", json={"name": "global-key"})

        assert resp.status_code == 201, resp.text
        assert resp.json()["tenant_id"] == 1

    def test_super_admin_explicit_honoured(
        self, client: TestClient
    ) -> None:
        """Super-admin can target any tenant."""
        _insert_tenant("default")
        acme = _insert_tenant("acme")
        _override_scope(TenantScope(is_super_admin=True))

        resp = client.post(
            "/ssh-keys",
            json={"name": "acme-key", "tenant_id": acme.id},
        )

        assert resp.status_code == 201, resp.text
        assert resp.json()["tenant_id"] == acme.id

    def test_single_tenant_operator_omitting_auto_derives(
        self, client: TestClient
    ) -> None:
        """Single-tenant operator without ``tenant_id`` — row lands
        in their tenant."""
        acme = _insert_tenant("acme")
        _override_scope(
            TenantScope(
                is_super_admin=False,
                tenant_ids=(int(acme.id or 0),),
                tenant_roles={int(acme.id or 0): OperatorRole.operator},
            )
        )

        resp = client.post("/ssh-keys", json={"name": "acme-key"})

        assert resp.status_code == 201, resp.text
        assert resp.json()["tenant_id"] == acme.id

    def test_single_tenant_operator_explicit_must_match(
        self, client: TestClient
    ) -> None:
        """Single-tenant operator with explicit ``tenant_id`` for
        another tenant — 403 (out of scope)."""
        acme = _insert_tenant("acme")
        beta = _insert_tenant("beta")
        _override_scope(
            TenantScope(
                is_super_admin=False,
                tenant_ids=(int(acme.id or 0),),
                tenant_roles={int(acme.id or 0): OperatorRole.operator},
            )
        )

        resp = client.post(
            "/ssh-keys",
            json={"name": "out-of-scope", "tenant_id": beta.id},
        )

        assert resp.status_code == 403, resp.text

    def test_multi_tenant_operator_omitting_returns_422(
        self, client: TestClient
    ) -> None:
        """Multi-tenant operator without ``tenant_id`` — 422
        demanding an explicit choice. The body names every tenant
        the operator could pick from so the dashboard can render the
        select widget straight from the error."""
        acme = _insert_tenant("acme")
        beta = _insert_tenant("beta")
        _override_scope(
            TenantScope(
                is_super_admin=False,
                tenant_ids=(int(acme.id or 0), int(beta.id or 0)),
                tenant_roles={
                    int(acme.id or 0): OperatorRole.operator,
                    int(beta.id or 0): OperatorRole.admin,
                },
            )
        )

        resp = client.post("/ssh-keys", json={"name": "ambiguous"})

        assert resp.status_code == 422, resp.text
        detail = resp.json().get("detail", "")
        assert "tenant_id" in detail.lower() or "tenant" in detail.lower()

    def test_multi_tenant_operator_explicit_in_scope_succeeds(
        self, client: TestClient
    ) -> None:
        acme = _insert_tenant("acme")
        beta = _insert_tenant("beta")
        _override_scope(
            TenantScope(
                is_super_admin=False,
                tenant_ids=(int(acme.id or 0), int(beta.id or 0)),
                tenant_roles={
                    int(acme.id or 0): OperatorRole.operator,
                    int(beta.id or 0): OperatorRole.admin,
                },
            )
        )

        resp = client.post(
            "/ssh-keys",
            json={"name": "explicit", "tenant_id": acme.id},
        )

        assert resp.status_code == 201, resp.text
        assert resp.json()["tenant_id"] == acme.id

    def test_no_tenant_operator_403s(self, client: TestClient) -> None:
        """An operator without any join row cannot create anything —
        explicit guard so a fresh registry never silently lands rows
        in the default tenant under a non-super-admin."""
        _insert_tenant("default")
        _override_scope(
            TenantScope(is_super_admin=False, tenant_ids=())
        )

        resp = client.post("/ssh-keys", json={"name": "orphan"})

        assert resp.status_code == 403, resp.text

    def test_auditor_role_blocks_create(self, client: TestClient) -> None:
        """Per-tenant auditor role admits reads but not creates."""
        acme = _insert_tenant("acme")
        _override_scope(
            TenantScope(
                is_super_admin=False,
                tenant_ids=(int(acme.id or 0),),
                tenant_roles={int(acme.id or 0): OperatorRole.auditor},
            )
        )

        resp = client.post(
            "/ssh-keys",
            json={"name": "blocked", "tenant_id": acme.id},
        )

        assert resp.status_code == 403, resp.text

    def test_unknown_tenant_id_returns_404(
        self, client: TestClient
    ) -> None:
        """Explicit ``tenant_id`` that points at no row — 404 names
        the missing id."""
        _override_scope(TenantScope(is_super_admin=True))

        resp = client.post(
            "/ssh-keys",
            json={"name": "x", "tenant_id": 9999},
        )

        assert resp.status_code == 404, resp.text
        assert "9999" in resp.text or "tenant" in resp.text.lower()


# ---------------------------------------------------------------------------
# /servers — same resolver, IPAM pool also checked against resolved tenant
# ---------------------------------------------------------------------------


class TestServersCreateTenantResolution:
    """The cycle 5 resolver applies to ``/servers`` too; the
    additional cycle 4 invariant (subnet inside the tenant's pool)
    is checked against the *resolved* tenant — not the SSH key's."""

    def _ssh_key(self, name: str) -> int:
        """Register an SSH key in the default tenant (super-admin
        path so the cycle 5 resolver doesn't intercept)."""
        from wg_manager.models import SSHKey

        with Session(db_module.engine) as session:
            row = SSHKey(name=name, tenant_id=1)
            session.add(row)
            session.commit()
            session.refresh(row)
            return int(row.id or 0)

    def test_explicit_tenant_id_routes_subnet_check(
        self, client: TestClient
    ) -> None:
        """Server explicit ``tenant_id`` honoured + subnet checked
        against THAT tenant's pool (not the SSH key's tenant's)."""
        acme = _insert_tenant("acme", "10.42.0.0/16")
        _insert_tenant("default")
        _override_scope(TenantScope(is_super_admin=True))

        key_id = self._ssh_key("ssh-key-1")
        resp = client.post(
            "/servers",
            json={
                "hostname": "acme-hub",
                "ssh_username": "ubuntu",
                "ssh_key_id": key_id,
                "endpoint_host": "acme-hub",
                "subnet": "10.42.5.0/24",
                "tenant_id": acme.id,
            },
        )

        assert resp.status_code == 202, resp.text
        body = resp.json()["server"]
        assert body["tenant_id"] == acme.id
        assert body["subnet"] == "10.42.5.0/24"

    def test_explicit_tenant_subnet_outside_pool_rejected(
        self, client: TestClient
    ) -> None:
        acme = _insert_tenant("acme", "10.42.0.0/16")
        _insert_tenant("default")
        _override_scope(TenantScope(is_super_admin=True))

        key_id = self._ssh_key("ssh-key-2")
        resp = client.post(
            "/servers",
            json={
                "hostname": "h",
                "ssh_username": "u",
                "ssh_key_id": key_id,
                "endpoint_host": "h",
                "subnet": "192.168.0.0/24",
                "tenant_id": acme.id,
            },
        )

        assert resp.status_code == 422, resp.text
        # Names the acme pool, not the SSH key's tenant's pool.
        assert "10.42.0.0/16" in resp.text or "pool" in resp.text.lower()

    def test_single_tenant_operator_inherits_tenant(
        self, client: TestClient
    ) -> None:
        """Server POST without tenant_id auto-derives from the
        operator's single tenant."""
        acme = _insert_tenant("acme", "10.42.0.0/16")
        _override_scope(
            TenantScope(
                is_super_admin=False,
                tenant_ids=(int(acme.id or 0),),
                tenant_roles={int(acme.id or 0): OperatorRole.operator},
            )
        )

        key_id = self._ssh_key("ssh-key-3")
        resp = client.post(
            "/servers",
            json={
                "hostname": "h",
                "ssh_username": "u",
                "ssh_key_id": key_id,
                "endpoint_host": "h",
                "subnet": "10.42.7.0/24",
            },
        )

        assert resp.status_code == 202, resp.text
        assert resp.json()["server"]["tenant_id"] == acme.id
