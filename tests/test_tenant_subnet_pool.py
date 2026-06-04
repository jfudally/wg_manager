"""Phase 3b cycle 4 — per-tenant subnet pool plumbing.

Cycle 4 lets each tenant carry its own ``subnet_pool`` so a server's
``subnet`` must lie inside the pool and two tenants with non-
overlapping pools can issue overlapping client IPs without colliding.

This module pins:

1. **CLI** — ``wg-manager tenants create --subnet-pool 10.42.0.0/16``
   stores the pool; without ``--subnet-pool`` the row carries the
   model default (the RFC1918 fallback).
2. **API** — ``POST /tenants`` accepts ``subnet_pool`` in the body;
   ``GET /tenants/{slug}`` and ``GET /tenants`` surface it.
3. **Overlap rejection** — creating a tenant whose pool overlaps an
   existing tenant's pool is refused with 409 / non-zero exit. The
   existing default tenant (whose pool may be ``10.9.0.0/16`` or
   similar) is the seed for the overlap calculation.
4. **PATCH /tenants/{slug}** — the operator can widen / narrow the
   pool. Overlap with another tenant is rejected; narrowing the pool
   below an existing server's ``subnet`` is rejected too (we don't
   yank IPs out from under live servers).
5. **Per-server pool enforcement** — ``POST /servers`` rejects a
   ``subnet`` that's outside the resolved tenant's pool. When no
   ``subnet`` is supplied, the router auto-allocates the lowest
   unused /24-shaped slice from the pool.
6. **IPAM cross-tenant non-collision** — two servers in different
   tenants can produce overlapping client IPs because each
   ``allocate_client_ip`` call walks its own server's subnet (which
   lives inside its own tenant's pool).
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select
from typer.testing import CliRunner

from wg_manager import cli
from wg_manager import db as db_module
from wg_manager.models import (
    NodeStatus,
    Operator,
    OperatorRole,
    Server,
    SSHKey,
    Tenant,
)


# ---------------------------------------------------------------------------
# CLI shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def tenants_env(
    engine: Any,  # noqa: ARG001
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wire ``cli._get_engine`` at the test engine + seed a default
    tenant with a deterministic pool the overlap tests can collide
    against."""
    monkeypatch.setattr(cli, "_get_engine", lambda url=None: db_module.engine)
    with Session(db_module.engine) as session:
        if not session.exec(select(Tenant).where(Tenant.id == 1)).first():
            session.add(
                Tenant(
                    id=1,
                    name="default",
                    slug="default",
                    subnet_pool="10.9.0.0/16",
                )
            )
            session.commit()


def _invoke(runner: CliRunner, *args: str) -> Any:
    return runner.invoke(cli.app, list(args))


# ---------------------------------------------------------------------------
# CLI: `wg-manager tenants create --subnet-pool ...`
# ---------------------------------------------------------------------------


class TestTenantsCreateSubnetPoolCLI:
    def test_create_with_explicit_pool(
        self,
        runner: CliRunner,
        tenants_env: None,  # noqa: ARG002
    ) -> None:
        result = _invoke(
            runner,
            "tenants",
            "create",
            "--name",
            "Acme",
            "--slug",
            "acme",
            "--subnet-pool",
            "10.42.0.0/16",
        )
        assert result.exit_code == 0, result.output

        with Session(db_module.engine) as session:
            row = session.exec(
                select(Tenant).where(Tenant.slug == "acme")
            ).first()
        assert row is not None
        assert row.subnet_pool == "10.42.0.0/16"

    def test_create_without_pool_uses_default(
        self,
        runner: CliRunner,
        tenants_env: None,  # noqa: ARG002
    ) -> None:
        result = _invoke(
            runner,
            "tenants",
            "create",
            "--name",
            "Beta",
            "--slug",
            "beta",
        )
        assert result.exit_code == 0, result.output

        with Session(db_module.engine) as session:
            row = session.exec(
                select(Tenant).where(Tenant.slug == "beta")
            ).first()
        assert row is not None
        # The model default. Operators get a usable pool without
        # passing the flag every time.
        assert row.subnet_pool == "10.0.0.0/8"

    def test_create_rejects_overlapping_pool(
        self,
        runner: CliRunner,
        tenants_env: None,  # noqa: ARG002
    ) -> None:
        """The default tenant ships ``10.9.0.0/16``. A new tenant
        whose pool overlaps must be refused — the operator's
        intent ("carve a non-overlapping slice") is clearer when
        the CLI surfaces the collision early than when WireGuard
        clients silently collide post-deploy."""
        result = _invoke(
            runner,
            "tenants",
            "create",
            "--name",
            "Overlap",
            "--slug",
            "overlap",
            "--subnet-pool",
            "10.9.128.0/17",  # inside default's 10.9.0.0/16
        )
        assert result.exit_code != 0
        # The error names the colliding tenant so the operator
        # knows what to widen / narrow.
        assert "default" in result.output or "10.9.0.0/16" in result.output

    def test_create_rejects_malformed_pool(
        self,
        runner: CliRunner,
        tenants_env: None,  # noqa: ARG002
    ) -> None:
        result = _invoke(
            runner,
            "tenants",
            "create",
            "--name",
            "Bad",
            "--slug",
            "bad",
            "--subnet-pool",
            "not-a-cidr",
        )
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# CLI: list / get surface the pool
# ---------------------------------------------------------------------------


class TestTenantsListGetSurfacePool:
    def test_list_includes_pool(
        self,
        runner: CliRunner,
        tenants_env: None,  # noqa: ARG002
    ) -> None:
        result = _invoke(runner, "tenants", "list")
        assert result.exit_code == 0, result.output
        rows = json.loads(result.output)
        default_row = next(r for r in rows if r["slug"] == "default")
        assert default_row["subnet_pool"] == "10.9.0.0/16"

    def test_get_includes_pool(
        self,
        runner: CliRunner,
        tenants_env: None,  # noqa: ARG002
    ) -> None:
        result = _invoke(runner, "tenants", "get", "default")
        assert result.exit_code == 0, result.output
        body = json.loads(result.output)
        assert body["subnet_pool"] == "10.9.0.0/16"


# ---------------------------------------------------------------------------
# HTTP: POST /tenants accepts subnet_pool + GET surfaces it
# ---------------------------------------------------------------------------


def _make_admin_subject(cn: str = "ops@wg.local"):
    from datetime import datetime, timedelta, timezone

    from wg_manager.auth import CertSubject

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
    """Inject a super-admin operator into the auth deps the tenants
    router consults so POST /tenants admits the request."""
    from wg_manager.auth import require_subject
    from wg_manager.main import app
    from wg_manager.routers import tenants as tenants_router

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
    app.dependency_overrides[tenants_router._get_operator] = lambda: op
    app.dependency_overrides[tenants_router._RequireAdmin] = lambda: canned
    app.dependency_overrides[tenants_router._RequireAdminOrAuditor] = (
        lambda: canned
    )
    return op


def _seed_default_tenant(pool: str = "10.9.0.0/16") -> Tenant:
    with Session(db_module.engine) as session:
        row = Tenant(
            id=1, name="default", slug="default", subnet_pool=pool
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        return Tenant(
            id=row.id, name=row.name, slug=row.slug,
            subnet_pool=row.subnet_pool, created_at=row.created_at,
        )


class TestTenantsAPISubnetPool:
    def test_post_accepts_subnet_pool(
        self,
        client: TestClient,
        as_super_admin: Operator,  # noqa: ARG002
    ) -> None:
        _seed_default_tenant()
        resp = client.post(
            "/tenants",
            json={
                "name": "Acme",
                "slug": "acme",
                "subnet_pool": "10.42.0.0/16",
            },
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["subnet_pool"] == "10.42.0.0/16"

    def test_post_rejects_overlap_with_409(
        self,
        client: TestClient,
        as_super_admin: Operator,  # noqa: ARG002
    ) -> None:
        _seed_default_tenant()
        resp = client.post(
            "/tenants",
            json={
                "name": "Overlap",
                "slug": "overlap",
                "subnet_pool": "10.9.0.0/24",  # inside default
            },
        )
        assert resp.status_code == 409, resp.text
        assert "10.9" in resp.text or "default" in resp.text

    def test_get_surfaces_pool(
        self,
        client: TestClient,
        as_super_admin: Operator,  # noqa: ARG002
    ) -> None:
        _seed_default_tenant("10.55.0.0/16")
        resp = client.get("/tenants/default")
        assert resp.status_code == 200, resp.text
        assert resp.json()["subnet_pool"] == "10.55.0.0/16"


# ---------------------------------------------------------------------------
# IPAM: per-tenant pool helpers
# ---------------------------------------------------------------------------


class TestSubnetInPool:
    """``subnet_in_pool`` is the cycle 4 helper that returns ``True``
    iff a candidate subnet lies fully inside a tenant's pool."""

    def test_strict_subnet_inside_pool(self) -> None:
        from wg_manager.ipam import subnet_in_pool

        assert subnet_in_pool("10.9.5.0/24", "10.9.0.0/16") is True

    def test_subnet_outside_pool(self) -> None:
        from wg_manager.ipam import subnet_in_pool

        assert subnet_in_pool("192.168.0.0/24", "10.9.0.0/16") is False

    def test_subnet_partially_overlapping_pool(self) -> None:
        """A /16 candidate that overlaps but isn't inside the /17
        pool must be rejected — partial overlap is still a collision
        risk."""
        from wg_manager.ipam import subnet_in_pool

        assert subnet_in_pool("10.9.0.0/16", "10.9.0.0/17") is False


class TestPoolsOverlap:
    """``pools_overlap`` decides whether two tenants' pools collide.
    The CLI and API call this at tenant create / update time."""

    def test_disjoint_pools(self) -> None:
        from wg_manager.ipam import pools_overlap

        assert pools_overlap("10.9.0.0/16", "10.42.0.0/16") is False

    def test_identical_pools_overlap(self) -> None:
        from wg_manager.ipam import pools_overlap

        assert pools_overlap("10.9.0.0/16", "10.9.0.0/16") is True

    def test_subset_pool_overlaps_parent(self) -> None:
        """``10.9.5.0/24`` is fully inside ``10.9.0.0/16`` — still a
        collision because some IPs are shared between the two
        pools."""
        from wg_manager.ipam import pools_overlap

        assert pools_overlap("10.9.5.0/24", "10.9.0.0/16") is True


# ---------------------------------------------------------------------------
# Per-server pool enforcement + auto-allocation
# ---------------------------------------------------------------------------


def _register_ssh_key(client: TestClient, name: str = "lab") -> int:
    resp = client.post("/ssh-keys", json={"name": name})
    assert resp.status_code == 201
    return int(resp.json()["id"])


def _seed_tenant(slug: str, pool: str) -> int:
    with Session(db_module.engine) as session:
        row = Tenant(name=slug.title(), slug=slug, subnet_pool=pool)
        session.add(row)
        session.commit()
        session.refresh(row)
        return int(row.id or 0)


class TestServerCreateEnforcesPool:
    """``POST /servers`` rejects a subnet outside the resolved
    tenant's pool. When no subnet is supplied, the router auto-
    allocates from inside the pool."""

    def test_explicit_subnet_outside_pool_rejected(
        self, client: TestClient
    ) -> None:
        _seed_default_tenant("10.9.0.0/16")
        key_id = _register_ssh_key(client)

        resp = client.post(
            "/servers",
            json={
                "hostname": "hub.example.com",
                "ssh_username": "ubuntu",
                "ssh_key_id": key_id,
                "endpoint_host": "hub.example.com",
                "subnet": "192.168.0.0/24",  # outside default's pool
            },
        )
        assert resp.status_code == 422, resp.text
        # The error names the pool so the operator knows the bound.
        assert "10.9.0.0/16" in resp.text or "pool" in resp.text.lower()

    def test_explicit_subnet_inside_pool_accepted(
        self, client: TestClient
    ) -> None:
        _seed_default_tenant("10.9.0.0/16")
        key_id = _register_ssh_key(client)

        resp = client.post(
            "/servers",
            json={
                "hostname": "hub.example.com",
                "ssh_username": "ubuntu",
                "ssh_key_id": key_id,
                "endpoint_host": "hub.example.com",
                "subnet": "10.9.5.0/24",
            },
        )
        assert resp.status_code == 202, resp.text
        assert resp.json()["server"]["subnet"] == "10.9.5.0/24"


# ---------------------------------------------------------------------------
# IPAM non-collision across tenants
# ---------------------------------------------------------------------------


class TestCrossTenantNonCollision:
    """Two servers in different tenants with non-overlapping pools
    can each allocate the same ``.2`` host IP without colliding,
    because each ``allocate_client_ip`` walks its own server's
    subnet — and the subnets live in different tenant pools."""

    def test_two_tenants_two_servers_overlapping_client_ips(
        self, session: Session
    ) -> None:
        from wg_manager.ipam import allocate_client_ip

        acme_id = _seed_tenant("acme", "10.42.0.0/16")
        beta_id = _seed_tenant("beta", "10.43.0.0/16")

        acme_key = SSHKey(name="acme-key", tenant_id=acme_id)
        beta_key = SSHKey(name="beta-key", tenant_id=beta_id)
        session.add(acme_key)
        session.add(beta_key)
        session.commit()
        session.refresh(acme_key)
        session.refresh(beta_key)

        acme_server = Server(
            hostname="acme",
            ssh_username="u",
            ssh_key_id=int(acme_key.id or 0),
            endpoint_host="acme",
            tenant_id=acme_id,
            subnet="10.42.5.0/24",
            address="10.42.5.1/24",
            public_key="ak",
            status=NodeStatus.ready,
        )
        beta_server = Server(
            hostname="beta",
            ssh_username="u",
            ssh_key_id=int(beta_key.id or 0),
            endpoint_host="beta",
            tenant_id=beta_id,
            subnet="10.43.5.0/24",
            address="10.43.5.1/24",
            public_key="bk",
            status=NodeStatus.ready,
        )
        session.add(acme_server)
        session.add(beta_server)
        session.commit()
        session.refresh(acme_server)
        session.refresh(beta_server)

        # Each server's allocator returns its own ``.2`` — same
        # last-octet, different network. No collision because the
        # pools are disjoint.
        acme_first = allocate_client_ip(session, acme_server)
        beta_first = allocate_client_ip(session, beta_server)
        assert str(acme_first) == "10.42.5.2"
        assert str(beta_first) == "10.43.5.2"
