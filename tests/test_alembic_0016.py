"""Tests for Phase 3b cycle 4: Alembic 0016 — add ``Tenant.subnet_pool``.

Cycle 3 layered scope filtering + per-tenant role gates on top of the
cycles 1-2 schema groundwork. Cycle 4 partitions IP space per tenant
so subnets cannot collide across tenant boundaries: each tenant
carries its own ``subnet_pool`` CIDR; server rows must allocate their
subnet from inside the pool; two tenants with non-overlapping pools
can issue overlapping client IPs without colliding because each peer
lives in its own tenant's slice.

This migration:

1. Adds a ``subnet_pool`` ``VARCHAR(64)`` column to ``tenant``.
2. Back-fills the column for every existing tenant row.
   * The reserved ``id=1`` (the ``default`` tenant from Alembic 0014)
     gets the configured ``Settings.default_subnet`` so a v0.1.0
     operator's existing servers keep working without changing
     their subnet.
   * Any other tenant rows added between cycles 2 and 4 get
     ``10.0.0.0/8`` as a safe fallback the operator can tighten via
     ``PATCH /tenants/{slug}``. We pick the largest RFC1918 block
     so the operator never sees an "out of IPs" failure on an
     unconfigured tenant; the dashboard surfaces the value so the
     operator can tighten it.
3. Tightens the column to NOT NULL once the back-fill completes —
   every tenant has a pool by construction.

Cycle 4's acceptance bar: an operator running ``alembic upgrade
head`` against a Phase-3b-cycle-3 deployment must come up cleanly,
with every existing tenant carrying a non-empty pool string.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text


def _alembic_config(database_url: str):
    from alembic.config import Config

    cfg = Config(str(Path(__file__).resolve().parent.parent / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", database_url)
    return cfg


@pytest.fixture()
def file_db_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> str:
    from wg_manager.config import settings as live_settings

    path = tmp_path / "wg_manager_cycle4_pool.sqlite"
    url = f"sqlite:///{path}"
    monkeypatch.setattr(live_settings, "database_url", url)
    return url


def _columns(database_url: str, table: str) -> dict[str, dict]:
    engine = create_engine(database_url)
    try:
        return {col["name"]: col for col in inspect(engine).get_columns(table)}
    finally:
        engine.dispose()


_REVISION_BEFORE = "0015_add_operator_tenant"
_REVISION_AT = "0016_add_tenant_subnet_pool"


# ---------------------------------------------------------------------------
# Column shape
# ---------------------------------------------------------------------------


class TestSubnetPoolColumnAdded:
    def test_column_exists(self, file_db_url: str) -> None:
        from alembic.command import upgrade

        upgrade(_alembic_config(file_db_url), "head")
        cols = _columns(file_db_url, "tenant")
        assert "subnet_pool" in cols

    def test_column_is_not_nullable(self, file_db_url: str) -> None:
        """After back-fill every row has a non-null pool, so the
        column tightens to NOT NULL. Cycle 5 may further validate
        the pool shape; cycle 4 keeps the column type minimal."""
        from alembic.command import upgrade

        upgrade(_alembic_config(file_db_url), "head")
        cols = _columns(file_db_url, "tenant")
        assert cols["subnet_pool"]["nullable"] is False


# ---------------------------------------------------------------------------
# Back-fill from prior-revision data
# ---------------------------------------------------------------------------


class TestBackfillFromPriorRevision:
    """Seed the schema at revision 0015, then upgrade. Every existing
    tenant must end up with a non-empty ``subnet_pool``."""

    def test_default_tenant_gets_settings_default_subnet(
        self, file_db_url: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The reserved ``id=1`` row carries the operator's existing
        ``Settings.default_subnet``; a v0.1.0 deployment keeps every
        existing server's subnet inside the tenant's pool without
        any operator action."""
        from wg_manager.config import settings as live_settings

        # Pin a recognisable default so the assertion can be exact.
        monkeypatch.setattr(live_settings, "default_subnet", "10.9.0.0/16")

        from alembic.command import upgrade

        upgrade(_alembic_config(file_db_url), "head")

        engine = create_engine(file_db_url)
        try:
            with engine.connect() as conn:
                row = conn.execute(
                    text(
                        "SELECT subnet_pool FROM tenant WHERE id = 1"
                    )
                ).first()
        finally:
            engine.dispose()
        assert row is not None
        assert row[0] == "10.9.0.0/16"

    def test_extra_tenants_get_fallback_pool(
        self, file_db_url: str
    ) -> None:
        """Tenants created between cycles 2 and 4 get the RFC1918
        ``10.0.0.0/8`` fallback so the operator never sees a "no
        IPs" failure on an unconfigured tenant. The dashboard
        surfaces the value so the operator can tighten via PATCH."""
        from alembic.command import upgrade

        upgrade(_alembic_config(file_db_url), _REVISION_BEFORE)

        now = datetime.now(timezone.utc).isoformat()
        engine = create_engine(file_db_url)
        try:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO tenant (name, slug, created_at) "
                        "VALUES ('Acme', 'acme', :ts)"
                    ),
                    {"ts": now},
                )
        finally:
            engine.dispose()

        upgrade(_alembic_config(file_db_url), "head")

        engine = create_engine(file_db_url)
        try:
            with engine.connect() as conn:
                row = conn.execute(
                    text(
                        "SELECT subnet_pool FROM tenant WHERE slug = 'acme'"
                    )
                ).first()
        finally:
            engine.dispose()
        assert row is not None
        assert row[0] == "10.0.0.0/8"


# ---------------------------------------------------------------------------
# Downgrade round-trip
# ---------------------------------------------------------------------------


class TestDowngradeRoundTrip:
    def test_downgrade_drops_column(self, file_db_url: str) -> None:
        from alembic.command import downgrade, upgrade

        upgrade(_alembic_config(file_db_url), _REVISION_AT)
        cols = _columns(file_db_url, "tenant")
        assert "subnet_pool" in cols

        downgrade(_alembic_config(file_db_url), _REVISION_BEFORE)

        cols = _columns(file_db_url, "tenant")
        assert "subnet_pool" not in cols

    def test_upgrade_downgrade_upgrade_is_idempotent(
        self, file_db_url: str
    ) -> None:
        from alembic.command import downgrade, upgrade

        upgrade(_alembic_config(file_db_url), _REVISION_AT)
        downgrade(_alembic_config(file_db_url), _REVISION_BEFORE)
        upgrade(_alembic_config(file_db_url), _REVISION_AT)

        cols = _columns(file_db_url, "tenant")
        assert "subnet_pool" in cols


# ---------------------------------------------------------------------------
# Tenant model surface
# ---------------------------------------------------------------------------


class TestTenantModelSurface:
    def test_tenant_has_subnet_pool_field(self) -> None:
        from wg_manager.models import Tenant

        assert "subnet_pool" in Tenant.model_fields

    def test_subnet_pool_has_sensible_default(self) -> None:
        """The Pydantic-level default matches the Alembic 0016
        back-fill fallback (the largest RFC1918 block) so any code
        path that constructs a Tenant without supplying a pool
        still lands a valid row. The DB column stays ``NOT NULL``
        (pinned by ``test_column_is_not_nullable``) so a manual
        SQL insert that explicitly nulls the column still trips."""
        from wg_manager.models import Tenant

        row = Tenant(name="defaulted", slug="defaulted")
        assert row.subnet_pool == "10.0.0.0/8"

    def test_tenant_with_pool_constructs(self) -> None:
        from wg_manager.models import Tenant

        row = Tenant(name="acme", slug="acme", subnet_pool="10.42.0.0/16")
        assert row.subnet_pool == "10.42.0.0/16"
