"""Tests for Phase 3b cycle 1: Alembic 0014 — add the ``tenant`` table
and the ``tenant_id`` foreign-key columns on the six resource tables.

Phase 3b moves wg-manager from a single-tenant deployment to a
namespace-style multi-tenant model. **Cycle 1 is schema groundwork
only** — zero behaviour change. The migration:

1. Creates a ``tenant`` table (``id`` / ``name`` unique / ``slug``
   unique / ``created_at``).
2. Inserts a ``default`` tenant row at id=1. Every existing row
   gets retro-assigned to it so no data is orphaned.
3. Adds a **nullable** ``tenant_id`` FK column to
   ``operator`` / ``server`` / ``client`` / ``sshkey`` /
   ``certificate`` / ``auditevent``. Nullable for cycle 1 so the
   migration is non-breaking; cycle 3 tightens to NOT NULL once the
   enforcement layer is in place.
4. Back-fills every existing row's ``tenant_id`` to 1 (the default
   tenant).

The acceptance bar for cycle 1: an operator running ``alembic
upgrade head`` against a v0.1.0 deployment must come up cleanly,
with every row owned by the default tenant, and no auth / routing
behaviour change visible to API clients.
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
    """On-disk SQLite URL ``alembic/env.py`` picks up via settings."""
    from wg_manager.config import settings as live_settings

    path = tmp_path / "wg_manager_phase3b_tenant.sqlite"
    url = f"sqlite:///{path}"
    monkeypatch.setattr(live_settings, "database_url", url)
    return url


def _columns(database_url: str, table: str) -> dict[str, dict]:
    engine = create_engine(database_url)
    try:
        return {col["name"]: col for col in inspect(engine).get_columns(table)}
    finally:
        engine.dispose()


def _table_names(database_url: str) -> set[str]:
    engine = create_engine(database_url)
    try:
        return set(inspect(engine).get_table_names())
    finally:
        engine.dispose()


def _foreign_keys(database_url: str, table: str) -> list[dict]:
    engine = create_engine(database_url)
    try:
        return inspect(engine).get_foreign_keys(table)
    finally:
        engine.dispose()


# Six resource tables that get a tenant_id FK.
_TENANTED_TABLES = (
    "operator",
    "server",
    "client",
    "sshkey",
    "certificate",
    "auditevent",
)


# ---------------------------------------------------------------------------
# Tenant table shape
# ---------------------------------------------------------------------------


class TestTenantTableCreated:
    def test_tenant_table_exists(self, file_db_url: str) -> None:
        from alembic.command import upgrade

        upgrade(_alembic_config(file_db_url), "head")
        assert "tenant" in _table_names(file_db_url)

    def test_tenant_columns(self, file_db_url: str) -> None:
        """Cycle 1's tenant row carries the minimum a namespace needs:
        an integer surrogate PK, a human-readable name, a URL-safe
        slug, and a creation timestamp. Cycles 2+ may extend; cycle
        1 keeps the shape minimal."""
        from alembic.command import upgrade

        upgrade(_alembic_config(file_db_url), "head")
        cols = _columns(file_db_url, "tenant")
        assert "id" in cols
        assert "name" in cols
        assert "slug" in cols
        assert "created_at" in cols

    def test_name_and_slug_not_nullable(self, file_db_url: str) -> None:
        """``name`` and ``slug`` carry meaning; an empty row is
        broken state."""
        from alembic.command import upgrade

        upgrade(_alembic_config(file_db_url), "head")
        cols = _columns(file_db_url, "tenant")
        assert cols["name"]["nullable"] is False
        assert cols["slug"]["nullable"] is False


class TestDefaultTenantInserted:
    """The ``default`` tenant is the home of every existing v0.1.0
    row after the migration. It must exist before the FK backfill
    runs (the migration writes it first)."""

    def test_default_tenant_row_exists(self, file_db_url: str) -> None:
        from alembic.command import upgrade

        upgrade(_alembic_config(file_db_url), "head")
        engine = create_engine(file_db_url)
        try:
            with engine.connect() as conn:
                row = conn.execute(
                    text("SELECT id, name, slug FROM tenant WHERE id = 1")
                ).first()
        finally:
            engine.dispose()
        assert row is not None
        assert row[0] == 1
        assert row[1] == "default"
        assert row[2] == "default"


# ---------------------------------------------------------------------------
# tenant_id columns on the six resource tables
# ---------------------------------------------------------------------------


class TestTenantIdColumnsAdded:
    """Every tenanted resource gets a nullable ``tenant_id`` FK.
    Nullable in cycle 1 so the migration is non-breaking — cycle 3
    tightens to NOT NULL once the auth-layer filtering enforces the
    invariant."""

    @pytest.mark.parametrize("table", _TENANTED_TABLES)
    def test_tenant_id_column_exists(
        self, file_db_url: str, table: str
    ) -> None:
        from alembic.command import upgrade

        upgrade(_alembic_config(file_db_url), "head")
        cols = _columns(file_db_url, table)
        assert "tenant_id" in cols, (
            f"{table} must grow a tenant_id column in cycle 1"
        )

    @pytest.mark.parametrize("table", _TENANTED_TABLES)
    def test_tenant_id_is_nullable(
        self, file_db_url: str, table: str
    ) -> None:
        """Cycle 1 keeps the column nullable so an operator who's
        mid-upgrade (some rows backfilled, some not) doesn't hit
        constraint violations. Cycle 3 will tighten."""
        from alembic.command import upgrade

        upgrade(_alembic_config(file_db_url), "head")
        cols = _columns(file_db_url, table)
        assert cols["tenant_id"]["nullable"] is True


class TestTenantIdFkPointsAtTenantTable:
    @pytest.mark.parametrize("table", _TENANTED_TABLES)
    def test_fk_references_tenant_id(
        self, file_db_url: str, table: str
    ) -> None:
        from alembic.command import upgrade

        upgrade(_alembic_config(file_db_url), "head")
        fks = _foreign_keys(file_db_url, table)
        tenant_fks = [
            fk
            for fk in fks
            if fk["referred_table"] == "tenant"
            and "tenant_id" in fk["constrained_columns"]
        ]
        assert tenant_fks, (
            f"{table}.tenant_id must reference tenant(id); got FKs: {fks}"
        )


# ---------------------------------------------------------------------------
# Backfill — every existing row lands in the default tenant
# ---------------------------------------------------------------------------


class TestBackfillFromPriorRevision:
    """Seed rows at revision 0013 (Phase 2e cycle 1), then upgrade
    to head. The migration's backfill step must retro-assign every
    existing row to the default tenant."""

    def test_existing_operator_rows_get_default_tenant(
        self, file_db_url: str
    ) -> None:
        from alembic.command import upgrade

        # Step 1: bring schema to the pre-0014 revision.
        upgrade(_alembic_config(file_db_url), "0013_add_audit_event_table")

        # Step 2: seed an Operator row at 0013 (when tenant_id does
        # not exist yet). Use raw SQL because the SQLModel class
        # already has tenant_id — we want to simulate a real
        # operator's database state from before the migration.
        engine = create_engine(file_db_url)
        now = datetime.now(timezone.utc).isoformat()
        try:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO operator (cn, role, status, created_at) "
                        "VALUES ('legacy-op@example.com', 'admin', 'active', :ts)"
                    ),
                    {"ts": now},
                )
        finally:
            engine.dispose()

        # Step 3: upgrade through 0014. Backfill should retro-assign.
        upgrade(_alembic_config(file_db_url), "head")

        engine = create_engine(file_db_url)
        try:
            with engine.connect() as conn:
                row = conn.execute(
                    text(
                        "SELECT tenant_id FROM operator WHERE cn = 'legacy-op@example.com'"
                    )
                ).first()
        finally:
            engine.dispose()

        assert row is not None
        assert row[0] == 1, (
            f"existing operator must be backfilled to default tenant "
            f"(id=1), got tenant_id={row[0]!r}"
        )


# ---------------------------------------------------------------------------
# Downgrade — reverses everything cleanly
# ---------------------------------------------------------------------------


class TestDowngradeRoundTrip:
    # Pin the surrounding revisions explicitly so adding 0015+ on top
    # doesn't quietly turn ``-1`` into "downgrade only the topmost
    # revision" — which was the regression that surfaced when Phase 3b
    # cycle 2 (Alembic 0015) landed.
    _TARGET_BEFORE_0014 = "0013_add_audit_event_table"
    _TARGET_AT_0014 = "0014_add_tenant_table"

    def test_downgrade_drops_tenant_table_and_columns(
        self, file_db_url: str
    ) -> None:
        from alembic.command import downgrade, upgrade

        upgrade(_alembic_config(file_db_url), self._TARGET_AT_0014)
        assert "tenant" in _table_names(file_db_url)

        downgrade(_alembic_config(file_db_url), self._TARGET_BEFORE_0014)

        names = _table_names(file_db_url)
        assert "tenant" not in names, (
            "downgrade must drop the tenant table"
        )
        # And the tenant_id columns must be gone from each resource.
        for table in _TENANTED_TABLES:
            cols = _columns(file_db_url, table)
            assert "tenant_id" not in cols, (
                f"downgrade must remove tenant_id from {table}"
            )

    def test_upgrade_downgrade_upgrade_is_idempotent(
        self, file_db_url: str
    ) -> None:
        from alembic.command import downgrade, upgrade

        upgrade(_alembic_config(file_db_url), self._TARGET_AT_0014)
        downgrade(_alembic_config(file_db_url), self._TARGET_BEFORE_0014)
        upgrade(_alembic_config(file_db_url), self._TARGET_AT_0014)

        # Default tenant must exist after the second upgrade —
        # backfill is run on every upgrade pass.
        engine = create_engine(file_db_url)
        try:
            with engine.connect() as conn:
                row = conn.execute(
                    text("SELECT id, name FROM tenant WHERE id = 1")
                ).first()
        finally:
            engine.dispose()
        assert row is not None
        assert row[1] == "default"
