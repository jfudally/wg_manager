"""Tests for Phase 3b cycle 2: Alembic 0015 — add the ``operatortenant``
join table.

Cycle 1 (Alembic 0014) shipped the ``Tenant`` row + a nullable
``tenant_id`` FK on every owned resource. Cycle 2 layers per-tenant
roles on top via a many-to-many join: one :class:`Operator` can be
attached to many tenants, one tenant can host many operators, and the
**per-tenant role** lives on the join — so a user can be ``admin`` in
their own tenant and ``auditor`` in another without two separate
operator rows.

The migration:

1. Creates the ``operatortenant`` table with ``id`` /
   ``operator_id`` FK / ``tenant_id`` FK / ``role`` / ``created_at``.
2. Unique constraint on ``(operator_id, tenant_id)`` so a duplicate
   attach is rejected at the DB layer (the CLI / API still surface a
   readable 4xx but the DB is the last line of defence).
3. Back-fills one join row per existing operator pointing at the
   ``default`` tenant (id=1), mirroring the operator's existing
   global ``role`` as the per-tenant role. **Zero behaviour change**
   for v0.1.0 callers: every operator stays in their existing tenant
   slot with their existing privileges; cycle 3's middleware filter
   is what flips per-tenant enforcement on.

The acceptance bar for cycle 2: an operator running ``alembic
upgrade head`` against a freshly-Cycle-1'd database must come up
cleanly, with every existing operator carrying a join row in the
default tenant, and no auth / routing behaviour change visible to
API clients.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError


def _alembic_config(database_url: str):
    from alembic.config import Config

    cfg = Config(str(Path(__file__).resolve().parent.parent / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", database_url)
    return cfg


@pytest.fixture()
def file_db_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> str:
    """On-disk SQLite URL the live env.py picks up via settings."""
    from wg_manager.config import settings as live_settings

    path = tmp_path / "wg_manager_phase3b_join.sqlite"
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


def _unique_constraints(database_url: str, table: str) -> list[dict]:
    engine = create_engine(database_url)
    try:
        return inspect(engine).get_unique_constraints(table)
    finally:
        engine.dispose()


_REVISION_BEFORE = "0014_add_tenant_table"
_REVISION_AT = "0015_add_operator_tenant"


# ---------------------------------------------------------------------------
# operatortenant table shape
# ---------------------------------------------------------------------------


class TestOperatorTenantTableCreated:
    """0015 creates a join table with the expected column set."""

    def test_operatortenant_table_exists(self, file_db_url: str) -> None:
        from alembic.command import upgrade

        upgrade(_alembic_config(file_db_url), "head")
        assert "operatortenant" in _table_names(file_db_url)

    def test_operatortenant_columns(self, file_db_url: str) -> None:
        """Cycle 2's join row carries the minimum a per-tenant role
        needs: a surrogate PK, the two FKs, the per-tenant role enum,
        and a creation timestamp for the audit trail."""
        from alembic.command import upgrade

        upgrade(_alembic_config(file_db_url), "head")
        cols = _columns(file_db_url, "operatortenant")
        assert {"id", "operator_id", "tenant_id", "role", "created_at"} <= set(
            cols
        )

    def test_fk_columns_are_not_nullable(self, file_db_url: str) -> None:
        """Both FKs are mandatory — a row with a null operator or
        tenant id is broken state."""
        from alembic.command import upgrade

        upgrade(_alembic_config(file_db_url), "head")
        cols = _columns(file_db_url, "operatortenant")
        assert cols["operator_id"]["nullable"] is False
        assert cols["tenant_id"]["nullable"] is False
        assert cols["role"]["nullable"] is False


class TestForeignKeyShape:
    """The two FKs point at ``operator(id)`` and ``tenant(id)``."""

    def test_operator_id_fk(self, file_db_url: str) -> None:
        from alembic.command import upgrade

        upgrade(_alembic_config(file_db_url), "head")
        fks = _foreign_keys(file_db_url, "operatortenant")
        match = [
            fk
            for fk in fks
            if fk["referred_table"] == "operator"
            and "operator_id" in fk["constrained_columns"]
        ]
        assert match, (
            f"operatortenant.operator_id must reference operator(id); "
            f"got FKs: {fks}"
        )

    def test_tenant_id_fk(self, file_db_url: str) -> None:
        from alembic.command import upgrade

        upgrade(_alembic_config(file_db_url), "head")
        fks = _foreign_keys(file_db_url, "operatortenant")
        match = [
            fk
            for fk in fks
            if fk["referred_table"] == "tenant"
            and "tenant_id" in fk["constrained_columns"]
        ]
        assert match, (
            f"operatortenant.tenant_id must reference tenant(id); "
            f"got FKs: {fks}"
        )


class TestUniqueOperatorTenantPair:
    """A given operator may be attached to a given tenant at most once.
    The CLI / API surface a readable 4xx; the unique constraint is the
    last line of defence."""

    def test_duplicate_attach_raises_integrity_error(
        self, file_db_url: str
    ) -> None:
        from alembic.command import upgrade

        upgrade(_alembic_config(file_db_url), "head")

        engine = create_engine(file_db_url)
        try:
            # Seed an operator we can attach to the default tenant.
            now = datetime.now(timezone.utc).isoformat()
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO operator (cn, role, status, created_at, "
                        "tenant_id) VALUES ('dup@wg.local', 'operator', "
                        "'active', :ts, 1)"
                    ),
                    {"ts": now},
                )
                op_row = conn.execute(
                    text("SELECT id FROM operator WHERE cn = 'dup@wg.local'")
                ).first()
                assert op_row is not None
                op_id = op_row[0]

                # First attach succeeds.
                conn.execute(
                    text(
                        "INSERT INTO operatortenant (operator_id, tenant_id, "
                        "role, created_at) VALUES (:op, 1, 'operator', :ts)"
                    ),
                    {"op": op_id, "ts": now},
                )

            # Second attach must trip the unique constraint.
            with pytest.raises(IntegrityError):
                with engine.begin() as conn:
                    conn.execute(
                        text(
                            "INSERT INTO operatortenant (operator_id, "
                            "tenant_id, role, created_at) VALUES "
                            "(:op, 1, 'admin', :ts)"
                        ),
                        {"op": op_id, "ts": now},
                    )
        finally:
            engine.dispose()

    def test_unique_constraint_declared(self, file_db_url: str) -> None:
        """The unique constraint must be declared at the schema level
        (so a DB migration tool reading the metadata sees it, not just
        the runtime SQL)."""
        from alembic.command import upgrade

        upgrade(_alembic_config(file_db_url), "head")

        uniques = _unique_constraints(file_db_url, "operatortenant")
        match = [
            uq
            for uq in uniques
            if set(uq["column_names"]) == {"operator_id", "tenant_id"}
        ]
        assert match, (
            "operatortenant must declare a unique constraint on "
            f"(operator_id, tenant_id); got: {uniques}"
        )


# ---------------------------------------------------------------------------
# Backfill — each operator gets a join row in the default tenant
# ---------------------------------------------------------------------------


class TestBackfillFromExistingOperators:
    """0015 mirrors each operator's existing global role into a join
    row pointing at the default tenant. Cycle 2 ships per-tenant role
    storage; the historical ``Operator.role`` column stays around for
    one release as the source-of-truth so a mid-upgrade rollback is
    safe."""

    def _seed_operator_pre_cycle2(
        self, file_db_url: str, cn: str, role: str
    ) -> int:
        """Bring schema to revision 0014, seed an operator, return its id."""
        from alembic.command import upgrade

        upgrade(_alembic_config(file_db_url), _REVISION_BEFORE)
        now = datetime.now(timezone.utc).isoformat()
        engine = create_engine(file_db_url)
        try:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO operator (cn, role, status, "
                        "created_at, tenant_id) VALUES "
                        "(:cn, :role, 'active', :ts, 1)"
                    ),
                    {"cn": cn, "role": role, "ts": now},
                )
                row = conn.execute(
                    text("SELECT id FROM operator WHERE cn = :cn"),
                    {"cn": cn},
                ).first()
        finally:
            engine.dispose()
        assert row is not None
        return int(row[0])

    @pytest.mark.parametrize(
        "global_role", ["admin", "operator", "auditor"]
    )
    def test_existing_operator_gets_default_tenant_join(
        self, file_db_url: str, global_role: str
    ) -> None:
        op_id = self._seed_operator_pre_cycle2(
            file_db_url, f"role-{global_role}@wg.local", global_role
        )

        from alembic.command import upgrade

        upgrade(_alembic_config(file_db_url), "head")

        engine = create_engine(file_db_url)
        try:
            with engine.connect() as conn:
                row = conn.execute(
                    text(
                        "SELECT tenant_id, role FROM operatortenant "
                        "WHERE operator_id = :op"
                    ),
                    {"op": op_id},
                ).first()
        finally:
            engine.dispose()

        assert row is not None, (
            f"existing operator with global role {global_role!r} must "
            "be back-filled into the default tenant"
        )
        assert row[0] == 1, f"expected tenant_id=1, got {row[0]!r}"
        assert row[1] == global_role, (
            f"per-tenant role must mirror the global role "
            f"(expected {global_role!r}, got {row[1]!r})"
        )

    def test_backfill_is_one_row_per_operator(
        self, file_db_url: str
    ) -> None:
        """Two distinct operator rows produce two distinct join rows
        — the backfill must not coalesce or skip operators."""
        self._seed_operator_pre_cycle2(
            file_db_url, "alice@wg.local", "admin"
        )
        self._seed_operator_pre_cycle2(
            file_db_url, "bob@wg.local", "operator"
        )

        from alembic.command import upgrade

        upgrade(_alembic_config(file_db_url), "head")

        engine = create_engine(file_db_url)
        try:
            with engine.connect() as conn:
                count = conn.execute(
                    text("SELECT COUNT(*) FROM operatortenant")
                ).scalar()
        finally:
            engine.dispose()
        assert count == 2, (
            f"expected one join row per operator (2 total); got {count!r}"
        )


# ---------------------------------------------------------------------------
# Downgrade round-trip
# ---------------------------------------------------------------------------


class TestDowngradeRoundTrip:
    def test_downgrade_drops_join_table(self, file_db_url: str) -> None:
        from alembic.command import downgrade, upgrade

        upgrade(_alembic_config(file_db_url), "head")
        assert "operatortenant" in _table_names(file_db_url)

        downgrade(_alembic_config(file_db_url), _REVISION_BEFORE)

        assert "operatortenant" not in _table_names(file_db_url)

    def test_upgrade_downgrade_upgrade_is_idempotent(
        self, file_db_url: str
    ) -> None:
        """Migration body has no one-shot side effects — re-applying it
        after a downgrade still arrives at the same shape with the
        default-tenant backfill intact."""
        from alembic.command import downgrade, upgrade

        # First upgrade. Seed an operator that the second upgrade pass
        # also needs to backfill.
        upgrade(_alembic_config(file_db_url), _REVISION_BEFORE)
        now = datetime.now(timezone.utc).isoformat()
        engine = create_engine(file_db_url)
        try:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO operator (cn, role, status, "
                        "created_at, tenant_id) VALUES "
                        "('roundtrip@wg.local', 'admin', 'active', "
                        ":ts, 1)"
                    ),
                    {"ts": now},
                )
        finally:
            engine.dispose()

        upgrade(_alembic_config(file_db_url), "head")
        downgrade(_alembic_config(file_db_url), _REVISION_BEFORE)
        upgrade(_alembic_config(file_db_url), "head")

        engine = create_engine(file_db_url)
        try:
            with engine.connect() as conn:
                row = conn.execute(
                    text(
                        "SELECT ot.tenant_id, ot.role FROM operatortenant ot "
                        "JOIN operator op ON op.id = ot.operator_id "
                        "WHERE op.cn = 'roundtrip@wg.local'"
                    )
                ).first()
        finally:
            engine.dispose()
        assert row is not None
        assert row[0] == 1
        assert row[1] == "admin"


# ---------------------------------------------------------------------------
# OperatorTenant model surface
# ---------------------------------------------------------------------------


class TestOperatorTenantModelSurface:
    """The SQLModel class is what the router + CLI consume. Pin the
    public shape so a future rename surfaces here before it breaks the
    HTTP contract."""

    def test_model_has_expected_fields(self) -> None:
        from wg_manager.models import OperatorTenant

        # SQLModel exposes fields via Pydantic's model_fields.
        fields = set(OperatorTenant.model_fields)
        assert {"id", "operator_id", "tenant_id", "role", "created_at"} <= fields

    def test_role_defaults_to_operator(self) -> None:
        """Per-tenant role defaults to ``operator`` — principle of
        least privilege, matches :class:`Operator.role`'s default."""
        from wg_manager.models import OperatorRole, OperatorTenant

        row = OperatorTenant(operator_id=1, tenant_id=1)
        assert row.role == OperatorRole.operator

    def test_repr_is_one_line_and_safe(self) -> None:
        """The repr keeps to a single line and exposes only ids + role —
        no private material to scrub but the regression-test bar for
        repr safety lives on every table."""
        from wg_manager.models import OperatorRole, OperatorTenant

        row = OperatorTenant(
            id=42, operator_id=7, tenant_id=3, role=OperatorRole.admin
        )
        text_repr = repr(row)
        assert "\n" not in text_repr
        assert "operator_id=7" in text_repr
        assert "tenant_id=3" in text_repr
        assert "role=" in text_repr
