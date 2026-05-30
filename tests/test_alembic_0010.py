"""Tests for Phase 2d CP3 first slice: ``Alembic 0010`` — add ``operator`` table.

CP3 introduces the ``Operator`` registry so a *valid* Vault-signed client
cert with an *unknown* CN is no longer accepted by
:class:`wg_manager.auth.MTLSAuthMiddleware` (the gap noted in
``SECURITY.md`` and threat T-7 after CP2 shipped). This revision lands
the table only — the middleware tightening and the ``Certificate``
registry follow in subsequent sub-slices so each step is reviewable in
isolation.

What this module pins down:

1. **Table creation.** ``alembic upgrade head`` creates an ``operator``
   table with ``id`` / ``cn`` / ``display_name`` / ``role`` / ``status``
   / ``created_at`` columns. ``cn`` is uniquely indexed; the table can
   be re-upgraded (idempotency) without error.
2. **Unique CN.** Two rows with the same ``cn`` cannot coexist —
   inserting a duplicate raises at the DB layer. Case-sensitivity is
   left to the DB default (the registry stores CNs verbatim).
3. **Downgrade.** Reversing 0010 drops the table. Round-trip
   (upgrade → downgrade → upgrade) is idempotent.

The migration is driven through Alembic's real
``command.upgrade`` / ``command.downgrade`` so an env.py regression
(logger reconfig, metadata import order, …) surfaces here too. Pattern
mirrors ``tests/test_alembic_0008.py``.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError


def _alembic_config(database_url: str):
    """Build an Alembic ``Config`` pointed at ``database_url``."""
    from alembic.config import Config

    cfg = Config(str(Path(__file__).resolve().parent.parent / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", database_url)
    return cfg


@pytest.fixture()
def file_db_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> str:
    """An on-disk SQLite URL ``alembic/env.py`` picks up via settings."""
    from wg_manager.config import settings as live_settings

    path = tmp_path / "wg_manager_cp3_op.sqlite"
    url = f"sqlite:///{path}"
    monkeypatch.setattr(live_settings, "database_url", url)
    return url


def _columns(database_url: str, table: str) -> set[str]:
    engine = create_engine(database_url)
    try:
        return {col["name"] for col in inspect(engine).get_columns(table)}
    finally:
        engine.dispose()


def _table_exists(database_url: str, table: str) -> bool:
    engine = create_engine(database_url)
    try:
        return inspect(engine).has_table(table)
    finally:
        engine.dispose()


class TestAlembic0010Upgrade:
    """0010 creates the ``operator`` table with the expected columns."""

    def test_upgrade_head_creates_operator_table(
        self, file_db_url: str
    ) -> None:
        """``alembic upgrade head`` brings the table into existence."""
        from alembic import command

        cfg = _alembic_config(file_db_url)
        # Sanity: the table does not exist before 0010.
        command.upgrade(cfg, "0009_drop_client_private_key_ct")
        assert not _table_exists(file_db_url, "operator"), (
            "operator table should not exist before 0010 lands"
        )

        command.upgrade(cfg, "head")

        assert _table_exists(file_db_url, "operator"), (
            "Alembic 0010 must create the operator table"
        )

    def test_upgrade_head_creates_expected_columns(
        self, file_db_url: str
    ) -> None:
        """The column set is the minimum CP3's middleware tightening needs."""
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "head")

        cols = _columns(file_db_url, "operator")
        # The shape the middleware + dashboard will read from. Future
        # CP3 sub-slices may add columns (last_seen_at, notes, …) — pin
        # the minimum, not the exact set.
        assert {
            "id",
            "cn",
            "display_name",
            "role",
            "status",
            "created_at",
        } <= cols, (
            f"operator table missing expected columns; got {cols!r}"
        )

    def test_cn_is_uniquely_indexed(self, file_db_url: str) -> None:
        """Two rows with the same CN cannot coexist."""
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "head")

        engine = create_engine(file_db_url)
        try:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO operator (cn, display_name, role, "
                        "status, created_at) VALUES "
                        "('ops@wg.local', 'Ops', 'admin', 'active', "
                        "'2026-05-29 00:00:00')"
                    )
                )
            with pytest.raises(IntegrityError):
                with engine.begin() as conn:
                    conn.execute(
                        text(
                            "INSERT INTO operator (cn, display_name, "
                            "role, status, created_at) VALUES "
                            "('ops@wg.local', 'Dupe', 'operator', "
                            "'active', '2026-05-29 00:00:01')"
                        )
                    )
        finally:
            engine.dispose()

    def test_upgrade_against_empty_db_is_a_no_op_relative_to_head(
        self, file_db_url: str
    ) -> None:
        """Fresh installs land directly on head with the table present."""
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "head")
        assert _table_exists(file_db_url, "operator")


class TestAlembic0010Downgrade:
    """Reversing 0010 drops the table cleanly."""

    _TARGET_BEFORE_0010 = "0009_drop_client_private_key_ct"
    _TARGET_AT_0010 = "0010_add_operator_table"

    def test_downgrade_drops_operator_table(
        self, file_db_url: str
    ) -> None:
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, self._TARGET_AT_0010)
        assert _table_exists(file_db_url, "operator")

        command.downgrade(cfg, self._TARGET_BEFORE_0010)

        assert not _table_exists(file_db_url, "operator"), (
            "0010 downgrade must drop the operator table"
        )

    def test_round_trip_upgrade_downgrade_upgrade_is_idempotent(
        self, file_db_url: str
    ) -> None:
        """Migration body has no one-shot side effects."""
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, self._TARGET_AT_0010)
        command.downgrade(cfg, self._TARGET_BEFORE_0010)
        command.upgrade(cfg, self._TARGET_AT_0010)
        assert _table_exists(file_db_url, "operator")


class TestOperatorEnums:
    """``OperatorRole`` and ``OperatorStatus`` carry the values CP3 needs."""

    def test_role_enum_values(self) -> None:
        """Three-tier role: admin > operator > auditor."""
        from wg_manager.models import OperatorRole

        assert OperatorRole.admin.value == "admin"
        assert OperatorRole.operator.value == "operator"
        assert OperatorRole.auditor.value == "auditor"

    def test_role_enum_is_str_subclass(self) -> None:
        """Subclassing str keeps the enum JSON-serialisable as its value."""
        from wg_manager.models import OperatorRole

        assert isinstance(OperatorRole.admin, str)

    def test_status_enum_values(self) -> None:
        """Binary lifecycle: active or disabled."""
        from wg_manager.models import OperatorStatus

        assert OperatorStatus.active.value == "active"
        assert OperatorStatus.disabled.value == "disabled"

    def test_status_enum_is_str_subclass(self) -> None:
        from wg_manager.models import OperatorStatus

        assert isinstance(OperatorStatus.active, str)


class TestOperatorModelDefaults:
    """The SQLModel-level defaults match the principle-of-least-privilege story."""

    def test_default_role_is_operator(self) -> None:
        """New rows default to ``operator`` — admin must be set explicitly."""
        from wg_manager.models import Operator, OperatorRole

        row = Operator(cn="ops@wg.local")
        assert row.role == OperatorRole.operator

    def test_default_status_is_active(self) -> None:
        """Newly-registered operators are usable immediately."""
        from wg_manager.models import Operator, OperatorStatus

        row = Operator(cn="ops@wg.local")
        assert row.status == OperatorStatus.active

    def test_display_name_is_optional(self) -> None:
        from wg_manager.models import Operator

        row = Operator(cn="ops@wg.local")
        assert row.display_name is None
