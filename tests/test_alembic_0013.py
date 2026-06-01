"""Tests for Phase 2e: ``Alembic 0013`` — add the ``auditevent`` table.

Phase 2e's first cycle introduces the application audit log. CP5 (Phase
2d) shipped the per-request audit *stream* via the ``wg_manager.audit``
named logger — admit / reject decisions from the mTLS middleware and
the ``bootstrap.host`` install event land in stderr as one-line JSON.
That stream is operationally useful but ephemeral; the dashboard and
``/audit`` endpoint that this phase delivers need a queryable
persistence layer for *mutations*.

What this module pins down:

1. **Table shape.** ``alembic upgrade head`` (with 0013 applied) creates
   an ``auditevent`` table whose columns and nullability match the
   on-paper schema:

   ====================  =========  ========  ============================
   Column                Type       Null?     Purpose
   ====================  =========  ========  ============================
   ``id``                int         no       surrogate PK
   ``ts``                datetime    no       when the event was emitted
   ``event``             str(64)     no       slug, e.g. ``server.create``
   ``actor_cn``          str(255)    yes      CN from mTLS cert
   ``actor_serial``      str(64)     yes      cert serial (decimal string)
   ``actor_role``        str(16)     yes      OperatorRole at action time
   ``resource_type``     str(32)     no       ``server`` / ``client`` / …
   ``resource_id``       int         yes      row id; NULL for global ops
   ``action``            str(16)     no       ``create`` / ``update`` / …
   ``before_hash``       str(64)     yes      SHA-256 of pre-row; NULL on create
   ``after_hash``        str(64)     yes      SHA-256 of post-row; NULL on delete
   ``payload``           text        yes      small JSON summary dict
   ``request_id``        str(64)     yes      correlation ID
   ====================  =========  ========  ============================

2. **Indexes.** Five indexes back the read patterns ``/audit`` will
   serve: ``ts`` (newest-first listing), ``event`` (filter by slug),
   ``actor_cn`` (filter by operator), plus a composite
   ``(resource_type, resource_id)`` so the "show events for server #7"
   query is a single index scan.

3. **NULL handling.** Creates leave ``before_hash=NULL``; deletes leave
   ``after_hash=NULL``; system-origin events (bootstrap-host, crypto
   rotate) leave ``actor_cn=NULL``. The migration must accept all three
   shapes.

4. **Downgrade.** Reversing 0013 drops the table and every index
   cleanly; upgrade → downgrade → upgrade is idempotent.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text


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

    path = tmp_path / "wg_manager_phase2e_audit.sqlite"
    url = f"sqlite:///{path}"
    monkeypatch.setattr(live_settings, "database_url", url)
    return url


def _columns(database_url: str, table: str) -> dict[str, dict]:
    """Return ``{column_name: column_info}`` for ``table``.

    ``column_info`` is the dict ``sqlalchemy.inspect`` returns —
    callers reach into ``nullable`` and ``type`` to assert shape.
    """
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


def _index_names(database_url: str, table: str) -> set[str]:
    engine = create_engine(database_url)
    try:
        return {ix["name"] for ix in inspect(engine).get_indexes(table)}
    finally:
        engine.dispose()


_REQUIRED_COLUMNS: dict[str, bool] = {
    # column name -> nullable?
    "id": False,
    "ts": False,
    "event": False,
    "actor_cn": True,
    "actor_serial": True,
    "actor_role": True,
    "resource_type": False,
    "resource_id": True,
    "action": False,
    "before_hash": True,
    "after_hash": True,
    "payload": True,
    "request_id": True,
}

_REQUIRED_INDEXES: set[str] = {
    "ix_auditevent_ts",
    "ix_auditevent_event",
    "ix_auditevent_actor_cn",
    "ix_auditevent_resource",
}


class TestAlembic0013Upgrade:
    """0013 creates the ``auditevent`` table + indexes."""

    def test_pre_0013_table_absent(self, file_db_url: str) -> None:
        """Pre-0013 the table does not exist — sanity check."""
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "0012_add_certificate_out_paths")
        assert "auditevent" not in _table_names(file_db_url)

    def test_upgrade_creates_table_with_required_columns(
        self, file_db_url: str
    ) -> None:
        """``upgrade head`` creates ``auditevent`` with the expected shape."""
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "head")

        assert "auditevent" in _table_names(file_db_url), (
            "auditevent table missing after upgrade to head"
        )
        cols = _columns(file_db_url, "auditevent")
        for name, expected_nullable in _REQUIRED_COLUMNS.items():
            assert name in cols, f"auditevent missing column {name!r}"
            assert cols[name]["nullable"] is expected_nullable, (
                f"column {name!r} nullable={cols[name]['nullable']!r}, "
                f"expected {expected_nullable!r}"
            )

    def test_upgrade_creates_required_indexes(self, file_db_url: str) -> None:
        """The four read-path indexes exist after upgrade."""
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "head")

        ix = _index_names(file_db_url, "auditevent")
        missing = _REQUIRED_INDEXES - ix
        assert not missing, (
            f"auditevent missing indexes {missing!r}; have {ix!r}"
        )


class TestAlembic0013RowShapes:
    """The table accepts the three legitimate row shapes."""

    def test_accepts_create_event_with_null_before_hash(
        self, file_db_url: str
    ) -> None:
        """A ``server.create`` row leaves ``before_hash=NULL``."""
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "head")

        engine = create_engine(file_db_url)
        try:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO auditevent (ts, event, actor_cn, "
                        "actor_serial, actor_role, resource_type, "
                        "resource_id, action, before_hash, after_hash, "
                        "payload, request_id) VALUES "
                        "(:ts, 'server.create', 'ops@wg.local', '12345', "
                        "'admin', 'server', 7, 'create', NULL, "
                        ":after, :payload, 'req-abc')"
                    ),
                    {
                        "ts": "2026-06-01 00:00:00",
                        "after": "a" * 64,
                        "payload": '{"name":"hub-1"}',
                    },
                )
            with engine.connect() as conn:
                row = conn.execute(
                    text(
                        "SELECT event, before_hash, after_hash "
                        "FROM auditevent WHERE request_id = 'req-abc'"
                    )
                ).one()
            assert row == ("server.create", None, "a" * 64)
        finally:
            engine.dispose()

    def test_accepts_delete_event_with_null_after_hash(
        self, file_db_url: str
    ) -> None:
        """A ``client.delete`` row leaves ``after_hash=NULL``."""
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "head")

        engine = create_engine(file_db_url)
        try:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO auditevent (ts, event, actor_cn, "
                        "actor_serial, actor_role, resource_type, "
                        "resource_id, action, before_hash, after_hash, "
                        "payload, request_id) VALUES "
                        "(:ts, 'client.delete', 'ops@wg.local', '12345', "
                        "'admin', 'client', 42, 'delete', :before, NULL, "
                        ":payload, 'req-del')"
                    ),
                    {
                        "ts": "2026-06-01 00:01:00",
                        "before": "b" * 64,
                        "payload": '{"name":"laptop-7"}',
                    },
                )
            with engine.connect() as conn:
                row = conn.execute(
                    text(
                        "SELECT event, before_hash, after_hash "
                        "FROM auditevent WHERE request_id = 'req-del'"
                    )
                ).one()
            assert row == ("client.delete", "b" * 64, None)
        finally:
            engine.dispose()

    def test_accepts_system_origin_event_with_null_actor(
        self, file_db_url: str
    ) -> None:
        """A bootstrap / crypto-rotate row leaves ``actor_cn=NULL``."""
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "head")

        engine = create_engine(file_db_url)
        try:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO auditevent (ts, event, actor_cn, "
                        "actor_serial, actor_role, resource_type, "
                        "resource_id, action, before_hash, after_hash, "
                        "payload, request_id) VALUES "
                        "(:ts, 'crypto.rotate', NULL, NULL, NULL, "
                        "'crypto', NULL, 'rotate', NULL, NULL, "
                        "'{}', NULL)"
                    ),
                    {"ts": "2026-06-01 00:02:00"},
                )
            with engine.connect() as conn:
                row = conn.execute(
                    text(
                        "SELECT event, actor_cn, resource_id, request_id "
                        "FROM auditevent WHERE event = 'crypto.rotate'"
                    )
                ).one()
            assert row == ("crypto.rotate", None, None, None)
        finally:
            engine.dispose()


class TestAlembic0013Downgrade:
    """Reversing 0013 drops the table cleanly."""

    def test_downgrade_round_trip(self, file_db_url: str) -> None:
        """upgrade → downgrade → upgrade returns the table cleanly."""
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "head")
        assert "auditevent" in _table_names(file_db_url)

        command.downgrade(cfg, "0012_add_certificate_out_paths")
        assert "auditevent" not in _table_names(file_db_url), (
            "downgrade must drop the auditevent table"
        )

        command.upgrade(cfg, "head")
        assert "auditevent" in _table_names(file_db_url)
        # Indexes return on re-upgrade.
        assert _REQUIRED_INDEXES <= _index_names(file_db_url, "auditevent")
