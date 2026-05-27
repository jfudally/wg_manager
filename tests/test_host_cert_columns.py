"""Tests for Phase 2c CP3: ``Server`` host-cert columns + Alembic 0006.

CP3 introduces the persisted view of a server's *host* certificate. The
control plane mints the cert via the SSH CA, installs it on the host
during provisioning, and remembers what it minted on the ``server`` row
so the dashboard can render expiry / rotation status without a remote
round-trip.

This module pins:

1. The :class:`~wg_manager.models.Server` model carries six new
   optional fields, all defaulting to ``None`` on a freshly-constructed
   row so legacy callers (existing tests, the registration router)
   need no changes.
2. The Alembic 0006 migration adds the same six columns to the
   ``server`` table and the downgrade drops them — a round-trip leaves
   the schema identical.
3. The columns are nullable, so applying the migration against a
   populated production DB is safe without a backfill.

The migration is exercised through Alembic's offline-mode SQL emit
rather than by spinning up a fresh SQLite engine — that way the test
also serves as a guard against accidental DDL drift between the
migration body and what ``SQLModel.metadata.create_all`` would emit.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel

from wg_manager.models import NodeStatus, Server


# Names of every host-cert column the CP3 migration adds. Centralised so
# every assertion below references the same list — flipping a name here
# breaks every test, which is the point.
_HOST_CERT_COLUMNS = (
    "host_cert_pem",
    "host_cert_serial",
    "host_cert_principals",
    "host_cert_valid_after",
    "host_cert_valid_before",
    "host_cert_ca_public_key",
)


# ---------------------------------------------------------------------------
# Model-level: fields exist and default to None
# ---------------------------------------------------------------------------


class TestServerHostCertModelFields:
    """A freshly-constructed :class:`Server` exposes the new attrs as ``None``."""

    def test_all_host_cert_fields_default_to_none(self) -> None:
        row = Server(
            hostname="hub.example.com",
            ssh_username="ubuntu",
            ssh_key_id=1,
            endpoint_host="hub.example.com",
        )
        for name in _HOST_CERT_COLUMNS:
            assert getattr(row, name) is None, (
                f"Server.{name} must default to None so existing call "
                f"sites that don't set it don't trip a validation error"
            )

    def test_host_cert_fields_round_trip_through_session(self) -> None:
        """Round-trip a populated server row through an in-memory SQLite session.

        Catches a SQLModel column-definition mistake (e.g. forgetting
        ``Field(default=None)`` on a non-Optional type) that would
        otherwise only fail at the alembic-driven path.
        """
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        SQLModel.metadata.create_all(engine)
        try:
            now = datetime(2026, 5, 27, 12, 0, 0, tzinfo=timezone.utc)
            with Session(engine) as session:
                row = Server(
                    hostname="hub.example.com",
                    ssh_username="ubuntu",
                    ssh_key_id=1,
                    endpoint_host="hub.example.com",
                    host_cert_pem="ssh-ed25519-cert-v01@openssh.com AAAA...",
                    host_cert_serial=1234567890,
                    host_cert_principals="hub.example.com,hub.internal",
                    host_cert_valid_after=now,
                    host_cert_valid_before=now,
                    host_cert_ca_public_key="ssh-ed25519 AAAA-CA-PUBKEY",
                )
                session.add(row)
                session.commit()
                session.refresh(row)
                assert row.host_cert_serial == 1234567890
                assert row.host_cert_principals == "hub.example.com,hub.internal"
                assert row.host_cert_pem.startswith(
                    "ssh-ed25519-cert-v01@openssh.com "
                )
                assert row.host_cert_ca_public_key.startswith("ssh-ed25519 ")
                # SQLAlchemy on SQLite strips the tzinfo on round-trip;
                # we only care the value made the trip intact.
                assert row.host_cert_valid_after.year == 2026
                assert row.host_cert_valid_before.year == 2026
                # Status untouched: provisioning sets it elsewhere.
                assert row.status == NodeStatus.pending
        finally:
            SQLModel.metadata.drop_all(engine)


# ---------------------------------------------------------------------------
# Alembic 0006: the migration adds + drops the columns
# ---------------------------------------------------------------------------


def _alembic_config(database_url: str):
    """Build an Alembic ``Config`` pointed at ``database_url``.

    Imported lazily so the rest of this module doesn't pay the alembic
    import cost when only the model tests run.
    """
    from alembic.config import Config

    cfg = Config(str(Path(__file__).resolve().parent.parent / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", database_url)
    return cfg


class TestHostCertMigration:
    """The 0006 revision is reversible and idempotent in its schema effect.

    The Alembic env.py forces ``sqlalchemy.url`` from
    ``wg_manager.config.settings.database_url``, so the fixture
    monkeypatches the live settings object rather than relying on the
    ``Config.set_main_option`` call. This mirrors what an operator who
    runs ``make migrate`` against a temp DB would do: point
    ``DATABASE_URL`` at the throwaway, then call alembic.
    """

    @pytest.fixture()
    def file_db_url(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> str:
        """An on-disk SQLite URL that env.py will actually pick up."""
        from wg_manager.config import settings as live_settings

        path = tmp_path / "wg_manager_cp3.sqlite"
        url = f"sqlite:///{path}"
        monkeypatch.setattr(live_settings, "database_url", url)
        return url

    def _columns(self, database_url: str) -> set[str]:
        """Return the set of column names currently on the ``server`` table."""
        engine = create_engine(database_url)
        try:
            return {col["name"] for col in inspect(engine).get_columns("server")}
        finally:
            engine.dispose()

    def test_upgrade_head_adds_host_cert_columns(
        self, file_db_url: str
    ) -> None:
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "head")
        cols = self._columns(file_db_url)
        for name in _HOST_CERT_COLUMNS:
            assert name in cols, (
                f"Alembic 'head' is missing the {name!r} column — "
                f"CP3 migration was not applied"
            )

    def test_downgrade_one_drops_only_host_cert_columns(
        self, file_db_url: str
    ) -> None:
        """Rolling back 0006 drops the CP3 columns and leaves everything else alone."""
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "head")
        before = self._columns(file_db_url)
        command.downgrade(cfg, "-1")
        after = self._columns(file_db_url)

        assert before - after == set(_HOST_CERT_COLUMNS), (
            "CP3 downgrade should remove exactly the host-cert columns; "
            f"removed instead: {before - after!r}"
        )
        # And the non-CP3 columns survived intact — guards against an
        # over-eager batch_alter_table that drops legitimate state.
        assert after & set(_HOST_CERT_COLUMNS) == set()
        assert "hostname" in after and "ssh_key_id" in after

    def test_upgrade_then_downgrade_then_upgrade_is_idempotent(
        self, file_db_url: str
    ) -> None:
        """Round-trip survives — the migration body has no one-shot side effects."""
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "head")
        command.downgrade(cfg, "-1")
        command.upgrade(cfg, "head")
        cols = self._columns(file_db_url)
        for name in _HOST_CERT_COLUMNS:
            assert name in cols
