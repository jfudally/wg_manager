"""Tests for Phase 2d CP4.3: ``Alembic 0012`` — record where each cert
was written.

CP4.3 grows the renewal flow: a `wg-manager certs renew` walker has to
know where on disk each cert was minted so the systemd timer can
rewrite the file in place. The CLI is the only path that writes to
disk (``POST /certs`` returns the PEMs in the response body and never
touches the filesystem), so the columns are nullable — API-issued
rows simply opt out of CLI-driven walker renewal.

What this module pins down:

1. **Column adds.** ``alembic upgrade head`` (with 0012 applied) gives
   the ``certificate`` table three new nullable string columns:
   ``out_cert_path`` / ``out_key_path`` / ``out_chain_path``.
2. **Backfill is intentionally NULL.** Pre-CP4.3 rows have no path
   information; the migration leaves them ``NULL`` rather than
   guessing. The CLI re-issue flow is the supported way to populate
   the columns retroactively.
3. **Downgrade.** Reversing 0012 drops the three columns cleanly;
   round-trip (upgrade → downgrade → upgrade) is idempotent.
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

    path = tmp_path / "wg_manager_cp43_renew.sqlite"
    url = f"sqlite:///{path}"
    monkeypatch.setattr(live_settings, "database_url", url)
    return url


def _columns(database_url: str, table: str) -> set[str]:
    engine = create_engine(database_url)
    try:
        return {col["name"] for col in inspect(engine).get_columns(table)}
    finally:
        engine.dispose()


_NEW_COLUMNS = {"out_cert_path", "out_key_path", "out_chain_path"}


class TestAlembic0012Upgrade:
    """0012 adds the three out-path columns to ``certificate``."""

    def test_upgrade_adds_three_path_columns(self, file_db_url: str) -> None:
        """The column set grows by exactly the three nullable strings."""
        from alembic import command

        cfg = _alembic_config(file_db_url)
        # Sanity: pre-0012 the columns aren't there.
        command.upgrade(cfg, "0011_add_certificate_table")
        before = _columns(file_db_url, "certificate")
        assert _NEW_COLUMNS.isdisjoint(before), (
            f"pre-0012, none of {_NEW_COLUMNS} should exist on certificate"
        )

        command.upgrade(cfg, "head")

        after = _columns(file_db_url, "certificate")
        assert _NEW_COLUMNS <= after, (
            f"certificate missing CP4.3 columns; got {after!r}"
        )

    def test_new_columns_accept_null(self, file_db_url: str) -> None:
        """Pre-CP4.3 rows + API-issued rows leave the columns NULL.

        Inserting a fresh row with the three columns omitted must
        succeed — that's the API path (no on-disk PEM to point at).
        """
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "head")

        engine = create_engine(file_db_url)
        try:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO certificate (serial, cert_type, "
                        "common_name, sans, not_before, not_after, "
                        "revoked, created_at) VALUES "
                        "(:serial, 'api', '127.0.0.1', '127.0.0.1', "
                        ":nbf, :naf, 0, :now)"
                    ),
                    {
                        "serial": "9100",
                        "nbf": "2026-05-31 00:00:00",
                        "naf": "2026-06-30 00:00:00",
                        "now": "2026-05-31 00:00:00",
                    },
                )
            with engine.connect() as conn:
                row = conn.execute(
                    text(
                        "SELECT out_cert_path, out_key_path, "
                        "out_chain_path FROM certificate "
                        "WHERE serial = :serial"
                    ),
                    {"serial": "9100"},
                ).one()
            assert row == (None, None, None), (
                "all three out-path columns must default to NULL"
            )
        finally:
            engine.dispose()

    def test_new_columns_accept_paths(self, file_db_url: str) -> None:
        """CLI-issued rows populate all three columns at once."""
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "head")

        engine = create_engine(file_db_url)
        try:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO certificate (serial, cert_type, "
                        "common_name, sans, not_before, not_after, "
                        "revoked, created_at, out_cert_path, "
                        "out_key_path, out_chain_path) VALUES "
                        "(:serial, 'api', '127.0.0.1', '127.0.0.1', "
                        ":nbf, :naf, 0, :now, :cert, :key, :chain)"
                    ),
                    {
                        "serial": "9101",
                        "nbf": "2026-05-31 00:00:00",
                        "naf": "2026-06-30 00:00:00",
                        "now": "2026-05-31 00:00:00",
                        "cert": "/etc/wg-manager/server.crt",
                        "key": "/etc/wg-manager/server.key",
                        "chain": "/etc/wg-manager/ca-bundle.crt",
                    },
                )
            with engine.connect() as conn:
                row = conn.execute(
                    text(
                        "SELECT out_cert_path, out_key_path, "
                        "out_chain_path FROM certificate "
                        "WHERE serial = :serial"
                    ),
                    {"serial": "9101"},
                ).one()
            assert row == (
                "/etc/wg-manager/server.crt",
                "/etc/wg-manager/server.key",
                "/etc/wg-manager/ca-bundle.crt",
            )
        finally:
            engine.dispose()


class TestAlembic0012Downgrade:
    """Reversing 0012 drops the three columns cleanly."""

    def test_downgrade_round_trip(self, file_db_url: str) -> None:
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "head")
        # All three columns are present after head.
        assert _NEW_COLUMNS <= _columns(file_db_url, "certificate")

        command.downgrade(cfg, "0011_add_certificate_table")
        assert _NEW_COLUMNS.isdisjoint(
            _columns(file_db_url, "certificate")
        ), "downgrade must drop the three out-path columns"

        # Re-upgrade is clean.
        command.upgrade(cfg, "head")
        assert _NEW_COLUMNS <= _columns(file_db_url, "certificate")
