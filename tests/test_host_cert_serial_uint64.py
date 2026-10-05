"""Host-cert serials are unsigned 64-bit and must round-trip through the DB.

Regression: Vault's SSH CA issues serials across the full ``uint64``
range, but ``server.host_cert_serial`` / ``client.host_cert_serial``
were signed ``BIGINT``. Roughly half of all Vault serials (anything
``>= 2**63``) failed the post-rotation persist on MySQL with
``(1264, "Out of range value for column 'host_cert_serial'")`` after
the new cert was already installed on the host, leaving the row
looking expired.

SQLite (the test engine) has the same signed 64-bit integer limit, so
these tests reproduce the failure without MySQL. The MySQL DDL is
pinned separately by compiling the column type against the MySQL
dialect, and the migration by Alembic's offline SQL mode.
"""

from __future__ import annotations

import io
from contextlib import redirect_stdout
from pathlib import Path

import pytest
from sqlalchemy.dialects import mysql
from sqlmodel import Session, select

from wg_manager.models import Client, Server, SSHKey

# Edges of the range Vault can hand back: the first value past signed
# BIGINT, and the largest uint64.
_SERIALS = (2**63, 2**64 - 1)


def _server(session: Session) -> Server:
    """Insert a minimal hub row (and its SSH role) the tests hang off."""
    key = SSHKey(name="lab", tenant_id=1)
    session.add(key)
    session.commit()
    session.refresh(key)
    server = Server(
        ssh_key_id=key.id,
        hostname="hub.example.com",
        ssh_username="azureuser",
        endpoint_host="hub.example.com",
        subnet="10.8.0.0/24",
        address="10.8.0.1/24",
    )
    session.add(server)
    session.commit()
    session.refresh(server)
    return server


@pytest.mark.parametrize("serial", _SERIALS)
def test_server_serial_round_trips_full_uint64(session: Session, serial: int) -> None:
    """A Vault serial >= 2**63 persists and reads back unchanged."""
    server = _server(session)
    server.host_cert_serial = serial
    session.add(server)
    session.commit()
    session.expire_all()

    loaded = session.exec(select(Server).where(Server.id == server.id)).one()
    assert loaded.host_cert_serial == serial


@pytest.mark.parametrize("serial", _SERIALS)
def test_client_serial_round_trips_full_uint64(session: Session, serial: int) -> None:
    """Client twin of the server test (Alembic 0017 columns)."""
    server = _server(session)
    client = Client(
        name="pihole-0",
        hostname="10.8.0.3",
        server_id=server.id,
        ssh_key_id=server.ssh_key_id,
    )
    client.host_cert_serial = serial
    session.add(client)
    session.commit()
    session.expire_all()

    loaded = session.exec(select(Client).where(Client.id == client.id)).one()
    assert loaded.host_cert_serial == serial


def test_existing_signed_range_serials_read_back_unchanged(session: Session) -> None:
    """Serials stored before the fix (all < 2**63) keep their value."""
    server = _server(session)
    server.host_cert_serial = 5677117278696306938
    session.add(server)
    session.commit()
    session.expire_all()

    loaded = session.exec(select(Server).where(Server.id == server.id)).one()
    assert loaded.host_cert_serial == 5677117278696306938


@pytest.mark.parametrize("model", [Server, Client])
def test_mysql_column_is_bigint_unsigned(model: type) -> None:
    """On MySQL the column must be BIGINT UNSIGNED to hold a uint64."""
    column = model.__table__.c.host_cert_serial
    ddl = column.type.compile(dialect=mysql.dialect())
    assert ddl == "BIGINT UNSIGNED"


# ---------------------------------------------------------------------------
# Alembic 0020
# ---------------------------------------------------------------------------

_REVISION_BEFORE = "0019_server_reconfig_generations"
_REVISION_AT = "0020_host_cert_serial_unsigned"


def _alembic_config(database_url: str):
    """Alembic config pointed at ``database_url`` (same shape as 0019's test)."""
    from alembic.config import Config

    cfg = Config(str(Path(__file__).resolve().parent.parent / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", database_url)
    return cfg


def _offline_sql(monkeypatch: pytest.MonkeyPatch, revision_range: str) -> str:
    """Render the MySQL SQL for ``revision_range`` without a live server."""
    from alembic.command import downgrade, upgrade

    from wg_manager.config import settings as live_settings

    url = "mysql+pymysql://u:p@localhost/wg"
    # alembic/env.py reads the URL from Settings, not the ini.
    monkeypatch.setattr(live_settings, "database_url", url)
    out = io.StringIO()
    with redirect_stdout(out):
        if revision_range.startswith(_REVISION_AT):
            downgrade(_alembic_config(url), revision_range, sql=True)
        else:
            upgrade(_alembic_config(url), revision_range, sql=True)
    return out.getvalue()


def test_upgrade_makes_both_serial_columns_unsigned_on_mysql(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """0020 widens server + client serials to BIGINT UNSIGNED."""
    sql = _offline_sql(monkeypatch, f"{_REVISION_BEFORE}:{_REVISION_AT}")
    for table in ("server", "client"):
        assert f"ALTER TABLE {table} MODIFY host_cert_serial BIGINT UNSIGNED NULL" in sql


def test_downgrade_clears_out_of_range_serials_before_narrowing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Narrowing back to signed BIGINT would fail on any serial >= 2**63.

    The downgrade NULLs those first (the serial is metadata only; the
    next rotation re-populates it) so it can't strand the schema.
    """
    sql = _offline_sql(monkeypatch, f"{_REVISION_AT}:{_REVISION_BEFORE}")
    for table in ("server", "client"):
        assert (
            f"UPDATE {table} SET host_cert_serial = NULL "
            f"WHERE host_cert_serial >= {2**63}"
        ) in sql
        assert f"ALTER TABLE {table} MODIFY host_cert_serial BIGINT NULL" in sql
        assert sql.index(f"UPDATE {table}") < sql.index(
            f"ALTER TABLE {table} MODIFY host_cert_serial BIGINT NULL"
        )


def test_upgrade_and_downgrade_run_on_sqlite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SQLite has no unsigned type; 0020 must be a clean no-op there."""
    from alembic.command import downgrade, upgrade

    from wg_manager.config import settings as live_settings

    url = f"sqlite:///{tmp_path / 'wg_manager_0020.sqlite'}"
    monkeypatch.setattr(live_settings, "database_url", url)
    cfg = _alembic_config(url)
    upgrade(cfg, _REVISION_AT)
    downgrade(cfg, _REVISION_BEFORE)
