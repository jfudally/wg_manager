"""``wg-manager db backup`` / ``db restore`` must cover every table.

The original backup hard-coded three tables (``sshkey``, ``server``,
``client``). Everything added since — tenants, operators, certificates,
audit events, discovered peers, enrollment tokens — was silently left
out, so a "backup" taken before a migration could not restore the
deployment.

Pinned behaviours:

1. A backup contains every table in ``SQLModel.metadata`` and is
   format version 2.
2. Backup from one database and restore into an empty one reproduces
   every row of every table exactly, including enum columns whose value
   differs from their name (``CertificateType.mysql_client`` is stored
   as ``"mysql-client"``).
3. Restore refuses to run over a non-empty table that isn't one of the
   original three (without ``--drop-existing``).
4. ``--drop-existing`` over a fully populated database works (children
   are deleted before parents).
5. A version 1 file (the old three-table format) still restores.

Each test uses its own SQLite files passed via ``--database-url``, so
no monkeypatching of the module-level engine is needed.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.sql.sqltypes import UTCDateTime
from typer.testing import CliRunner

from wg_manager import cli
from wg_manager.models import (
    AuditEvent,
    Certificate,
    CertificateType,
    Client,
    DiscoveredPeer,
    EnrollmentToken,
    Operator,
    OperatorTenant,
    Server,
    SSHKey,
    Tenant,
)

NOW = datetime(2026, 9, 27, 12, 0, 0, tzinfo=timezone.utc)
# What wg-manager wrote into backups before sqlmodel 0.0.45: the columns
# read back naive, so their ISO strings carry no offset.
NOW_NAIVE_ISO = NOW.replace(tzinfo=None).isoformat()


def _make_db(path: Path) -> tuple[str, Any]:
    """Create an empty SQLite database with the full schema.

    :param path: File to create the database in.
    :return: ``(url, engine)`` for the new database.
    """
    url = f"sqlite:///{path}"
    engine = create_engine(url)
    SQLModel.metadata.create_all(engine)
    return url, engine


def _seed_every_table(engine: Any) -> None:
    """Insert at least one row into every table, respecting FKs."""
    with Session(engine) as s:
        tenant = Tenant(name="Acme", slug="acme")
        s.add(tenant)
        s.flush()
        operator = Operator(cn="ops@acme.example", tenant_id=tenant.id)
        s.add(operator)
        s.flush()
        s.add(OperatorTenant(operator_id=operator.id, tenant_id=tenant.id))
        key = SSHKey(name="lab", tenant_id=tenant.id)
        s.add(key)
        s.flush()
        server = Server(
            hostname="hub.example.com",
            ssh_username="ubuntu",
            ssh_key_id=key.id,
            endpoint_host="hub.example.com",
            tenant_id=tenant.id,
        )
        s.add(server)
        s.flush()
        s.add(Client(name="alpha", server_id=server.id, tenant_id=tenant.id))
        s.add(DiscoveredPeer(server_id=server.id, public_key="PEERPUB"))
        s.add(
            EnrollmentToken(
                server_id=server.id,
                ssh_key_id=key.id,
                ssh_username="ubuntu",
                token_hash="0" * 64,
                expires_at=NOW + timedelta(hours=1),
                tenant_id=tenant.id,
            )
        )
        s.add(
            Certificate(
                serial="0a:0b",
                # Value "mysql-client" differs from the member name —
                # the restore must map it back to the enum member.
                cert_type=CertificateType.mysql_client,
                common_name="mysql-client",
                not_before=NOW,
                not_after=NOW + timedelta(days=30),
            )
        )
        s.add(
            AuditEvent(
                event="server.create",
                resource_type="server",
                action="create",
                tenant_id=tenant.id,
            )
        )
        s.commit()


def _snapshot(engine: Any) -> dict[str, list[tuple[Any, ...]]]:
    """Return every row of every table, ordered by primary key."""
    out: dict[str, list[tuple[Any, ...]]] = {}
    with engine.connect() as conn:
        for table in SQLModel.metadata.sorted_tables:
            stmt = select(table).order_by(*table.primary_key.columns)
            out[table.name] = [tuple(r) for r in conn.execute(stmt)]
    return out


def _run(runner: CliRunner, *args: str) -> Any:
    """Invoke the CLI and fail loudly with its output on a non-zero exit."""
    result = runner.invoke(cli.app, list(args))
    assert result.exit_code == 0, result.output
    return result


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def test_backup_includes_every_table(runner: CliRunner, tmp_path: Path) -> None:
    url, engine = _make_db(tmp_path / "src.db")
    _seed_every_table(engine)
    out = tmp_path / "backup.json"

    _run(runner, "db", "backup", "--output", str(out), "--database-url", url)

    data = json.loads(out.read_text())
    assert data["version"] == 2
    expected = {t.name for t in SQLModel.metadata.sorted_tables}
    assert set(data["tables"]) == expected
    for name in expected:
        assert len(data["tables"][name]) >= 1, f"{name} has no rows"


def test_backup_writes_datetimes_in_utc(runner: CliRunner, tmp_path: Path) -> None:
    """Every datetime in the file carries an explicit UTC offset."""
    url, engine = _make_db(tmp_path / "src.db")
    _seed_every_table(engine)
    out = tmp_path / "backup.json"

    _run(runner, "db", "backup", "--output", str(out), "--database-url", url)

    data = json.loads(out.read_text())
    stamps = [
        row[col.name]
        for table in SQLModel.metadata.sorted_tables
        for row in data["tables"][table.name]
        for col in table.columns
        if isinstance(col.type, UTCDateTime) and row.get(col.name) is not None
    ]
    assert stamps, "seed data should include datetimes"
    for stamp in stamps:
        assert datetime.fromisoformat(stamp).utcoffset() == timedelta(0), stamp


def test_round_trip_into_empty_db_preserves_every_row(
    runner: CliRunner, tmp_path: Path
) -> None:
    src_url, src = _make_db(tmp_path / "src.db")
    dst_url, dst = _make_db(tmp_path / "dst.db")
    _seed_every_table(src)
    out = tmp_path / "backup.json"

    _run(runner, "db", "backup", "--output", str(out), "--database-url", src_url)
    _run(runner, "db", "restore", "--input", str(out), "--database-url", dst_url)

    assert _snapshot(dst) == _snapshot(src)


def test_restore_refuses_when_any_table_has_rows(
    runner: CliRunner, tmp_path: Path
) -> None:
    src_url, src = _make_db(tmp_path / "src.db")
    dst_url, dst = _make_db(tmp_path / "dst.db")
    _seed_every_table(src)
    out = tmp_path / "backup.json"
    _run(runner, "db", "backup", "--output", str(out), "--database-url", src_url)

    # Only a table outside the original three is non-empty.
    with Session(dst) as s:
        s.add(Tenant(name="Other", slug="other"))
        s.commit()

    result = runner.invoke(
        cli.app,
        ["db", "restore", "--input", str(out), "--database-url", dst_url],
    )
    assert result.exit_code == 1
    assert "tenant" in result.output


def test_drop_existing_over_fully_populated_db(
    runner: CliRunner, tmp_path: Path
) -> None:
    url, engine = _make_db(tmp_path / "src.db")
    _seed_every_table(engine)
    before = _snapshot(engine)
    out = tmp_path / "backup.json"
    _run(runner, "db", "backup", "--output", str(out), "--database-url", url)

    _run(
        runner,
        "db", "restore", "--input", str(out), "--database-url", url,
        "--drop-existing",
    )

    assert _snapshot(engine) == before


def test_version_1_backup_still_restores(
    runner: CliRunner, tmp_path: Path
) -> None:
    """Files written by v0.6.x and earlier carry only three tables.

    Their datetimes are naive ISO strings (wg-manager read columns back
    naive until sqlmodel 0.0.45); restore treats them as UTC.
    """
    dst_url, dst = _make_db(tmp_path / "dst.db")
    v1 = {
        "version": 1,
        "tables": {
            "sshkey": [
                {"id": 1, "name": "lab", "created_at": NOW_NAIVE_ISO,
                 "mode": "ca", "tenant_id": None},
            ],
            "server": [
                {"id": 1, "hostname": "hub.example.com", "ssh_port": 22,
                 "ssh_username": "ubuntu", "ssh_key_id": 1,
                 "endpoint_host": "hub.example.com", "status": "ready",
                 "created_at": NOW_NAIVE_ISO},
            ],
            "client": [],
        },
    }
    infile = tmp_path / "v1.json"
    infile.write_text(json.dumps(v1))

    _run(runner, "db", "restore", "--input", str(infile), "--database-url", dst_url)

    with Session(dst) as s:
        assert [k.name for k in s.exec(select(SSHKey)).scalars()] == ["lab"]
        servers = list(s.exec(select(Server)).scalars())
        assert [x.hostname for x in servers] == ["hub.example.com"]
        assert servers[0].created_at == NOW
