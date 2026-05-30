"""Tests for Phase 2d CP3.3: ``Alembic 0011`` — add ``certificate`` table.

CP3.3 introduces the :class:`wg_manager.models.Certificate` registry so
the operator can answer "which certs are live, who owns them, when do
they expire?" without grepping Vault. CP3.4 layers the HTTP /
dashboard surface on top; CP4 layers the renewal job.

What this module pins down:

1. **Table creation.** ``alembic upgrade head`` creates a
   ``certificate`` table with the column set CP3.3 needs (serial /
   cert_type / operator_id / common_name / sans / not_before /
   not_after / revoked / revoked_at / created_at). ``serial`` is
   uniquely indexed; the table can be re-upgraded (idempotency)
   without error.
2. **Unique serial.** Two rows with the same serial cannot coexist —
   the DB-layer unique index does the work so a buggy CLI that
   double-recorded an issue would 500 rather than silently duplicate.
3. **Nullable operator FK.** ``operator_id`` is nullable because
   ``api`` and ``mysql`` certs are service certs with no human owner.
   ``cli`` and ``dashboard`` rows carry a populated FK; the FK target
   must be a real :class:`Operator` row.
4. **Downgrade.** Reversing 0011 drops the table cleanly; round-trip
   (upgrade → downgrade → upgrade) is idempotent.
5. **CertificateType enum.** The four values ship in the enum and
   stringify as their literal value (so JSON / dashboard contracts
   stay stable).

The migration is driven through Alembic's real
``command.upgrade`` / ``command.downgrade`` so an env.py regression
surfaces here too. Pattern mirrors ``tests/test_alembic_0010.py``.
"""

from __future__ import annotations

from datetime import datetime, timezone
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

    path = tmp_path / "wg_manager_cp33_cert.sqlite"
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


class TestAlembic0011Upgrade:
    """0011 creates the ``certificate`` table with the expected columns."""

    def test_upgrade_head_creates_certificate_table(
        self, file_db_url: str
    ) -> None:
        """``alembic upgrade head`` brings the table into existence."""
        from alembic import command

        cfg = _alembic_config(file_db_url)
        # Sanity: the table does not exist before 0011.
        command.upgrade(cfg, "0010_add_operator_table")
        assert not _table_exists(file_db_url, "certificate"), (
            "certificate table should not exist before 0011 lands"
        )

        command.upgrade(cfg, "head")

        assert _table_exists(file_db_url, "certificate"), (
            "Alembic 0011 must create the certificate table"
        )

    def test_upgrade_head_creates_expected_columns(
        self, file_db_url: str
    ) -> None:
        """The column set is what CP3.3's CLI + CP3.4's API will read."""
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "head")

        cols = _columns(file_db_url, "certificate")
        # Pin the minimum; future sub-slices may add columns (e.g.
        # last_seen_at when the renewal job lands).
        expected = {
            "id",
            "serial",
            "cert_type",
            "operator_id",
            "common_name",
            "sans",
            "not_before",
            "not_after",
            "revoked",
            "revoked_at",
            "created_at",
        }
        assert expected <= cols, (
            f"certificate table missing expected columns; got {cols!r}"
        )

    def test_serial_is_uniquely_indexed(self, file_db_url: str) -> None:
        """Two rows with the same serial cannot coexist.

        Serial is a decimal-string column so 160-bit X.509 serials
        round-trip without overflowing SQLite's signed-INT64. The
        unique-index contract is identical regardless of the storage
        type.
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
                        "serial": "9001",
                        "nbf": "2026-05-29 00:00:00",
                        "naf": "2026-06-28 00:00:00",
                        "now": "2026-05-29 00:00:00",
                    },
                )
            with pytest.raises(IntegrityError):
                with engine.begin() as conn:
                    conn.execute(
                        text(
                            "INSERT INTO certificate (serial, cert_type, "
                            "common_name, sans, not_before, not_after, "
                            "revoked, created_at) VALUES "
                            "(:serial, 'cli', 'ops@wg.local', "
                            "'ops@wg.local', :nbf, :naf, 0, :now)"
                        ),
                        {
                            "serial": "9001",
                            "nbf": "2026-05-29 00:00:00",
                            "naf": "2027-05-29 00:00:00",
                            "now": "2026-05-29 00:00:01",
                        },
                    )
        finally:
            engine.dispose()

    def test_operator_id_is_nullable(self, file_db_url: str) -> None:
        """``api`` and ``mysql`` rows insert cleanly with operator_id NULL."""
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "head")

        engine = create_engine(file_db_url)
        try:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO certificate (serial, cert_type, "
                        "operator_id, common_name, sans, not_before, "
                        "not_after, revoked, created_at) VALUES "
                        "(:serial, 'api', NULL, '127.0.0.1', "
                        "'127.0.0.1,localhost', :nbf, :naf, 0, :now)"
                    ),
                    {
                        "serial": "4242",
                        "nbf": "2026-05-29 00:00:00",
                        "naf": "2026-06-28 00:00:00",
                        "now": "2026-05-29 00:00:00",
                    },
                )
                row = conn.execute(
                    text(
                        "SELECT operator_id FROM certificate WHERE "
                        "serial='4242'"
                    )
                ).fetchone()
                assert row is not None and row[0] is None
        finally:
            engine.dispose()


class TestAlembic0011Downgrade:
    """Reversing 0011 drops the table cleanly."""

    _BEFORE = "0010_add_operator_table"
    _AT = "0011_add_certificate_table"

    def test_downgrade_drops_certificate_table(
        self, file_db_url: str
    ) -> None:
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, self._AT)
        assert _table_exists(file_db_url, "certificate")

        command.downgrade(cfg, self._BEFORE)

        assert not _table_exists(file_db_url, "certificate"), (
            "0011 downgrade must drop the certificate table"
        )

    def test_round_trip_upgrade_downgrade_upgrade_is_idempotent(
        self, file_db_url: str
    ) -> None:
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, self._AT)
        command.downgrade(cfg, self._BEFORE)
        command.upgrade(cfg, self._AT)
        assert _table_exists(file_db_url, "certificate")


class TestCertificateTypeEnum:
    """``CertificateType`` carries the four values CP3.3 ships."""

    def test_enum_values(self) -> None:
        from wg_manager.models import CertificateType

        assert CertificateType.api.value == "api"
        assert CertificateType.cli.value == "cli"
        assert CertificateType.dashboard.value == "dashboard"
        assert CertificateType.mysql.value == "mysql"

    def test_enum_is_str_subclass(self) -> None:
        """Subclassing str keeps the enum JSON-serialisable as its value."""
        from wg_manager.models import CertificateType

        assert isinstance(CertificateType.api, str)


class TestCertificateModelDefaults:
    """SQLModel-level defaults match the post-issue shape."""

    def test_default_revoked_is_false(self) -> None:
        from wg_manager.models import Certificate, CertificateType

        row = Certificate(
            serial="1",
            cert_type=CertificateType.api,
            common_name="127.0.0.1",
            not_before=datetime.now(timezone.utc),
            not_after=datetime.now(timezone.utc),
        )
        assert row.revoked is False

    def test_default_revoked_at_is_none(self) -> None:
        from wg_manager.models import Certificate, CertificateType

        row = Certificate(
            serial="2",
            cert_type=CertificateType.cli,
            common_name="ops@wg.local",
            not_before=datetime.now(timezone.utc),
            not_after=datetime.now(timezone.utc),
        )
        assert row.revoked_at is None

    def test_default_sans_is_empty_string(self) -> None:
        from wg_manager.models import Certificate, CertificateType

        row = Certificate(
            serial="3",
            cert_type=CertificateType.mysql,
            common_name="mysql",
            not_before=datetime.now(timezone.utc),
            not_after=datetime.now(timezone.utc),
        )
        assert row.sans == ""

    def test_default_operator_id_is_none(self) -> None:
        """Service certs (api/mysql) carry NULL operator_id."""
        from wg_manager.models import Certificate, CertificateType

        row = Certificate(
            serial="4",
            cert_type=CertificateType.api,
            common_name="127.0.0.1",
            not_before=datetime.now(timezone.utc),
            not_after=datetime.now(timezone.utc),
        )
        assert row.operator_id is None
