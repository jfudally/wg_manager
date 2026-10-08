"""Tests for Alembic 0022: source-network binding on ``enrollmenttoken``.

``allowed_cidrs`` backs the optional ``allowed_cidrs`` field on
``POST /enrollment-tokens``. It's nullable (NULL = redeemable from
anywhere), so existing tokens behave exactly as before the upgrade.

The revision was first published as ``0022_enrollment_token_source_binding``.
At 36 characters that id overflows MySQL's ``alembic_version.version_num``
(``VARCHAR(32)``): the ``ADD COLUMN`` committed, the version update failed,
and every retry hit "Duplicate column name". The id is now short enough,
and the upgrade skips a column that a failed attempt already added.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text

_REVISION_BEFORE = "0021_enrollment_token_revocation"
_REVISION_AT = "0022_enroll_token_source_binding"
_COLUMNS = ("allowed_cidrs",)


def _alembic_config(database_url: str):
    from alembic.config import Config

    cfg = Config(str(Path(__file__).resolve().parent.parent / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", database_url)
    return cfg


@pytest.fixture()
def file_db_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    from wg_manager.config import settings as live_settings

    url = f"sqlite:///{tmp_path / 'wg_manager_0022.sqlite'}"
    monkeypatch.setattr(live_settings, "database_url", url)
    return url


def _token_columns(url: str) -> dict[str, dict]:
    engine = create_engine(url)
    try:
        return {c["name"]: c for c in inspect(engine).get_columns("enrollmenttoken")}
    finally:
        engine.dispose()


def test_upgrade_adds_nullable_columns(file_db_url: str) -> None:
    from alembic.command import upgrade

    upgrade(_alembic_config(file_db_url), _REVISION_AT)
    cols = _token_columns(file_db_url)
    for name in _COLUMNS:
        assert name in cols
        assert cols[name]["nullable"], name


def test_downgrade_drops_columns(file_db_url: str) -> None:
    from alembic.command import downgrade, upgrade

    cfg = _alembic_config(file_db_url)
    upgrade(cfg, _REVISION_AT)
    downgrade(cfg, _REVISION_BEFORE)
    assert not set(_COLUMNS) & set(_token_columns(file_db_url))


def test_model_has_columns() -> None:
    from wg_manager.models import EnrollmentToken

    assert set(_COLUMNS) <= set(EnrollmentToken.__table__.columns.keys())


def test_upgrade_completes_when_a_failed_attempt_added_the_column(
    file_db_url: str,
) -> None:
    """The half-applied state v0.9.0/v0.10.0 left on MySQL upgrades cleanly."""
    from alembic.command import upgrade

    cfg = _alembic_config(file_db_url)
    upgrade(cfg, _REVISION_BEFORE)
    engine = create_engine(file_db_url)
    try:
        with engine.begin() as conn:
            conn.execute(
                text("ALTER TABLE enrollmenttoken ADD COLUMN allowed_cidrs VARCHAR(1024)")
            )
    finally:
        engine.dispose()

    upgrade(cfg, _REVISION_AT)

    assert "allowed_cidrs" in _token_columns(file_db_url)
    engine = create_engine(file_db_url)
    try:
        with engine.connect() as conn:
            version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
    finally:
        engine.dispose()
    assert version == _REVISION_AT
