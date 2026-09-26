"""Tests for Alembic 0018 — the ``enrollmenttoken`` table (Phase 3f MVP).

The table backs single-/multi-use enrollment tokens that let a fresh
host join the fleet from userdata. Only the SHA-256 of each token is
stored, so ``token_hash`` must be unique (it is the lookup key on
redemption) and there must be no plaintext column.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect

_REVISION_BEFORE = "0017_client_host_cert_columns"
_REVISION_AT = "0018_add_enrollment_token"
_COLUMNS = {
    "id",
    "tenant_id",
    "server_id",
    "ssh_key_id",
    "ssh_username",
    "name_prefix",
    "token_hash",
    "max_uses",
    "use_count",
    "expires_at",
    "created_by_cn",
    "created_at",
}


def _alembic_config(database_url: str):
    from alembic.config import Config

    cfg = Config(str(Path(__file__).resolve().parent.parent / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", database_url)
    return cfg


@pytest.fixture()
def file_db_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    from wg_manager.config import settings as live_settings

    url = f"sqlite:///{tmp_path / 'wg_manager_0018.sqlite'}"
    monkeypatch.setattr(live_settings, "database_url", url)
    return url


def _inspect(database_url: str):
    engine = create_engine(database_url)
    return engine, inspect(engine)


def test_upgrade_creates_table_with_expected_columns(file_db_url: str) -> None:
    from alembic.command import upgrade

    upgrade(_alembic_config(file_db_url), _REVISION_AT)
    engine, insp = _inspect(file_db_url)
    try:
        cols = {c["name"]: c for c in insp.get_columns("enrollmenttoken")}
    finally:
        engine.dispose()
    assert set(cols) == _COLUMNS
    # Every column that the redemption path relies on is NOT NULL.
    for name in ("server_id", "ssh_key_id", "ssh_username", "token_hash",
                 "max_uses", "use_count", "expires_at"):
        assert not cols[name]["nullable"], name


def test_token_hash_is_unique(file_db_url: str) -> None:
    from alembic.command import upgrade

    upgrade(_alembic_config(file_db_url), _REVISION_AT)
    engine, insp = _inspect(file_db_url)
    try:
        unique_cols = [
            tuple(ix["column_names"])
            for ix in insp.get_indexes("enrollmenttoken")
            if ix["unique"]
        ] + [
            tuple(uc["column_names"])
            for uc in insp.get_unique_constraints("enrollmenttoken")
        ]
    finally:
        engine.dispose()
    assert ("token_hash",) in unique_cols


def test_downgrade_drops_table(file_db_url: str) -> None:
    from alembic.command import downgrade, upgrade

    cfg = _alembic_config(file_db_url)
    upgrade(cfg, _REVISION_AT)
    downgrade(cfg, _REVISION_BEFORE)
    engine, insp = _inspect(file_db_url)
    try:
        assert "enrollmenttoken" not in insp.get_table_names()
    finally:
        engine.dispose()


def test_model_matches_migrations_at_head(file_db_url: str) -> None:
    """The SQLModel table and the migration chain agree on the column set.

    Compared at ``head`` rather than at 0018, so later migrations that
    add columns (0020's revocation columns) don't break this check.
    """
    from alembic.command import upgrade

    from wg_manager.models import EnrollmentToken

    upgrade(_alembic_config(file_db_url), "head")
    engine, insp = _inspect(file_db_url)
    try:
        migrated = {c["name"] for c in insp.get_columns("enrollmenttoken")}
    finally:
        engine.dispose()
    assert _COLUMNS <= migrated
    assert set(EnrollmentToken.__table__.columns.keys()) == migrated
