"""Tests for Alembic 0019: hub reconfigure generation counters.

``server.reconfig_requested_gen`` / ``reconfig_applied_gen`` let
``reconfigure_server_task`` coalesce bursts without losing updates. They
must be NOT NULL with a server default of 0, so existing rows start out
"in sync" and the upgrade doesn't block on a populated DB.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect

_REVISION_BEFORE = "0018_add_enrollment_token"
_REVISION_AT = "0019_server_reconfig_generations"
_COLUMNS = ("reconfig_requested_gen", "reconfig_applied_gen")


def _alembic_config(database_url: str):
    from alembic.config import Config

    cfg = Config(str(Path(__file__).resolve().parent.parent / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", database_url)
    return cfg


@pytest.fixture()
def file_db_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    from wg_manager.config import settings as live_settings

    url = f"sqlite:///{tmp_path / 'wg_manager_0019.sqlite'}"
    monkeypatch.setattr(live_settings, "database_url", url)
    return url


def _server_columns(url: str) -> dict[str, dict]:
    engine = create_engine(url)
    try:
        return {c["name"]: c for c in inspect(engine).get_columns("server")}
    finally:
        engine.dispose()


def test_upgrade_adds_not_null_zero_default_columns(file_db_url: str) -> None:
    from alembic.command import upgrade

    upgrade(_alembic_config(file_db_url), _REVISION_AT)
    cols = _server_columns(file_db_url)
    for name in _COLUMNS:
        assert name in cols
        assert not cols[name]["nullable"], name
        assert str(cols[name]["default"]).strip("'\"") == "0", name


def test_downgrade_drops_columns(file_db_url: str) -> None:
    from alembic.command import downgrade, upgrade

    cfg = _alembic_config(file_db_url)
    upgrade(cfg, _REVISION_AT)
    downgrade(cfg, _REVISION_BEFORE)
    assert not set(_COLUMNS) & set(_server_columns(file_db_url))


def test_model_has_columns() -> None:
    from wg_manager.models import Server

    assert set(_COLUMNS) <= set(Server.__table__.columns.keys())
