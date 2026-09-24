"""Tests for Alembic 0017 — host-cert columns on ``client``.

Mirrors 0006 (which added the same six columns to ``server``) so
SSH-provisioned clients can record the host cert the SSH CA last
issued them and ``POST /clients/{id}/rotate-host-cert`` has somewhere
to write the rotated cert. All columns are nullable: manual clients
never get a host cert, and existing rows stay NULL until their next
provision or rotation.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect

_REVISION_BEFORE = "0016_add_tenant_subnet_pool"
_REVISION_AT = "0017_client_host_cert_columns"
_COLUMNS = {
    "host_cert_pem",
    "host_cert_serial",
    "host_cert_principals",
    "host_cert_valid_after",
    "host_cert_valid_before",
    "host_cert_ca_public_key",
}


def _alembic_config(database_url: str):
    from alembic.config import Config

    cfg = Config(str(Path(__file__).resolve().parent.parent / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", database_url)
    return cfg


@pytest.fixture()
def file_db_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    from wg_manager.config import settings as live_settings

    url = f"sqlite:///{tmp_path / 'wg_manager_0017.sqlite'}"
    monkeypatch.setattr(live_settings, "database_url", url)
    return url


def _client_columns(database_url: str) -> dict[str, dict]:
    engine = create_engine(database_url)
    try:
        return {c["name"]: c for c in inspect(engine).get_columns("client")}
    finally:
        engine.dispose()


def test_upgrade_adds_nullable_host_cert_columns(file_db_url: str) -> None:
    from alembic.command import upgrade

    upgrade(_alembic_config(file_db_url), _REVISION_AT)
    cols = _client_columns(file_db_url)
    assert _COLUMNS <= set(cols)
    assert all(cols[name]["nullable"] for name in _COLUMNS)


def test_downgrade_drops_host_cert_columns(file_db_url: str) -> None:
    from alembic.command import downgrade, upgrade

    cfg = _alembic_config(file_db_url)
    upgrade(cfg, _REVISION_AT)
    downgrade(cfg, _REVISION_BEFORE)
    assert not (_COLUMNS & set(_client_columns(file_db_url)))
