"""Alembic environment for wg-manager.

Pulls the database URL from :mod:`wg_manager.config` so it always matches
what the running app uses, and exposes ``SQLModel.metadata`` (populated by
importing :mod:`wg_manager.models`) for autogenerate support.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool
from sqlmodel import SQLModel

# Ensure all model classes are registered on SQLModel.metadata.
import wg_manager.models  # noqa: F401
from wg_manager.config import settings
from wg_manager.db import _resolve_mysql_ssl

config = context.config

if config.config_file_name is not None:
    # ``disable_existing_loggers=False`` is critical: with the default
    # (``True``), running ``alembic`` programmatically from a pytest
    # process silently turns off every logger that isn't named in
    # alembic.ini — including ``wg_manager.tasks``, which the SSH-error
    # regression tests assert on via ``caplog``. Preserving existing
    # loggers means the app's logging contract survives an in-process
    # alembic invocation (test suite, CLI helpers, ``make migrate``).
    fileConfig(config.config_file_name, disable_existing_loggers=False)

# Inject the runtime URL so it never has to be duplicated in alembic.ini.
config.set_main_option("sqlalchemy.url", settings.database_url)

target_metadata = SQLModel.metadata


def run_migrations_offline() -> None:
    """Run migrations without a live DB connection (emit SQL only)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live DB connection.

    Mirrors :func:`wg_manager.db._build_engine`'s MySQL TLS wiring so a
    ``make migrate`` against a TLS-required MySQL (Phase 2d CP4 prod
    posture) inherits the same ``ssl={ca, cert, key, check_hostname}``
    ``connect_args`` the app + worker use. Without this, the
    migrations engine bypasses TLS and MySQL rejects the connection
    with ``Connections using insecure transport are prohibited``.
    """
    # ``_resolve_mysql_ssl`` returns ``{}`` for SQLite + cleartext-
    # MySQL (the pre-CP4 path), so the call is a no-op in dev / test
    # configurations — only the prod-shaped TLS posture grows the
    # ``connect_args`` dict.
    connect_args = _resolve_mysql_ssl(settings.database_url, settings)
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        connect_args=connect_args,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
