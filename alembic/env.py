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

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

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
    """Run migrations against a live DB connection."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
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
