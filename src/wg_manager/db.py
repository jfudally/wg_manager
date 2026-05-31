"""Database engine and session dependency.

Phase 2d CP4.1 wires MySQL TLS connect args into the engine: when
:attr:`Settings.database_tls_required` is ``True`` and the URL resolves
to a MySQL driver, :func:`_resolve_mysql_ssl` materialises the
``ssl.{ca,cert,key,check_hostname}`` dict pymysql expects. The helper
is split out from :func:`_build_engine` so the wiring is unit-testable
without standing up MySQL.
"""

from __future__ import annotations

import os
from collections.abc import Generator
from typing import Any

from sqlalchemy.engine import Engine
from sqlmodel import Session, SQLModel, create_engine

from wg_manager.config import Settings, settings

_MYSQL_DRIVERS = ("mysql", "mariadb")


def _is_mysql_url(url: str) -> bool:
    """Whether ``url`` resolves to a MySQL/MariaDB SQLAlchemy driver.

    :param url: SQLAlchemy connection URL.
    :type url: str
    :return: ``True`` for ``mysql+*://`` and ``mariadb+*://`` shapes;
        ``False`` for SQLite, PostgreSQL, and friends.
    :rtype: bool
    """
    scheme = url.split("://", 1)[0].lower()
    base = scheme.split("+", 1)[0]
    return base in _MYSQL_DRIVERS


def _resolve_mysql_ssl(
    url: str, settings_obj: Settings | None = None
) -> dict[str, Any]:
    """Materialise pymysql ``ssl`` connect-args from Settings.

    Returns ``{}`` (i.e. "no TLS") for any of:

    - Non-MySQL URLs (SQLite, Postgres, …).
    - MySQL URL with ``DATABASE_TLS_REQUIRED=false`` — the pre-CP4
      cleartext path stays available for tests and old deployments.

    Returns ``{"ssl": {"ca": ..., "cert": ..., "key": ...,
    "check_hostname": True}}`` when MySQL + TLS is required and all
    three PEM paths point at readable files.

    :param url: SQLAlchemy connection URL.
    :type url: str
    :param settings_obj: Settings instance to read TLS fields from.
        Defaults to the module-level :data:`settings` singleton; tests
        inject a custom instance to pin a specific configuration.
    :type settings_obj: Settings | None
    :return: A dict suitable for ``create_engine(connect_args=...)``.
    :rtype: dict[str, Any]
    :raises RuntimeError: When ``database_tls_required=True`` but any
        of the three PEM paths is unset or points at a non-existent
        file. The error names which env var is misconfigured so a
        misformatted ``.env`` fails at startup with a clear message.
    """
    s = settings_obj if settings_obj is not None else settings
    if not _is_mysql_url(url):
        return {}
    if not s.database_tls_required:
        return {}

    paths: dict[str, str | None] = {
        "DATABASE_TLS_CA_PEM": s.database_tls_ca_pem,
        "DATABASE_TLS_CERT_PEM": s.database_tls_cert_pem,
        "DATABASE_TLS_KEY_PEM": s.database_tls_key_pem,
    }
    for env_var, value in paths.items():
        if value is None or value == "":
            raise RuntimeError(
                f"{env_var} is required when DATABASE_TLS_REQUIRED=true"
            )
        if not os.path.isfile(value):
            raise RuntimeError(
                f"{env_var} path {value!r} not found on disk"
            )

    return {
        "ssl": {
            "ca": str(s.database_tls_ca_pem),
            "cert": str(s.database_tls_cert_pem),
            "key": str(s.database_tls_key_pem),
            "check_hostname": True,
        }
    }


def _build_engine(url: str, settings_obj: Settings | None = None) -> Engine:
    """Create a SQLAlchemy engine for the given URL.

    :param url: SQLAlchemy connection URL.
    :type url: str
    :param settings_obj: Settings instance used to resolve MySQL TLS
        connect args; defaults to the module-level singleton.
    :type settings_obj: Settings | None
    :return: A configured SQLAlchemy engine.
    :rtype: Engine
    """
    connect_args: dict[str, Any] = {}
    if url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    connect_args.update(_resolve_mysql_ssl(url, settings_obj))
    return create_engine(url, echo=False, pool_pre_ping=True, connect_args=connect_args)


engine: Engine = _build_engine(settings.database_url)


def init_db() -> None:
    """Create all SQLModel tables on the configured engine.

    :return: None.
    :rtype: None
    """
    # Import side-effect: ensures models are registered on metadata.
    from wg_manager import models  # noqa: F401

    SQLModel.metadata.create_all(engine)


def get_session() -> Generator[Session, Any, None]:
    """FastAPI dependency yielding a scoped SQLModel session.

    :return: A session bound to the shared engine.
    :rtype: Generator[Session, Any, None]
    """
    with Session(engine) as session:
        yield session
