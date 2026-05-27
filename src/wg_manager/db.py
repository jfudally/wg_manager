"""Database engine and session dependency."""

from __future__ import annotations

from collections.abc import Generator
from typing import Any

from sqlalchemy.engine import Engine
from sqlmodel import Session, SQLModel, create_engine

from wg_manager.config import settings


def _build_engine(url: str) -> Engine:
    """Create a SQLAlchemy engine for the given URL.

    :param url: SQLAlchemy connection URL.
    :type url: str
    :return: A configured SQLAlchemy engine.
    :rtype: Engine
    """
    connect_args: dict[str, Any] = {}
    if url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
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
