"""Every model datetime is stored as UTC and read back aware.

sqlmodel 0.0.45 maps plain ``datetime`` fields to its ``UTCDateTime``
column type: writes must be timezone-aware (a naive value raises at
execute time) and are converted to UTC; reads come back aware UTC even
from backends whose ``DATETIME`` has no zone (MySQL, SQLite). The
column DDL is unchanged (``DATETIME``), so no migration is involved.

Pinned behaviours:

1. No model datetime column opts out into naive storage. A field
   annotated ``NaiveDatetime`` would read back naive and break every
   comparison against ``datetime.now(timezone.utc)``; adding one should
   be a deliberate change to this test.
2. An aware value in any zone round-trips as the same instant, in UTC.
3. A naive value is refused rather than silently stored in an unknown
   zone.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import DateTime
from sqlalchemy.exc import StatementError
from sqlalchemy.types import TypeDecorator
from sqlmodel import Session, SQLModel, select
from sqlmodel.sql.sqltypes import UTCDateTime

import wg_manager.models  # noqa: F401 — registers every table
from wg_manager.models import SSHKey


def _datetime_columns() -> list[Any]:
    """Every ``DateTime``-backed column, across all tables.

    Matches decorated types too (``UTCDateTime`` wraps ``DateTime``);
    ``python_type`` can't be used because a ``TypeDecorator`` raises
    ``NotImplementedError`` for it.
    """
    out = []
    for table in SQLModel.metadata.sorted_tables:
        for column in table.columns:
            base = column.type
            if isinstance(base, TypeDecorator):
                base = base.impl_instance
            if isinstance(base, DateTime):
                out.append(column)
    return out


def test_every_datetime_column_is_utc() -> None:
    """All datetime columns use ``UTCDateTime`` (none opt into naive)."""
    columns = _datetime_columns()
    # Sanity: the walk found the timestamps the models are known to have.
    assert len(columns) >= 10
    naive = [
        f"{c.table.name}.{c.name}"
        for c in columns
        if not isinstance(c.type, UTCDateTime)
    ]
    assert naive == []


def test_aware_value_round_trips_as_the_same_utc_instant(engine: Any) -> None:
    """A non-UTC aware write reads back aware, in UTC, same instant."""
    plus_two = timezone(timedelta(hours=2))
    written = datetime(2026, 10, 8, 14, 30, tzinfo=plus_two)
    with Session(engine) as s:
        s.add(SSHKey(name="lab", created_at=written))
        s.commit()

    with Session(engine) as s:
        (row,) = s.exec(select(SSHKey)).all()
    assert row.created_at.tzinfo == timezone.utc
    assert row.created_at == written
    assert row.created_at.hour == 12


def test_naive_value_is_refused(engine: Any) -> None:
    """A naive write raises instead of storing an ambiguous instant."""
    with Session(engine) as s:
        s.add(SSHKey(name="lab", created_at=datetime(2026, 10, 8, 12, 0)))
        with pytest.raises(StatementError, match="timezone information"):
            s.commit()
