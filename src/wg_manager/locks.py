"""Per-row advisory locks for multi-worker Celery safety.

Phase 3d cycle 3 — every Celery task that mutates a single row
(``provision_server``, ``rotate_host_cert``, ``reconfigure_server``,
``provision_client``) acquires an advisory lock on entry. The lock
is connection-scoped and self-releases when its connection closes, so
a worker that crashes mid-task leaves no stranded lock for the next
re-delivery to walk into.

Two backends:

* **MySQL** (``pymysql:`` URL) — uses ``GET_LOCK(name, timeout)`` and
  ``RELEASE_LOCK(name)``. ``GET_LOCK`` returns ``1`` on success, ``0``
  on timeout (another connection holds it), ``NULL`` on driver error.
  The wrapper treats only ``1`` as "acquired".
* **SQLite** (test suite) — no-op acquire that always returns
  ``True``. SQLite's tests use ``StaticPool`` with a single
  connection, so there is no multi-connection contention shape
  worth modelling at the helper level. The task-layer integration
  tests cover the "what does the task do when the lock is
  contended" branch via a monkey-patched lock function.

The lock name shape is ``wgm:<scope>:<row_id>`` so the namespace
doesn't collide with other apps using ``GET_LOCK`` against a shared
MySQL. ``<scope>`` is a short literal — ``server`` / ``client`` /
``ssh_key`` — and ``<row_id>`` is the row's surrogate PK as a
positive integer.

A failed acquire is **not** an error. The yielded boolean is the
caller's branch point — return early with a ``{"status":"skipped"}``
result and let the broker decide whether to re-deliver later (when
the holding worker finishes).
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import text
from sqlmodel import Session

logger = logging.getLogger(__name__)

# Conservative default — wait at most this long for another worker
# to finish. In practice the tasks are short (seconds), so a few
# seconds of patience absorbs the common "two workers picked up
# adjacent provisions in the same batch" race without queuing
# unbounded waiters.
_DEFAULT_LOCK_TIMEOUT_SECONDS = 5


def lock_name_for(scope: str, row_id: int) -> str:
    """Build the canonical lock name ``wgm:<scope>:<row_id>``.

    :param scope: Short literal naming the row type
        (``server`` / ``client`` / ``ssh_key``). Must be non-empty.
    :param row_id: Row's surrogate primary key. Must be a positive
        integer (0 / negative are operator error — rows don't have
        non-positive primary keys).
    :returns: The lock name.
    :raises ValueError: When either argument is invalid.
    """
    if not scope:
        raise ValueError("lock scope must be a non-empty string")
    if row_id <= 0:
        raise ValueError(
            f"lock row_id must be positive; got {row_id!r}"
        )
    return f"wgm:{scope}:{row_id}"


def _is_mysql_session(session: Session) -> bool:
    """Return ``True`` iff ``session``'s bind speaks MySQL.

    Branch keeps SQLite's test path off the ``GET_LOCK`` codepath —
    pymysql exposes ``GET_LOCK`` natively but SQLite has no
    equivalent and would fail at SQL-parse time.
    """
    bind = session.get_bind()
    return bind.dialect.name in ("mysql", "mariadb")


@contextmanager
def task_row_lock(
    session: Session,
    scope: str,
    row_id: int,
    *,
    timeout_seconds: int = _DEFAULT_LOCK_TIMEOUT_SECONDS,
) -> Iterator[bool]:
    """Acquire an advisory row lock, yielding ``True`` on success.

    Usage::

        with task_row_lock(session, "server", server_id) as acquired:
            if not acquired:
                return {"status": "skipped", "reason": "concurrent_run"}
            # ... do the work ...

    On MySQL the lock is held until ``RELEASE_LOCK`` (run on context
    exit) or the underlying connection closes. On SQLite the
    acquire is a no-op that always yields ``True`` — the test
    suite's single-connection ``StaticPool`` has no contention
    shape to model. Tests that need to exercise the contended
    branch monkey-patch this function directly.

    :param session: Active SQLModel session. Only its bind is used: the
        lock is taken on a dedicated connection from the same engine, so
        commits, rollbacks or a failed flush inside the protected region
        can't strand it.
    :param scope: See :func:`lock_name_for`.
    :param row_id: See :func:`lock_name_for`.
    :param timeout_seconds: Max wait. ``0`` returns immediately if
        the lock is contended (the "fail fast" shape suitable for
        Celery's at-least-once re-delivery — letting the broker
        retry later is cheaper than queuing waiters).
    :yields: ``True`` on acquired, ``False`` on contention / timeout.
    """
    name = lock_name_for(scope, row_id)

    if not _is_mysql_session(session):
        # SQLite test path. The contract is "yield True" — tests
        # that need the contended-acquire branch monkey-patch this
        # function at the call site.
        yield True
        return

    # The lock rides on a dedicated connection, not the session's.
    # GET_LOCK is owned by one MySQL connection, and the session hands
    # its connection back to the pool on every commit/rollback, so a
    # RELEASE_LOCK issued through the session can land on a different
    # connection. Worse, a failed flush (e.g. the host-cert serial
    # DataError) leaves the session needing a rollback, so the release
    # raised and the lock leaked onto a pooled connection until the
    # worker restarted. A connection we own is unaffected by either.
    conn = session.get_bind().connect()
    acquired = False
    try:
        # GET_LOCK returns 1 on success, 0 on timeout, NULL on driver
        # error. Treat anything other than 1 as "not acquired".
        acquired = (
            conn.execute(
                text("SELECT GET_LOCK(:name, :timeout)"),
                {"name": name, "timeout": timeout_seconds},
            ).scalar()
            == 1
        )
        yield acquired
    finally:
        try:
            if acquired:
                released = conn.execute(
                    text("SELECT RELEASE_LOCK(:name)"), {"name": name}
                ).scalar()
                if released != 1:
                    raise RuntimeError(f"RELEASE_LOCK returned {released!r}")
        except Exception:
            # Don't mask the caller's exception, but don't leak the
            # lock either: invalidating closes the connection for real
            # (rather than returning it to the pool), and MySQL drops
            # a closed connection's named locks.
            logger.exception("failed to release advisory lock %s; dropping connection", name)
            conn.invalidate()
        finally:
            conn.close()


__all__ = [
    "lock_name_for",
    "task_row_lock",
]
