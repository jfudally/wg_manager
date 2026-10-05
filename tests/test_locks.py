"""Phase 3d cycle 3 — per-row advisory locks (MySQL ``GET_LOCK``).

Cycle 2's audit classified the four mutating Celery tasks
(``provision_server``, ``rotate_host_cert``, ``reconfigure_server``,
``provision_client``) as ``BENIGN_OVERWRITE`` — safe under
``acks_late=True`` + ``reject_on_worker_lost=True`` re-delivery
because every remote SSH command is guarded for re-run safety.
That's true for **serial** replay (one worker dies, broker
re-queues to another worker after the first fully terminates).

Two workers racing the *same* row in parallel is a different
shape — and the deployment-time hazard that cycle 3 fixes. Two
parallel ``provision_server`` invocations on ``server_id=7`` would
cause: two concurrent ``apt-get install``s (dpkg has its own lock,
so one blocks, but the wait is invisible to the operator); two
concurrent ``wg-quick down/up`` cycles (a real interface flap); two
host certs minted (wasted Vault signatures). All operationally
safe, all operationally wasteful.

Cycle 3 ships a per-row advisory lock the tasks acquire on entry:

* On **MySQL**, the lock uses ``GET_LOCK(name, timeout)`` and
  ``RELEASE_LOCK(name)``. The name shape is ``wgm:<scope>:<row_id>``
  (e.g. ``wgm:server:7``). The lock is connection-scoped; closing
  the session releases it.
* On **SQLite** (the test suite), the lock is a no-op acquire
  because in-memory SQLite has no multi-connection contention
  shape worth modelling. Tests verify the *contract* via the lock
  helper's return value and the task-layer integration.

When a task can't acquire the lock (``GET_LOCK`` returns 0 because
another worker holds it), it returns
``{"status": "skipped", "reason": "concurrent_run", ...}`` without
making any side-effecting calls. The skipped result is recorded as
the task's normal return value so the API's
``GET /tasks/{id}`` polling path surfaces it.

This module pins the lock helper's contract; the task-level
integration tests live in ``tests/test_task_locks.py``.
"""

from __future__ import annotations

import pytest


class TestLockNameShape:
    """The lock name carries enough scope to disambiguate row
    types — ``wgm:server:7`` vs ``wgm:client:7`` — without
    needing a global counter / nonce. The prefix keeps the
    namespace clean if the operator's MySQL is shared with other
    apps using ``GET_LOCK``."""

    def test_lock_name_for_server_row(self) -> None:
        from wg_manager.locks import lock_name_for

        assert lock_name_for("server", 7) == "wgm:server:7"

    def test_lock_name_for_client_row(self) -> None:
        from wg_manager.locks import lock_name_for

        assert lock_name_for("client", 42) == "wgm:client:42"

    def test_lock_name_rejects_empty_scope(self) -> None:
        from wg_manager.locks import lock_name_for

        with pytest.raises(ValueError):
            lock_name_for("", 1)

    def test_lock_name_rejects_non_positive_row_id(self) -> None:
        from wg_manager.locks import lock_name_for

        with pytest.raises(ValueError):
            lock_name_for("server", 0)
        with pytest.raises(ValueError):
            lock_name_for("server", -3)


# ---------------------------------------------------------------------------
# task_row_lock — context manager contract
# ---------------------------------------------------------------------------


class TestTaskRowLockContract:
    """``task_row_lock(session, scope, row_id)`` yields ``True`` on
    successful acquire, ``False`` on contention. The yielded
    boolean is what the caller branches on — failed acquire is
    **not** an error (the caller decides whether to skip or
    retry).

    On SQLite the helper is a no-op acquire — always yields
    ``True`` — because SQLite's tests don't model multi-connection
    contention. The MySQL path is exercised in the integration
    tests; this module pins the contract shape."""

    def test_yields_true_on_acquire(
        self, session: object
    ) -> None:
        from wg_manager.locks import task_row_lock

        with task_row_lock(session, "server", 7) as acquired:
            assert acquired is True

    def test_release_runs_on_context_exit(
        self, session: object
    ) -> None:
        """After exiting the context, the same scope+row can be
        re-acquired (proving the release happened)."""
        from wg_manager.locks import task_row_lock

        with task_row_lock(session, "server", 7) as acquired:
            assert acquired is True
        # Second acquire — would block / fail if release didn't
        # run. SQLite no-op never holds, so this trivially passes;
        # the test exists to document the contract.
        with task_row_lock(session, "server", 7) as acquired:
            assert acquired is True

    def test_release_runs_on_exception(
        self, session: object
    ) -> None:
        """If the protected block raises, the release still
        fires. Caller's exception propagates."""
        from wg_manager.locks import task_row_lock

        with pytest.raises(RuntimeError):
            with task_row_lock(session, "server", 7) as acquired:
                assert acquired is True
                raise RuntimeError("boom")
        # Lock released — re-acquire succeeds.
        with task_row_lock(session, "server", 7) as acquired:
            assert acquired is True

    def test_distinct_scopes_do_not_collide(
        self, session: object
    ) -> None:
        """``wgm:server:7`` and ``wgm:client:7`` are independent
        locks even though they share a row id."""
        from wg_manager.locks import task_row_lock

        with task_row_lock(session, "server", 7) as s_acq:
            assert s_acq is True
            with task_row_lock(session, "client", 7) as c_acq:
                assert c_acq is True


# ---------------------------------------------------------------------------
# MySQL release path — modelled on SQLite with fake GET_LOCK / RELEASE_LOCK
# ---------------------------------------------------------------------------


class _FakeNamedLocks:
    """Connection-scoped named locks with MySQL's ``GET_LOCK`` semantics.

    Registered as SQL functions on every SQLite DBAPI connection, so the
    real ``task_row_lock`` SQL runs unchanged. Each lock is owned by the
    DBAPI connection that took it: re-entrant for the owner, ``0`` for
    anyone else, released only by the owner's ``RELEASE_LOCK`` or by
    that connection actually closing — exactly the property that makes
    a swallowed release leak the lock onto a pooled connection.
    """

    def __init__(self) -> None:
        self.owners: dict[str, int] = {}

    def install(self, engine) -> None:
        """Register GET_LOCK / RELEASE_LOCK on ``engine``'s connections."""
        from sqlalchemy import event

        @event.listens_for(engine, "connect")
        def _register(dbapi_conn, _record) -> None:
            me = id(dbapi_conn)

            def get_lock(name: str, _timeout: int) -> int:
                if self.owners.get(name, me) != me:
                    return 0
                self.owners[name] = me
                return 1

            def release_lock(name: str) -> int | None:
                if self.owners.get(name) != me:
                    return 0
                del self.owners[name]
                return 1

            dbapi_conn.create_function("GET_LOCK", 2, get_lock)
            dbapi_conn.create_function("RELEASE_LOCK", 1, release_lock)

        @event.listens_for(engine, "close")
        def _closed(dbapi_conn, _record) -> None:
            # Server-side: closing a connection drops its named locks.
            me = id(dbapi_conn)
            for name in [n for n, o in self.owners.items() if o == me]:
                del self.owners[name]


class TestTaskRowLockReleaseAfterFailedFlush:
    """Regression: a failed flush must not leak the advisory lock.

    In production a host-cert rotation's commit raised ``DataError``
    (serial out of range). That left the session needing a rollback,
    so the ``RELEASE_LOCK`` in ``task_row_lock``'s ``finally`` raised
    too, was swallowed, and the lock stayed held on the pooled
    connection. Every later rotation of that row was skipped with
    ``concurrent_run`` until the worker restarted.
    """

    @pytest.fixture()
    def locking_engine(self, tmp_path, monkeypatch):
        """File-backed SQLite (real pool, many connections) with fake locks."""
        from sqlalchemy import create_engine
        from sqlmodel import SQLModel

        import wg_manager.locks as locks
        import wg_manager.models  # noqa: F401 — populate metadata

        engine = create_engine(f"sqlite:///{tmp_path / 'locks.sqlite'}")
        fake = _FakeNamedLocks()
        fake.install(engine)
        SQLModel.metadata.create_all(engine)
        # Take the MySQL branch so the real GET_LOCK SQL runs.
        monkeypatch.setattr(locks, "_is_mysql_session", lambda _s: True)
        yield engine, fake
        engine.dispose()

    def test_lock_released_when_protected_flush_fails(self, locking_engine) -> None:
        """After an IntegrityError on commit, another connection can lock the row."""
        from sqlalchemy.exc import IntegrityError
        from sqlmodel import Session

        from wg_manager.locks import lock_name_for, task_row_lock
        from wg_manager.models import Operator

        engine, fake = locking_engine
        with Session(engine) as seed:
            seed.add(Operator(cn="dup"))
            seed.commit()

        with Session(engine) as session:
            with pytest.raises(IntegrityError):
                with task_row_lock(session, "server", 1) as acquired:
                    assert acquired is True
                    # Duplicate unique CN: the flush fails and the
                    # session is left needing a rollback, like the
                    # serial-overflow DataError did.
                    session.add(Operator(cn="dup"))
                    session.commit()

            assert lock_name_for("server", 1) not in fake.owners

    def test_lock_released_on_success_path(self, locking_engine) -> None:
        """The normal commit-then-exit path still releases the lock."""
        from sqlmodel import Session

        from wg_manager.locks import lock_name_for, task_row_lock
        from wg_manager.models import Operator

        engine, fake = locking_engine
        with Session(engine) as session:
            with task_row_lock(session, "server", 1) as acquired:
                assert acquired is True
                session.add(Operator(cn="ok"))
                session.commit()
            assert lock_name_for("server", 1) not in fake.owners

    def test_contended_lock_yields_false(self, locking_engine) -> None:
        """A lock held by another connection is reported as not acquired."""
        from sqlalchemy import text
        from sqlmodel import Session

        from wg_manager.locks import lock_name_for, task_row_lock

        engine, _fake = locking_engine
        with engine.connect() as holder:
            holder.execute(
                text("SELECT GET_LOCK(:n, 0)"), {"n": lock_name_for("server", 1)}
            )
            with Session(engine) as session:
                with task_row_lock(session, "server", 1, timeout_seconds=0) as acquired:
                    assert acquired is False
