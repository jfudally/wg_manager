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
