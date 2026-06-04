"""Phase 3d cycle 2 — Celery worker HA config + task contract pins.

Cycle 1 made the API stateless behind a load balancer. Cycle 2 makes
the **Celery worker side** safe to run as 2+ replicas. The config
contract this module pins:

* ``task_acks_late=True`` (already shipped in Phase 1) — tasks are
  acknowledged on success, not on receipt. A worker that picks up a
  task and dies before completing it doesn't ack, and the broker
  re-delivers to another worker.
* ``task_reject_on_worker_lost=True`` (cycle 2 ships this) — hard
  worker death (SIGKILL, OOM kill, container terminated) is treated
  the same as a graceful failure: the task is requeued rather than
  silently dropped. Without this flag, a worker SIGKILL'd mid-task
  would leave the task in the "acknowledged but never completed"
  limbo Celery calls "worker lost".
* ``task_reject_on_worker_lost`` only matters in combination with
  ``acks_late=True`` — together they form the at-least-once delivery
  contract every cycle 2 task is written against.

The "task is safe to run more than once" contract is documented in
the per-task docstrings (audit verdict in
[`docs/deploy/ha-control-plane.md`](../docs/deploy/ha-control-plane.md)
§ "Celery worker scaling"). This module sanity-checks that every
shipped task is registered with the canonical config — adding a new
task without `task_acks_late` semantics in mind would slip past
review unless something pinned the invariant.
"""

from __future__ import annotations

import pytest


class TestCeleryAtLeastOnceConfig:
    """The two flags that together produce the at-least-once
    delivery contract. ``acks_late`` was already shipped; cycle 2
    adds ``reject_on_worker_lost``."""

    def test_task_acks_late_true(self) -> None:
        from wg_manager.celery_app import celery_app

        assert celery_app.conf.task_acks_late is True

    def test_task_reject_on_worker_lost_true(self) -> None:
        """Without this, a SIGKILL'd worker mid-task drops the task
        silently. With it, the broker requeues so another worker
        retries. Requires ``acks_late=True`` to be meaningful."""
        from wg_manager.celery_app import celery_app

        assert celery_app.conf.task_reject_on_worker_lost is True


class TestEveryShippedTaskIsRegistered:
    """Sanity check: every public task name that ships is actually
    registered with the celery_app. Catches a refactor that
    accidentally drops a task's ``@celery_app.task`` decorator —
    which would silently break provisioning at scale (the broker
    accepts the send, no worker is subscribed)."""

    _EXPECTED_TASK_NAMES = frozenset(
        {
            "wg_manager.tasks.provision_server",
            "wg_manager.tasks.rotate_host_cert",
            "wg_manager.tasks.reconfigure_server",
            "wg_manager.tasks.provision_client",
            "wg_manager.tasks.discover_peers",
            "wg_manager.tasks.discover_all_peers",
        }
    )

    def test_every_task_name_present(self) -> None:
        from wg_manager.celery_app import celery_app

        # Force the tasks module to import + register.
        import wg_manager.tasks  # noqa: F401

        registered = set(celery_app.tasks.keys())
        missing = self._EXPECTED_TASK_NAMES - registered
        assert missing == set(), (
            f"these tasks were expected but aren't registered: {missing}"
        )


class TestIdempotencyContractInDocstrings:
    """Each task carries a one-line cycle 2 verdict in its docstring
    so a future maintainer reviewing the function sees the
    classification next to the code. Catches a refactor that
    rewrites a task body but forgets to re-examine the
    idempotency story."""

    @pytest.mark.parametrize(
        "task_name",
        [
            "provision_server_task",
            "rotate_host_cert_task",
            "reconfigure_server_task",
            "provision_client_task",
            "discover_peers_task",
            "discover_all_peers_task",
        ],
    )
    def test_task_docstring_carries_phase_3d_verdict(
        self, task_name: str
    ) -> None:
        import wg_manager.tasks as tasks_module

        fn = getattr(tasks_module, task_name)
        # Celery's task decorator wraps the function; the original
        # callable is at ``.run`` for ``bind=True`` tasks.
        underlying = getattr(fn, "run", fn)
        doc = underlying.__doc__ or ""
        # The verdict lives in a "Phase 3d cycle 2" stanza. Pin the
        # marker so the docstring can't drop the audit verdict
        # without the test catching it.
        assert "Phase 3d cycle 2" in doc, (
            f"{task_name}.__doc__ must carry a Phase 3d cycle 2 "
            f"idempotency-contract verdict; got: {doc[:200]!r}"
        )
