"""Hub reconfigure: no lost updates under contention, coalesced bursts.

Regression suite for the Phase 3f hardening item. ``reconfigure_server_task``
used to return ``skipped`` when another reconfigure held the hub lock. The
holder may have read the client list *before* the triggering change was
committed, so that peer never reached the hub. It stayed out until some
unrelated later reconfigure.

The fix is two generation counters on ``server`` (Alembic 0019):

* :func:`wg_manager.tasks.request_reconfigure` bumps
  ``reconfig_requested_gen`` and dispatches the task with that
  generation.
* The task reads ``requested`` **before** the client list, applies it,
  and then raises ``reconfig_applied_gen`` to that value.
* A task whose generation is already applied does nothing, so a burst
  of N changes costs about 2 hub restarts instead of N.
* On lock contention the task **retries** instead of skipping.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from celery.exceptions import Retry
from sqlmodel import Session

from tests.conftest import FakeSSHRunner
from wg_manager import db as db_module
from wg_manager import tasks as tasks_module
from wg_manager.models import Client, NodeStatus, Server, SSHKey
from wg_manager.tasks import (
    RECONFIGURE_MAX_RETRIES,
    reconfigure_server_task,
    request_reconfigure,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def hub(engine: Any, monkeypatch: pytest.MonkeyPatch) -> int:
    """A ready hub with a fake SSH runner wired in; returns its id."""
    FakeSSHRunner.COMMANDS = []
    monkeypatch.setattr(tasks_module, "SSHRunner", FakeSSHRunner)
    with Session(engine) as s:
        key = SSHKey(name="ops", tenant_id=1)
        s.add(key)
        s.commit()
        s.refresh(key)
        row = Server(
            hostname="hub.example.com", ssh_username="ubuntu",
            ssh_key_id=key.id, endpoint_host="hub.example.com",
            public_key="HUB=", status=NodeStatus.ready, tenant_id=1,
            subnet="10.9.0.0/24", address="10.9.0.1/24",
        )
        s.add(row)
        s.commit()
        s.refresh(row)
        return int(row.id or 0)


def _add_client(server_id: int, name: str, pub: str, ip: str) -> None:
    with Session(db_module.engine) as s:
        s.add(Client(name=name, server_id=server_id, address=f"{ip}/32",
                     public_key=pub, is_manual=True, status=NodeStatus.ready,
                     tenant_id=1))
        s.commit()


def _gens(server_id: int) -> tuple[int, int]:
    with Session(db_module.engine) as s:
        row = s.get(Server, server_id)
        return row.reconfig_requested_gen, row.reconfig_applied_gen


def _hub_writes() -> list[str]:
    """Rendered hub configs written so far (one per applied reconfigure)."""
    return [cmd for _, cmd in FakeSSHRunner.COMMANDS if "wg0.conf.tpl <<" in cmd]


@pytest.fixture()
def captured(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Capture dispatches from request_reconfigure instead of running them."""
    calls: list[dict[str, Any]] = []

    class _R:
        id = "task-id"

    def _apply_async(args=(), kwargs=None, **opts):
        calls.append({"args": tuple(args), "kwargs": dict(kwargs or {})})
        return _R()

    monkeypatch.setattr(reconfigure_server_task, "apply_async", _apply_async)
    return calls


# ---------------------------------------------------------------------------
# request_reconfigure
# ---------------------------------------------------------------------------


class TestRequestReconfigure:
    def test_bumps_requested_and_dispatches_with_generation(
        self, hub: int, captured: list[dict[str, Any]]
    ) -> None:
        r1 = request_reconfigure(hub)
        request_reconfigure(hub)
        assert _gens(hub) == (2, 0)
        assert captured == [
            {"args": (hub,), "kwargs": {"generation": 1}},
            {"args": (hub,), "kwargs": {"generation": 2}},
        ]
        assert r1.id == "task-id"

    def test_unknown_server_raises(self, hub: int, captured: list) -> None:
        with pytest.raises(ValueError):
            request_reconfigure(99999)
        assert captured == []


# ---------------------------------------------------------------------------
# Task behaviour
# ---------------------------------------------------------------------------


class TestApplyAndCoalesce:
    def test_apply_records_applied_generation(self, hub: int, captured: list) -> None:
        request_reconfigure(hub)
        result = reconfigure_server_task(hub, generation=1)
        assert result["status"] == "applied"
        assert result["generation"] == 1
        assert _gens(hub) == (1, 1)
        assert len(_hub_writes()) == 1

    def test_already_applied_generation_is_coalesced(
        self, hub: int, captured: list
    ) -> None:
        request_reconfigure(hub)
        request_reconfigure(hub)
        # The newest task runs first and covers both requests...
        assert reconfigure_server_task(hub, generation=2)["status"] == "applied"
        # ...so the older one has nothing to do: no SSH, no hub restart.
        before = len(FakeSSHRunner.COMMANDS)
        result = reconfigure_server_task(hub, generation=1)
        assert result["status"] == "coalesced"
        assert len(FakeSSHRunner.COMMANDS) == before

    def test_burst_costs_one_restart(self, hub: int, captured: list) -> None:
        for i in range(10):
            _add_client(hub, f"c{i}", f"PUB{i}=", f"10.9.0.{i + 2}")
            request_reconfigure(hub)
        statuses = [
            reconfigure_server_task(*c["args"], **c["kwargs"])["status"]
            for c in reversed(captured)
        ]
        assert statuses.count("applied") == 1
        assert statuses.count("coalesced") == 9
        assert all(f"PUB{i}=" in _hub_writes()[0] for i in range(10))

    def test_legacy_message_without_generation_always_applies(
        self, hub: int, captured: list
    ) -> None:
        """Messages queued before the upgrade carry no generation."""
        assert reconfigure_server_task(hub)["status"] == "applied"
        assert reconfigure_server_task(hub)["status"] == "applied"
        assert len(_hub_writes()) == 2

    def test_ssh_failure_leaves_applied_untouched(
        self, hub: int, captured: list
    ) -> None:
        from wg_manager.ssh import SSHConnectionError

        request_reconfigure(hub)
        FakeSSHRunner.RAISE_ON_ENTER = {
            "hub.example.com": SSHConnectionError("down", host="hub.example.com", port=22)
        }
        try:
            with pytest.raises(RuntimeError):
                reconfigure_server_task(hub, generation=1)
        finally:
            FakeSSHRunner.RAISE_ON_ENTER = {}
        assert _gens(hub) == (1, 0)  # a later task will still apply it


class TestNoLostUpdate:
    def test_change_committed_mid_apply_is_picked_up_next(
        self, hub: int, captured: list, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The race itself. Task A reads the client list, then a new
        client commits and requests generation 2 while A is still
        writing to the hub. A must record only generation 1, so task 2
        still applies and the new peer reaches the hub."""
        _add_client(hub, "first", "FIRST=", "10.9.0.2")
        request_reconfigure(hub)

        real = tasks_module._ready_clients_for
        injected = {"done": False}

        def _read_then_race(session: Session, server_id: int):
            clients = real(session, server_id)
            if not injected["done"]:
                injected["done"] = True
                _add_client(hub, "late", "LATE=", "10.9.0.3")
                request_reconfigure(hub)
            return clients

        monkeypatch.setattr(tasks_module, "_ready_clients_for", _read_then_race)
        first = reconfigure_server_task(hub, generation=1)
        assert first["generation"] == 1
        assert "LATE=" not in _hub_writes()[-1]
        assert _gens(hub) == (2, 1)

        second = reconfigure_server_task(hub, generation=2)
        assert second["status"] == "applied"
        assert "LATE=" in _hub_writes()[-1]
        assert _gens(hub) == (2, 2)


# ---------------------------------------------------------------------------
# Contention
# ---------------------------------------------------------------------------


def _lock_contended_n_times(monkeypatch: pytest.MonkeyPatch, n: int) -> list[int]:
    """Make the first ``n`` lock acquisitions fail; record every attempt."""
    attempts: list[int] = []

    @contextmanager
    def _lock(*_a: Any, **_k: Any) -> Iterator[bool]:
        attempts.append(1)
        yield len(attempts) > n

    monkeypatch.setattr(tasks_module, "task_row_lock", _lock)
    return attempts


@pytest.fixture()
def eager_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    """Let Celery run eager retries instead of propagating ``Retry``.

    The suite sets ``task_eager_propagates=True``. Celery's eager retry
    loop re-applies the task without forwarding ``throw=False``, so the
    setting itself has to be off for the retry chain to run.
    """
    from wg_manager.celery_app import celery_app

    monkeypatch.setattr(celery_app.conf, "task_eager_propagates", False)


class TestContention:
    def test_contention_retries_instead_of_skipping(
        self, hub: int, captured: list, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        request_reconfigure(hub)
        _lock_contended_n_times(monkeypatch, 1)
        with pytest.raises(Retry):
            reconfigure_server_task(hub, generation=1)
        assert _hub_writes() == []

    def test_retry_eventually_applies(
        self, hub: int, captured: list, monkeypatch: pytest.MonkeyPatch,
        eager_retries: None,
    ) -> None:
        request_reconfigure(hub)
        attempts = _lock_contended_n_times(monkeypatch, 2)
        result = reconfigure_server_task.apply(
            args=(hub,), kwargs={"generation": 1}
        )
        assert result.successful(), result.traceback
        assert result.result["status"] == "applied"
        assert len(attempts) == 3
        assert _gens(hub) == (1, 1)

    def test_gives_up_loudly_after_max_retries(
        self, hub: int, captured: list, monkeypatch: pytest.MonkeyPatch,
        eager_retries: None,
    ) -> None:
        request_reconfigure(hub)
        attempts = _lock_contended_n_times(monkeypatch, 10_000)
        result = reconfigure_server_task.apply(
            args=(hub,), kwargs={"generation": 1}
        )
        assert result.failed()
        assert len(attempts) == RECONFIGURE_MAX_RETRIES + 1


# ---------------------------------------------------------------------------
# Every dispatch site goes through request_reconfigure
# ---------------------------------------------------------------------------


def test_no_direct_delay_calls_remain() -> None:
    """``reconfigure_server_task.delay(`` bypasses the generation bump,
    which would bring the lost update back. Only request_reconfigure may
    dispatch the task."""
    from pathlib import Path

    src = Path(tasks_module.__file__).parent
    offenders = [
        str(p.relative_to(src))
        for p in src.rglob("*.py")
        if "reconfigure_server_task.delay(" in p.read_text()
    ]
    assert offenders == []
