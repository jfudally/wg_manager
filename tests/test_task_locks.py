"""Phase 3d cycle 3 — task-level advisory lock integration.

For each of the four mutating Celery tasks (``provision_server``,
``rotate_host_cert``, ``reconfigure_server``, ``provision_client``):

1. **Lock acquired.** Normal happy-path runs hit ``task_row_lock``
   before doing any SSH / DB-mutation work. Tests pin the call
   shape (scope + row id) so a refactor that drops the lock trips
   here.
2. **Lock contended.** When the lock helper returns ``False``
   (another worker holds it), the task returns
   ``{"status": "skipped", "reason": "concurrent_run", ...}``
   without making any side-effecting calls — no SSH session, no DB
   row flip, no audit emission.

Tests monkey-patch ``task_row_lock`` per-case rather than spinning
two parallel sessions, because the SQLite test engine has no
multi-connection contention shape and the production
``GET_LOCK``-based contended branch is covered indirectly through
the helper's contract tests.
"""

from __future__ import annotations

import base64
from contextlib import contextmanager
from typing import Any, Iterator

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from tests.conftest import FakeSSHRunner


_SAMPLE_PEM = "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEBODY\n-----END OPENSSH PRIVATE KEY-----\n"
_SAMPLE_PEM_B64 = base64.b64encode(_SAMPLE_PEM.encode("utf-8")).decode("ascii")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@contextmanager
def _patch_lock_contended(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Monkey-patch ``task_row_lock`` so every acquire returns ``False``.

    Simulates the "another worker holds the lock" branch without
    needing two real MySQL connections. The patched context manager
    yields ``False`` and runs no SQL.
    """
    @contextmanager
    def _contended(*args: Any, **kwargs: Any) -> Iterator[bool]:
        yield False

    import wg_manager.tasks as tasks_module

    monkeypatch.setattr(tasks_module, "task_row_lock", _contended)
    try:
        yield
    finally:
        # monkeypatch fixture handles restore.
        pass


@contextmanager
def _record_lock_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[list[tuple[str, int]]]:
    """Monkey-patch ``task_row_lock`` to record (scope, row_id) and
    still yield ``True``. Lets tests pin the call shape the task
    actually uses."""
    calls: list[tuple[str, int]] = []
    import wg_manager.tasks as tasks_module

    real_lock = tasks_module.task_row_lock

    @contextmanager
    def _recording(
        session: Any, scope: str, row_id: int, **kwargs: Any
    ) -> Iterator[bool]:
        calls.append((scope, row_id))
        with real_lock(session, scope, row_id, **kwargs) as acquired:
            yield acquired

    monkeypatch.setattr(tasks_module, "task_row_lock", _recording)
    yield calls


def _register_key(client: TestClient) -> int:
    resp = client.post("/ssh-keys", json={"name": "lab"})
    assert resp.status_code == 201, resp.text
    return int(resp.json()["id"])


def _register_server(client: TestClient, key_id: int) -> int:
    resp = client.post(
        "/servers",
        json={
            "hostname": "hub.example.com",
            "ssh_username": "ubuntu",
            "ssh_key_id": key_id,
            "endpoint_host": "hub.example.com",
        },
    )
    assert resp.status_code == 202, resp.text
    return int(resp.json()["server"]["id"])


def _register_client_row(
    client: TestClient, key_id: int, server_id: int
) -> int:
    resp = client.post(
        "/clients",
        json={
            "name": "spoke",
            "hostname": "spoke.example.com",
            "ssh_username": "ubuntu",
            "ssh_key_id": key_id,
            "server_id": server_id,
        },
    )
    assert resp.status_code == 202, resp.text
    return int(resp.json()["client"]["id"])


# ---------------------------------------------------------------------------
# Lock-acquired path: each task records the right (scope, row_id)
# ---------------------------------------------------------------------------


class TestEachTaskAcquiresExpectedLock:
    def test_provision_server_locks_on_server_row(
        self,
        client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        with _record_lock_calls(monkeypatch) as calls:
            key_id = _register_key(client)
            server_id = _register_server(client, key_id)

        # The provision_server task fires synchronously under eager
        # mode during the POST. Look for the server-scoped lock.
        server_locks = [c for c in calls if c[0] == "server"]
        assert (
            "server", server_id
        ) in server_locks, f"calls: {calls}"

    def test_rotate_host_cert_locks_on_server_row(
        self,
        client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        key_id = _register_key(client)
        server_id = _register_server(client, key_id)
        FakeSSHRunner.COMMANDS.clear()

        with _record_lock_calls(monkeypatch) as calls:
            resp = client.post(f"/servers/{server_id}/rotate-host-cert")
            assert resp.status_code == 202, resp.text

        assert (
            "server", server_id
        ) in calls, f"calls: {calls}"

    def test_reconfigure_server_locks_on_server_row(
        self,
        client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        key_id = _register_key(client)
        server_id = _register_server(client, key_id)
        FakeSSHRunner.COMMANDS.clear()

        with _record_lock_calls(monkeypatch) as calls:
            # Reconfigure dispatches inside provision_client too;
            # fire a client provision to drive the reconfigure path.
            client_id = _register_client_row(client, key_id, server_id)
            assert client_id > 0

        # provision_client locks on client row + dispatches
        # reconfigure_server which locks on server row.
        assert ("server", server_id) in calls, f"calls: {calls}"
        assert ("client", client_id) in calls, f"calls: {calls}"

    def test_provision_client_locks_on_client_row(
        self,
        client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        key_id = _register_key(client)
        server_id = _register_server(client, key_id)
        FakeSSHRunner.COMMANDS.clear()

        with _record_lock_calls(monkeypatch) as calls:
            client_id = _register_client_row(client, key_id, server_id)

        assert ("client", client_id) in calls, f"calls: {calls}"


# ---------------------------------------------------------------------------
# Lock contended: each task returns skipped + makes no side effects
# ---------------------------------------------------------------------------


class TestEachTaskSkipsOnContention:
    """When ``task_row_lock`` yields ``False``, the task must return
    a ``{"status": "skipped"}`` envelope without firing SSH commands
    or flipping the row's state."""

    def test_provision_server_skipped_on_contention(
        self,
        client: TestClient,
        engine: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Seed a row directly (bypass the POST which would itself
        # fire the task). Then drive provision_server_task with a
        # contended lock.
        from wg_manager.models import NodeStatus, SSHKey, Server

        with Session(engine) as s:
            key = SSHKey(name="lab", tenant_id=1)
            s.add(key)
            s.commit()
            s.refresh(key)
            server = Server(
                hostname="hub.example.com",
                ssh_username="ubuntu",
                ssh_key_id=key.id,
                endpoint_host="hub.example.com",
                address="10.9.0.1/24",
                subnet="10.9.0.0/24",
                tenant_id=1,
                status=NodeStatus.pending,
            )
            s.add(server)
            s.commit()
            s.refresh(server)
            server_id = int(server.id or 0)

        FakeSSHRunner.COMMANDS.clear()
        with _patch_lock_contended(monkeypatch):
            from wg_manager.tasks import provision_server_task

            result = provision_server_task(server_id)

        assert isinstance(result, dict)
        assert result.get("status") == "skipped"
        assert result.get("reason") == "concurrent_run"
        # No SSH commands fired.
        assert FakeSSHRunner.COMMANDS == []
        # Row stays in pending (the existing state) — not flipped
        # to ready or error.
        with Session(engine) as s:
            row = s.get(Server, server_id)
            assert row is not None
            assert row.status == NodeStatus.pending

    def test_rotate_host_cert_skipped_on_contention(
        self,
        client: TestClient,
        engine: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from wg_manager.models import NodeStatus, SSHKey, Server

        with Session(engine) as s:
            key = SSHKey(name="lab", tenant_id=1)
            s.add(key)
            s.commit()
            s.refresh(key)
            server = Server(
                hostname="hub.example.com",
                ssh_username="ubuntu",
                ssh_key_id=key.id,
                endpoint_host="hub.example.com",
                address="10.9.0.1/24",
                subnet="10.9.0.0/24",
                tenant_id=1,
                status=NodeStatus.ready,
            )
            s.add(server)
            s.commit()
            s.refresh(server)
            server_id = int(server.id or 0)

        FakeSSHRunner.COMMANDS.clear()
        with _patch_lock_contended(monkeypatch):
            from wg_manager.tasks import rotate_host_cert_task

            result = rotate_host_cert_task(server_id)

        assert result.get("status") == "skipped"
        assert FakeSSHRunner.COMMANDS == []

    def test_reconfigure_server_skipped_on_contention(
        self,
        client: TestClient,
        engine: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from wg_manager.models import NodeStatus, SSHKey, Server

        with Session(engine) as s:
            key = SSHKey(name="lab", tenant_id=1)
            s.add(key)
            s.commit()
            s.refresh(key)
            server = Server(
                hostname="hub.example.com",
                ssh_username="ubuntu",
                ssh_key_id=key.id,
                endpoint_host="hub.example.com",
                address="10.9.0.1/24",
                subnet="10.9.0.0/24",
                tenant_id=1,
                status=NodeStatus.ready,
            )
            s.add(server)
            s.commit()
            s.refresh(server)
            server_id = int(server.id or 0)

        FakeSSHRunner.COMMANDS.clear()
        with _patch_lock_contended(monkeypatch):
            from wg_manager.tasks import reconfigure_server_task

            result = reconfigure_server_task(server_id)

        assert result.get("status") == "skipped"
        assert FakeSSHRunner.COMMANDS == []

    def test_provision_client_skipped_on_contention(
        self,
        client: TestClient,
        engine: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from wg_manager.models import (
            Client as ClientRow,
            NodeStatus,
            SSHKey,
            Server,
        )

        with Session(engine) as s:
            key = SSHKey(name="lab", tenant_id=1)
            s.add(key)
            s.commit()
            s.refresh(key)
            server = Server(
                hostname="hub.example.com",
                ssh_username="ubuntu",
                ssh_key_id=key.id,
                endpoint_host="hub.example.com",
                address="10.9.0.1/24",
                subnet="10.9.0.0/24",
                tenant_id=1,
                status=NodeStatus.ready,
            )
            s.add(server)
            s.commit()
            s.refresh(server)
            row = ClientRow(
                name="spoke",
                hostname="spoke.example.com",
                ssh_username="ubuntu",
                ssh_key_id=key.id,
                server_id=int(server.id or 0),
                address="10.9.0.2/32",
                public_key="",
                tenant_id=1,
                status=NodeStatus.pending,
            )
            s.add(row)
            s.commit()
            s.refresh(row)
            client_id = int(row.id or 0)

        FakeSSHRunner.COMMANDS.clear()
        with _patch_lock_contended(monkeypatch):
            from wg_manager.tasks import provision_client_task

            result = provision_client_task(client_id)

        assert result.get("status") == "skipped"
        assert FakeSSHRunner.COMMANDS == []
