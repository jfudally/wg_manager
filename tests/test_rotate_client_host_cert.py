"""Tests for ``POST /clients/{id}/rotate-host-cert`` — client host-cert rotation.

Client-side twin of :mod:`tests.test_rotate_host_cert`. Before this
change only hubs could re-mint their SSH host certificate; a client's
cert (installed by ``bootstrap-host``) silently expired after
``SSH_HOST_CERT_TTL_SECONDS`` and the next CA-mode session to it
failed until the operator re-bootstrapped by hand.

Pinned contract:

* ``provision_client_task`` installs + persists a host cert on every
  successful provision (parity with ``provision_server_task``), so the
  row's ``host_cert_*`` columns are populated from day one.
* The endpoint 404s on a missing client, 400s on a manual client (no
  SSH — same code ``/reprovision`` uses), 409s when the SSH key row is
  gone, and otherwise returns 202 + ``{task_id, client}``.
* :func:`wg_manager.tasks.rotate_client_host_cert_task` re-mints,
  overwrites the columns, holds the ``client`` row lock, and turns SSH
  failures into one clean ``RuntimeError`` without touching the row.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from tests.conftest import FakeSSHRunner
from wg_manager.models import Client, NodeStatus


_CLIENT_HOST = "spoke.example.com"


def _register_ready_client(client: TestClient) -> int:
    """Register an SSH key, a ready hub, and a ready SSH client. Returns client id."""
    key_id = int(client.post("/ssh-keys", json={"name": "lab"}).json()["id"])
    server = client.post(
        "/servers",
        json={
            "hostname": "hub.example.com",
            "ssh_username": "ubuntu",
            "ssh_key_id": key_id,
            "endpoint_host": "hub.example.com",
        },
    )
    assert server.status_code == 202, server.text
    resp = client.post(
        "/clients",
        json={
            "name": "spoke",
            "hostname": _CLIENT_HOST,
            "ssh_username": "ubuntu",
            "ssh_key_id": key_id,
            "server_id": int(server.json()["server"]["id"]),
        },
    )
    assert resp.status_code == 202, resp.text
    return int(resp.json()["client"]["id"])


def _get_row(engine: Any, client_id: int) -> Client:
    """Load a fresh copy of the client row outside the request session."""
    with Session(engine) as s:
        row = s.get(Client, client_id)
        assert row is not None
        s.expunge(row)
        return row


class TestProvisionInstallsClientHostCert:
    def test_provision_persists_host_cert_columns(
        self, client: TestClient, engine: Any
    ) -> None:
        """A freshly provisioned client carries a cert with its hostname as principal."""
        client_id = _register_ready_client(client)

        row = _get_row(engine, client_id)
        assert row.status == NodeStatus.ready
        assert row.host_cert_serial is not None
        assert row.host_cert_principals == _CLIENT_HOST
        assert row.host_cert_valid_before is not None
        assert row.host_cert_pem
        assert row.host_cert_ca_public_key

    def test_client_read_exposes_cert_metadata(self, client: TestClient) -> None:
        """``GET /clients/{id}`` and the list surface all six ``host_cert_*`` fields.

        Same set as ``ServerRead`` (#106): the cert body and signing CA
        pubkey are public material, and the CA key lets callers spot rows
        still pinned to a CA that has since been rotated.
        """
        client_id = _register_ready_client(client)

        one = client.get(f"/clients/{client_id}").json()
        listed = next(c for c in client.get("/clients").json() if c["id"] == client_id)
        for body in (one, listed):
            assert isinstance(body["host_cert_serial"], int)
            assert body["host_cert_valid_after"]
            assert body["host_cert_valid_before"]
            assert body["host_cert_principals"] == _CLIENT_HOST
            assert body["host_cert_pem"].startswith("ssh-ed25519-cert-v01@openssh.com ")
            assert body["host_cert_ca_public_key"].startswith("ssh-")

    def test_manual_client_has_null_cert_fields(self, client: TestClient) -> None:
        """Manual clients never get a host cert; the fields are present but null."""
        _register_ready_client(client)
        server_id = client.get("/servers").json()[0]["id"]
        manual_id = client.post(
            "/clients/manual", json={"name": "phone", "server_id": server_id}
        ).json()["client"]["id"]

        body = client.get(f"/clients/{manual_id}").json()
        assert body["host_cert_pem"] is None
        assert body["host_cert_ca_public_key"] is None


class TestRotateClientHostCertEndpoint:
    def test_returns_202_and_envelope(self, client: TestClient, engine: Any) -> None:
        client_id = _register_ready_client(client)
        first_serial = _get_row(engine, client_id).host_cert_serial

        resp = client.post(f"/clients/{client_id}/rotate-host-cert")
        assert resp.status_code == 202, resp.text
        body = resp.json()
        assert body["task_id"]
        assert body["client"]["id"] == client_id

        # Eager Celery ran the task inside the request.
        row = _get_row(engine, client_id)
        assert row.host_cert_serial is not None
        assert row.host_cert_serial != first_serial

    def test_returns_404_when_client_missing(self, client: TestClient) -> None:
        resp = client.post("/clients/9999/rotate-host-cert")
        assert resp.status_code == 404, resp.text

    def test_returns_400_for_manual_client(self, client: TestClient) -> None:
        """Manual clients have no SSH access, so there's nothing to rotate."""
        _register_ready_client(client)
        server_id = client.get("/servers").json()[0]["id"]
        manual = client.post(
            "/clients/manual", json={"name": "phone", "server_id": server_id}
        )
        assert manual.status_code in (200, 201, 202), manual.text
        manual_id = manual.json()["client"]["id"]

        resp = client.post(f"/clients/{manual_id}/rotate-host-cert")
        assert resp.status_code == 400, resp.text
        assert "manual" in resp.json()["detail"].lower()


    def test_returns_409_when_ssh_key_row_missing(
        self, client: TestClient, engine: Any
    ) -> None:
        """A dangling ``ssh_key_id`` is a conflict, not a task-side crash."""
        from wg_manager.models import SSHKey

        client_id = _register_ready_client(client)
        with Session(engine) as s:
            row = s.get(Client, client_id)
            assert row is not None
            key = s.get(SSHKey, row.ssh_key_id)
            # SQLite doesn't enforce the FK here, mirroring the "broken
            # constraint" case the endpoint defends against.
            s.delete(key)
            s.commit()

        resp = client.post(f"/clients/{client_id}/rotate-host-cert")
        assert resp.status_code == 409, resp.text
        assert "no longer exists" in resp.json()["detail"]


class TestRotateClientHostCertTask:
    def test_overwrites_existing_host_cert_columns(
        self, client: TestClient, engine: Any
    ) -> None:
        from wg_manager.tasks import rotate_client_host_cert_task

        client_id = _register_ready_client(client)
        before = _get_row(engine, client_id)

        result = rotate_client_host_cert_task(client_id)

        assert result["status"] == "ok"
        assert result["client_id"] == client_id
        assert result["serial"] != before.host_cert_serial
        after = _get_row(engine, client_id)
        assert after.host_cert_serial == result["serial"]
        assert after.host_cert_valid_before is not None
        assert before.host_cert_valid_before is not None
        assert after.host_cert_valid_before >= before.host_cert_valid_before
        assert result["valid_before"] == after.host_cert_valid_before.isoformat()

    def test_ssh_failure_raises_clean_error_and_leaves_row(
        self, client: TestClient, engine: Any
    ) -> None:
        from wg_manager.ssh import SSHConnectionError
        from wg_manager.tasks import rotate_client_host_cert_task

        client_id = _register_ready_client(client)
        before = _get_row(engine, client_id)
        FakeSSHRunner.RAISE_ON_ENTER[_CLIENT_HOST] = SSHConnectionError(
            "connection refused", host=_CLIENT_HOST, port=22
        )

        with pytest.raises(RuntimeError, match="host-cert rotation failed for client"):
            rotate_client_host_cert_task(client_id)

        after = _get_row(engine, client_id)
        assert after.host_cert_serial == before.host_cert_serial
        assert after.status == NodeStatus.ready

    def test_locks_on_client_row(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import wg_manager.tasks as tasks_module
        from wg_manager.tasks import rotate_client_host_cert_task

        client_id = _register_ready_client(client)
        calls: list[tuple[str, int]] = []
        real_lock = tasks_module.task_row_lock

        @contextmanager
        def _recording(session: Any, scope: str, row_id: int) -> Iterator[bool]:
            calls.append((scope, row_id))
            with real_lock(session, scope, row_id) as acquired:
                yield acquired

        monkeypatch.setattr(tasks_module, "task_row_lock", _recording)
        rotate_client_host_cert_task(client_id)
        assert ("client", client_id) in calls

    def test_skipped_on_lock_contention(
        self, client: TestClient, engine: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import wg_manager.tasks as tasks_module
        from wg_manager.tasks import rotate_client_host_cert_task

        client_id = _register_ready_client(client)
        before = _get_row(engine, client_id)

        @contextmanager
        def _contended(*_: Any, **__: Any) -> Iterator[bool]:
            yield False

        monkeypatch.setattr(tasks_module, "task_row_lock", _contended)
        FakeSSHRunner.COMMANDS.clear()

        result = rotate_client_host_cert_task(client_id)

        assert result == {
            "status": "skipped",
            "reason": "concurrent_run",
            "client_id": client_id,
        }
        assert FakeSSHRunner.COMMANDS == []
        assert _get_row(engine, client_id).host_cert_serial == before.host_cert_serial
