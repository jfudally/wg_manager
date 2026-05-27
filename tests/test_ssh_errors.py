"""Tests for graceful handling of SSH connection failures inside Celery tasks.

When the remote host is unreachable, refuses the connection, or fails
authentication, the task should:

* log a single concise ``ERROR``-level message (no stack trace);
* mark the relevant DB row's ``status`` to ``error`` (where applicable);
* raise a clean :class:`RuntimeError` so Celery records the task as
  ``FAILURE`` — but with a tidy message instead of a giant traceback.
"""

from __future__ import annotations

import base64
import logging
import socket

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from tests.conftest import FakeSSHRunner
from wg_manager.models import DiscoveredPeer, NodeStatus, Server
from wg_manager.ssh import SSHConnectionError
from wg_manager.tasks import (
    discover_peers_task,
    provision_client_task,
    provision_server_task,
)

_SAMPLE_PEM = "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEBODY\n-----END OPENSSH PRIVATE KEY-----\n"
_SAMPLE_PEM_B64 = base64.b64encode(_SAMPLE_PEM.encode("utf-8")).decode("ascii")


def _bootstrap_server(client: TestClient) -> int:
    """Register an SSH key and a ready server. Returns the server ID."""
    key_id = int(
        client.post(
            "/ssh-keys",
            json={"name": "lab", "private_key_b64": _SAMPLE_PEM_B64},
        ).json()["id"]
    )
    server_resp = client.post(
        "/servers",
        json={
            "hostname": "hub.example.com",
            "ssh_username": "ubuntu",
            "ssh_key_id": key_id,
            "endpoint_host": "hub.example.com",
        },
    )
    assert server_resp.status_code == 202
    return int(server_resp.json()["server"]["id"])


class TestDiscoverTimeout:
    """Discovery is a read operation, so an unreachable host should not fail
    the task — it should be logged, returned in the result with
    ``status="ssh_failed"``, and otherwise treated as "no peers from this
    host." Provisioning tasks still raise on SSH errors because they have a
    pending row that needs to flip to ``error``."""

    def test_timeout_is_logged_and_returns_failed_status(
        self,
        client: TestClient,
        engine: object,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        server_id = _bootstrap_server(client)

        FakeSSHRunner.RAISE_ON_ENTER["hub.example.com"] = socket.timeout(
            "timed out"
        )

        with caplog.at_level(logging.ERROR, logger="wg_manager.tasks"):
            result = discover_peers_task(server_id)

        # No exception — task returns a failure summary instead.
        assert result["server_id"] == server_id
        assert result["status"] == "ssh_failed"
        assert "hub.example.com" in result["error"]
        assert result["peer_count"] == 0

        # One concise ERROR log line, no exc_info.
        ssh_records = [r for r in caplog.records if "hub.example.com" in r.getMessage()]
        assert ssh_records, "expected an ERROR log mentioning the host"
        assert all(r.exc_info is None for r in ssh_records), (
            "log records should not include a stack trace"
        )

        # No DiscoveredPeer rows should have been persisted.
        with Session(engine) as session:  # type: ignore[arg-type]
            rows = session.exec(select(DiscoveredPeer)).all()
            assert list(rows) == []

    def test_endpoint_returns_202_and_task_succeeds(
        self,
        client: TestClient,
    ) -> None:
        """The router still returns 202 and the underlying task ends in
        SUCCESS state (with status="ssh_failed" in the payload) — eager
        mode propagates exceptions, so if discovery still raised this
        would 500."""
        server_id = _bootstrap_server(client)
        FakeSSHRunner.RAISE_ON_ENTER["hub.example.com"] = socket.timeout(
            "timed out"
        )

        resp = client.post(f"/servers/{server_id}/discover")
        assert resp.status_code == 202, resp.text
        assert "task_id" in resp.json()


class TestDiscoverAllSurvivesPerHostFailure:
    """``POST /servers/discover-all`` walks every server. Per-host SSH
    failures must be logged and skipped — the overall task continues and
    still discovers peers on the healthy hosts."""

    def test_one_host_unreachable_others_still_discovered(
        self,
        client: TestClient,
        engine: object,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        # First (healthy) server.
        key_id = int(
            client.post(
                "/ssh-keys",
                json={"name": "lab", "private_key_b64": _SAMPLE_PEM_B64},
            ).json()["id"]
        )
        ok_id = int(
            client.post(
                "/servers",
                json={
                    "hostname": "ok.example.com",
                    "ssh_username": "ubuntu",
                    "ssh_key_id": key_id,
                    "endpoint_host": "ok.example.com",
                },
            ).json()["server"]["id"]
        )
        # Second (unreachable) server. We register it with a custom subnet
        # so the IP allocator doesn't collide.
        bad_id = int(
            client.post(
                "/servers",
                json={
                    "hostname": "bad.example.com",
                    "ssh_username": "ubuntu",
                    "ssh_key_id": key_id,
                    "endpoint_host": "bad.example.com",
                },
            ).json()["server"]["id"]
        )

        # Healthy host returns one peer; unreachable host times out.
        FakeSSHRunner.OUTPUTS[("ok.example.com", "wg show wg0 dump")] = (
            "SRV_PRIV\tSRV_PUB\t51820\toff\n"
            "PEER_OK\t(none)\t(none)\t10.9.0.7/32\t0\t0\t0\toff\n"
        )
        FakeSSHRunner.RAISE_ON_ENTER["bad.example.com"] = socket.timeout(
            "timed out"
        )

        with caplog.at_level(logging.ERROR, logger="wg_manager.tasks"):
            resp = client.post("/servers/discover-all")
            assert resp.status_code == 202, resp.text

        # Peers on the healthy server were persisted.
        ok_peers = client.get(f"/servers/{ok_id}/discovered-peers").json()
        assert len(ok_peers) == 1
        assert ok_peers[0]["public_key"] == "PEER_OK"

        # No rows for the unreachable server.
        bad_peers = client.get(f"/servers/{bad_id}/discovered-peers").json()
        assert bad_peers == []

        # The bad host should have been logged.
        assert any(
            "bad.example.com" in r.getMessage() for r in caplog.records
        ), "expected an ERROR log mentioning the unreachable host"


class TestProvisionServerTimeout:
    def test_marks_server_error_and_raises_cleanly(
        self,
        client: TestClient,
        engine: object,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        # Register an SSH key, then drop a Server row directly so we can
        # invoke the task in isolation (without the eager-mode HTTP path
        # blowing up before we get to assert anything).
        key_id = int(
            client.post(
                "/ssh-keys",
                json={"name": "lab", "private_key_b64": _SAMPLE_PEM_B64},
            ).json()["id"]
        )
        with Session(engine) as session:  # type: ignore[arg-type]
            srv = Server(
                hostname="unreachable.example.com",
                ssh_username="ubuntu",
                ssh_key_id=key_id,
                endpoint_host="unreachable.example.com",
                subnet="10.9.0.0/24",
                address="10.9.0.1/24",
                status=NodeStatus.pending,
            )
            session.add(srv)
            session.commit()
            session.refresh(srv)
            server_id = srv.id

        FakeSSHRunner.RAISE_ON_ENTER["unreachable.example.com"] = TimeoutError(
            "connection timed out after 15s"
        )

        with caplog.at_level(logging.ERROR, logger="wg_manager.tasks"):
            with pytest.raises(RuntimeError) as exc_info:
                provision_server_task(server_id)

        # Tidy exception, no chained traceback.
        assert "unreachable.example.com" in str(exc_info.value)
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__suppress_context__ is True

        # Row's status must have flipped to ``error``.
        with Session(engine) as session:  # type: ignore[arg-type]
            row = session.get(Server, server_id)
            assert row is not None
            assert row.status == NodeStatus.error

        # No stack trace attached to the log record.
        assert any(
            r.exc_info is None and "unreachable.example.com" in r.getMessage()
            for r in caplog.records
        )


class TestProvisionClientTimeout:
    def test_client_marked_error_on_ssh_timeout(
        self,
        client: TestClient,
        engine: object,
    ) -> None:
        # Bootstrap a ready server first (happy path).
        server_id = _bootstrap_server(client)

        # Now configure the *client* host to time out before registering it.
        FakeSSHRunner.RAISE_ON_ENTER["alpha.example.com"] = SSHConnectionError(
            "SSH connection to alpha.example.com:22 timed out after 15s"
        )

        from wg_manager.celery_app import celery_app

        original = celery_app.conf.task_eager_propagates
        celery_app.conf.task_eager_propagates = False
        try:
            resp = client.post(
                "/clients",
                json={
                    "name": "alpha",
                    "hostname": "alpha.example.com",
                    "ssh_username": "ubuntu",
                    "ssh_key_id": 1,
                    "server_id": server_id,
                },
            )
        finally:
            celery_app.conf.task_eager_propagates = original

        # The HTTP request still returns 202 — provisioning is async.
        assert resp.status_code == 202, resp.text
        client_id = resp.json()["client"]["id"]

        # And the client row should be in ``error`` state since the task
        # ran (eagerly) and caught the timeout.
        body = client.get(f"/clients/{client_id}").json()
        assert body["status"] == "error"
