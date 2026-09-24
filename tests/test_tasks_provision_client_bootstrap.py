"""Tests for the combined bootstrap-then-provision flow on **clients**.

Mirrors :mod:`tests.test_tasks_provision_bootstrap` for the spoke side.
Before this change only ``POST /servers`` accepted the operator's OOB
SSH key, so every SSH-provisioned client needed a separate
``wg-manager bootstrap-host`` run before registration — otherwise the
CA-mode runner failed with ``host cert signed by an untrusted CA``.

``POST /clients`` now takes the same optional
``bootstrap_ssh_key_pem`` / ``bootstrap_ssh_key_passphrase`` pair:

* When the PEM is supplied, the router encrypts it before queueing and
  :func:`wg_manager.tasks.provision_client_task` runs
  :func:`bootstrap_host` against the client BEFORE opening the CA-mode
  provision session.
* When the PEM is omitted, the task behaves exactly as before.

These tests pin both halves plus the failure path and the
"broker never sees plaintext" contract.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from tests.conftest import FakeSSHRunner
from tests.test_tasks_provision_bootstrap import _RecordingBootstrapRunner
from wg_manager.models import Client, NodeStatus


_PLAINTEXT_PEM = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "CLIENTBOOTSTRAP\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)


@pytest.fixture(autouse=True)
def _reset_bootstrap_runner() -> None:
    """Clear the recorder between tests (class-level state)."""
    _RecordingBootstrapRunner.CONSTRUCTIONS = []


@pytest.fixture
def recording_bootstrap(monkeypatch: pytest.MonkeyPatch) -> None:
    """Swap the real bootstrap runner for the recording stand-in."""
    from wg_manager import tasks as tasks_module

    monkeypatch.setattr(
        tasks_module, "BootstrapSSHRunner", _RecordingBootstrapRunner
    )


def _ready_server(client: TestClient) -> tuple[int, int]:
    """Register an SSH key + a ready hub (no bootstrap). Returns (key_id, server_id)."""
    key_id = int(client.post("/ssh-keys", json={"name": "lab"}).json()["id"])
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
    return key_id, int(resp.json()["server"]["id"])


def _client_payload(key_id: int, server_id: int, **extra: Any) -> dict[str, Any]:
    """Build a ``POST /clients`` body for ``spoke.example.com``."""
    return {
        "name": "spoke",
        "hostname": "spoke.example.com",
        "ssh_username": "ubuntu",
        "ssh_key_id": key_id,
        "server_id": server_id,
        **extra,
    }


def _client_commands() -> list[str]:
    """Commands the CA-mode FakeSSHRunner ran against the client host."""
    return [cmd for host, cmd in FakeSSHRunner.COMMANDS if host == "spoke.example.com"]


class TestClientProvisionBootstraps:
    """A client registration carrying bootstrap material lays down CA trust first."""

    def test_bootstrap_runs_before_provision_when_pem_supplied(
        self, client: TestClient, recording_bootstrap: None
    ) -> None:
        """The bootstrap runner dials the *client* with the decrypted PEM."""
        key_id, server_id = _ready_server(client)

        resp = client.post(
            "/clients",
            json=_client_payload(
                key_id, server_id, bootstrap_ssh_key_pem=_PLAINTEXT_PEM
            ),
        )
        assert resp.status_code == 202, resp.text

        assert len(_RecordingBootstrapRunner.CONSTRUCTIONS) == 1
        built = _RecordingBootstrapRunner.CONSTRUCTIONS[0]
        assert built["key_pem"] == _PLAINTEXT_PEM
        assert built["host"] == "spoke.example.com"
        assert built["port"] == 22
        assert built["username"] == "ubuntu"
        assert built["passphrase"] is None
        # The CA-mode provision session still ran against the client.
        assert _client_commands(), "client provision must run after bootstrap"
        assert client.get(f"/clients/{resp.json()['client']['id']}").json()[
            "status"
        ] == "ready"

    def test_passphrase_is_decrypted_and_threaded_to_runner(
        self, client: TestClient, recording_bootstrap: None
    ) -> None:
        """An encrypted-key passphrase reaches the runner as plaintext."""
        key_id, server_id = _ready_server(client)

        resp = client.post(
            "/clients",
            json=_client_payload(
                key_id,
                server_id,
                bootstrap_ssh_key_pem=_PLAINTEXT_PEM,
                bootstrap_ssh_key_passphrase="hunter2",
            ),
        )
        assert resp.status_code == 202, resp.text
        assert _RecordingBootstrapRunner.CONSTRUCTIONS[0]["passphrase"] == "hunter2"

    def test_provision_skips_bootstrap_when_pem_omitted(
        self, client: TestClient, recording_bootstrap: None
    ) -> None:
        """No PEM → no bootstrap session; already-bootstrapped clients unchanged."""
        key_id, server_id = _ready_server(client)

        resp = client.post("/clients", json=_client_payload(key_id, server_id))
        assert resp.status_code == 202, resp.text
        assert _RecordingBootstrapRunner.CONSTRUCTIONS == []
        assert _client_commands()

    def test_bootstrap_failure_marks_client_error_and_skips_provision(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A bootstrap SSH failure flips the client to ``error`` without provisioning.

        Eager Celery (``task_eager_propagates=True``) re-raises the
        task's clean ``RuntimeError`` out of the request — see the
        server-side twin for why that's a test-only shape.
        """
        from wg_manager import tasks as tasks_module
        from wg_manager.ssh import SSHConnectionError

        class _BrokenBootstrap(_RecordingBootstrapRunner):
            def __enter__(self) -> "_BrokenBootstrap":
                raise SSHConnectionError(
                    "SSH authentication failed for ubuntu@spoke: bad key",
                    host="spoke.example.com",
                    port=22,
                )

        key_id, server_id = _ready_server(client)
        monkeypatch.setattr(tasks_module, "BootstrapSSHRunner", _BrokenBootstrap)

        with pytest.raises(RuntimeError, match="provisioning failed.*bad key"):
            client.post(
                "/clients",
                json=_client_payload(
                    key_id, server_id, bootstrap_ssh_key_pem="garbage"
                ),
            )

        assert _client_commands() == [], "provision must not run when bootstrap fails"
        from wg_manager.db import engine

        with Session(engine) as fresh:
            row = fresh.exec(select(Client).where(Client.name == "spoke")).one()
            assert row.status == NodeStatus.error


class TestClientBootstrapRouter:
    """Router-side contract: validation + encryption before the broker."""

    def test_passphrase_without_pem_is_rejected(self, client: TestClient) -> None:
        """A passphrase alone is ambiguous intent — 422, no row created."""
        key_id, server_id = _ready_server(client)

        resp = client.post(
            "/clients",
            json=_client_payload(
                key_id, server_id, bootstrap_ssh_key_passphrase="orphan"
            ),
        )
        assert resp.status_code == 422, resp.text
        assert client.get("/clients").json() == []

    def test_broker_never_sees_plaintext_key_material(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``provision_client_task.delay`` receives ciphertext + context only."""
        from wg_manager.routers import clients as clients_router

        key_id, server_id = _ready_server(client)

        captured: dict[str, Any] = {}

        class _FakeAsyncResult:
            id = "fake-task-id"

        def _capture_delay(*args: Any, **kwargs: Any) -> _FakeAsyncResult:
            captured["args"] = args
            captured["kwargs"] = kwargs
            return _FakeAsyncResult()

        monkeypatch.setattr(
            clients_router.provision_client_task, "delay", _capture_delay
        )

        resp = client.post(
            "/clients",
            json=_client_payload(
                key_id,
                server_id,
                bootstrap_ssh_key_pem=_PLAINTEXT_PEM,
                bootstrap_ssh_key_passphrase="hunter2",
            ),
        )
        assert resp.status_code == 202, resp.text

        kwargs = captured["kwargs"]
        assert kwargs["bootstrap_pem_ciphertext"]
        assert kwargs["bootstrap_passphrase_ciphertext"]
        assert kwargs["bootstrap_pem_context"] == "provision-client:bootstrap-pem"
        assert (
            kwargs["bootstrap_passphrase_context"]
            == "provision-client:bootstrap-passphrase"
        )
        serialized = repr(captured)
        assert "CLIENTBOOTSTRAP" not in serialized
        assert "hunter2" not in serialized
