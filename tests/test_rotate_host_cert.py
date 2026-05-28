"""Tests for Phase 2c CP3.3: ``POST /servers/{id}/rotate-host-cert``.

The rotate endpoint is operator-driven re-minting of a server's host
certificate before its TTL expires (or after a Vault CA rotation
invalidates the current signer). It must:

* 404 when the server doesn't exist.
* 409 when the global SSH auth mode is ``legacy`` — host certs only
  make sense in CA mode, and silently no-op'ing would leave the
  operator wondering why the row's columns never changed.
* In CA mode, dispatch a Celery task that opens an SSH session,
  re-runs the host-side install, and overwrites the row's host_cert
  columns with the freshly-minted cert. The endpoint returns 202 +
  ``{task_id, server}`` for parity with the other server-side async
  endpoints.

The task itself (:func:`wg_manager.tasks.rotate_host_cert_task`) is
also tested directly to pin the per-row update semantics — the
endpoint test asserts the contract; the task test asserts the
behaviour.
"""

from __future__ import annotations


import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from tests.conftest import FakeSSHRunner, promote_all_keys_to_ca
from wg_manager.models import Server


_HOST_PUBKEY = (
    "ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAINcv8wY+y8d0KcKZ6t6S/n7JoYx7M3jzqu7K2YgQGvD7"
    " root@cp3-rotate.example.com"
)


def _register_host_pubkey(host: str) -> None:
    FakeSSHRunner.OUTPUTS[(host, "ssh_host_ed25519_key.pub")] = _HOST_PUBKEY + "\n"


def _enable_ca_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SSH_AUTH_MODE", "ca")
    monkeypatch.setenv("SSH_CA_BACKEND", "local")
    monkeypatch.delenv("SSH_CA_LOCAL_DEV_PEM", raising=False)


def _register_server(
    client: TestClient,
    hostname: str,
    *,
    ca_mode_session: Session | None = None,
) -> int:
    """Register an SSH key + server.

    Pass ``ca_mode_session=session`` (Phase 2c CP4.1) to flip the
    freshly-created SSH key into CA mode before the server POST, so
    the task layer routes through the cert branch and CP3's host-cert
    install runs.
    """
    key_id = int(
        client.post(
            "/ssh-keys",
            json={"name": "cp3-rot"},
        ).json()["id"]
    )
    if ca_mode_session is not None:
        promote_all_keys_to_ca(ca_mode_session)
    resp = client.post(
        "/servers",
        json={
            "hostname": hostname,
            "ssh_username": "ubuntu",
            "ssh_key_id": key_id,
            "endpoint_host": hostname,
        },
    )
    assert resp.status_code == 202, resp.text
    return int(resp.json()["server"]["id"])


# ---------------------------------------------------------------------------
# Endpoint shape
# ---------------------------------------------------------------------------


class TestRotateHostCertEndpoint:
    """``POST /servers/{id}/rotate-host-cert`` contract."""

    def test_returns_202_and_envelope_in_ca_mode(
        self,
        client: TestClient,
        engine: object,
        session: Session,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _enable_ca_mode(monkeypatch)
        host = "rot-ok.example.com"
        _register_host_pubkey(host)
        # CP4.1: ca_mode_session promotes the SSH key into CA mode so
        # the row's key passes the rotate endpoint's precondition.
        server_id = _register_server(client, host, ca_mode_session=session)

        resp = client.post(f"/servers/{server_id}/rotate-host-cert")

        assert resp.status_code == 202, resp.text
        body = resp.json()
        assert "task_id" in body and body["task_id"]
        assert body["server"]["id"] == server_id
        # And the row's columns reflect the rotation (eager mode ran
        # the task synchronously). Serial differs from the cert minted
        # at provisioning time because the CA picks a fresh
        # ``secrets.randbits(63)`` for each issuance.
        with Session(engine) as session:  # type: ignore[arg-type]
            row = session.get(Server, server_id)
            assert row is not None
            assert row.host_cert_serial is not None
            assert row.host_cert_principals == host

    def test_returns_404_when_server_missing(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _enable_ca_mode(monkeypatch)
        resp = client.post("/servers/9999/rotate-host-cert")
        assert resp.status_code == 404, resp.text

    # Phase 2c CP4.4 retired the legacy-mode rotation guard: every
    # SSHKey row is CA-mode by construction now, so the "rotate in
    # legacy mode" branch the original test pinned is no longer
    # reachable. The 404-when-server-missing case above still holds
    # and is the only remaining precondition.


# ---------------------------------------------------------------------------
# Task-level: in-place rotation overwrites the columns
# ---------------------------------------------------------------------------


class TestRotateHostCertTask:
    """``rotate_host_cert_task`` re-mints + persists, even on an already-populated row."""

    def test_overwrites_existing_host_cert_columns(
        self,
        client: TestClient,
        engine: object,
        session: Session,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _enable_ca_mode(monkeypatch)
        host = "rot-overwrite.example.com"
        _register_host_pubkey(host)
        # CP4.1: ca_mode_session promotes the SSH key into CA mode.
        server_id = _register_server(client, host, ca_mode_session=session)

        # Snapshot the first cert's serial so we can prove rotation
        # produced a different one.
        with Session(engine) as session:  # type: ignore[arg-type]
            row = session.get(Server, server_id)
            assert row is not None
            first_serial = row.host_cert_serial
            first_valid_before = row.host_cert_valid_before
            assert first_serial is not None

        from wg_manager.tasks import rotate_host_cert_task

        result = rotate_host_cert_task(server_id)

        assert result["server_id"] == server_id
        assert result["status"] == "ok"
        assert result["serial"] != first_serial

        with Session(engine) as session:  # type: ignore[arg-type]
            row = session.get(Server, server_id)
            assert row is not None
            assert row.host_cert_serial == result["serial"]
            assert row.host_cert_valid_before is not None
            # New cert is at least as far out as the old one (TTL
            # didn't shrink mid-test).
            assert row.host_cert_valid_before >= first_valid_before
