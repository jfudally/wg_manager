"""Tests for CP3.2 task wiring: provision_server persists host-cert columns.

Pin the behaviour the task layer must guarantee:

* When ``SSH_AUTH_MODE=ca`` is on, a successful
  :func:`wg_manager.tasks.provision_server_task` run leaves the
  ``server`` row with every CP3.1 host-cert column populated —
  serial, principals, validity window, the cert body, and the
  signing CA's pubkey snapshot.
* The signing CA on the row matches the live
  :attr:`wg_manager.ssh_ca.SSHCABackend.ca_public_key`. A skew between
  the column and the CA would defeat the audit-on-rotation use case
  the column exists for.
* When CA mode is **off**, those columns stay ``None``. CP3 must not
  retro-fit a host cert on a Phase 2b row whose operator hasn't
  opted in yet.
* When the host has no ed25519 pubkey (the helper raises), the row
  goes to ``error`` status with the columns left ``None`` — provisioning
  fails cleanly without writing a half-populated row.
"""

from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from tests.conftest import FakeSSHRunner
from wg_manager.models import NodeStatus, Server


_SAMPLE_PEM = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "cp3-host-cert-canary\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)
_SAMPLE_PEM_B64 = base64.b64encode(_SAMPLE_PEM.encode("utf-8")).decode("ascii")

# A real ed25519 public key body. The CA-mint path actually parses
# this via cryptography.serialization.load_ssh_public_identity, so we
# need a syntactically valid OpenSSH ed25519 pubkey or the mint fails
# before the column-write assertion runs.
_HOST_PUBKEY = (
    "ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAINcv8wY+y8d0KcKZ6t6S/n7JoYx7M3jzqu7K2YgQGvD7"
    " root@cp3-task.example.com"
)


def _enable_ca_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """Flip the SSH auth seam into CA mode for the duration of the test."""
    monkeypatch.setenv("SSH_AUTH_MODE", "ca")
    monkeypatch.setenv("SSH_CA_BACKEND", "local")
    monkeypatch.delenv("SSH_CA_LOCAL_DEV_PEM", raising=False)


def _register_host_pubkey(host: str, pubkey: str = _HOST_PUBKEY) -> None:
    """Make FakeSSHRunner's ``cat ssh_host_ed25519_key.pub`` return ``pubkey``."""
    FakeSSHRunner.OUTPUTS[(host, "ssh_host_ed25519_key.pub")] = pubkey + "\n"


def _register_server(client: TestClient, hostname: str) -> int:
    """Register an SSH key + server and return the server id.

    The eagerly-run task drives provisioning to completion; we assert
    on the resulting row's host_cert_* columns in each test.
    """
    key_id = int(
        client.post(
            "/ssh-keys",
            json={"name": "cp3-task", "private_key_b64": _SAMPLE_PEM_B64},
        ).json()["id"]
    )
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
# CA mode — full population
# ---------------------------------------------------------------------------


class TestProvisionServerPersistsHostCert:
    """Successful CA-mode provisioning fills every CP3.1 column on the row."""

    def test_all_host_cert_columns_populated(
        self,
        client: TestClient,
        engine: object,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _enable_ca_mode(monkeypatch)
        host = "ca-prov.example.com"
        _register_host_pubkey(host)

        server_id = _register_server(client, host)

        with Session(engine) as session:  # type: ignore[arg-type]
            row = session.get(Server, server_id)
            assert row is not None
            assert row.status == NodeStatus.ready, (
                f"provisioning was supposed to succeed; status={row.status}"
            )
            assert row.host_cert_pem and row.host_cert_pem.startswith(
                "ssh-ed25519-cert-v01@openssh.com "
            ), "host_cert_pem must hold the actual cert body the helper minted"
            assert row.host_cert_serial is not None and row.host_cert_serial > 0
            assert row.host_cert_principals == host, (
                f"principals column should be the comma list of cert "
                f"principals; got {row.host_cert_principals!r}"
            )
            assert row.host_cert_valid_after is not None
            assert row.host_cert_valid_before is not None
            assert row.host_cert_valid_before > row.host_cert_valid_after
            assert row.host_cert_ca_public_key
            assert row.host_cert_ca_public_key.strip().startswith(
                "ssh-ed25519 "
            )


# ---------------------------------------------------------------------------
# Legacy mode — must NOT touch the columns
# ---------------------------------------------------------------------------


class TestLegacyProvisionLeavesHostCertNull:
    """When CA mode is off, the new columns stay ``None`` on a provision."""

    def test_columns_remain_null(
        self,
        client: TestClient,
        engine: object,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("SSH_AUTH_MODE", "legacy")
        host = "legacy-prov.example.com"
        _register_host_pubkey(host)

        server_id = _register_server(client, host)

        with Session(engine) as session:  # type: ignore[arg-type]
            row = session.get(Server, server_id)
            assert row is not None
            assert row.status == NodeStatus.ready
            for name in (
                "host_cert_pem",
                "host_cert_serial",
                "host_cert_principals",
                "host_cert_valid_after",
                "host_cert_valid_before",
                "host_cert_ca_public_key",
            ):
                assert getattr(row, name) is None, (
                    f"legacy provisioning should not populate {name}; "
                    f"got {getattr(row, name)!r}"
                )


# ---------------------------------------------------------------------------
# Missing host pubkey — fails cleanly
# ---------------------------------------------------------------------------


class TestProvisionFailsWhenHostKeyMissing:
    """If the host has no ed25519 pubkey, provisioning surfaces a clean error."""

    def test_row_marked_error_no_half_written_columns(
        self,
        client: TestClient,
        engine: object,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _enable_ca_mode(monkeypatch)
        # Note: we deliberately do NOT register a host pubkey output.
        # The FakeSSHRunner returns "" for the probe, triggering the
        # ``host public key is empty`` branch in
        # :func:`wg_manager.host_ssh.install_host_cert`.
        # Disable eager propagation so the failure surfaces as a 202 +
        # the row going to ``error``, matching the production HTTP path.
        from wg_manager.celery_app import celery_app

        original = celery_app.conf.task_eager_propagates
        celery_app.conf.task_eager_propagates = False
        try:
            server_id = _register_server(client, "no-host-key.example.com")
        finally:
            celery_app.conf.task_eager_propagates = original

        with Session(engine) as session:  # type: ignore[arg-type]
            row = session.get(Server, server_id)
            assert row is not None
            assert row.status == NodeStatus.error, (
                f"missing host pubkey should leave row in error; "
                f"status={row.status}"
            )
            # And no half-written columns on the failed row.
            assert row.host_cert_pem is None
            assert row.host_cert_serial is None
