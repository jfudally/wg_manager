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

from tests.conftest import FakeSSHRunner, promote_all_keys_to_ca
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


def _register_server(
    client: TestClient,
    hostname: str,
    *,
    ca_mode_session: Session | None = None,
) -> int:
    """Register an SSH key + server and return the server id.

    The eagerly-run task drives provisioning to completion; we assert
    on the resulting row's host_cert_* columns in each test.

    Pass ``ca_mode_session=session`` (Phase 2c CP4.1) to flip the
    freshly-created SSH key into CA mode before the server POST. The
    routing seam reads ``SSHKey.mode``, not the global env var, so
    tests that want CA-mode provisioning have to promote the key
    explicitly. The flip is the test-only equivalent of CP4.2's
    ``wg-manager ssh migrate-to-ca`` CLI.
    """
    key_id = int(
        client.post(
            "/ssh-keys",
            json={"name": "cp3-task"},
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
# CA mode — full population
# ---------------------------------------------------------------------------


class TestProvisionServerPersistsHostCert:
    """Successful CA-mode provisioning fills every CP3.1 column on the row."""

    def test_all_host_cert_columns_populated(
        self,
        client: TestClient,
        engine: object,
        session: Session,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _enable_ca_mode(monkeypatch)
        host = "ca-prov.example.com"
        _register_host_pubkey(host)

        # CP4.1: flip the freshly-created key into CA mode so the
        # routing seam picks the cert branch and the host-cert install
        # runs.
        server_id = _register_server(client, host, ca_mode_session=session)

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


# Phase 2c CP4.4 retired the legacy provisioning path — every
# provision now mints a host cert and populates the CP3.1 columns by
# construction, so the prior "legacy provisioning leaves the columns
# null" suite is no longer reachable. The "host has no ed25519
# pubkey" failure path below still applies and is the remaining
# pin against a half-applied install.


class TestProvisionFailsWhenHostKeyMissing:
    """If the host has no ed25519 pubkey, provisioning surfaces a clean error."""

    def test_row_marked_error_no_half_written_columns(
        self,
        client: TestClient,
        engine: object,
        session: Session,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _enable_ca_mode(monkeypatch)
        # Opt this host out of FakeSSHRunner's CP4.4 default that
        # always returns a canned ed25519 pubkey — the failure-mode
        # test needs the runner to mirror the real not-yet-keygen-ed
        # shape (empty stdout from the probe), which hits
        # :func:`wg_manager.host_ssh._read_host_pubkey`'s "host pubkey
        # is empty" branch.
        from tests.conftest import FakeSSHRunner

        host = "no-host-key.example.com"
        FakeSSHRunner.SUPPRESS_HOST_PUBKEY.add(host)
        # Disable eager propagation so the failure surfaces as a 202 +
        # the row going to ``error``, matching the production HTTP path.
        from wg_manager.celery_app import celery_app

        original = celery_app.conf.task_eager_propagates
        celery_app.conf.task_eager_propagates = False
        try:
            server_id = _register_server(
                client,
                host,
                ca_mode_session=session,
            )
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
