"""Tests for Phase 2c CP2: Celery tasks mint per-session user certs.

When ``SSH_AUTH_MODE=ca`` is in effect, each provisioning / discovery
task must construct its :class:`SSHRunner` with a freshly minted
:class:`UserCert` rather than a long-lived private key resolved from
the ``sshkey`` row. CP4 will flip the per-row default and drop the
plaintext (and ciphertext) columns; CP2 only proves the wiring is in
place and gated by the setting so an operator can opt in today.

The behavioural contract these tests pin down:

* On every task entry point — ``provision_server_task``,
  ``reconfigure_server_task``, ``provision_client_task``,
  ``discover_peers_task`` — when the setting is ``ca``, the runner
  receives a non-empty ``cert_pem`` *and* a matching ``ca_public_key``.
* The cert is a real OpenSSH user certificate whose principals
  include the row's ``ssh_username`` (i.e. we ask the CA for a
  principal the target sshd will accept).
* The signature key embedded in the cert matches the ``ca_public_key``
  passed to the runner — a single CA instance mints the cert *and*
  advertises the host-trust anchor, so there is no skew between the
  client-auth and host-trust halves of the session.
* Legacy mode (default ``SSH_AUTH_MODE=legacy``) is untouched: the
  runner receives no cert and the stored private key flows through
  as before. This is the Phase 2b regression guarantee.
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import (
    SSHCertificate,
    SSHCertificateType,
    load_ssh_public_identity,
)
from fastapi.testclient import TestClient
from sqlmodel import Session

from tests.conftest import FakeSSHRunner
from wg_manager.models import NodeStatus, Server


_SAMPLE_PEM = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "ssh-ca-mode-canary\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)
_SAMPLE_PEM_B64 = base64.b64encode(_SAMPLE_PEM.encode("utf-8")).decode("ascii")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _enable_ca_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """Flip the SSH auth seam into CA mode for the duration of the test.

    Both knobs are required: ``SSH_AUTH_MODE`` tells the task layer to
    mint per-session, and ``SSH_CA_BACKEND`` keeps the in-process
    ed25519 backend so we don't need a Vault container.
    """
    monkeypatch.setenv("SSH_AUTH_MODE", "ca")
    monkeypatch.setenv("SSH_CA_BACKEND", "local")
    monkeypatch.delenv("SSH_CA_LOCAL_DEV_PEM", raising=False)


def _parse_cert(cert_pem: str) -> SSHCertificate:
    """Parse an OpenSSH cert body, asserting it is a certificate."""
    identity = load_ssh_public_identity(cert_pem.encode())
    assert isinstance(identity, SSHCertificate), (
        f"expected SSHCertificate, got {type(identity).__name__}"
    )
    return identity


def _assert_cert_matches_ca(cert_pem: str, ca_public_key: str) -> SSHCertificate:
    """Verify the cert's signing key matches the advertised CA public key."""
    cert = _parse_cert(cert_pem)
    signer_blob = cert.signature_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    signer_body = signer_blob.split(b" ")[1].decode("ascii")
    ca_body = ca_public_key.strip().split()[1]
    assert signer_body == ca_body, (
        "cert signer does not match advertised CA — runner would not trust the host "
        "even if a host cert was present"
    )
    return cert


def _bootstrap_ready_server(client: TestClient, *, hostname: str = "hub.example.com") -> int:
    """Register an SSH key + ready server through the API and return the server ID.

    The HTTP provision call runs eagerly under the test config and
    flips the row to ``ready`` so subsequent reconfigure / discover
    tasks have a real server to talk to. ``FakeSSHRunner.CERTS_USED``
    is cleared after bootstrap so the test only inspects the runner
    construction that the *act* under test caused.
    """
    key_id = int(
        client.post(
            "/ssh-keys",
            json={"name": "lab", "private_key_b64": _SAMPLE_PEM_B64},
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
    server_id = int(resp.json()["server"]["id"])
    # Eager mode ran the task and should have marked the row ready.
    FakeSSHRunner.CERTS_USED.clear()
    FakeSSHRunner.KEYS_USED.clear()
    return server_id


# ---------------------------------------------------------------------------
# CA-mode behavioural matrix — runs against every task entry point
# ---------------------------------------------------------------------------


class TestProvisionServerCertMode:
    """``provision_server_task`` mints a per-session user cert under CA mode."""

    def test_runner_receives_cert_and_ca(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _enable_ca_mode(monkeypatch)

        key_id = int(
            client.post(
                "/ssh-keys",
                json={"name": "lab", "private_key_b64": _SAMPLE_PEM_B64},
            ).json()["id"]
        )
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

        # The eagerly-run provision_server_task should have driven a
        # cert-mode runner construction with principals = ["ubuntu"].
        cert_records = [
            r for r in FakeSSHRunner.CERTS_USED if r[0] == "hub.example.com"
        ]
        assert cert_records, "no SSHRunner constructed for hub.example.com"
        host, cert_pem, ca_public_key, username = cert_records[0]
        assert cert_pem, "task layer did not mint a per-session user cert"
        assert ca_public_key, "task layer did not pass a CA public key for host trust"

        cert = _assert_cert_matches_ca(cert_pem, ca_public_key)
        assert cert.type == SSHCertificateType.USER, (
            "task minted a host cert instead of a user cert"
        )
        principals = [
            p.decode() if isinstance(p, bytes) else p
            for p in cert.valid_principals
        ]
        assert username in principals, (
            f"cert principals {principals!r} do not include the row's "
            f"ssh_username {username!r} — sshd will reject this cert"
        )


class TestReconfigureServerCertMode:
    """``reconfigure_server_task`` (the post-client-add fast path) also mints."""

    def test_runner_receives_cert_and_ca(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Bootstrap without CA mode so the initial provision uses legacy creds
        # (we're not testing the bootstrap path here — we're testing what
        # the *reconfigure* call does once CA mode is on).
        server_id = _bootstrap_ready_server(client, hostname="hub2.example.com")

        _enable_ca_mode(monkeypatch)
        from wg_manager.tasks import reconfigure_server_task

        reconfigure_server_task(server_id)

        cert_records = [
            r for r in FakeSSHRunner.CERTS_USED if r[0] == "hub2.example.com"
        ]
        assert cert_records, "reconfigure did not construct an SSHRunner"
        host, cert_pem, ca_public_key, username = cert_records[-1]
        assert cert_pem and ca_public_key, (
            "reconfigure runner missing cert / ca_public_key in CA mode"
        )
        _assert_cert_matches_ca(cert_pem, ca_public_key)


class TestProvisionClientCertMode:
    """``provision_client_task`` mints a cert and uses the client row's ssh_username."""

    def test_runner_receives_cert_and_ca(
        self,
        client: TestClient,
        engine: object,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Bootstrap the server in legacy mode so it lands ``ready`` cheaply.
        server_id = _bootstrap_ready_server(client, hostname="hub3.example.com")

        _enable_ca_mode(monkeypatch)
        client_resp = client.post(
            "/clients",
            json={
                "name": "alpha",
                "hostname": "alpha.example.com",
                "ssh_username": "deploy",
                "ssh_key_id": 1,
                "server_id": server_id,
            },
        )
        assert client_resp.status_code == 202, client_resp.text

        client_records = [
            r for r in FakeSSHRunner.CERTS_USED if r[0] == "alpha.example.com"
        ]
        assert client_records, "no SSHRunner constructed for alpha.example.com"
        host, cert_pem, ca_public_key, username = client_records[0]
        assert cert_pem and ca_public_key, (
            "client provisioning runner missing cert / ca_public_key in CA mode"
        )
        cert = _assert_cert_matches_ca(cert_pem, ca_public_key)
        principals = [
            p.decode() if isinstance(p, bytes) else p
            for p in cert.valid_principals
        ]
        assert "deploy" in principals, (
            f"client provisioning cert principals {principals!r} do not "
            "match the row's ssh_username"
        )


class TestDiscoverPeersCertMode:
    """Discovery is read-only but still goes over SSH — must use CA mode too."""

    def test_runner_receives_cert_and_ca(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        server_id = _bootstrap_ready_server(client, hostname="hub4.example.com")

        _enable_ca_mode(monkeypatch)
        # Provide a minimal valid `wg show wg0 dump` body so discovery
        # succeeds — this isolates the test to the *runner construction*
        # path rather than the discovery-error fallback.
        FakeSSHRunner.OUTPUTS[("hub4.example.com", "wg show wg0 dump")] = (
            "SRV_PRIV\tSRV_PUB\t51820\toff\n"
        )

        from wg_manager.tasks import discover_peers_task

        result = discover_peers_task(server_id)
        assert result["status"] == "ok", result

        cert_records = [
            r for r in FakeSSHRunner.CERTS_USED if r[0] == "hub4.example.com"
        ]
        assert cert_records, "discovery did not construct an SSHRunner"
        host, cert_pem, ca_public_key, username = cert_records[-1]
        assert cert_pem and ca_public_key, (
            "discovery runner missing cert / ca_public_key in CA mode"
        )
        _assert_cert_matches_ca(cert_pem, ca_public_key)


# ---------------------------------------------------------------------------
# Legacy mode regression — default behaviour MUST be unchanged
# ---------------------------------------------------------------------------


class TestLegacyModeUnchanged:
    """With ``SSH_AUTH_MODE`` unset / ``legacy``, no cert is minted."""

    def test_provision_server_no_cert_in_legacy_mode(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SSH_AUTH_MODE", "legacy")
        key_id = int(
            client.post(
                "/ssh-keys",
                json={"name": "lab", "private_key_b64": _SAMPLE_PEM_B64},
            ).json()["id"]
        )
        client.post(
            "/servers",
            json={
                "hostname": "legacy.example.com",
                "ssh_username": "ubuntu",
                "ssh_key_id": key_id,
                "endpoint_host": "legacy.example.com",
            },
        )
        legacy_records = [
            r for r in FakeSSHRunner.CERTS_USED if r[0] == "legacy.example.com"
        ]
        assert legacy_records, "expected at least one SSHRunner construction"
        for _host, cert_pem, ca_public_key, _username in legacy_records:
            assert cert_pem is None, (
                f"legacy mode unexpectedly produced a cert: {cert_pem!r}"
            )
            assert ca_public_key is None, (
                f"legacy mode unexpectedly passed a CA pubkey: "
                f"{ca_public_key!r}"
            )
