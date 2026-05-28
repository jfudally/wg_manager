"""Tests for Phase 2c CP4.2: ``POST /ssh-keys/{id}/migrate-to-ca``.

CP4.2 ships the *bootstrap* path between the two SSH auth modes:
take a row that is still on stored-key (legacy) auth — or a row
that was prematurely labelled ``ca`` but never had its hosts
bootstrapped — and walk every server that uses the row through
the host-side CA install, then flip the row to ``mode=ca`` and
discard the ciphertext columns. The end state is a row that no
longer carries any plaintext SSH material at all.

The endpoint takes a one-shot ``private_key_b64`` body so the
helper can open a legacy SSH session to each host. The private
key is **never** persisted: the helper uses it in-memory to
connect, runs :func:`wg_manager.host_ssh.install_host_cert`, then
drops the body. After every server succeeds, the row's
``private_key_ct`` and ``passphrase_ct`` columns are nulled.

What this module pins down for 4.2:

1. **Endpoint contract.** 200 with a per-server result envelope;
   404 when the key id is unknown; 422 when ``private_key_b64``
   is malformed; works whether the row was ``mode=legacy`` (the
   standard migration path) or ``mode=ca`` with NULL pk_ct (the
   2026-05-27 deployment shape).
2. **Side effects.** On full success: each server's ``host_cert_*``
   columns get a fresh serial / validity window from the CA, and
   the SSH key row flips to ``mode=ca`` with both ciphertext
   columns NULLed. ``install_host_cert`` is invoked once per
   server.
3. **Partial failure semantics.** If any server's bootstrap
   fails, the row's mode is **not** flipped — leaving the
   operator with a clean retry path. The response still returns
   200 with per-server failures listed so the operator can fix
   the unreachable host and re-run.
4. **No-op happy case.** A key with zero servers still flips to
   ``mode=ca`` and discards ciphertext: the operator's intent is
   clear and there's nothing to bootstrap.
5. **Auth path.** The bootstrap SSH session is *always* legacy
   (no cert / no CA pubkey passed), regardless of the row's
   current mode — the whole point is to reach a host that does
   not yet trust the CA.
"""

from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from tests.conftest import FakeSSHRunner
from wg_manager.models import SSHKey, SSHKeyMode, Server


_SAMPLE_PEM = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "cp4-2-bootstrap-canary\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)
_SAMPLE_PEM_B64 = base64.b64encode(_SAMPLE_PEM.encode("utf-8")).decode("ascii")
_HOST_PUBKEY = (
    "ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAINcv8wY+y8d0KcKZ6t6S/n7JoYx7M3jzqu7K2YgQGvD7"
    " root@cp4-2.example.com"
)


def _enable_ca_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    """Configure the local-dev CA backend so the helper can mint host certs.

    The migration endpoint needs an :class:`SSHCABackend` to sign host
    certs against each target host's pubkey. ``SSH_CA_BACKEND=local``
    spins up an ephemeral signer in-process so tests stay hermetic
    (no Vault dependency).
    """
    monkeypatch.setenv("SSH_CA_BACKEND", "local")
    monkeypatch.delenv("SSH_CA_LOCAL_DEV_PEM", raising=False)


def _register_host_pubkey(host: str) -> None:
    FakeSSHRunner.OUTPUTS[(host, "ssh_host_ed25519_key.pub")] = _HOST_PUBKEY + "\n"


def _post_key(client: TestClient, name: str = "cp4-2-key") -> int:
    """Register an SSH key and return its row id."""
    resp = client.post(
        "/ssh-keys",
        json={"name": name, "private_key_b64": _SAMPLE_PEM_B64},
    )
    assert resp.status_code == 201, resp.text
    return int(resp.json()["id"])


def _register_legacy_server(client: TestClient, key_id: int, hostname: str) -> int:
    """Register a server that uses ``key_id`` in legacy mode.

    The key must be in mode=legacy at the time of POST so the
    provision task uses the legacy SSH path (TOFU enabled) — this is
    the standard pre-CP4.2 setup. The host pubkey probe must be
    registered before the POST so the eager provision task succeeds.
    """
    _register_host_pubkey(hostname)
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


def _flip_key_to_ca(session: Session, key_id: int) -> None:
    """Direct-DB flip used to model the 2026-05-27 broken-deployment shape."""
    row = session.get(SSHKey, key_id)
    assert row is not None
    row.mode = SSHKeyMode.ca
    row.private_key_ct = None
    row.passphrase_ct = None
    session.add(row)
    session.commit()


# ---------------------------------------------------------------------------
# Endpoint shape: 404 / 422 / unknown-key paths
# ---------------------------------------------------------------------------


class TestMigrateToCAEndpointShape:
    """Pure-HTTP precondition checks: the body schema and 404 path."""

    def test_unknown_key_returns_404(
        self,
        client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _enable_ca_backend(monkeypatch)
        resp = client.post(
            "/ssh-keys/9999/migrate-to-ca",
            json={"private_key_b64": _SAMPLE_PEM_B64},
        )
        assert resp.status_code == 404, resp.text

    def test_malformed_private_key_b64_returns_422(
        self,
        client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _enable_ca_backend(monkeypatch)
        key_id = _post_key(client)
        resp = client.post(
            f"/ssh-keys/{key_id}/migrate-to-ca",
            json={"private_key_b64": "!!!not-base64!!!"},
        )
        assert resp.status_code == 422, resp.text

    def test_missing_private_key_b64_returns_422(
        self,
        client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _enable_ca_backend(monkeypatch)
        key_id = _post_key(client)
        resp = client.post(f"/ssh-keys/{key_id}/migrate-to-ca", json={})
        assert resp.status_code == 422, resp.text


# ---------------------------------------------------------------------------
# Happy path: legacy row → ca, one server
# ---------------------------------------------------------------------------


class TestMigrateToCAHappyPath:
    """Single-server legacy row gets bootstrapped end-to-end."""

    def test_response_envelope_lists_per_server_result(
        self,
        client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _enable_ca_backend(monkeypatch)
        key_id = _post_key(client)
        host = "hub1.example.com"
        server_id = _register_legacy_server(client, key_id, host)

        resp = client.post(
            f"/ssh-keys/{key_id}/migrate-to-ca",
            json={"private_key_b64": _SAMPLE_PEM_B64},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()

        assert body["key_id"] == key_id
        assert body["mode"] == "ca", (
            "row mode must flip to 'ca' once every server succeeded"
        )
        assert body["servers_total"] == 1
        assert body["servers_ok"] == 1
        assert body["servers_failed"] == 0

        results = body["results"]
        assert len(results) == 1
        assert results[0]["server_id"] == server_id
        assert results[0]["hostname"] == host
        assert results[0]["status"] == "ok"
        assert results[0]["cert_serial"] is not None
        assert results[0]["valid_before"] is not None
        assert results[0]["error"] is None

    def test_persists_host_cert_columns_on_server_row(
        self,
        client: TestClient,
        session: Session,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _enable_ca_backend(monkeypatch)
        key_id = _post_key(client)
        host = "hub2.example.com"
        server_id = _register_legacy_server(client, key_id, host)

        resp = client.post(
            f"/ssh-keys/{key_id}/migrate-to-ca",
            json={"private_key_b64": _SAMPLE_PEM_B64},
        )
        assert resp.status_code == 200, resp.text

        # Re-fetch the row from the DB; the endpoint mutates it in-place
        # alongside the row-mode flip.
        session.expire_all()
        row = session.get(Server, server_id)
        assert row is not None
        assert row.host_cert_pem, "host cert PEM should be persisted"
        assert row.host_cert_serial is not None
        assert row.host_cert_principals == host
        assert row.host_cert_valid_after is not None
        assert row.host_cert_valid_before is not None
        assert row.host_cert_ca_public_key, "CA pubkey should be persisted"

    def test_nulls_ciphertext_columns_after_success(
        self,
        client: TestClient,
        session: Session,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _enable_ca_backend(monkeypatch)
        key_id = _post_key(client)
        host = "hub3.example.com"
        _register_legacy_server(client, key_id, host)

        # Sanity: ciphertext is populated before the migration.
        pre = session.get(SSHKey, key_id)
        assert pre is not None
        assert pre.private_key_ct is not None, (
            "fixture precondition: legacy row should have populated "
            "private_key_ct before migration"
        )

        resp = client.post(
            f"/ssh-keys/{key_id}/migrate-to-ca",
            json={"private_key_b64": _SAMPLE_PEM_B64},
        )
        assert resp.status_code == 200, resp.text

        session.expire_all()
        row = session.get(SSHKey, key_id)
        assert row is not None
        assert row.mode == SSHKeyMode.ca
        assert row.private_key_ct is None, (
            "post-migration: stored ciphertext must be cleared so the "
            "row carries no plaintext SSH material at rest"
        )
        assert row.passphrase_ct is None

    def test_uses_legacy_ssh_path_not_ca(
        self,
        client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Bootstrap SSH session must be legacy (no cert / no CA pubkey).

        The whole point of CP4.2 is to reach a host that does *not* yet
        trust the CA — so the SSH session has to fall back to TOFU,
        which means no ``cert_pem`` / ``ca_public_key`` arguments to
        :class:`SSHRunner`. CA-mode construction here would re-introduce
        the chicken-and-egg the migration is meant to break.
        """
        _enable_ca_backend(monkeypatch)
        key_id = _post_key(client)
        host = "hub-legacy-bootstrap.example.com"
        _register_legacy_server(client, key_id, host)

        FakeSSHRunner.CERTS_USED.clear()
        FakeSSHRunner.KEYS_USED.clear()

        resp = client.post(
            f"/ssh-keys/{key_id}/migrate-to-ca",
            json={"private_key_b64": _SAMPLE_PEM_B64},
        )
        assert resp.status_code == 200, resp.text

        bootstrap_records = [
            r for r in FakeSSHRunner.CERTS_USED if r[0] == host
        ]
        assert bootstrap_records, "no SSHRunner ever constructed for the host"
        # cert_pem and ca_public_key must be None for every bootstrap
        # construction. (FakeSSHRunner records every construction so
        # earlier provisioning sessions also appear — they're legacy
        # too in this fixture, so the check is uniform.)
        assert all(
            cert_pem is None and ca_pub is None
            for _host, cert_pem, ca_pub, _user in bootstrap_records
        ), f"bootstrap SSH session used CA mode: {bootstrap_records!r}"


# ---------------------------------------------------------------------------
# Already-ca-with-null-ct: the user's 2026-05-27 deployment shape
# ---------------------------------------------------------------------------


class TestMigrateToCAReentrantCase:
    """Row already mode=ca with NULL pk_ct still completes the bootstrap.

    Reproduces the case fixed on 2026-05-27: the smart Alembic 0007
    backfill labelled rows with NULL ``private_key_ct`` as ``ca``,
    matching the deployment's pre-CP4.1 behaviour — but the hosts
    themselves had never been bootstrapped with a CA-signed host cert.
    The migration endpoint must work for this shape too: take the
    one-shot legacy key the operator supplies, install the cert on
    every host, and leave the row's already-correct ``ca`` mode
    intact.
    """

    def test_runs_install_on_each_server(
        self,
        client: TestClient,
        session: Session,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _enable_ca_backend(monkeypatch)
        key_id = _post_key(client)
        host = "hub-reentrant.example.com"
        server_id = _register_legacy_server(client, key_id, host)
        # Now manually flip the row into the broken-but-labelled-ca
        # state CP4.1's smart backfill produces on real data.
        _flip_key_to_ca(session, key_id)

        resp = client.post(
            f"/ssh-keys/{key_id}/migrate-to-ca",
            json={"private_key_b64": _SAMPLE_PEM_B64},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()

        assert body["mode"] == "ca"
        assert body["servers_ok"] == 1
        assert body["servers_failed"] == 0
        assert body["results"][0]["status"] == "ok"
        assert body["results"][0]["server_id"] == server_id

        session.expire_all()
        srv = session.get(Server, server_id)
        assert srv is not None
        assert srv.host_cert_serial is not None, (
            "the reentrant migration must still install the host cert "
            "(this is the whole point — the row was labelled ca without "
            "the hosts ever being bootstrapped)"
        )


# ---------------------------------------------------------------------------
# Partial failure semantics
# ---------------------------------------------------------------------------


class TestMigrateToCAPartialFailure:
    """If one server fails, the row's mode stays so the operator can retry."""

    def test_one_host_unreachable_does_not_flip_row_mode(
        self,
        client: TestClient,
        session: Session,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _enable_ca_backend(monkeypatch)
        key_id = _post_key(client)
        ok_host = "hub-ok.example.com"
        bad_host = "hub-unreachable.example.com"
        ok_server = _register_legacy_server(client, key_id, ok_host)
        bad_server = _register_legacy_server(client, key_id, bad_host)

        # Simulate an unreachable host: SSHRunner.__enter__ raises.
        from wg_manager.ssh import SSHConnectionError

        FakeSSHRunner.RAISE_ON_ENTER[bad_host] = SSHConnectionError(
            "connection refused"
        )

        resp = client.post(
            f"/ssh-keys/{key_id}/migrate-to-ca",
            json={"private_key_b64": _SAMPLE_PEM_B64},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()

        assert body["servers_total"] == 2
        assert body["servers_ok"] == 1
        assert body["servers_failed"] == 1
        assert body["mode"] == "legacy", (
            "row mode must stay 'legacy' when any server's bootstrap "
            "failed — flipping would brick the failed host until an "
            "operator manually fixes the row"
        )

        by_id = {r["server_id"]: r for r in body["results"]}
        assert by_id[ok_server]["status"] == "ok"
        assert by_id[bad_server]["status"] == "ssh_failed"
        assert by_id[bad_server]["error"]
        assert "connection refused" in by_id[bad_server]["error"]

        # Ciphertext stays so the operator can re-run after fixing the host.
        session.expire_all()
        row = session.get(SSHKey, key_id)
        assert row is not None
        assert row.mode == SSHKeyMode.legacy
        assert row.private_key_ct is not None


# ---------------------------------------------------------------------------
# Zero-server edge case
# ---------------------------------------------------------------------------


class TestMigrateToCAZeroServers:
    """A key that no server references still flips to ``mode=ca``."""

    def test_zero_servers_flips_mode_and_nulls_ct(
        self,
        client: TestClient,
        session: Session,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _enable_ca_backend(monkeypatch)
        key_id = _post_key(client, name="cp4-2-orphan")

        resp = client.post(
            f"/ssh-keys/{key_id}/migrate-to-ca",
            json={"private_key_b64": _SAMPLE_PEM_B64},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()

        assert body["servers_total"] == 0
        assert body["servers_ok"] == 0
        assert body["servers_failed"] == 0
        assert body["results"] == []
        assert body["mode"] == "ca", (
            "operator's intent is unambiguous when no hosts use the key; "
            "flipping with no servers is the no-op fast path"
        )

        session.expire_all()
        row = session.get(SSHKey, key_id)
        assert row is not None
        assert row.mode == SSHKeyMode.ca
        assert row.private_key_ct is None
        assert row.passphrase_ct is None
