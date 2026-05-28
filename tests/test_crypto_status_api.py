"""Tests for ``GET /crypto/status`` — Phase 2b checkpoint 3 / CP4.4 update.

The status endpoint powers the dashboard's "Crypto status" panel. It
must report, in a stable JSON shape:

* the active backend (``"local-dev"`` or ``"vault-transit"``);
* the current key version (``1`` for local-dev, Transit
  ``latest_version`` for vault);
* per-table counts of how many rows have ciphertext
  (``client_encrypted``) vs. manual rows that bypassed the encryption
  seam and ended up with a NULL ciphertext column (``client_legacy``).

Phase 2c CP4.4 dropped the sshkey ciphertext columns entirely (every
row is now a name-and-mode label), so the response shape lost its
``sshkey_*`` half. The remaining shape is what the dashboard panel
still renders.
"""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlmodel import Session

from wg_manager.models import Client, NodeStatus, Server


def _seed_orphan_manual_client(engine: object, *, name: str = "phone") -> int:
    """Insert a manual ``Client`` row that bypasses the encryption seam."""
    with Session(engine) as s:  # type: ignore[arg-type]
        srv = Server(
            hostname="hub.example.com",
            ssh_username="ubuntu",
            ssh_key_id=1,
            endpoint_host="hub.example.com",
            status=NodeStatus.ready,
            public_key="HUBPUBKEY",
        )
        s.add(srv)
        s.commit()
        s.refresh(srv)
        row = Client(
            name=name,
            server_id=srv.id,
            address="10.9.0.42/32",
            public_key="CLIENTPUBKEY",
            is_manual=True,
            status=NodeStatus.ready,
        )
        s.add(row)
        s.commit()
        s.refresh(row)
        assert row.private_key_ct is None
        return int(row.id)


class TestCryptoStatus:
    def test_reports_backend_and_key_version(self, client: TestClient) -> None:
        """Identifies the active backend and its current key version."""
        resp = client.get("/crypto/status")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["backend"] == "local-dev"
        assert body["key_version"] == 1

    def test_counts_zero_on_empty_database(self, client: TestClient) -> None:
        """All client-row counts are zero when no clients exist."""
        body = client.get("/crypto/status").json()
        assert body["client_encrypted"] == 0
        assert body["client_legacy"] == 0
        # Post-CP4.4 the sshkey counts are gone.
        assert "sshkey_encrypted" not in body
        assert "sshkey_legacy" not in body

    def test_counts_orphan_manual_client_as_legacy(
        self, client: TestClient, engine: object
    ) -> None:
        """Manual-client orphans (no ciphertext) count toward client_legacy.

        SSH-provisioned clients legitimately have no key material and
        must NOT inflate the bucket — only manual rows that should
        have ciphertext but don't.
        """
        _seed_orphan_manual_client(engine, name="phone")

        body = client.get("/crypto/status").json()
        assert body["client_legacy"] == 1
        assert body["client_encrypted"] == 0

    def test_ssh_provisioned_client_is_not_counted(
        self, client: TestClient, engine: object
    ) -> None:
        """SSH-provisioned clients keep their key on the device — not us.

        They land in the DB with ``private_key_ct=NULL`` *and*
        ``is_manual=False`` and must not inflate either bucket.
        """
        with Session(engine) as s:  # type: ignore[arg-type]
            srv = Server(
                hostname="hub.example.com",
                ssh_username="ubuntu",
                ssh_key_id=1,
                endpoint_host="hub.example.com",
                status=NodeStatus.ready,
                public_key="HUBPUBKEY",
            )
            s.add(srv)
            s.commit()
            s.refresh(srv)
            row = Client(
                name="laptop",
                server_id=srv.id,
                address="10.9.0.99/32",
                public_key="LAPTOPPUB",
                # Neither plaintext nor ciphertext set — SSH-provisioned.
                is_manual=False,
                status=NodeStatus.ready,
            )
            s.add(row)
            s.commit()

        body = client.get("/crypto/status").json()
        assert body["client_legacy"] == 0
        assert body["client_encrypted"] == 0

    def test_response_shape_is_stable(self, client: TestClient) -> None:
        """Lock the JSON shape so the dashboard can rely on it."""
        body = client.get("/crypto/status").json()
        assert set(body.keys()) >= {
            "backend",
            "key_version",
            "client_encrypted",
            "client_legacy",
        }
        assert isinstance(body["backend"], str)
        assert isinstance(body["key_version"], int)
