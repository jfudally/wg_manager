"""Tests for ``GET /crypto/status`` — Phase 2b checkpoint 3.

The status endpoint is the API surface that powers the dashboard's
"Crypto status" panel. It must report, in a stable JSON shape:

* the active backend (``"local-dev"`` or ``"vault-transit"``);
* the current key version (``1`` for local-dev, Transit ``latest_version``
  for vault);
* per-table counts of how many rows have ciphertext (``_encrypted``)
  vs. rows that bypassed the encryption seam and ended up with a NULL
  ciphertext column (``_legacy``).

Post-Phase-2b the legacy plaintext columns were dropped in Alembic
0005; the only way a row can show up as ``_legacy`` now is a direct
INSERT that skipped ``wg_manager.crypto`` entirely. We exercise that
shape so operators can still spot mis-imported rows in the panel.

These tests use the existing ``client`` fixture, which mounts the real
FastAPI app against an in-memory SQLite engine with the test
:class:`LocalDevBackend` wired through.
"""

from __future__ import annotations

import base64

from fastapi.testclient import TestClient
from sqlmodel import Session

from wg_manager.models import Client, NodeStatus, SSHKey, Server


_SAMPLE_PEM = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEBODY\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)
_SAMPLE_PEM_B64 = base64.b64encode(_SAMPLE_PEM.encode("utf-8")).decode("ascii")


def _seed_orphan_sshkey(engine: object, *, name: str) -> int:
    """Insert an ``SSHKey`` row that bypasses the encryption seam.

    Such a row can only appear in production through a direct INSERT
    (or a restore of a backup that pre-dates Phase 2b). The status
    endpoint must count those toward ``sshkey_legacy`` so the operator
    can spot them and clean them up.
    """
    with Session(engine) as s:  # type: ignore[arg-type]
        row = SSHKey(name=name)
        s.add(row)
        s.commit()
        s.refresh(row)
        assert row.private_key_ct is None
        assert row.id is not None
        return int(row.id)


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
        """Identifies the active backend and its current key version.

        The test suite wires ``LocalDevBackend`` (see ``conftest.py``), so
        the response must name that backend and report key_version=1
        (LocalDevBackend does not rotate).
        """
        resp = client.get("/crypto/status")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["backend"] == "local-dev"
        assert body["key_version"] == 1

    def test_counts_zero_on_empty_database(self, client: TestClient) -> None:
        """All row counts are zero when no SSH keys or clients exist.

        Confirms the endpoint does not invent rows and is safe to call
        before any operator data has been registered.
        """
        body = client.get("/crypto/status").json()
        assert body["sshkey_encrypted"] == 0
        assert body["sshkey_legacy"] == 0
        assert body["client_encrypted"] == 0
        assert body["client_legacy"] == 0

    def test_counts_freshly_created_sshkey_as_encrypted(
        self, client: TestClient
    ) -> None:
        """Rows registered via the API are encrypted by the dual-write path.

        The status endpoint must reflect that — a freshly-created SSH
        key counts toward ``sshkey_encrypted``, not ``sshkey_legacy``.
        Otherwise operators would chase phantom "legacy" rows that the
        normal create flow already handles.
        """
        resp = client.post(
            "/ssh-keys",
            json={"name": "lab", "private_key_b64": _SAMPLE_PEM_B64},
        )
        assert resp.status_code == 201, resp.text

        body = client.get("/crypto/status").json()
        assert body["sshkey_encrypted"] == 1
        assert body["sshkey_legacy"] == 0

    def test_counts_orphan_sshkey_as_legacy(
        self, client: TestClient, engine: object
    ) -> None:
        """An SSHKey row inserted bypassing the encryption seam is legacy.

        Post-0005 the column drop means a row can only show up
        unencrypted via a direct INSERT (or a restored old backup).
        The status endpoint must flag those so the operator can spot
        and rewrap them."""
        _seed_orphan_sshkey(engine, name="orphan-lab")

        body = client.get("/crypto/status").json()
        assert body["sshkey_encrypted"] == 0
        assert body["sshkey_legacy"] == 1

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
        """Lock the JSON shape so the dashboard can rely on it.

        Adding new keys later is fine; renaming or removing one of
        these breaks the panel and the UI test suite.
        """
        body = client.get("/crypto/status").json()
        assert set(body.keys()) >= {
            "backend",
            "key_version",
            "sshkey_encrypted",
            "sshkey_legacy",
            "client_encrypted",
            "client_legacy",
        }
        assert isinstance(body["backend"], str)
        assert isinstance(body["key_version"], int)
