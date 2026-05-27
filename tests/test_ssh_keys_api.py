"""/ssh-keys router tests."""

from __future__ import annotations

import base64
from typing import Any

from fastapi.testclient import TestClient
from sqlmodel import Session

from wg_manager.crypto import (
    make_backend,
    resolve_sshkey_passphrase,
    resolve_sshkey_private,
)
from wg_manager.models import SSHKey


_SAMPLE_PEM = "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEBODY\n-----END OPENSSH PRIVATE KEY-----\n"
_SAMPLE_PEM_B64 = base64.b64encode(_SAMPLE_PEM.encode("utf-8")).decode("ascii")
_REPLACEMENT_PEM = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\nROTATEDBODY\n-----END OPENSSH PRIVATE KEY-----\n"
)
_REPLACEMENT_PEM_B64 = base64.b64encode(_REPLACEMENT_PEM.encode("utf-8")).decode("ascii")


def _create_key(client: TestClient, name: str, passphrase: str | None = None) -> dict[str, Any]:
    """POST a fresh SSH key and return the parsed response body."""
    payload: dict[str, Any] = {"name": name, "private_key_b64": _SAMPLE_PEM_B64}
    if passphrase is not None:
        payload["passphrase"] = passphrase
    resp = client.post("/ssh-keys", json=payload)
    assert resp.status_code == 201, resp.text
    return resp.json()


class TestSSHKeysAPI:
    def test_create_lists_and_never_returns_private_key(self, client: TestClient) -> None:
        resp = client.post(
            "/ssh-keys",
            json={
                "name": "lab",
                "private_key_b64": _SAMPLE_PEM_B64,
            },
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["name"] == "lab"
        assert "private_key" not in body
        assert "passphrase" not in body
        key_id = body["id"]

        list_resp = client.get("/ssh-keys")
        assert list_resp.status_code == 200
        rows = list_resp.json()
        assert len(rows) == 1
        assert "private_key" not in rows[0]

        get_resp = client.get(f"/ssh-keys/{key_id}")
        assert get_resp.status_code == 200
        assert "private_key" not in get_resp.json()

    def test_duplicate_name_conflicts(self, client: TestClient) -> None:
        payload = {"name": "dup", "private_key_b64": _SAMPLE_PEM_B64}
        assert client.post("/ssh-keys", json=payload).status_code == 201
        assert client.post("/ssh-keys", json=payload).status_code == 409

    def test_delete_unreferenced(self, client: TestClient) -> None:
        created = client.post(
            "/ssh-keys",
            json={"name": "k", "private_key_b64": _SAMPLE_PEM_B64},
        ).json()
        resp = client.delete(f"/ssh-keys/{created['id']}")
        assert resp.status_code == 204
        assert client.get(f"/ssh-keys/{created['id']}").status_code == 404


class TestSSHKeyUpdate:
    """PATCH /ssh-keys/{id} — edit name / passphrase / private key body in place.

    The private key body is never returned in any response (consistent with
    ``SSHKeyRead``); these tests therefore verify body-level changes by
    reading the row directly from the DB via a fresh :class:`Session`.
    """

    def test_patch_rename_succeeds_and_hides_secret(self, client: TestClient) -> None:
        """Rename returns the updated row but never echoes the private key."""
        created = _create_key(client, "lab")

        resp = client.patch(
            f"/ssh-keys/{created['id']}", json={"name": "lab-renamed"}
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["id"] == created["id"]
        assert body["name"] == "lab-renamed"
        # Response schema must never leak the credential body.
        assert "private_key" not in body
        assert "passphrase" not in body

        # And the rename is reflected on subsequent GETs.
        fetched = client.get(f"/ssh-keys/{created['id']}").json()
        assert fetched["name"] == "lab-renamed"

    def test_patch_private_key_body_persists_to_db(
        self, client: TestClient, engine: Any
    ) -> None:
        """Replacing the key body writes the new PEM to disk but never returns it."""
        created = _create_key(client, "lab")

        resp = client.patch(
            f"/ssh-keys/{created['id']}",
            json={"private_key_b64": _REPLACEMENT_PEM_B64},
        )
        assert resp.status_code == 200, resp.text
        assert "private_key" not in resp.json()

        # The new key body must be persisted — verified via the
        # decrypt seam so we exercise the same code path the tasks do.
        backend = make_backend()
        with Session(engine) as s:
            row = s.get(SSHKey, created["id"])
            assert row is not None
            assert resolve_sshkey_private(backend, row) == _REPLACEMENT_PEM

    def test_patch_passphrase_persists_to_db(
        self, client: TestClient, engine: Any
    ) -> None:
        """Setting a passphrase persists, and the response continues to hide it."""
        created = _create_key(client, "lab")

        resp = client.patch(
            f"/ssh-keys/{created['id']}", json={"passphrase": "new-secret"}
        )
        assert resp.status_code == 200, resp.text
        assert "passphrase" not in resp.json()

        backend = make_backend()
        with Session(engine) as s:
            row = s.get(SSHKey, created["id"])
            assert row is not None
            assert resolve_sshkey_passphrase(backend, row) == "new-secret"

    def test_patch_all_fields_at_once(
        self, client: TestClient, engine: Any
    ) -> None:
        """Updating name + passphrase + private key body in one PATCH all stick."""
        created = _create_key(client, "lab", passphrase="old-secret")

        resp = client.patch(
            f"/ssh-keys/{created['id']}",
            json={
                "name": "lab2",
                "passphrase": "new-secret",
                "private_key_b64": _REPLACEMENT_PEM_B64,
            },
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["name"] == "lab2"

        backend = make_backend()
        with Session(engine) as s:
            row = s.get(SSHKey, created["id"])
            assert row is not None
            assert row.name == "lab2"
            assert resolve_sshkey_passphrase(backend, row) == "new-secret"
            assert resolve_sshkey_private(backend, row) == _REPLACEMENT_PEM

    def test_patch_partial_leaves_unspecified_fields(
        self, client: TestClient, engine: Any
    ) -> None:
        """Omitted fields keep their previous values; null is treated as omitted."""
        created = _create_key(client, "lab", passphrase="keep-me")

        resp = client.patch(
            f"/ssh-keys/{created['id']}",
            json={"name": "lab-renamed", "passphrase": None, "private_key_b64": None},
        )
        assert resp.status_code == 200, resp.text

        backend = make_backend()
        with Session(engine) as s:
            row = s.get(SSHKey, created["id"])
            assert row is not None
            assert row.name == "lab-renamed"
            # private_key and passphrase must be untouched.
            assert resolve_sshkey_private(backend, row) == _SAMPLE_PEM
            assert resolve_sshkey_passphrase(backend, row) == "keep-me"

    def test_patch_unknown_returns_404(self, client: TestClient) -> None:
        resp = client.patch("/ssh-keys/999", json={"name": "x"})
        assert resp.status_code == 404

    def test_patch_name_collision_returns_409(self, client: TestClient) -> None:
        """Renaming onto a name already used by *another* key conflicts."""
        _create_key(client, "alpha")
        beta = _create_key(client, "beta")

        resp = client.patch(f"/ssh-keys/{beta['id']}", json={"name": "alpha"})
        assert resp.status_code == 409, resp.text
        assert "already exists" in resp.json()["detail"].lower()

    def test_patch_renaming_to_same_name_is_noop(self, client: TestClient) -> None:
        """Renaming a key onto its own existing name isn't a collision."""
        created = _create_key(client, "lab")
        resp = client.patch(f"/ssh-keys/{created['id']}", json={"name": "lab"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["name"] == "lab"

    def test_patch_invalid_base64_returns_422(self, client: TestClient) -> None:
        """Garbage in ``private_key_b64`` is rejected before touching the row."""
        created = _create_key(client, "lab")
        resp = client.patch(
            f"/ssh-keys/{created['id']}",
            json={"private_key_b64": "not valid base64!!!"},
        )
        assert resp.status_code == 422, resp.text


class TestSSHKeyEncryptionAtRest:
    """Phase 2b: the router populates the ``_ct`` ciphertext columns.

    These regressions pin the dual-write contract: every ``POST`` /
    ``PATCH`` that touches a secret field also writes the encrypted
    form, so once the drop-plaintext migration ships the rows are
    already safe.
    """

    def test_create_populates_private_key_ct(
        self, client: TestClient, engine: Any
    ) -> None:
        created = _create_key(client, "lab", passphrase="hunter2")
        backend = make_backend()

        with Session(engine) as s:
            row = s.get(SSHKey, created["id"])
            assert row is not None
            # Ciphertext column populated and prefixed by the backend marker.
            assert row.private_key_ct is not None
            assert row.private_key_ct.startswith(backend.blob_prefix)
            assert row.passphrase_ct is not None
            assert row.passphrase_ct.startswith(backend.blob_prefix)
            # And the round-trip decrypts back to the originals.
            assert resolve_sshkey_private(backend, row) == _SAMPLE_PEM
            assert resolve_sshkey_passphrase(backend, row) == "hunter2"

    def test_create_without_passphrase_skips_passphrase_ct(
        self, client: TestClient, engine: Any
    ) -> None:
        """An unset passphrase produces no ciphertext — no padding-oracle bait."""
        created = _create_key(client, "lab")
        with Session(engine) as s:
            row = s.get(SSHKey, created["id"])
            assert row is not None
            assert row.private_key_ct is not None
            assert row.passphrase_ct is None

    def test_patch_private_key_replaces_ciphertext(
        self, client: TestClient, engine: Any
    ) -> None:
        """Rotating the PEM rewrites ``private_key_ct`` so the old blob
        cannot decrypt back to the old plaintext after the drop."""
        created = _create_key(client, "lab")
        with Session(engine) as s:
            original_ct = s.get(SSHKey, created["id"]).private_key_ct

        resp = client.patch(
            f"/ssh-keys/{created['id']}",
            json={"private_key_b64": _REPLACEMENT_PEM_B64},
        )
        assert resp.status_code == 200, resp.text

        backend = make_backend()
        with Session(engine) as s:
            row = s.get(SSHKey, created["id"])
            assert row is not None
            assert row.private_key_ct is not None
            assert row.private_key_ct != original_ct
            assert resolve_sshkey_private(backend, row) == _REPLACEMENT_PEM

    def test_patch_passphrase_replaces_ciphertext(
        self, client: TestClient, engine: Any
    ) -> None:
        created = _create_key(client, "lab", passphrase="old")
        resp = client.patch(
            f"/ssh-keys/{created['id']}", json={"passphrase": "new"}
        )
        assert resp.status_code == 200, resp.text

        backend = make_backend()
        with Session(engine) as s:
            row = s.get(SSHKey, created["id"])
            assert row is not None
            assert resolve_sshkey_passphrase(backend, row) == "new"

    def test_patch_other_fields_leaves_ct_untouched(
        self, client: TestClient, engine: Any
    ) -> None:
        """Renaming must not touch the ciphertext — that would be churn
        for no security benefit and risks burning a Transit operation."""
        created = _create_key(client, "lab")
        with Session(engine) as s:
            original_pk_ct = s.get(SSHKey, created["id"]).private_key_ct

        resp = client.patch(
            f"/ssh-keys/{created['id']}", json={"name": "lab2"}
        )
        assert resp.status_code == 200, resp.text

        with Session(engine) as s:
            row = s.get(SSHKey, created["id"])
            assert row is not None
            assert row.private_key_ct == original_pk_ct
