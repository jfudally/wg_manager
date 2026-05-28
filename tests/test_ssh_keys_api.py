"""/ssh-keys router tests.

Phase 2c CP4.4 reduced the SSH-key surface to a name-and-mode label:
the row carries no key material, so the create / update endpoints
only accept ``name``. The pre-CP4.4 ``private_key_b64`` /
``passphrase`` fields are rejected at the schema layer (``extra=
"forbid"``) so an upgrader still posting them sees a 422 instead of
a silently-dropped credential they think was stored.
"""

from __future__ import annotations

from fastapi.testclient import TestClient


class TestSSHKeysAPI:
    def test_create_lists_and_never_returns_private_key(
        self, client: TestClient
    ) -> None:
        resp = client.post("/ssh-keys", json={"name": "lab"})
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["name"] == "lab"
        # CP4.4 removed every notion of a stored private key from the
        # response shape.
        assert "private_key" not in body
        assert "passphrase" not in body
        assert "encrypted" not in body
        # The new row defaults to CA mode.
        assert body["mode"] == "ca"
        key_id = body["id"]

        list_resp = client.get("/ssh-keys")
        assert list_resp.status_code == 200
        rows = list_resp.json()
        assert len(rows) == 1
        assert "private_key" not in rows[0]
        assert rows[0]["mode"] == "ca"

        get_resp = client.get(f"/ssh-keys/{key_id}")
        assert get_resp.status_code == 200
        body = get_resp.json()
        assert "private_key" not in body
        assert body["mode"] == "ca"

    def test_duplicate_name_conflicts(self, client: TestClient) -> None:
        assert client.post("/ssh-keys", json={"name": "dup"}).status_code == 201
        assert client.post("/ssh-keys", json={"name": "dup"}).status_code == 409

    def test_create_with_legacy_pem_body_is_rejected(
        self, client: TestClient
    ) -> None:
        """A pre-CP4.4 client still sending ``private_key_b64`` gets 422.

        Silently dropping the field would leave an upgrader thinking
        the row stored their credential — and then crashing the first
        time a task tries to use it. ``extra='forbid'`` on
        :class:`SSHKeyCreate` makes the rejection explicit.
        """
        resp = client.post(
            "/ssh-keys",
            json={"name": "lab", "private_key_b64": "Zm9v"},
        )
        assert resp.status_code == 422, resp.text

    def test_delete_unreferenced(self, client: TestClient) -> None:
        created = client.post("/ssh-keys", json={"name": "k"}).json()
        resp = client.delete(f"/ssh-keys/{created['id']}")
        assert resp.status_code == 204
        assert client.get(f"/ssh-keys/{created['id']}").status_code == 404


class TestSSHKeyUpdate:
    """PATCH /ssh-keys/{id} — rename only post-CP4.4."""

    def test_patch_rename_succeeds(self, client: TestClient) -> None:
        created = client.post("/ssh-keys", json={"name": "lab"}).json()

        resp = client.patch(
            f"/ssh-keys/{created['id']}", json={"name": "lab-renamed"}
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["id"] == created["id"]
        assert body["name"] == "lab-renamed"

        fetched = client.get(f"/ssh-keys/{created['id']}").json()
        assert fetched["name"] == "lab-renamed"

    def test_patch_with_legacy_pem_body_is_rejected(
        self, client: TestClient
    ) -> None:
        """``private_key_b64`` / ``passphrase`` are forbidden on the wire."""
        created = client.post("/ssh-keys", json={"name": "lab"}).json()
        resp = client.patch(
            f"/ssh-keys/{created['id']}",
            json={"private_key_b64": "Zm9v"},
        )
        assert resp.status_code == 422, resp.text

        resp = client.patch(
            f"/ssh-keys/{created['id']}", json={"passphrase": "hunter2"}
        )
        assert resp.status_code == 422, resp.text

    def test_patch_unknown_returns_404(self, client: TestClient) -> None:
        resp = client.patch("/ssh-keys/999", json={"name": "x"})
        assert resp.status_code == 404

    def test_patch_name_collision_returns_409(self, client: TestClient) -> None:
        """Renaming onto a name already used by *another* key conflicts."""
        client.post("/ssh-keys", json={"name": "alpha"}).json()
        beta = client.post("/ssh-keys", json={"name": "beta"}).json()

        resp = client.patch(f"/ssh-keys/{beta['id']}", json={"name": "alpha"})
        assert resp.status_code == 409, resp.text
        assert "already exists" in resp.json()["detail"].lower()

    def test_patch_renaming_to_same_name_is_noop(
        self, client: TestClient
    ) -> None:
        """Renaming a key onto its own existing name isn't a collision."""
        created = client.post("/ssh-keys", json={"name": "lab"}).json()
        resp = client.patch(
            f"/ssh-keys/{created['id']}", json={"name": "lab"}
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["name"] == "lab"
