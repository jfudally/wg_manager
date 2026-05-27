"""/servers router tests."""

from __future__ import annotations

import base64

from fastapi.testclient import TestClient

from tests.conftest import FakeSSHRunner


_SAMPLE_PEM = "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEBODY\n-----END OPENSSH PRIVATE KEY-----\n"
_SAMPLE_PEM_B64 = base64.b64encode(_SAMPLE_PEM.encode("utf-8")).decode("ascii")


def _register_key(client: TestClient) -> int:
    resp = client.post(
        "/ssh-keys",
        json={"name": "lab", "private_key_b64": _SAMPLE_PEM_B64},
    )
    assert resp.status_code == 201
    return int(resp.json()["id"])


class TestServersAPI:
    def test_register_dispatches_task_and_provisions(self, client: TestClient) -> None:
        key_id = _register_key(client)
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
        body = resp.json()
        assert "task_id" in body
        assert body["server"]["address"] == "10.9.0.1/24"

        # Eager mode runs the task inline; the row should now be ready.
        server_id = body["server"]["id"]
        get_resp = client.get(f"/servers/{server_id}")
        assert get_resp.status_code == 200
        get_body = get_resp.json()
        assert get_body["status"] == "ready"
        assert get_body["public_key"] == "PUBKEY::hub.example.com"

        # The task ID should resolve to a SUCCESS state.
        task_resp = client.get(f"/tasks/{body['task_id']}")
        assert task_resp.status_code == 200
        task_body = task_resp.json()
        assert task_body["state"] == "SUCCESS"
        assert task_body["result"]["server_id"] == server_id

        cmds = [c for host, c in FakeSSHRunner.COMMANDS if host == "hub.example.com"]
        joined = "\n".join(cmds)
        assert "apt-get install" in joined and "wireguard" in joined
        assert "wg genkey" in joined
        assert "systemctl enable wg-quick@wg0" in joined

    def test_reprovision_overwrites_existing_server(self, client: TestClient) -> None:
        key_id = _register_key(client)
        created = client.post(
            "/servers",
            json={
                "hostname": "hub.example.com",
                "ssh_username": "ubuntu",
                "ssh_key_id": key_id,
                "endpoint_host": "hub.example.com",
            },
        ).json()["server"]
        FakeSSHRunner.COMMANDS.clear()

        resp = client.post(f"/servers/{created['id']}/reprovision")
        assert resp.status_code == 202, resp.text
        body = resp.json()
        assert "task_id" in body
        assert client.get(f"/servers/{created['id']}").json()["status"] == "ready"

        joined = "\n".join(
            c for host, c in FakeSSHRunner.COMMANDS if host == "hub.example.com"
        )
        assert "apt-get install" in joined
        assert "systemctl restart wg-quick@wg0" in joined

    def test_reprovision_unknown_server_404(self, client: TestClient) -> None:
        resp = client.post("/servers/999/reprovision")
        assert resp.status_code == 404

    def test_reprovision_brings_down_existing_wg0_before_rewrite(
        self, client: TestClient
    ) -> None:
        """Server reprovision must `wg-quick down wg0` before rewriting the hub config.

        A stale hub interface left over from a previous half-failed run keeps
        the old peer list bound; the new ``wg0.conf`` then either fails to
        attach or silently never takes effect. The teardown must precede the
        config rewrite.
        """
        key_id = _register_key(client)
        created = client.post(
            "/servers",
            json={
                "hostname": "hub.example.com",
                "ssh_username": "ubuntu",
                "ssh_key_id": key_id,
                "endpoint_host": "hub.example.com",
            },
        ).json()["server"]
        FakeSSHRunner.COMMANDS.clear()

        resp = client.post(f"/servers/{created['id']}/reprovision")
        assert resp.status_code == 202, resp.text

        hub_cmds = [
            c for host, c in FakeSSHRunner.COMMANDS if host == "hub.example.com"
        ]
        joined = "\n".join(hub_cmds)
        assert "wg-quick down wg0" in joined
        down_idx = next(
            i for i, c in enumerate(hub_cmds) if "wg-quick down wg0" in c
        )
        rewrite_idx = next(
            i
            for i, c in enumerate(hub_cmds)
            if "/tmp/wg0.conf.tpl" in c and "cat >" in c
        )
        assert down_idx < rewrite_idx, (
            "wg-quick down must precede the wg0.conf rewrite; "
            f"down at {down_idx}, rewrite at {rewrite_idx}"
        )

    def test_register_with_custom_subnet(self, client: TestClient) -> None:
        key_id = _register_key(client)
        resp = client.post(
            "/servers",
            json={
                "hostname": "hub.example.com",
                "ssh_username": "ubuntu",
                "ssh_key_id": key_id,
                "endpoint_host": "hub.example.com",
                "subnet": "10.42.0.0/16",
            },
        )
        assert resp.status_code == 202, resp.text
        body = resp.json()
        # Server picks the first host of the supplied subnet, with the same
        # prefix length applied so wg-quick can route on the interface.
        assert body["server"]["subnet"] == "10.42.0.0/16"
        assert body["server"]["address"] == "10.42.0.1/16"

    def test_register_default_subnet_unchanged(self, client: TestClient) -> None:
        """Omitting subnet preserves the legacy 10.9.0.0/24 default."""
        key_id = _register_key(client)
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
        body = resp.json()
        assert body["server"]["subnet"] == "10.9.0.0/24"
        assert body["server"]["address"] == "10.9.0.1/24"

    def test_register_rejects_host_bits_set(self, client: TestClient) -> None:
        """``10.0.0.5/24`` carries host bits — reject rather than silently coerce."""
        key_id = _register_key(client)
        resp = client.post(
            "/servers",
            json={
                "hostname": "hub.example.com",
                "ssh_username": "ubuntu",
                "ssh_key_id": key_id,
                "endpoint_host": "hub.example.com",
                "subnet": "10.0.0.5/24",
            },
        )
        assert resp.status_code == 422, resp.text

    def test_register_rejects_too_narrow_prefix(self, client: TestClient) -> None:
        """``/31`` and ``/32`` leave no room for a server + at least one client."""
        key_id = _register_key(client)
        resp = client.post(
            "/servers",
            json={
                "hostname": "hub.example.com",
                "ssh_username": "ubuntu",
                "ssh_key_id": key_id,
                "endpoint_host": "hub.example.com",
                "subnet": "10.0.0.0/31",
            },
        )
        assert resp.status_code == 422, resp.text

    def test_register_rejects_malformed_subnet(self, client: TestClient) -> None:
        key_id = _register_key(client)
        resp = client.post(
            "/servers",
            json={
                "hostname": "hub.example.com",
                "ssh_username": "ubuntu",
                "ssh_key_id": key_id,
                "endpoint_host": "hub.example.com",
                "subnet": "not-a-cidr",
            },
        )
        assert resp.status_code == 422, resp.text

    def test_list_and_get(self, client: TestClient) -> None:
        key_id = _register_key(client)
        created = client.post(
            "/servers",
            json={
                "hostname": "hub.example.com",
                "ssh_username": "ubuntu",
                "ssh_key_id": key_id,
                "endpoint_host": "hub.example.com",
            },
        ).json()["server"]

        list_resp = client.get("/servers")
        assert list_resp.status_code == 200
        assert len(list_resp.json()) == 1

        get_resp = client.get(f"/servers/{created['id']}")
        assert get_resp.status_code == 200
        assert get_resp.json()["id"] == created["id"]


def _register_server(client: TestClient, key_id: int, host: str = "hub.example.com") -> int:
    """Register ``host`` as a server using ``key_id`` and return the new row's id."""
    resp = client.post(
        "/servers",
        json={
            "hostname": host,
            "ssh_username": "ubuntu",
            "ssh_key_id": key_id,
            "endpoint_host": host,
        },
    )
    assert resp.status_code == 202, resp.text
    return int(resp.json()["server"]["id"])


def _register_client(client: TestClient, key_id: int, server_id: int, name: str) -> int:
    """Register a managed client peer against ``server_id``."""
    resp = client.post(
        "/clients",
        json={
            "name": name,
            "hostname": f"{name}.example.com",
            "ssh_username": "ubuntu",
            "ssh_key_id": key_id,
            "server_id": server_id,
        },
    )
    assert resp.status_code == 202, resp.text
    return int(resp.json()["client"]["id"])


class TestServerDelete:
    """DELETE /servers/{id} — refuse-by-default with force=true cascade override."""

    def test_delete_orphan_server_returns_204(self, client: TestClient) -> None:
        key_id = _register_key(client)
        server_id = _register_server(client, key_id)

        resp = client.delete(f"/servers/{server_id}")
        assert resp.status_code == 204, resp.text

        assert client.get(f"/servers/{server_id}").status_code == 404

    def test_delete_with_attached_clients_returns_409(self, client: TestClient) -> None:
        key_id = _register_key(client)
        server_id = _register_server(client, key_id)
        _register_client(client, key_id, server_id, "alpha")

        resp = client.delete(f"/servers/{server_id}")
        assert resp.status_code == 409, resp.text
        assert "client" in resp.json()["detail"].lower()

        # Server row must still be present after the refused delete.
        assert client.get(f"/servers/{server_id}").status_code == 200

    def test_delete_with_force_cascades(self, client: TestClient) -> None:
        key_id = _register_key(client)
        server_id = _register_server(client, key_id)
        client_id = _register_client(client, key_id, server_id, "alpha")

        resp = client.delete(f"/servers/{server_id}?force=true")
        assert resp.status_code == 204, resp.text

        assert client.get(f"/servers/{server_id}").status_code == 404
        # Attached managed clients should have been cascaded.
        assert client.get(f"/clients/{client_id}").status_code == 404

    def test_delete_unknown_server_returns_404(self, client: TestClient) -> None:
        resp = client.delete("/servers/999")
        assert resp.status_code == 404


class TestServerUpdate:
    """PATCH /servers/{id} — partial update of operator-supplied fields only."""

    def test_patch_updates_editable_fields(self, client: TestClient) -> None:
        key_id = _register_key(client)
        server_id = _register_server(client, key_id)

        # Register a second SSH key so we can verify ssh_key_id can be changed.
        other_key_id = int(
            client.post(
                "/ssh-keys",
                json={"name": "lab2", "private_key_b64": _SAMPLE_PEM_B64},
            ).json()["id"]
        )

        resp = client.patch(
            f"/servers/{server_id}",
            json={
                "hostname": "hub-renamed.example.com",
                "ssh_port": 2222,
                "ssh_username": "deploy",
                "ssh_key_id": other_key_id,
                "endpoint_host": "vpn.example.com",
                "endpoint_port": 52000,
            },
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["hostname"] == "hub-renamed.example.com"
        assert body["ssh_port"] == 2222
        assert body["ssh_username"] == "deploy"
        assert body["ssh_key_id"] == other_key_id
        assert body["endpoint_host"] == "vpn.example.com"
        assert body["endpoint_port"] == 52000

    def test_patch_partial_update_leaves_unspecified_fields(
        self, client: TestClient
    ) -> None:
        key_id = _register_key(client)
        server_id = _register_server(client, key_id)
        before = client.get(f"/servers/{server_id}").json()

        resp = client.patch(
            f"/servers/{server_id}",
            json={"endpoint_host": "new.example.com"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["endpoint_host"] == "new.example.com"
        # Untouched fields keep their values.
        assert body["hostname"] == before["hostname"]
        assert body["ssh_username"] == before["ssh_username"]
        assert body["subnet"] == before["subnet"]
        assert body["address"] == before["address"]
        assert body["public_key"] == before["public_key"]
        assert body["status"] == before["status"]

    def test_patch_rejects_unknown_ssh_key(self, client: TestClient) -> None:
        key_id = _register_key(client)
        server_id = _register_server(client, key_id)

        resp = client.patch(
            f"/servers/{server_id}",
            json={"ssh_key_id": 999_999},
        )
        assert resp.status_code == 404, resp.text
        assert "ssh key" in resp.json()["detail"].lower()

    def test_patch_ignores_readonly_fields(self, client: TestClient) -> None:
        key_id = _register_key(client)
        server_id = _register_server(client, key_id)
        before = client.get(f"/servers/{server_id}").json()

        # Extra/disallowed fields should be silently ignored — schema-driven
        # so the row remains untouched.
        resp = client.patch(
            f"/servers/{server_id}",
            json={
                "subnet": "10.42.0.0/24",
                "address": "10.42.0.1/24",
                "public_key": "BOGUS",
                "status": "error",
                "interface": "wg42",
            },
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["subnet"] == before["subnet"]
        assert body["address"] == before["address"]
        assert body["public_key"] == before["public_key"]
        assert body["status"] == before["status"]
        assert body["interface"] == before["interface"]

    def test_patch_unknown_server_returns_404(self, client: TestClient) -> None:
        resp = client.patch("/servers/999", json={"hostname": "x.example.com"})
        assert resp.status_code == 404
