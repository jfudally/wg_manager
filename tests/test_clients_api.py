"""/clients router tests."""

from __future__ import annotations

import base64
from typing import Any

from fastapi.testclient import TestClient
from sqlmodel import Session

from tests.conftest import FakeSSHRunner
from wg_manager.models import NodeStatus, Server


_SAMPLE_PEM = "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEBODY\n-----END OPENSSH PRIVATE KEY-----\n"
_SAMPLE_PEM_B64 = base64.b64encode(_SAMPLE_PEM.encode("utf-8")).decode("ascii")


def _bootstrap_server(client: TestClient) -> tuple[int, int]:
    """Register an SSH key and a ready server. Returns (key_id, server_id)."""
    key_id = int(
        client.post(
            "/ssh-keys",
            json={"name": "lab"},
        ).json()["id"]
    )
    server_resp = client.post(
        "/servers",
        json={
            "hostname": "hub.example.com",
            "ssh_username": "ubuntu",
            "ssh_key_id": key_id,
            "endpoint_host": "hub.example.com",
        },
    )
    assert server_resp.status_code == 202
    server_id = int(server_resp.json()["server"]["id"])
    return key_id, server_id


class TestClientsAPI:
    def test_two_clients_get_sequential_ips(self, client: TestClient) -> None:
        key_id, server_id = _bootstrap_server(client)

        first = client.post(
            "/clients",
            json={
                "name": "alpha",
                "hostname": "alpha.example.com",
                "ssh_username": "ubuntu",
                "ssh_key_id": key_id,
                "server_id": server_id,
            },
        )
        assert first.status_code == 202, first.text
        first_body = first.json()
        assert "task_id" in first_body
        assert first_body["client"]["address"] == "10.9.0.2/32"

        first_id = first_body["client"]["id"]
        first_get = client.get(f"/clients/{first_id}").json()
        assert first_get["status"] == "ready"
        assert first_get["public_key"] == "PUBKEY::alpha.example.com"

        second = client.post(
            "/clients",
            json={
                "name": "beta",
                "hostname": "beta.example.com",
                "ssh_username": "ubuntu",
                "ssh_key_id": key_id,
                "server_id": server_id,
            },
        )
        assert second.status_code == 202, second.text
        assert second.json()["client"]["address"] == "10.9.0.3/32"

        # After both client registrations the hub should have been
        # reconfigured (wg0.conf rewritten + wg-quick restarted) and contain
        # both peer pubkeys in its config body.
        server_cmds = [c for host, c in FakeSSHRunner.COMMANDS if host == "hub.example.com"]
        joined = "\n".join(server_cmds)
        assert "PUBKEY::alpha.example.com" in joined
        assert "PUBKEY::beta.example.com" in joined
        assert joined.count("systemctl restart wg-quick@wg0") >= 2

    def test_reprovision_overwrites_existing_client(self, client: TestClient) -> None:
        key_id, server_id = _bootstrap_server(client)
        created = client.post(
            "/clients",
            json={
                "name": "alpha",
                "hostname": "alpha.example.com",
                "ssh_username": "ubuntu",
                "ssh_key_id": key_id,
                "server_id": server_id,
            },
        ).json()["client"]
        FakeSSHRunner.COMMANDS.clear()

        resp = client.post(f"/clients/{created['id']}/reprovision")
        assert resp.status_code == 202, resp.text
        body = resp.json()
        assert "task_id" in body
        # The row starts the reprovision in ``pending`` but the eagerly-run
        # task drives it back to ``ready``.
        assert client.get(f"/clients/{created['id']}").json()["status"] == "ready"

        # The client host must have been touched again, and the hub must
        # have been reconfigured as a follow-up.
        alpha_cmds = "\n".join(
            c for host, c in FakeSSHRunner.COMMANDS if host == "alpha.example.com"
        )
        hub_cmds = "\n".join(
            c for host, c in FakeSSHRunner.COMMANDS if host == "hub.example.com"
        )
        assert "apt-get install" in alpha_cmds
        assert "PUBKEY::alpha.example.com" in hub_cmds
        assert "systemctl restart wg-quick@wg0" in hub_cmds

    def test_reprovision_unknown_client_404(self, client: TestClient) -> None:
        resp = client.post("/clients/999/reprovision")
        assert resp.status_code == 404

    def test_reprovision_brings_down_existing_wg0_before_rewrite(
        self, client: TestClient
    ) -> None:
        """Reprovision must `wg-quick down wg0` before writing the new config.

        Skipping this would leave a stale tunnel running with the old keys
        and peers — the new config either fails to bind or silently never
        takes effect. The teardown step must precede the config rewrite.
        """
        key_id, server_id = _bootstrap_server(client)
        created = client.post(
            "/clients",
            json={
                "name": "alpha",
                "hostname": "alpha.example.com",
                "ssh_username": "ubuntu",
                "ssh_key_id": key_id,
                "server_id": server_id,
            },
        ).json()["client"]
        FakeSSHRunner.COMMANDS.clear()

        resp = client.post(f"/clients/{created['id']}/reprovision")
        assert resp.status_code == 202, resp.text

        alpha_cmds = [
            c for host, c in FakeSSHRunner.COMMANDS if host == "alpha.example.com"
        ]
        joined = "\n".join(alpha_cmds)
        # The canonical teardown command must appear in the reprovision flow.
        assert "wg-quick down wg0" in joined
        # And it must precede the rewrite of /etc/wireguard/wg0.conf — running
        # it after the rewrite defeats the purpose (we'd tear down the new
        # config we just wrote).
        down_idx = next(
            i for i, c in enumerate(alpha_cmds) if "wg-quick down wg0" in c
        )
        rewrite_idx = next(
            i
            for i, c in enumerate(alpha_cmds)
            if "/tmp/wg0.conf.tpl" in c and "cat >" in c
        )
        assert down_idx < rewrite_idx, (
            "wg-quick down must precede the wg0.conf rewrite; "
            f"down at {down_idx}, rewrite at {rewrite_idx}"
        )

    def test_rejects_when_server_not_ready(self, client: TestClient) -> None:
        # No server registered at all → 404 from the router pre-check.
        key_id = int(
            client.post(
                "/ssh-keys",
                json={"name": "lab"},
            ).json()["id"]
        )
        resp = client.post(
            "/clients",
            json={
                "name": "orphan",
                "hostname": "orphan.example.com",
                "ssh_username": "ubuntu",
                "ssh_key_id": key_id,
                "server_id": 999,
            },
        )
        assert resp.status_code == 404

    def test_list_and_get(self, client: TestClient) -> None:
        key_id, server_id = _bootstrap_server(client)
        created = client.post(
            "/clients",
            json={
                "name": "alpha",
                "hostname": "alpha.example.com",
                "ssh_username": "ubuntu",
                "ssh_key_id": key_id,
                "server_id": server_id,
            },
        ).json()["client"]

        list_resp = client.get("/clients")
        assert list_resp.status_code == 200
        assert len(list_resp.json()) == 1

        get_resp = client.get(f"/clients/{created['id']}")
        assert get_resp.status_code == 200
        assert get_resp.json()["id"] == created["id"]


def _register_managed_client(
    client: TestClient,
    key_id: int,
    server_id: int,
    name: str,
) -> dict[str, object]:
    """Register a managed client peer and return its full row dict."""
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
    return resp.json()["client"]


class TestClientDelete:
    """DELETE /clients/{id} — DB delete + hub reconfigure dispatch."""

    def test_delete_returns_202_with_task_id(self, client: TestClient) -> None:
        key_id, server_id = _bootstrap_server(client)
        created = _register_managed_client(client, key_id, server_id, "alpha")
        FakeSSHRunner.COMMANDS.clear()

        resp = client.delete(f"/clients/{created['id']}")
        assert resp.status_code == 202, resp.text
        body = resp.json()
        assert "task_id" in body
        assert body["client_id"] == created["id"]
        assert body["server_id"] == server_id

    def test_delete_removes_row(self, client: TestClient) -> None:
        key_id, server_id = _bootstrap_server(client)
        created = _register_managed_client(client, key_id, server_id, "alpha")

        resp = client.delete(f"/clients/{created['id']}")
        assert resp.status_code == 202

        # Row is gone afterwards.
        assert client.get(f"/clients/{created['id']}").status_code == 404

    def test_delete_dispatches_hub_reconfigure(self, client: TestClient) -> None:
        key_id, server_id = _bootstrap_server(client)
        first = _register_managed_client(client, key_id, server_id, "alpha")
        # Register a second client too so the hub config rebuild after delete
        # still contains a peer entry we can assert against.
        second = _register_managed_client(client, key_id, server_id, "beta")
        FakeSSHRunner.COMMANDS.clear()

        resp = client.delete(f"/clients/{first['id']}")
        assert resp.status_code == 202, resp.text

        # The Celery follow-up task is eagerly run; the task_id resolves to SUCCESS.
        task_resp = client.get(f"/tasks/{resp.json()['task_id']}")
        assert task_resp.status_code == 200
        assert task_resp.json()["state"] == "SUCCESS"

        hub_cmds = "\n".join(
            c for host, c in FakeSSHRunner.COMMANDS if host == "hub.example.com"
        )
        # Hub config was rewritten and wg-quick restarted, AND the deleted
        # client's peer entry is no longer in the rendered config body.
        assert "systemctl restart wg-quick@wg0" in hub_cmds
        assert "PUBKEY::alpha.example.com" not in hub_cmds
        # The surviving client must still be present in the new config.
        assert "PUBKEY::beta.example.com" in hub_cmds
        # Avoid an unused-binding warning for `second`.
        _ = second

    def test_delete_unknown_client_returns_404(self, client: TestClient) -> None:
        resp = client.delete("/clients/999")
        assert resp.status_code == 404


class TestClientUpdate:
    """PATCH /clients/{id} — partial update of operator-supplied fields only."""

    def test_patch_updates_editable_fields(self, client: TestClient) -> None:
        key_id, server_id = _bootstrap_server(client)
        created = _register_managed_client(client, key_id, server_id, "alpha")

        other_key_id = int(
            client.post(
                "/ssh-keys",
                json={"name": "lab2"},
            ).json()["id"]
        )

        resp = client.patch(
            f"/clients/{created['id']}",
            json={
                "name": "alpha-renamed",
                "hostname": "alpha-new.example.com",
                "ssh_port": 2222,
                "ssh_username": "deploy",
                "ssh_key_id": other_key_id,
            },
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["name"] == "alpha-renamed"
        assert body["hostname"] == "alpha-new.example.com"
        assert body["ssh_port"] == 2222
        assert body["ssh_username"] == "deploy"
        assert body["ssh_key_id"] == other_key_id

    def test_patch_partial_update_leaves_unspecified_fields(
        self, client: TestClient
    ) -> None:
        key_id, server_id = _bootstrap_server(client)
        created = _register_managed_client(client, key_id, server_id, "alpha")
        before = client.get(f"/clients/{created['id']}").json()

        resp = client.patch(
            f"/clients/{created['id']}",
            json={"hostname": "renamed.example.com"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["hostname"] == "renamed.example.com"
        assert body["name"] == before["name"]
        assert body["ssh_username"] == before["ssh_username"]
        assert body["server_id"] == before["server_id"]
        assert body["address"] == before["address"]
        assert body["public_key"] == before["public_key"]
        assert body["status"] == before["status"]

    def test_patch_rejects_unknown_ssh_key(self, client: TestClient) -> None:
        key_id, server_id = _bootstrap_server(client)
        created = _register_managed_client(client, key_id, server_id, "alpha")

        resp = client.patch(
            f"/clients/{created['id']}",
            json={"ssh_key_id": 999_999},
        )
        assert resp.status_code == 404, resp.text
        assert "ssh key" in resp.json()["detail"].lower()

    def test_patch_rejects_duplicate_name(self, client: TestClient) -> None:
        key_id, server_id = _bootstrap_server(client)
        _ = _register_managed_client(client, key_id, server_id, "alpha")
        beta = _register_managed_client(client, key_id, server_id, "beta")

        resp = client.patch(
            f"/clients/{beta['id']}",
            json={"name": "alpha"},
        )
        assert resp.status_code == 409, resp.text
        assert "already exists" in resp.json()["detail"].lower()

    def test_patch_ignores_readonly_fields(self, client: TestClient) -> None:
        key_id, server_id = _bootstrap_server(client)
        created = _register_managed_client(client, key_id, server_id, "alpha")
        before = client.get(f"/clients/{created['id']}").json()

        resp = client.patch(
            f"/clients/{created['id']}",
            json={
                "server_id": 9999,
                "address": "10.99.0.99/32",
                "public_key": "BOGUS",
                "status": "error",
            },
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["server_id"] == before["server_id"]
        assert body["address"] == before["address"]
        assert body["public_key"] == before["public_key"]
        assert body["status"] == before["status"]

    def test_patch_unknown_client_returns_404(self, client: TestClient) -> None:
        resp = client.patch("/clients/999", json={"name": "x"})
        assert resp.status_code == 404


class TestClientsSSHConfigExport:
    """GET /clients/export/ssh-config — render a usable ~/.ssh/config block.

    Each managed client becomes one entry whose ``Host`` alias is the
    client's ``name`` with a ``.vpn`` suffix, whose ``HostName`` is the
    wg-assigned IP (with the ``/32`` stripped), whose ``User`` is the
    client's stored ``ssh_username``, and whose ``IdentityFile`` points
    at ``~/.ssh/<key-name>`` — the operator is expected to have placed
    the key under ``$HOME/.ssh/`` themselves.
    """

    def test_export_returns_text_plain(self, client: TestClient) -> None:
        key_id, server_id = _bootstrap_server(client)
        _register_managed_client(client, key_id, server_id, "alpha")

        resp = client.get("/clients/export/ssh-config")
        assert resp.status_code == 200, resp.text
        # text/plain — this body is meant to be appended to ~/.ssh/config.
        content_type = resp.headers["content-type"]
        assert content_type.startswith("text/plain")

    def test_export_renders_single_client_block(self, client: TestClient) -> None:
        key_id, server_id = _bootstrap_server(client)
        _register_managed_client(client, key_id, server_id, "alpha")

        body = client.get("/clients/export/ssh-config").text
        # The exact block the test fixture's setup produces:
        # - name "alpha" → Host alpha.vpn
        # - first allocated client IP in 10.9.0.0/24 is 10.9.0.2
        # - ssh_username "ubuntu" → User ubuntu
        # - SSHKey was registered with name "lab" → IdentityFile ~/.ssh/lab
        expected = (
            "Host alpha.vpn\n"
            "    HostName 10.9.0.2\n"
            "    User ubuntu\n"
            "    IdentityFile ~/.ssh/lab\n"
        )
        assert expected in body

    def test_export_omits_cidr_prefix_from_hostname(
        self, client: TestClient
    ) -> None:
        """The ``/32`` suffix on Client.address must not leak into HostName."""
        key_id, server_id = _bootstrap_server(client)
        _register_managed_client(client, key_id, server_id, "alpha")

        body = client.get("/clients/export/ssh-config").text
        assert "HostName 10.9.0.2/32" not in body
        assert "HostName 10.9.0.2" in body

    def test_export_lists_every_client(self, client: TestClient) -> None:
        key_id, server_id = _bootstrap_server(client)
        _register_managed_client(client, key_id, server_id, "alpha")
        _register_managed_client(client, key_id, server_id, "beta")

        body = client.get("/clients/export/ssh-config").text
        assert "Host alpha.vpn" in body
        assert "Host beta.vpn" in body
        # Each block is separated by a blank line so the file stays readable.
        assert "\n\n" in body

    def test_export_uses_per_client_ssh_username(
        self, client: TestClient
    ) -> None:
        """A client patched to a different ssh_username surfaces in the export."""
        key_id, server_id = _bootstrap_server(client)
        created = _register_managed_client(client, key_id, server_id, "alpha")
        patch_resp = client.patch(
            f"/clients/{created['id']}",
            json={"ssh_username": "deploy"},
        )
        assert patch_resp.status_code == 200, patch_resp.text

        body = client.get("/clients/export/ssh-config").text
        assert "User deploy" in body
        assert "User ubuntu" not in body

    def test_export_uses_per_client_ssh_key_name(
        self, client: TestClient
    ) -> None:
        """IdentityFile path comes from the SSHKey row, not the client itself."""
        key_id, server_id = _bootstrap_server(client)
        # Register a second SSH key with a different name and point alpha at it.
        other_key_id = int(
            client.post(
                "/ssh-keys",
                json={"name": "prod"},
            ).json()["id"]
        )
        created = _register_managed_client(client, key_id, server_id, "alpha")
        client.patch(
            f"/clients/{created['id']}",
            json={"ssh_key_id": other_key_id},
        )

        body = client.get("/clients/export/ssh-config").text
        assert "IdentityFile ~/.ssh/prod" in body
        # The original "lab" key name must not appear for alpha.
        assert "IdentityFile ~/.ssh/lab" not in body

    def test_export_empty_when_no_clients(self, client: TestClient) -> None:
        # No bootstrap_server: nothing managed.
        resp = client.get("/clients/export/ssh-config")
        assert resp.status_code == 200, resp.text
        assert resp.text == ""

    def test_export_skips_manual_clients(self, client: TestClient) -> None:
        """Manual (un-provisioned) clients have no SSH credentials, so the
        SSH-config export must skip them entirely — they shouldn't appear
        as broken ``Host`` blocks in the rendered file."""
        key_id, server_id = _bootstrap_server(client)
        _register_managed_client(client, key_id, server_id, "alpha")
        manual_resp = client.post(
            "/clients/manual",
            json={"name": "phone", "server_id": server_id},
        )
        assert manual_resp.status_code == 201, manual_resp.text

        body = client.get("/clients/export/ssh-config").text
        assert "Host alpha.vpn" in body
        # The manual peer must not surface in the SSH config export.
        assert "Host phone.vpn" not in body


# ---------------------------------------------------------------------------
# Manual clients — register without SSH provisioning
# ---------------------------------------------------------------------------


class TestManualClient:
    """POST /clients/manual — register a client we won't SSH into.

    For devices that wg-manager can't reach over SSH (phones, IoT, locked-
    down embedded boxes) the user creates the row with a server-generated
    WireGuard keypair, fetches the rendered ``wg0.conf``, and installs it
    on the device themselves. The hub is reconfigured automatically so the
    new peer is admitted.
    """

    def test_register_creates_ready_client(self, client: TestClient) -> None:
        key_id, server_id = _bootstrap_server(client)
        _ = key_id  # the manual flow does not need an SSH key

        resp = client.post(
            "/clients/manual",
            json={"name": "phone", "server_id": server_id},
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        # Manual rows are ready immediately — no Celery task to wait on.
        assert body["client"]["status"] == "ready"
        assert body["client"]["is_manual"] is True
        # A server-generated public key was assigned.
        assert body["client"]["public_key"], body
        # First free IP in the 10.9.0.0/24 subnet.
        assert body["client"]["address"] == "10.9.0.2/32"
        # The follow-up hub reconfigure task ID is returned for polling.
        assert "task_id" in body

    def test_register_returns_wg_config_body_once(
        self, client: TestClient
    ) -> None:
        """``POST /clients/manual`` must return the rendered ``wg0.conf``
        body in the response so the operator can capture it at
        registration time. Post-redesign the control plane does **not**
        persist the private key, so this single response is the only
        moment the body can be obtained — there is no separate
        ``GET /clients/{id}/config`` to re-fetch it from later."""
        _, server_id = _bootstrap_server(client)
        resp = client.post(
            "/clients/manual",
            json={"name": "phone", "server_id": server_id},
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        # The wg_config field sits alongside ``task_id`` and ``client``.
        assert "wg_config" in body, body
        wg_config = body["wg_config"]
        assert isinstance(wg_config, str)
        # The body must look like a real WireGuard config — Interface +
        # Peer sections, a non-empty PrivateKey, the assigned address,
        # and the hub's pubkey / endpoint.
        assert "[Interface]" in wg_config
        assert "[Peer]" in wg_config
        assert "PrivateKey = " in wg_config
        # No placeholder leaked through — the renderer received a real key.
        assert "PrivateKey = \n" not in wg_config
        assert "Address = 10.9.0.2/32" in wg_config
        assert "PublicKey = PUBKEY::hub.example.com" in wg_config
        assert "Endpoint = hub.example.com:51820" in wg_config
        assert "AllowedIPs = 10.9.0.0/24" in wg_config

    def test_register_does_not_persist_private_key(
        self, client: TestClient, engine: Any
    ) -> None:
        """The architectural pivot: the control plane has no operational
        use for a manual client's private key once the operator has
        captured the config, so we never persist it. This test pins
        that invariant — touching the row directly after registration
        proves the private key was generated, used in the response, and
        immediately dropped (the row carries only the public key)."""
        from wg_manager.models import Client

        _, server_id = _bootstrap_server(client)
        resp = client.post(
            "/clients/manual",
            json={"name": "phone", "server_id": server_id},
        )
        assert resp.status_code == 201, resp.text
        client_id = int(resp.json()["client"]["id"])

        with Session(engine) as s:
            row = s.get(Client, client_id)
            assert row is not None
            # Public key is still pinned (the hub needs it).
            assert row.public_key != ""
            # Private key is **not** stored — neither via the legacy
            # plaintext column (gone since Alembic 0005) nor the
            # encrypt-at-rest column (gone since the redesign).
            assert not hasattr(row, "private_key_ct") or row.private_key_ct is None

    def test_register_does_not_require_ssh_fields(self, client: TestClient) -> None:
        _, server_id = _bootstrap_server(client)
        # Only name + server_id are required. No hostname, ssh_username,
        # ssh_key_id — the device is reached by hand, not by wg-manager.
        resp = client.post(
            "/clients/manual",
            json={"name": "phone", "server_id": server_id},
        )
        assert resp.status_code == 201, resp.text

    def test_register_reconfigures_hub_with_new_peer(
        self, client: TestClient
    ) -> None:
        _, server_id = _bootstrap_server(client)
        FakeSSHRunner.COMMANDS.clear()

        resp = client.post(
            "/clients/manual",
            json={"name": "phone", "server_id": server_id},
        )
        assert resp.status_code == 201, resp.text
        public_key = resp.json()["client"]["public_key"]

        hub_cmds = "\n".join(
            c for host, c in FakeSSHRunner.COMMANDS if host == "hub.example.com"
        )
        # The hub must have been touched (wg0.conf rewritten + restarted)
        # and the manual client's public key must appear in the new config.
        assert public_key in hub_cmds
        assert "systemctl restart wg-quick@wg0" in hub_cmds

    def test_register_rejects_duplicate_name(self, client: TestClient) -> None:
        key_id, server_id = _bootstrap_server(client)
        _register_managed_client(client, key_id, server_id, "phone")

        resp = client.post(
            "/clients/manual",
            json={"name": "phone", "server_id": server_id},
        )
        assert resp.status_code == 409, resp.text

    def test_register_unknown_server_returns_404(self, client: TestClient) -> None:
        resp = client.post(
            "/clients/manual",
            json={"name": "phone", "server_id": 999},
        )
        assert resp.status_code == 404

    def test_register_rejects_when_server_not_ready(
        self, client: TestClient, engine: Any
    ) -> None:
        """The hub's public key is needed to render the manual client's
        config — so the server must be in ``ready`` state. A still-pending
        server must produce 400 rather than handing the user a config that
        points at an empty PublicKey."""
        # Drop a Server row directly so it stays in ``pending`` without us
        # having to run the provisioning task (eager-mode would otherwise
        # propagate any SSH failure back through the HTTP path).
        key_id = int(
            client.post(
                "/ssh-keys",
                json={"name": "lab"},
            ).json()["id"]
        )
        with Session(engine) as session:
            srv = Server(
                hostname="hub.example.com",
                ssh_username="ubuntu",
                ssh_key_id=key_id,
                endpoint_host="hub.example.com",
                subnet="10.9.0.0/24",
                address="10.9.0.1/24",
                status=NodeStatus.pending,
            )
            session.add(srv)
            session.commit()
            session.refresh(srv)
            server_id = srv.id

        resp = client.post(
            "/clients/manual",
            json={"name": "phone", "server_id": server_id},
        )
        assert resp.status_code == 400, resp.text

    def test_register_allocates_next_ip_across_modes(
        self, client: TestClient
    ) -> None:
        """Manual and managed clients share the same IPAM pool — a manual
        client registered after a managed one must take ``.3``, not
        ``.2`` again."""
        key_id, server_id = _bootstrap_server(client)
        _register_managed_client(client, key_id, server_id, "alpha")

        resp = client.post(
            "/clients/manual",
            json={"name": "phone", "server_id": server_id},
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["client"]["address"] == "10.9.0.3/32"

    def test_reprovision_rejects_manual_client(self, client: TestClient) -> None:
        """Manual clients have no SSH credentials, so reprovision (which
        SSHes into the device) cannot work. The router must refuse with
        a 400 rather than letting Celery blow up at task time."""
        _, server_id = _bootstrap_server(client)
        created = client.post(
            "/clients/manual",
            json={"name": "phone", "server_id": server_id},
        ).json()["client"]

        resp = client.post(f"/clients/{created['id']}/reprovision")
        assert resp.status_code == 400, resp.text


class TestRetiredConfigEndpoint:
    """``GET /clients/{id}/config`` was retired in the manual-client
    redesign — the wg0.conf body is now delivered exactly once on the
    ``POST /clients/manual`` response, and the control plane no longer
    stores anything that would let it re-render the config later. The
    endpoint must be gone (FastAPI returns 404 for an unknown route).

    The two pre-existing legacy-broken rows (manual clients with
    ``private_key_ct`` already NULL) land in the same end state as a
    fresh manual client and need no special handling.
    """

    def test_config_endpoint_is_gone_for_manual_client(
        self, client: TestClient
    ) -> None:
        _, server_id = _bootstrap_server(client)
        created = client.post(
            "/clients/manual",
            json={"name": "phone", "server_id": server_id},
        ).json()["client"]

        # The route was deleted, so FastAPI 404s regardless of whether
        # the client_id is valid.
        resp = client.get(f"/clients/{created['id']}/config")
        assert resp.status_code == 404, resp.text

    def test_config_endpoint_is_gone_for_managed_client(
        self, client: TestClient
    ) -> None:
        key_id, server_id = _bootstrap_server(client)
        created = _register_managed_client(client, key_id, server_id, "alpha")

        resp = client.get(f"/clients/{created['id']}/config")
        assert resp.status_code == 404, resp.text
