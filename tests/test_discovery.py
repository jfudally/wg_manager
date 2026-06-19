"""Tests for peer discovery: importing existing WireGuard peers from a host.

The discovery flow SSHes into a server, runs ``wg show <iface> dump``, parses
each peer line, and upserts a row into the ``discoveredpeer`` table. Peers
whose public key already matches a managed :class:`Client` row are flagged
``is_managed=True``.
"""

from __future__ import annotations

import base64

from fastapi.testclient import TestClient

from tests.conftest import FakeSSHRunner
from wg_manager.wireguard import parse_wg_dump

_SAMPLE_PEM = "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEBODY\n-----END OPENSSH PRIVATE KEY-----\n"
_SAMPLE_PEM_B64 = base64.b64encode(_SAMPLE_PEM.encode("utf-8")).decode("ascii")


# Realistic ``wg show wg0 dump`` output: line 1 is the local interface
# (private, public, listen-port, fwmark), each subsequent tab-separated line
# is a peer (public-key, preshared-key, endpoint, allowed-ips,
# latest-handshake (epoch seconds), rx-bytes, tx-bytes, persistent-keepalive).
_WG_DUMP = (
    "SRV_PRIV_KEY\tSRV_PUB_KEY\t51820\toff\n"
    "PEER_ALPHA_PUBKEY\t(none)\t203.0.113.10:51820\t10.9.0.2/32\t1715000000\t1024\t2048\t25\n"
    "PEER_BETA_PUBKEY\t(none)\t(none)\t10.9.0.3/32\t0\t0\t0\toff\n"
)


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


class TestParseWgDump:
    """Pure-parser unit tests — no SSH, no DB."""

    def test_parses_interface_and_peers(self) -> None:
        ifc, peers = parse_wg_dump(_WG_DUMP)
        assert ifc.public_key == "SRV_PUB_KEY"
        assert ifc.listen_port == 51820
        assert len(peers) == 2

        alpha = peers[0]
        assert alpha.public_key == "PEER_ALPHA_PUBKEY"
        assert alpha.allowed_ips == "10.9.0.2/32"
        assert alpha.endpoint == "203.0.113.10:51820"
        assert alpha.last_handshake_epoch == 1715000000
        assert alpha.rx_bytes == 1024
        assert alpha.tx_bytes == 2048
        assert alpha.persistent_keepalive == 25

        beta = peers[1]
        assert beta.public_key == "PEER_BETA_PUBKEY"
        # "(none)" endpoint should normalise to ``None``.
        assert beta.endpoint is None
        # ``last_handshake_epoch == 0`` means "never" — keep the raw value.
        assert beta.last_handshake_epoch == 0
        # "off" keepalive should normalise to ``None``.
        assert beta.persistent_keepalive is None

    def test_ignores_blank_lines(self) -> None:
        dump = "\n\nSRV_PRIV\tSRV_PUB\t51820\toff\n\nP\t(none)\t(none)\t10.0.0.2/32\t0\t0\t0\toff\n\n"
        ifc, peers = parse_wg_dump(dump)
        assert ifc.public_key == "SRV_PUB"
        assert len(peers) == 1


class TestDiscoverEndpoint:
    def test_discover_populates_database(self, client: TestClient) -> None:
        _key_id, server_id = _bootstrap_server(client)

        # Tell the FakeSSHRunner: when anything resembling
        # ``wg show wg0 dump`` runs on the hub, return our canned output.
        FakeSSHRunner.OUTPUTS[("hub.example.com", "wg show wg0 dump")] = _WG_DUMP

        resp = client.post(f"/servers/{server_id}/discover")
        assert resp.status_code == 202, resp.text
        body = resp.json()
        assert "task_id" in body
        assert body["server"]["id"] == server_id

        peers = client.get(f"/servers/{server_id}/discovered-peers").json()
        assert len(peers) == 2
        by_key = {p["public_key"]: p for p in peers}
        assert by_key["PEER_ALPHA_PUBKEY"]["allowed_ips"] == "10.9.0.2/32"
        assert by_key["PEER_ALPHA_PUBKEY"]["endpoint"] == "203.0.113.10:51820"
        assert by_key["PEER_ALPHA_PUBKEY"]["server_id"] == server_id
        # Neither peer matches any managed Client row, so both must be
        # is_managed=False.
        assert all(p["is_managed"] is False for p in peers)

    def test_discover_is_idempotent(self, client: TestClient) -> None:
        _key_id, server_id = _bootstrap_server(client)
        FakeSSHRunner.OUTPUTS[("hub.example.com", "wg show wg0 dump")] = _WG_DUMP

        client.post(f"/servers/{server_id}/discover")
        first = client.get(f"/servers/{server_id}/discovered-peers").json()
        client.post(f"/servers/{server_id}/discover")
        second = client.get(f"/servers/{server_id}/discovered-peers").json()

        # Second run must not duplicate rows — upsert by (server_id, public_key).
        assert len(first) == len(second) == 2
        first_ids = sorted(p["id"] for p in first)
        second_ids = sorted(p["id"] for p in second)
        assert first_ids == second_ids

    def test_discover_flags_already_managed_clients(self, client: TestClient) -> None:
        key_id, server_id = _bootstrap_server(client)

        # Register a managed client first; capture the public_key the fake
        # provisioner assigns to it (``PUBKEY::<host>``).
        managed = client.post(
            "/clients",
            json={
                "name": "alpha",
                "hostname": "alpha.example.com",
                "ssh_username": "ubuntu",
                "ssh_key_id": key_id,
                "server_id": server_id,
            },
        ).json()["client"]
        managed_pubkey = client.get(f"/clients/{managed['id']}").json()["public_key"]

        dump = (
            "SRV_PRIV\tSRV_PUB\t51820\toff\n"
            f"{managed_pubkey}\t(none)\t(none)\t10.9.0.2/32\t0\t0\t0\toff\n"
            "STRANGER_PUBKEY\t(none)\t198.51.100.1:51820\t10.9.0.99/32\t1\t10\t20\toff\n"
        )
        FakeSSHRunner.OUTPUTS[("hub.example.com", "wg show wg0 dump")] = dump

        resp = client.post(f"/servers/{server_id}/discover")
        assert resp.status_code == 202, resp.text

        peers = client.get(f"/servers/{server_id}/discovered-peers").json()
        by_key = {p["public_key"]: p for p in peers}
        assert by_key[managed_pubkey]["is_managed"] is True
        assert by_key["STRANGER_PUBKEY"]["is_managed"] is False

    def test_discover_prunes_vanished_peers(self, client: TestClient) -> None:
        """A peer absent from a later pass is pruned, not left as stale data.

        Discovery is the operator's source of truth for "what is on the wire
        right now". A peer that has been removed from the server's running
        config must disappear from the discovered-peers table on the next
        pass — otherwise the table accumulates ghosts that never clear.
        """
        _key_id, server_id = _bootstrap_server(client)

        # First pass: both ALPHA and BETA are present on the wire.
        FakeSSHRunner.OUTPUTS[("hub.example.com", "wg show wg0 dump")] = _WG_DUMP
        client.post(f"/servers/{server_id}/discover")
        first = client.get(f"/servers/{server_id}/discovered-peers").json()
        assert {p["public_key"] for p in first} == {
            "PEER_ALPHA_PUBKEY",
            "PEER_BETA_PUBKEY",
        }

        # Second pass: BETA has been removed from the server — only ALPHA
        # is still reported by ``wg show``.
        only_alpha = (
            "SRV_PRIV_KEY\tSRV_PUB_KEY\t51820\toff\n"
            "PEER_ALPHA_PUBKEY\t(none)\t203.0.113.10:51820\t10.9.0.2/32\t1715000000\t1024\t2048\t25\n"
        )
        FakeSSHRunner.OUTPUTS[("hub.example.com", "wg show wg0 dump")] = only_alpha
        client.post(f"/servers/{server_id}/discover")
        second = client.get(f"/servers/{server_id}/discovered-peers").json()

        # BETA must be gone — the stale row is pruned, not accumulated.
        assert {p["public_key"] for p in second} == {"PEER_ALPHA_PUBKEY"}

    def test_discover_prune_is_scoped_to_server(self, client: TestClient) -> None:
        """Pruning a server's vanished peers must not touch another server."""
        _key_id, server_a = _bootstrap_server(client)
        # Register a second, distinct server.
        key_b = int(client.post("/ssh-keys", json={"name": "lab2"}).json()["id"])
        server_b = int(
            client.post(
                "/servers",
                json={
                    "hostname": "hub2.example.com",
                    "ssh_username": "ubuntu",
                    "ssh_key_id": key_b,
                    "endpoint_host": "hub2.example.com",
                },
            ).json()["server"]["id"]
        )

        # Discover peers on both servers.
        FakeSSHRunner.OUTPUTS[("hub.example.com", "wg show wg0 dump")] = _WG_DUMP
        FakeSSHRunner.OUTPUTS[("hub2.example.com", "wg show wg0 dump")] = _WG_DUMP
        client.post(f"/servers/{server_a}/discover")
        client.post(f"/servers/{server_b}/discover")

        # Re-run discovery on A with an empty peer list. B's peers must remain.
        empty_dump = "SRV_PRIV_KEY\tSRV_PUB_KEY\t51820\toff\n"
        FakeSSHRunner.OUTPUTS[("hub.example.com", "wg show wg0 dump")] = empty_dump
        client.post(f"/servers/{server_a}/discover")

        peers_a = client.get(f"/servers/{server_a}/discovered-peers").json()
        peers_b = client.get(f"/servers/{server_b}/discovered-peers").json()
        assert peers_a == []
        assert {p["public_key"] for p in peers_b} == {
            "PEER_ALPHA_PUBKEY",
            "PEER_BETA_PUBKEY",
        }

    def test_ssh_failure_does_not_prune(self, client: TestClient) -> None:
        """A failed pass yields no data, so it must not wipe known peers.

        Pruning keys off "what this pass observed". An SSH failure observes
        *nothing*, which is categorically different from "the server has no
        peers" — treating it as the latter would clear the whole table every
        time a host is briefly unreachable.
        """
        import socket

        _key_id, server_id = _bootstrap_server(client)
        FakeSSHRunner.OUTPUTS[("hub.example.com", "wg show wg0 dump")] = _WG_DUMP
        client.post(f"/servers/{server_id}/discover")
        assert len(client.get(f"/servers/{server_id}/discovered-peers").json()) == 2

        # Next pass: the host is unreachable.
        FakeSSHRunner.RAISE_ON_ENTER["hub.example.com"] = socket.timeout(
            "connection timed out"
        )
        client.post(f"/servers/{server_id}/discover")

        # The previously-known peers must survive an unreachable pass.
        peers = client.get(f"/servers/{server_id}/discovered-peers").json()
        assert {p["public_key"] for p in peers} == {
            "PEER_ALPHA_PUBKEY",
            "PEER_BETA_PUBKEY",
        }

    def test_discover_unknown_server_404(self, client: TestClient) -> None:
        resp = client.post("/servers/999/discover")
        assert resp.status_code == 404
