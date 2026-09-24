"""Tasks pass each row's last-issued cert principals to the SSH runner.

``KnownHostsCAPolicy`` matches the host cert's principals against the
name being dialed. If an operator renames a row (``PATCH`` hostname),
the host still carries the cert wg-manager issued for the *old* name,
so a strict match would lock the control plane out — including the
reprovision/rotation that would fix it. :func:`wg_manager.tasks._open_runner`
therefore also accepts the principals recorded in the row's
``host_cert_principals`` (a cert this control plane issued and
recorded), and the next provision/rotation replaces it with a cert for
the new name.
"""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient
from sqlmodel import Session

from tests.conftest import FakeSSHRunner
from wg_manager.models import Server


def _accepted_for(host: str) -> list[tuple[str, ...]]:
    return [p for h, p in FakeSSHRunner.ACCEPTED_PRINCIPALS if h == host]


def _recorded_principals(engine: Any, server_id: int) -> str | None:
    """Read the row directly (independent of what ServerRead exposes)."""
    with Session(engine) as s:
        row = s.get(Server, server_id)
        assert row is not None
        return row.host_cert_principals


def test_renamed_server_accepts_previously_issued_principal(
    client: TestClient, engine: Any
) -> None:
    key_id = int(client.post("/ssh-keys", json={"name": "lab"}).json()["id"])
    server_id = client.post(
        "/servers",
        json={
            "hostname": "old-hub.example.com",
            "ssh_username": "ubuntu",
            "ssh_key_id": key_id,
            "endpoint_host": "old-hub.example.com",
        },
    ).json()["server"]["id"]
    assert _recorded_principals(engine, server_id) == "old-hub.example.com"

    resp = client.patch(f"/servers/{server_id}", json={"hostname": "new-hub.example.com"})
    assert resp.status_code == 200, resp.text
    FakeSSHRunner.ACCEPTED_PRINCIPALS.clear()

    assert client.post(f"/servers/{server_id}/reprovision").status_code == 202

    assert ("old-hub.example.com",) in _accepted_for("new-hub.example.com")
    # The reprovision re-issued the cert for the new name.
    assert _recorded_principals(engine, server_id) == "new-hub.example.com"


def test_fresh_row_accepts_only_its_own_name(client: TestClient) -> None:
    """No recorded cert yet → no extra principals beyond the dial name."""
    key_id = int(client.post("/ssh-keys", json={"name": "lab"}).json()["id"])
    FakeSSHRunner.ACCEPTED_PRINCIPALS.clear()
    client.post(
        "/servers",
        json={
            "hostname": "fresh-hub.example.com",
            "ssh_username": "ubuntu",
            "ssh_key_id": key_id,
            "endpoint_host": "fresh-hub.example.com",
        },
    )
    assert _accepted_for("fresh-hub.example.com")[0] == ()
