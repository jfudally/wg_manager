"""Phase 3f MVP — ``POST /v1/enroll`` on the enrollment listener.

A fresh host presents an enrollment token (``Authorization: Bearer``)
plus its own WireGuard and SSH host public keys. The control plane:

* consumes the token atomically, rolling back on any later failure,
* allocates a VPN address and creates a **managed** client row that
  the worker will dial at that address,
* signs the host's SSH key with principals it controls (the VPN IP
  only, never the host-supplied hostname),
* returns a WireGuard config with no private key in it, plus the SSH
  user CA and host cert,
* audits the enrollment and queues a hub reconfigure.

Every token failure (missing, unknown, expired, used up) returns the
same 401 body, so a caller can't probe token state.
"""

from __future__ import annotations

import base64
import logging
from collections.abc import Generator
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from wg_manager import db as db_module
from wg_manager import enroll_app as enroll_app_module
from wg_manager.db import get_session
from wg_manager.enroll_app import ENROLL_PATH, create_enroll_app
from wg_manager.enrollment import mint_token
from wg_manager.models import (
    AuditEvent,
    Client,
    EnrollmentToken,
    NodeStatus,
    Server,
    SSHKey,
)
from wg_manager.ssh_ca import make_ssh_ca_backend
from wg_manager.wireguard import generate_wireguard_keypair

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def dispatched(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Record hub-reconfigure dispatches instead of running them."""
    calls: list[int] = []

    class _Result:
        id = "task-reconf"

    def _request(server_id: int) -> _Result:
        calls.append(server_id)
        return _Result()

    monkeypatch.setattr(enroll_app_module, "request_reconfigure", _request)
    return calls


@pytest.fixture()
def enroll(engine: Any, dispatched: list[int]) -> Generator[TestClient, None, None]:
    """TestClient for the enrollment app bound to the test DB."""
    app = create_enroll_app()

    def _session() -> Generator[Session, None, None]:
        with Session(engine) as s:
            yield s

    app.dependency_overrides[get_session] = _session
    with TestClient(app) as tc:
        yield tc


@pytest.fixture()
def hub() -> int:
    """A ready hub in tenant 1 with an SSH key; returns the server id."""
    with Session(db_module.engine) as s:
        key = SSHKey(name="ops", tenant_id=1)
        s.add(key)
        s.commit()
        s.refresh(key)
        row = Server(
            hostname="hub.example.com",
            ssh_username="ubuntu",
            ssh_key_id=key.id,
            endpoint_host="hub.example.com",
            endpoint_port=51820,
            public_key="HUBPUBKEY=",
            status=NodeStatus.ready,
            tenant_id=1,
            subnet="10.9.0.0/24",
            address="10.9.0.1/24",
        )
        s.add(row)
        s.commit()
        s.refresh(row)
        return int(row.id or 0)


def _mint(server_id: int, *, max_uses: int = 1, ttl: int = 3600) -> str:
    with Session(db_module.engine) as s:
        server = s.get(Server, server_id)
        key = s.get(SSHKey, server.ssh_key_id)
        _, token = mint_token(
            s, server=server, ssh_key=key, ssh_username="wgmgr",
            name_prefix="web", ttl_seconds=ttl, max_uses=max_uses,
            created_by_cn="admin",
        )
        s.commit()
        return token


def _host_keys() -> tuple[str, str]:
    """Return ``(wg_public_key, ssh_ed25519_public_key_openssh)``."""
    _, wg_pub = generate_wireguard_keypair()
    ssh_pub = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ).decode()
    return wg_pub, ssh_pub + " root@host"


def _body(hostname: str = "ip-172-31-5-9", **over: Any) -> dict[str, Any]:
    wg_pub, ssh_pub = _host_keys()
    return {"hostname": hostname, "wg_public_key": wg_pub,
            "ssh_host_public_key": ssh_pub, **over}


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _token_row() -> EnrollmentToken:
    with Session(db_module.engine) as s:
        return s.exec(select(EnrollmentToken)).one()


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestEnrollHappyPath:
    def test_creates_managed_client_and_returns_material(
        self, enroll: TestClient, hub: int, dispatched: list[int]
    ) -> None:
        token = _mint(hub)
        body = _body()
        resp = enroll.post(ENROLL_PATH, json=body, headers=_auth(token))
        assert resp.status_code == 201, resp.text
        out = resp.json()

        assert out["address"] == "10.9.0.2/32"
        assert out["name"] == "web-ip-172-31-5-9"
        assert out["ssh_username"] == "wgmgr"

        # Config: hub peer present, private key NOT present, key loaded
        # from the host-local file the SSH-provisioned flow also uses.
        cfg = out["wg_config"]
        assert "PrivateKey" not in cfg
        assert "PostUp = wg set %i private-key /etc/wireguard/privatekey" in cfg
        assert "PublicKey = HUBPUBKEY=" in cfg
        assert "Endpoint = hub.example.com:51820" in cfg
        assert "Address = 10.9.0.2/32" in cfg
        assert "AllowedIPs = 10.9.0.0/24" in cfg

        # SSH trust material.
        ca = make_ssh_ca_backend()
        assert out["user_ca_public_key"] == ca.ca_public_key
        assert out["host_certificate"].startswith("ssh-ed25519-cert-v01@openssh.com ")
        assert out["host_cert_principals"] == ["10.9.0.2"]

        with Session(db_module.engine) as s:
            c = s.exec(select(Client)).one()
            assert c.is_manual is False
            assert c.status == NodeStatus.ready
            assert c.hostname == "10.9.0.2"  # worker dials the VPN IP
            assert c.public_key == body["wg_public_key"]
            assert c.ssh_username == "wgmgr"
            assert c.ssh_key_id is not None
            assert c.tenant_id == 1
            assert c.host_cert_serial is not None
            assert c.host_cert_principals == "10.9.0.2"
            assert c.host_cert_ca_public_key == ca.ca_public_key

        assert _token_row().use_count == 1
        assert dispatched == [hub]

    def test_audits_enrollment(self, enroll: TestClient, hub: int) -> None:
        token = _mint(hub)
        enroll.post(ENROLL_PATH, json=_body(), headers=_auth(token))
        with Session(db_module.engine) as s:
            ev = s.exec(select(AuditEvent).where(AuditEvent.event == "client.enroll")).one()
        assert ev.resource_type == "client"
        assert ev.tenant_id == 1
        assert token not in (ev.payload or "")
        assert '"token_id"' in (ev.payload or "")

    def test_multi_use_token_allocates_distinct_addresses(
        self, enroll: TestClient, hub: int
    ) -> None:
        token = _mint(hub, max_uses=2)
        a = enroll.post(ENROLL_PATH, json=_body("a"), headers=_auth(token))
        b = enroll.post(ENROLL_PATH, json=_body("b"), headers=_auth(token))
        c = enroll.post(ENROLL_PATH, json=_body("c"), headers=_auth(token))
        assert (a.status_code, b.status_code, c.status_code) == (201, 201, 401)
        assert a.json()["address"] != b.json()["address"]


# ---------------------------------------------------------------------------
# Token failures — uniform 401
# ---------------------------------------------------------------------------


class TestTokenFailures:
    def _post(self, enroll: TestClient, headers: dict[str, str]):
        return enroll.post(ENROLL_PATH, json=_body(), headers=headers)

    def test_all_token_failures_look_identical(
        self, enroll: TestClient, hub: int
    ) -> None:
        used = _mint(hub)
        assert self._post(enroll, _auth(used)).status_code == 201

        with Session(db_module.engine) as s:
            server = s.get(Server, hub)
            key = s.get(SSHKey, server.ssh_key_id)
            row, expired = mint_token(
                s, server=server, ssh_key=key, ssh_username="wgmgr",
                name_prefix="web", ttl_seconds=3600, max_uses=1,
                created_by_cn=None,
            )
            row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            s.commit()

        responses = [
            self._post(enroll, {}),                          # no header
            self._post(enroll, {"Authorization": "Basic x"}),  # wrong scheme
            self._post(enroll, _auth("wgmenr_nope")),         # unknown
            self._post(enroll, _auth(expired)),               # expired
            self._post(enroll, _auth(used)),                  # used up
        ]
        assert [r.status_code for r in responses] == [401] * 5
        assert len({r.text for r in responses}) == 1
        assert all(r.headers.get("www-authenticate") == "Bearer" for r in responses)

    def test_reject_is_logged_without_token(
        self, enroll: TestClient, hub: int, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.INFO, logger="wg_manager.audit")
        self._post(enroll, _auth("wgmenr_secret-value"))
        lines = [r.getMessage() for r in caplog.records if r.name == "wg_manager.audit"]
        assert any('"enroll.reject"' in m and "unknown_token" in m for m in lines)
        assert not any("wgmenr_secret-value" in m for m in lines)


# ---------------------------------------------------------------------------
# Request validation
# ---------------------------------------------------------------------------


class TestValidation:
    @pytest.mark.parametrize(
        "over",
        [
            {"hostname": "UPPER"},
            {"hostname": "has space"},
            {"hostname": "-lead"},
            {"hostname": "x" * 64},
            {"wg_public_key": "not-base64!"},
            {"wg_public_key": base64.b64encode(b"short").decode()},
            {"ssh_host_public_key": "garbage"},
        ],
    )
    def test_rejects_bad_fields(
        self, enroll: TestClient, hub: int, over: dict[str, Any]
    ) -> None:
        token = _mint(hub)
        resp = enroll.post(ENROLL_PATH, json=_body(**over), headers=_auth(token))
        assert resp.status_code == 422, over
        assert _token_row().use_count == 0

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"json": {"junk": 1}},                        # wrong shape
            {"json": _body(hostname="UPPER")},            # bad field
            {"content": b"{not json"},                    # unparseable
            {},                                           # no body at all
        ],
    )
    @pytest.mark.parametrize(
        "headers", [{}, {"Authorization": "Bearer wgmenr_nope"}]
    )
    def test_auth_runs_before_validation(
        self,
        enroll: TestClient,
        hub: int,
        kwargs: dict[str, Any],
        headers: dict[str, str],
    ) -> None:
        """An unauthenticated caller can't probe the schema via 422s.

        Whatever the body, a missing or unknown token gets the same 401
        as a well-formed request would.
        """
        baseline = enroll.post(ENROLL_PATH, json=_body(), headers=headers)
        resp = enroll.post(ENROLL_PATH, headers=headers, **kwargs)
        assert resp.status_code == 401
        assert resp.text == baseline.text
        assert resp.headers.get("www-authenticate") == "Bearer"

    def test_used_up_token_with_bad_body_is_401(
        self, enroll: TestClient, hub: int
    ) -> None:
        token = _mint(hub)
        assert enroll.post(ENROLL_PATH, json=_body(), headers=_auth(token)).status_code == 201
        resp = enroll.post(ENROLL_PATH, json={"junk": 1}, headers=_auth(token))
        assert resp.status_code == 401

    def test_malformed_json_with_valid_token_is_422(
        self, enroll: TestClient, hub: int
    ) -> None:
        token = _mint(hub)
        resp = enroll.post(ENROLL_PATH, content=b"{not json", headers=_auth(token))
        assert resp.status_code == 422
        assert _token_row().use_count == 0

    def test_rejects_non_ed25519_host_key(self, enroll: TestClient, hub: int) -> None:
        """sshd is configured with the ed25519 host cert path only."""
        rsa = generate_private_key(public_exponent=65537, key_size=2048)
        pub = rsa.public_key().public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
        ).decode()
        token = _mint(hub)
        resp = enroll.post(
            ENROLL_PATH, json=_body(ssh_host_public_key=pub), headers=_auth(token)
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Failures after the token is consumed roll it back
# ---------------------------------------------------------------------------


class TestRollback:
    def test_duplicate_name_409_keeps_token(self, enroll: TestClient, hub: int) -> None:
        first = _mint(hub)
        assert enroll.post(ENROLL_PATH, json=_body("dup"), headers=_auth(first)).status_code == 201
        second = _mint(hub)
        resp = enroll.post(ENROLL_PATH, json=_body("dup"), headers=_auth(second))
        assert resp.status_code == 409
        with Session(db_module.engine) as s:
            uses = sorted(t.use_count for t in s.exec(select(EnrollmentToken)).all())
        assert uses == [0, 1]

    def test_duplicate_wg_key_409(self, enroll: TestClient, hub: int) -> None:
        token = _mint(hub, max_uses=2)
        body = _body("one")
        assert enroll.post(ENROLL_PATH, json=body, headers=_auth(token)).status_code == 201
        again = {**_body("two"), "wg_public_key": body["wg_public_key"]}
        assert enroll.post(ENROLL_PATH, json=again, headers=_auth(token)).status_code == 409

    def test_hub_not_ready_503_keeps_token(self, enroll: TestClient, hub: int) -> None:
        token = _mint(hub)
        with Session(db_module.engine) as s:
            server = s.get(Server, hub)
            server.status = NodeStatus.pending
            s.add(server)
            s.commit()
        resp = enroll.post(ENROLL_PATH, json=_body(), headers=_auth(token))
        assert resp.status_code == 503
        assert _token_row().use_count == 0

    def test_ca_failure_502_keeps_token(
        self, enroll: TestClient, hub: int, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from wg_manager.ssh_ca import SSHCAError

        class _BrokenCA:
            ca_public_key = "ssh-ed25519 AAAA ca"

            def mint_host_cert(self, **_: Any):
                raise SSHCAError("vault sealed")

        monkeypatch.setattr(enroll_app_module, "make_ssh_ca_backend", lambda *_: _BrokenCA())
        token = _mint(hub)
        resp = enroll.post(ENROLL_PATH, json=_body(), headers=_auth(token))
        assert resp.status_code == 502
        assert "vault sealed" not in resp.text  # no backend detail leaks
        assert _token_row().use_count == 0
        with Session(db_module.engine) as s:
            assert s.exec(select(Client)).all() == []


# ---------------------------------------------------------------------------
# Principal hygiene
# ---------------------------------------------------------------------------


class TestPrincipals:
    def test_host_supplied_name_never_becomes_a_principal(
        self, enroll: TestClient, hub: int
    ) -> None:
        """A token holder claiming the hub's name must not get a host cert
        the worker would accept when dialling the hub."""
        token = _mint(hub)
        resp = enroll.post(
            ENROLL_PATH, json=_body("hub.example.com"), headers=_auth(token)
        )
        assert resp.status_code == 201
        assert resp.json()["host_cert_principals"] == ["10.9.0.2"]
