"""Phase 3f MVP — minting enrollment tokens over the mTLS operator API.

``POST /v1/enrollment-tokens`` is admin-only (per-tenant admin on the
hub's tenant, or super-admin). It returns the plaintext token exactly
once, stores only its SHA-256, and writes an audit row that doesn't
contain the token.
"""

from __future__ import annotations

import hashlib
from datetime import timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from wg_manager import db as db_module
from wg_manager.enrollment import as_utc, generate_token, hash_token
from wg_manager.main import app
from wg_manager.models import (
    AuditEvent,
    EnrollmentToken,
    NodeStatus,
    OperatorRole,
    Server,
    SSHKey,
    Tenant,
)
from wg_manager.tenant_scope import TenantScope, get_tenant_scope

URL = "/v1/enrollment-tokens"


def _seed(status: NodeStatus = NodeStatus.ready, tenant_id: int = 1) -> tuple[int, int]:
    """Insert an SSH key + hub directly; return ``(ssh_key_id, server_id)``."""
    with Session(db_module.engine) as s:
        if s.get(Tenant, tenant_id) is None:
            s.add(Tenant(id=tenant_id, name=f"t{tenant_id}", slug=f"t{tenant_id}"))
            s.commit()
        key = SSHKey(name=f"ops-{tenant_id}", tenant_id=tenant_id)
        s.add(key)
        s.commit()
        s.refresh(key)
        hub = Server(
            hostname="hub.example.com",
            ssh_username="ubuntu",
            ssh_key_id=key.id,
            endpoint_host="hub.example.com",
            public_key="HUBPUB=",
            status=status,
            tenant_id=tenant_id,
            subnet=f"10.{tenant_id}.0.0/24",
            address=f"10.{tenant_id}.0.1/24",
        )
        s.add(hub)
        s.commit()
        s.refresh(hub)
        return int(key.id or 0), int(hub.id or 0)


def _body(key_id: int, server_id: int, **extra: Any) -> dict[str, Any]:
    return {"server_id": server_id, "ssh_key_id": key_id,
            "ssh_username": "ubuntu", **extra}


@pytest.fixture()
def scoped():
    """Pin the caller's tenant scope for one test; always cleaned up."""
    def _set(scope: TenantScope) -> None:
        app.dependency_overrides[get_tenant_scope] = lambda: scope
    yield _set
    app.dependency_overrides.pop(get_tenant_scope, None)


class TestTokenPrimitives:
    def test_generated_tokens_are_prefixed_unique_and_high_entropy(self) -> None:
        tokens = {generate_token() for _ in range(50)}
        assert len(tokens) == 50
        for t in tokens:
            assert t.startswith("wgmenr_")
            assert len(t) >= 7 + 43  # 32 random bytes, urlsafe-b64

    def test_hash_is_sha256_hex(self) -> None:
        assert hash_token("abc") == hashlib.sha256(b"abc").hexdigest()

    def test_as_utc_attaches_tz_to_naive(self) -> None:
        from datetime import datetime, timezone

        naive = datetime(2026, 1, 1, 12, 0)
        assert as_utc(naive).tzinfo is timezone.utc


class TestMintHappyPath:
    def test_returns_plaintext_once_and_stores_only_hash(
        self, client: TestClient
    ) -> None:
        key_id, server_id = _seed()
        resp = client.post(URL, json=_body(key_id, server_id))
        assert resp.status_code == 201, resp.text
        body = resp.json()
        token = body["token"]
        assert token.startswith("wgmenr_")
        assert body["server_id"] == server_id
        assert body["max_uses"] == 1
        assert body["tenant_id"] == 1

        with Session(db_module.engine) as s:
            row = s.exec(select(EnrollmentToken)).one()
            assert row.token_hash == hash_token(token)
            assert token not in repr(row)
            assert row.ssh_username == "ubuntu"
            assert row.name_prefix == "node"
            assert row.use_count == 0

    def test_ttl_and_uses_are_honoured(self, client: TestClient) -> None:
        key_id, server_id = _seed()
        resp = client.post(
            URL, json=_body(key_id, server_id, ttl_seconds=600, max_uses=5,
                            name_prefix="web")
        )
        assert resp.status_code == 201, resp.text
        with Session(db_module.engine) as s:
            row = s.exec(select(EnrollmentToken)).one()
            window = as_utc(row.expires_at) - as_utc(row.created_at)
            assert timedelta(seconds=595) < window <= timedelta(seconds=605)
            assert row.max_uses == 5
            assert row.name_prefix == "web"

    def test_audit_row_written_without_token(self, client: TestClient) -> None:
        key_id, server_id = _seed()
        token = client.post(URL, json=_body(key_id, server_id)).json()["token"]
        with Session(db_module.engine) as s:
            events = s.exec(
                select(AuditEvent).where(AuditEvent.event == "enrollment_token.create")
            ).all()
        assert len(events) == 1
        assert events[0].resource_type == "enrollment_token"
        assert token not in (events[0].payload or "")
        assert hash_token(token) not in (events[0].payload or "")


class TestMintValidation:
    @pytest.mark.parametrize(
        "extra",
        [
            {"ttl_seconds": 59},
            {"ttl_seconds": 7 * 86400 + 1},
            {"max_uses": 0},
            {"max_uses": 101},
            {"name_prefix": "Bad_Prefix"},
            {"name_prefix": "-leading"},
            {"ssh_username": "root; rm -rf /"},
        ],
    )
    def test_rejects_out_of_range_fields(
        self, client: TestClient, extra: dict[str, Any]
    ) -> None:
        key_id, server_id = _seed()
        resp = client.post(URL, json=_body(key_id, server_id, **extra))
        assert resp.status_code == 422, extra

    def test_unknown_server_404(self, client: TestClient) -> None:
        key_id, _ = _seed()
        assert client.post(URL, json=_body(key_id, 999)).status_code == 404

    def test_unknown_ssh_key_404(self, client: TestClient) -> None:
        _, server_id = _seed()
        assert client.post(URL, json=_body(999, server_id)).status_code == 404

    def test_hub_not_ready_400(self, client: TestClient) -> None:
        key_id, server_id = _seed(status=NodeStatus.pending)
        assert client.post(URL, json=_body(key_id, server_id)).status_code == 400

    def test_ssh_key_from_other_tenant_400(self, client: TestClient) -> None:
        """The management identity must belong to the hub's tenant."""
        _, server_id = _seed(tenant_id=1)
        other_key, _ = _seed(tenant_id=2)
        resp = client.post(URL, json=_body(other_key, server_id))
        assert resp.status_code == 400


class TestMintAuthorization:
    def test_tenant_operator_forbidden(self, client: TestClient, scoped) -> None:
        key_id, server_id = _seed()
        scoped(TenantScope(is_super_admin=False, tenant_ids=(1,),
                           tenant_roles={1: OperatorRole.operator}))
        assert client.post(URL, json=_body(key_id, server_id)).status_code == 403

    def test_tenant_admin_allowed(self, client: TestClient, scoped) -> None:
        key_id, server_id = _seed()
        scoped(TenantScope(is_super_admin=False, tenant_ids=(1,),
                           tenant_roles={1: OperatorRole.admin}))
        assert client.post(URL, json=_body(key_id, server_id)).status_code == 201

    def test_admin_of_other_tenant_forbidden(
        self, client: TestClient, scoped
    ) -> None:
        key_id, server_id = _seed(tenant_id=1)
        _seed(tenant_id=2)
        scoped(TenantScope(is_super_admin=False, tenant_ids=(2,),
                           tenant_roles={2: OperatorRole.admin}))
        assert client.post(URL, json=_body(key_id, server_id)).status_code == 403

    def test_not_on_enroll_listener(self) -> None:
        """Minting is an operator action; it must never be reachable
        from the cert-optional enrollment port."""
        from wg_manager.enroll_app import create_enroll_app

        tc = TestClient(create_enroll_app())
        assert tc.post(URL, json={}).status_code == 404


# ---------------------------------------------------------------------------
# List + revoke (Phase 3f hardening)
# ---------------------------------------------------------------------------


def _mint_via_api(client: TestClient, key_id: int, server_id: int, **extra: Any) -> int:
    resp = client.post(URL, json=_body(key_id, server_id, **extra))
    assert resp.status_code == 201, resp.text
    return int(resp.json()["id"])


def _set_row(token_id: int, **values: Any) -> None:
    with Session(db_module.engine) as s:
        row = s.get(EnrollmentToken, token_id)
        for k, v in values.items():
            setattr(row, k, v)
        s.commit()


class TestList:
    def test_lists_tokens_without_secrets(self, client: TestClient) -> None:
        key_id, server_id = _seed()
        token_id = _mint_via_api(client, key_id, server_id, max_uses=3)
        resp = client.get(URL)
        assert resp.status_code == 200, resp.text
        [item] = resp.json()
        assert item["id"] == token_id
        assert item["server_id"] == server_id
        assert item["tenant_id"] == 1
        assert item["max_uses"] == 3
        assert item["use_count"] == 0
        assert item["status"] == "active"
        assert item["revoked_at"] is None
        assert "token" not in item
        assert "token_hash" not in item

    def test_status_reflects_expiry_uses_and_revocation(
        self, client: TestClient
    ) -> None:
        from datetime import datetime, timezone

        key_id, server_id = _seed()
        ids = [_mint_via_api(client, key_id, server_id) for _ in range(4)]
        past = datetime.now(timezone.utc) - timedelta(seconds=1)
        _set_row(ids[1], expires_at=past)
        _set_row(ids[2], use_count=1)
        _set_row(ids[3], revoked_at=datetime.now(timezone.utc))
        statuses = {i["id"]: i["status"] for i in client.get(URL).json()}
        assert statuses == {
            ids[0]: "active",
            ids[1]: "expired",
            ids[2]: "exhausted",
            ids[3]: "revoked",
        }

    def test_newest_first(self, client: TestClient) -> None:
        key_id, server_id = _seed()
        ids = [_mint_via_api(client, key_id, server_id) for _ in range(3)]
        assert [i["id"] for i in client.get(URL).json()] == ids[::-1]

    def test_active_filter(self, client: TestClient) -> None:
        from datetime import datetime, timezone

        key_id, server_id = _seed()
        live = _mint_via_api(client, key_id, server_id)
        dead = _mint_via_api(client, key_id, server_id)
        _set_row(dead, revoked_at=datetime.now(timezone.utc))
        assert [i["id"] for i in client.get(URL, params={"active": True}).json()] == [live]

    def test_server_filter(self, client: TestClient) -> None:
        key_a, hub_a = _seed(tenant_id=1)
        key_b, hub_b = _seed(tenant_id=2)
        _mint_via_api(client, key_a, hub_a)
        b = _mint_via_api(client, key_b, hub_b)
        assert [i["id"] for i in client.get(URL, params={"server_id": hub_b}).json()] == [b]

    def test_tenant_admin_sees_only_own_tenant(self, client: TestClient, scoped) -> None:
        key1, hub1 = _seed(tenant_id=1)
        key2, hub2 = _seed(tenant_id=2)
        mine = _mint_via_api(client, key1, hub1)
        _mint_via_api(client, key2, hub2)
        scoped(TenantScope(is_super_admin=False, tenant_ids=(1,),
                           tenant_roles={1: OperatorRole.admin}))
        assert [i["id"] for i in client.get(URL).json()] == [mine]

    def test_non_admin_sees_nothing(self, client: TestClient, scoped) -> None:
        """Tokens are admin objects, like minting."""
        key_id, server_id = _seed()
        _mint_via_api(client, key_id, server_id)
        scoped(TenantScope(is_super_admin=False, tenant_ids=(1,),
                           tenant_roles={1: OperatorRole.operator}))
        assert client.get(URL).json() == []


class TestRevoke:
    def test_revokes_and_audits(self, client: TestClient) -> None:
        key_id, server_id = _seed()
        token_id = _mint_via_api(client, key_id, server_id)
        resp = client.post(f"{URL}/{token_id}/revoke")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "revoked"
        assert body["revoked_at"] is not None
        with Session(db_module.engine) as s:
            events = s.exec(
                select(AuditEvent).where(AuditEvent.event == "enrollment_token.revoke")
            ).all()
        assert len(events) == 1
        assert events[0].resource_id == token_id

    def test_idempotent(self, client: TestClient) -> None:
        key_id, server_id = _seed()
        token_id = _mint_via_api(client, key_id, server_id)
        first = client.post(f"{URL}/{token_id}/revoke").json()
        second = client.post(f"{URL}/{token_id}/revoke")
        assert second.status_code == 200
        assert second.json()["revoked_at"] == first["revoked_at"]
        with Session(db_module.engine) as s:
            events = s.exec(
                select(AuditEvent).where(AuditEvent.event == "enrollment_token.revoke")
            ).all()
        assert len(events) == 1

    def test_unknown_404(self, client: TestClient) -> None:
        assert client.post(f"{URL}/999/revoke").status_code == 404

    def test_tenant_operator_forbidden(self, client: TestClient, scoped) -> None:
        key_id, server_id = _seed()
        token_id = _mint_via_api(client, key_id, server_id)
        scoped(TenantScope(is_super_admin=False, tenant_ids=(1,),
                           tenant_roles={1: OperatorRole.operator}))
        assert client.post(f"{URL}/{token_id}/revoke").status_code == 403

    def test_admin_of_other_tenant_forbidden(self, client: TestClient, scoped) -> None:
        key_id, server_id = _seed(tenant_id=1)
        _seed(tenant_id=2)
        token_id = _mint_via_api(client, key_id, server_id)
        scoped(TenantScope(is_super_admin=False, tenant_ids=(2,),
                           tenant_roles={2: OperatorRole.admin}))
        assert client.post(f"{URL}/{token_id}/revoke").status_code == 403

    def test_not_on_enroll_listener(self) -> None:
        from wg_manager.enroll_app import create_enroll_app

        tc = TestClient(create_enroll_app())
        assert tc.get(URL).status_code == 404
        assert tc.post(f"{URL}/1/revoke").status_code == 404
