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
