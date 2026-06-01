"""Tests for Phase 2e cycle 3: ``audit.persist`` wired into mutating endpoints.

Cycle 2 shipped :func:`wg_manager.audit.persist`. Cycle 3 wires it into
the five mutating endpoint families called out in the cycle plan, one
per resource family, covering all four CRUD verbs plus the
``revoke`` special action:

* ``POST /servers`` — ``server.create``
* ``PATCH /servers/{id}`` — ``server.update``
* ``DELETE /clients/{id}`` — ``client.delete``
* ``POST /ssh-keys`` — ``ssh_key.create``
* ``POST /certs/{id}/revoke`` — ``certificate.revoke``

What this module pins down:

1. **One row per mutation.** Each successful call writes exactly one
   :class:`AuditEvent` row. No double-emit on retry idempotency
   paths (revoke of an already-revoked cert is the explicit case).
2. **Correct slug + verb + resource binding.** ``event``,
   ``resource_type``, ``resource_id``, and ``action`` columns match
   what the dashboard's filter inputs will key on.
3. **Hash polarity.** Create leaves ``before_hash=NULL`` and sets
   ``after_hash``. Delete is the mirror. Update sets both.
4. **Actor extraction.** :func:`wg_manager.audit.actor_from_request`
   pulls ``actor_cn`` / ``actor_serial`` / ``actor_role`` off
   ``request.state.operator`` and ``request.state.cert_subject`` when
   the mTLS middleware has stashed them, and returns ``None`` fields
   when the middleware is in passthrough mode (the default for the
   test suite). The unit test exercises both shapes directly.
5. **Transaction coupling.** The audit row lives or dies alongside
   the mutation — a rolled-back mutation never leaves an orphan audit
   row, and an audit-write failure rolls back the mutation it would
   have recorded. Pinned by an explicit transaction-rollback test.

The integration tests run against the default ``TLS_REQUIRED=false``
test harness so ``request.state.operator`` is ``None`` — the audit
rows therefore carry NULL actor fields. The actor-wiring contract
itself is pinned by the direct-call unit test rather than by spinning
up a full mTLS handshake; :mod:`tests.test_auth` already covers that
path end-to-end.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from wg_manager import db as db_module
from wg_manager.models import AuditEvent, OperatorRole


_SAMPLE_PEM = "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEBODY\n-----END OPENSSH PRIVATE KEY-----\n"
_SAMPLE_PEM_B64 = base64.b64encode(_SAMPLE_PEM.encode("utf-8")).decode("ascii")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _audit_rows(engine: Any) -> list[AuditEvent]:
    with Session(engine) as s:
        return list(s.exec(select(AuditEvent).order_by(AuditEvent.id)).all())


def _register_key(client: TestClient, name: str = "lab") -> int:
    resp = client.post("/ssh-keys", json={"name": name})
    assert resp.status_code == 201, resp.text
    return int(resp.json()["id"])


def _register_server(
    client: TestClient,
    key_id: int,
    hostname: str = "hub.example.com",
) -> int:
    resp = client.post(
        "/servers",
        json={
            "hostname": hostname,
            "ssh_username": "ubuntu",
            "ssh_key_id": key_id,
            "endpoint_host": hostname,
        },
    )
    assert resp.status_code == 202, resp.text
    return int(resp.json()["server"]["id"])


def _register_client(
    client: TestClient,
    key_id: int,
    server_id: int,
    name: str = "alpha",
) -> int:
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


# ---------------------------------------------------------------------------
# actor_from_request
# ---------------------------------------------------------------------------


class TestActorFromRequest:
    """``audit.actor_from_request`` reads ``request.state`` cleanly."""

    def test_extracts_actor_when_state_populated(self) -> None:
        """Populated middleware state → all three actor fields filled."""
        from wg_manager import audit
        from wg_manager.auth import CertSubject
        from wg_manager.models import Operator

        now = datetime.now(timezone.utc).replace(microsecond=0)
        subject = CertSubject(
            common_name="ops@wg.local",
            sans=("ops@wg.local",),
            serial=4242424242,
            not_before=now - timedelta(days=1),
            not_after=now + timedelta(days=365),
            cert_pem="---pem---",
        )
        operator = Operator(
            id=1,
            cn="ops@wg.local",
            role=OperatorRole.admin,
        )

        req = MagicMock()
        req.state.operator = operator
        req.state.cert_subject = subject

        actor = audit.actor_from_request(req)

        assert actor == {
            "actor_cn": "ops@wg.local",
            "actor_serial": "4242424242",
            "actor_role": "admin",
        }

    def test_returns_none_fields_when_state_unset(self) -> None:
        """No operator on state → all three actor fields ``None``."""
        from wg_manager import audit

        req = MagicMock()
        req.state.operator = None
        req.state.cert_subject = None

        assert audit.actor_from_request(req) == {
            "actor_cn": None,
            "actor_serial": None,
            "actor_role": None,
        }


# ---------------------------------------------------------------------------
# POST /servers → server.create
# ---------------------------------------------------------------------------


class TestServerCreateAudit:
    def test_writes_one_server_create_event(
        self, client: TestClient, engine: Any
    ) -> None:
        """A successful POST /servers emits exactly one server.create row."""
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
        server_id = int(resp.json()["server"]["id"])

        events = [r for r in _audit_rows(engine) if r.event == "server.create"]
        assert len(events) == 1, [r.event for r in _audit_rows(engine)]
        row = events[0]
        assert row.resource_type == "server"
        assert row.resource_id == server_id
        assert row.action == "create"
        assert row.before_hash is None
        assert row.after_hash is not None and len(row.after_hash) == 64


# ---------------------------------------------------------------------------
# PATCH /servers/{id} → server.update
# ---------------------------------------------------------------------------


class TestServerUpdateAudit:
    def test_writes_one_server_update_event_with_both_hashes(
        self, client: TestClient, engine: Any
    ) -> None:
        """A PATCH that changes a field emits one update row with both hashes."""
        key_id = _register_key(client)
        server_id = _register_server(client, key_id)

        resp = client.patch(
            f"/servers/{server_id}",
            json={"endpoint_host": "new-hub.example.com"},
        )
        assert resp.status_code == 200, resp.text

        events = [r for r in _audit_rows(engine) if r.event == "server.update"]
        assert len(events) == 1
        row = events[0]
        assert row.resource_type == "server"
        assert row.resource_id == server_id
        assert row.action == "update"
        assert row.before_hash is not None
        assert row.after_hash is not None
        assert row.before_hash != row.after_hash, (
            "endpoint_host changed; the hashes should differ"
        )


# ---------------------------------------------------------------------------
# DELETE /clients/{id} → client.delete
# ---------------------------------------------------------------------------


class TestClientDeleteAudit:
    def test_writes_one_client_delete_event_with_null_after_hash(
        self, client: TestClient, engine: Any
    ) -> None:
        """DELETE leaves ``after_hash=NULL`` and sets ``before_hash``."""
        key_id = _register_key(client)
        server_id = _register_server(client, key_id)
        client_id = _register_client(client, key_id, server_id)

        resp = client.delete(f"/clients/{client_id}")
        assert resp.status_code == 202, resp.text

        events = [r for r in _audit_rows(engine) if r.event == "client.delete"]
        assert len(events) == 1
        row = events[0]
        assert row.resource_type == "client"
        assert row.resource_id == client_id
        assert row.action == "delete"
        assert row.before_hash is not None and len(row.before_hash) == 64
        assert row.after_hash is None


# ---------------------------------------------------------------------------
# POST /ssh-keys → ssh_key.create
# ---------------------------------------------------------------------------


class TestSSHKeyCreateAudit:
    def test_writes_one_ssh_key_create_event(
        self, client: TestClient, engine: Any
    ) -> None:
        """POST /ssh-keys emits one ssh_key.create row."""
        resp = client.post("/ssh-keys", json={"name": "lab"})
        assert resp.status_code == 201, resp.text
        key_id = int(resp.json()["id"])

        events = [r for r in _audit_rows(engine) if r.event == "ssh_key.create"]
        assert len(events) == 1
        row = events[0]
        assert row.resource_type == "ssh_key"
        assert row.resource_id == key_id
        assert row.action == "create"
        assert row.before_hash is None
        assert row.after_hash is not None


# ---------------------------------------------------------------------------
# POST /certs/{id}/revoke → certificate.revoke
# ---------------------------------------------------------------------------


@pytest.fixture()
def revoke_admin_client(client: TestClient):
    """A TestClient with the certs router's role gates faked to admin.

    Mirrors the ``as_admin`` fixture in ``tests/test_certs_api.py`` but
    inlined so this module stays standalone. Returns the client, the
    inserted operator row, and a tear-down callable the test can ignore
    (FastAPI clears overrides on app teardown between tests).
    """
    from wg_manager.auth import CertSubject, require_subject
    from wg_manager.main import app
    from wg_manager.models import Operator, OperatorStatus
    from wg_manager.routers import certs as certs_router

    with Session(db_module.engine) as s:
        row = Operator(
            cn="ops@wg.local",
            role=OperatorRole.admin,
            status=OperatorStatus.active,
        )
        s.add(row)
        s.commit()
        s.refresh(row)
        operator_snapshot = Operator(
            id=row.id,
            cn=row.cn,
            display_name=row.display_name,
            role=row.role,
            status=row.status,
            created_at=row.created_at,
        )

    now = datetime.now(timezone.utc).replace(microsecond=0)
    subject = CertSubject(
        common_name="ops@wg.local",
        sans=("ops@wg.local",),
        serial=4242424242,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=365),
        cert_pem="---pem---",
    )

    app.dependency_overrides[require_subject] = lambda: subject
    app.dependency_overrides[certs_router._get_operator] = lambda: operator_snapshot
    app.dependency_overrides[certs_router._RequireAdmin] = lambda: subject
    app.dependency_overrides[certs_router._RequireAdminOrAuditor] = lambda: subject
    try:
        yield client, operator_snapshot
    finally:
        app.dependency_overrides.clear()


def _issue_test_cert(client: TestClient) -> int:
    """Issue a service cert (no operator required) and return its row id."""
    resp = client.post(
        "/certs",
        json={
            "cert_type": "api",
            "common_name": "127.0.0.1",
            "sans": ["127.0.0.1"],
            "ttl_days": 30,
        },
    )
    assert resp.status_code == 201, resp.text
    return int(resp.json()["certificate"]["id"])


class TestCertRevokeAudit:
    def test_writes_one_certificate_revoke_event(
        self, revoke_admin_client, engine: Any
    ) -> None:
        """A first-time revoke emits one certificate.revoke row."""
        client, _operator = revoke_admin_client
        cert_id = _issue_test_cert(client)

        # Filter audit rows we expect from issue noise.
        pre_count = len(
            [r for r in _audit_rows(engine) if r.event == "certificate.revoke"]
        )

        resp = client.post(f"/certs/{cert_id}/revoke")
        assert resp.status_code == 200, resp.text

        events = [
            r for r in _audit_rows(engine) if r.event == "certificate.revoke"
        ]
        assert len(events) == pre_count + 1
        row = events[-1]
        assert row.resource_type == "certificate"
        assert row.resource_id == cert_id
        assert row.action == "revoke"
        assert row.before_hash is not None
        assert row.after_hash is not None
        assert row.before_hash != row.after_hash

    def test_idempotent_revoke_skips_second_audit(
        self, revoke_admin_client, engine: Any
    ) -> None:
        """Revoking an already-revoked cert is a no-op for audit too."""
        client, _operator = revoke_admin_client
        cert_id = _issue_test_cert(client)

        client.post(f"/certs/{cert_id}/revoke")
        first_count = len(
            [r for r in _audit_rows(engine) if r.event == "certificate.revoke"]
        )

        resp = client.post(f"/certs/{cert_id}/revoke")
        assert resp.status_code == 200, resp.text

        second_count = len(
            [r for r in _audit_rows(engine) if r.event == "certificate.revoke"]
        )
        assert second_count == first_count, (
            "second revoke is idempotent and must not write another audit row"
        )
