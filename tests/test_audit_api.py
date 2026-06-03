"""Tests for Phase 2e cycle 4: read-only ``GET /audit`` endpoint.

Cycles 1-3 shipped the table, the :func:`wg_manager.audit.persist`
helper, and wired the helper into five mutating endpoints. Cycle 4
exposes the rows over HTTP so the dashboard can render them. The
endpoint is intentionally narrow:

* **Read-only.** No POST / PATCH / DELETE — the audit log is append-
  only, owned by :func:`wg_manager.audit.persist`. The HTTP surface
  is the dashboard's (and an auditor's CLI session's) one-way view
  into that log.
* **Newest-first, paginated.** Default ordering is ``ts DESC, id DESC``
  so the table reads top-down. ``limit`` caps the response size
  (default 100, max 500); ``offset`` walks the pages.
* **Filterable.** Five exact-match filters cover the question the
  dashboard's "show me everything that happened to server #7" search
  has to answer in one round-trip: ``event``, ``actor_cn``,
  ``resource_type``, ``resource_id``, plus a ``since`` / ``until`` time
  window.
* **Role-gated.** Admin and auditor only. A plain operator gets 403
  via the same ``_RequireAdminOrAuditor`` dep ``GET /certs`` uses —
  audit-log access is a read tier above peer-management.

The response envelope carries ``items`` + ``total`` + ``limit`` +
``offset`` rather than a bare list so the dashboard can render a
correct ``Showing X-Y of Z`` line without a second request. ``payload``
is decoded back to a dict (rather than left as the compact-JSON
string :class:`AuditEvent` stores) for client convenience — the
dashboard would have to parse it anyway, and centralising the parse
keeps every consumer agreeing on the shape.

Conftest defaults to ``TLS_REQUIRED=false`` so production
:class:`MTLSAuthMiddleware` is in passthrough mode; we exercise the
role gate by overriding the router-level deps the same way
``test_certs_api`` does.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from wg_manager import db as db_module
from wg_manager.auth import CertSubject, require_subject
from wg_manager.main import app
from wg_manager.models import (
    AuditEvent,
    Operator,
    OperatorRole,
    OperatorStatus,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_subject(cn: str) -> CertSubject:
    """Build a CertSubject suitable for dependency-override use."""
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return CertSubject(
        common_name=cn,
        sans=(cn,),
        serial=4242424242,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=365),
        cert_pem=f"---fake-pem-for-{cn}---",
    )


def _insert_operator(
    cn: str,
    role: OperatorRole = OperatorRole.admin,
    status: OperatorStatus = OperatorStatus.active,
) -> Operator:
    """Insert an Operator and return a detached snapshot.

    Mirrors the snapshot shape ``MTLSAuthMiddleware._resolve_operator``
    parks on ``request.state`` — session-free so handlers reading it
    after the session has closed don't trigger a lazy-load.
    """
    with Session(db_module.engine) as session:
        row = Operator(cn=cn, role=role, status=status)
        session.add(row)
        session.commit()
        session.refresh(row)
        return Operator(
            id=row.id,
            cn=row.cn,
            display_name=row.display_name,
            role=row.role,
            status=row.status,
            created_at=row.created_at,
        )


def _override_auth(
    *,
    operator: Operator,
    role_deps: Iterable[Any] = (),
) -> None:
    """Patch the router's auth deps so the request looks authenticated."""
    canned = _make_subject(operator.cn)
    app.dependency_overrides[require_subject] = lambda: canned
    from wg_manager.routers import audit as audit_router

    app.dependency_overrides[audit_router._get_operator] = lambda: operator
    for dep in role_deps:
        app.dependency_overrides[dep] = lambda: canned


@pytest.fixture()
def as_admin(client: TestClient) -> tuple[TestClient, Operator]:
    """``client`` wrapped so every request sees an admin operator."""
    from wg_manager.routers import audit as audit_router

    operator = _insert_operator("ops@wg.local", role=OperatorRole.admin)
    _override_auth(
        operator=operator,
        role_deps=(audit_router._RequireAdminOrAuditor,),
    )
    return client, operator


@pytest.fixture()
def as_auditor(client: TestClient) -> tuple[TestClient, Operator]:
    """``client`` for an auditor — read-only access (which suffices here)."""
    from wg_manager.routers import audit as audit_router

    operator = _insert_operator("audit@wg.local", role=OperatorRole.auditor)
    _override_auth(
        operator=operator,
        role_deps=(audit_router._RequireAdminOrAuditor,),
    )
    return client, operator


@pytest.fixture()
def as_operator(client: TestClient) -> tuple[TestClient, Operator]:
    """``client`` for a plain operator — neither admin nor auditor.

    The role-gated dep is intentionally NOT overridden so the production
    role check raises 403.
    """
    operator = _insert_operator("user@wg.local", role=OperatorRole.operator)
    canned = _make_subject(operator.cn)
    app.dependency_overrides[require_subject] = lambda: canned
    from wg_manager.routers import audit as audit_router

    app.dependency_overrides[audit_router._get_operator] = lambda: operator
    return client, operator


def _seed_audit_row(
    *,
    ts: datetime,
    event: str = "server.create",
    actor_cn: str | None = "ops@wg.local",
    actor_serial: str | None = "4242424242",
    actor_role: str | None = "admin",
    resource_type: str = "server",
    resource_id: int | None = 1,
    action: str = "create",
    before_hash: str | None = None,
    after_hash: str | None = "a" * 64,
    payload: dict[str, Any] | None = None,
    request_id: str | None = "req-1",
) -> AuditEvent:
    """Insert one :class:`AuditEvent` straight into the test DB.

    Bypasses :func:`wg_manager.audit.persist` so the test pins the
    endpoint's filter/pagination shape independently of the persistence
    path (which has its own coverage in ``test_audit_persist``).
    """
    row = AuditEvent(
        ts=ts,
        event=event,
        actor_cn=actor_cn,
        actor_serial=actor_serial,
        actor_role=actor_role,
        resource_type=resource_type,
        resource_id=resource_id,
        action=action,
        before_hash=before_hash,
        after_hash=after_hash,
        payload=(
            json.dumps(payload, separators=(",", ":"))
            if payload is not None
            else None
        ),
        request_id=request_id,
    )
    with Session(db_module.engine) as session:
        session.add(row)
        session.commit()
        session.refresh(row)
        return row


# ---------------------------------------------------------------------------
# Role gating
# ---------------------------------------------------------------------------


class TestRoleGating:
    """``GET /audit`` is admin / auditor only; plain operators 403."""

    def test_admin_can_list(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        resp = client.get("/audit")
        assert resp.status_code == 200, resp.text

    def test_auditor_can_list(
        self, as_auditor: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_auditor
        resp = client.get("/audit")
        assert resp.status_code == 200, resp.text

    def test_plain_operator_is_forbidden(
        self, as_operator: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_operator
        resp = client.get("/audit")
        assert resp.status_code == 403, resp.text


# ---------------------------------------------------------------------------
# Empty / shape
# ---------------------------------------------------------------------------


class TestResponseShape:
    """The envelope and per-row shape the dashboard renders against."""

    def test_empty_list_returns_envelope(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        resp = client.get("/audit")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body == {
            "items": [],
            "total": 0,
            "limit": 100,
            "offset": 0,
        }

    def test_row_shape_mirrors_audit_event(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        ts = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        row = _seed_audit_row(
            ts=ts,
            event="server.create",
            payload={"hostname": "hub.example.com"},
        )

        body = client.get("/audit").json()
        assert body["total"] == 1
        (item,) = body["items"]
        assert item["id"] == row.id
        assert item["event"] == "server.create"
        assert item["actor_cn"] == "ops@wg.local"
        assert item["actor_serial"] == "4242424242"
        assert item["actor_role"] == "admin"
        assert item["resource_type"] == "server"
        assert item["resource_id"] == 1
        assert item["action"] == "create"
        assert item["before_hash"] is None
        assert item["after_hash"] == "a" * 64
        # Payload comes back as a parsed dict, not the raw compact-JSON
        # string the column stores. The dashboard would have to parse
        # it anyway; centralising the parse keeps every consumer
        # agreeing on the shape.
        assert item["payload"] == {"hostname": "hub.example.com"}
        assert item["request_id"] == "req-1"
        # ts comes back as an ISO string parseable round-trip
        assert isinstance(item["ts"], str)
        assert "2026-06-01" in item["ts"]

    def test_payload_null_round_trips_as_none(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        ts = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        _seed_audit_row(ts=ts, payload=None)
        (item,) = client.get("/audit").json()["items"]
        assert item["payload"] is None


# ---------------------------------------------------------------------------
# Ordering
# ---------------------------------------------------------------------------


class TestOrdering:
    """Newest first so the dashboard table reads top-down."""

    def test_newest_first(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        base = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        oldest = _seed_audit_row(ts=base, event="server.create")
        middle = _seed_audit_row(
            ts=base + timedelta(hours=1), event="client.delete"
        )
        newest = _seed_audit_row(
            ts=base + timedelta(hours=2), event="ssh_key.create"
        )

        items = client.get("/audit").json()["items"]
        assert [i["id"] for i in items] == [newest.id, middle.id, oldest.id]


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------


class TestFilters:
    """Filter inputs the dashboard wires to ``?event=`` / ``?actor_cn=`` / …"""

    def test_filter_by_event_slug(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        base = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        target = _seed_audit_row(ts=base, event="server.create")
        _seed_audit_row(ts=base + timedelta(minutes=1), event="client.delete")

        body = client.get("/audit", params={"event": "server.create"}).json()
        assert body["total"] == 1
        assert [i["id"] for i in body["items"]] == [target.id]

    def test_filter_by_actor_cn(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        base = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        target = _seed_audit_row(ts=base, actor_cn="alice@wg.local")
        _seed_audit_row(
            ts=base + timedelta(minutes=1), actor_cn="bob@wg.local"
        )

        body = client.get(
            "/audit", params={"actor_cn": "alice@wg.local"}
        ).json()
        assert body["total"] == 1
        assert [i["id"] for i in body["items"]] == [target.id]

    def test_filter_by_resource_type_and_id(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        base = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        target = _seed_audit_row(
            ts=base, resource_type="server", resource_id=7
        )
        # Same id, different type — must NOT match.
        _seed_audit_row(
            ts=base + timedelta(minutes=1),
            resource_type="client",
            resource_id=7,
        )
        # Same type, different id — must NOT match.
        _seed_audit_row(
            ts=base + timedelta(minutes=2),
            resource_type="server",
            resource_id=8,
        )

        body = client.get(
            "/audit",
            params={"resource_type": "server", "resource_id": 7},
        ).json()
        assert body["total"] == 1
        assert [i["id"] for i in body["items"]] == [target.id]

    def test_filter_by_resource_type_only(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        base = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        a = _seed_audit_row(
            ts=base, resource_type="server", resource_id=1
        )
        b = _seed_audit_row(
            ts=base + timedelta(minutes=1),
            resource_type="server",
            resource_id=2,
        )
        _seed_audit_row(
            ts=base + timedelta(minutes=2),
            resource_type="client",
            resource_id=1,
        )

        body = client.get("/audit", params={"resource_type": "server"}).json()
        assert body["total"] == 2
        assert sorted(i["id"] for i in body["items"]) == sorted(
            [a.id, b.id]
        )

    def test_filter_by_time_window(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        base = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        # too old
        _seed_audit_row(ts=base, event="server.create")
        # in window
        inside = _seed_audit_row(
            ts=base + timedelta(hours=2), event="server.update"
        )
        # too new
        _seed_audit_row(
            ts=base + timedelta(hours=5), event="client.delete"
        )

        since = (base + timedelta(hours=1)).isoformat()
        until = (base + timedelta(hours=3)).isoformat()
        body = client.get(
            "/audit", params={"since": since, "until": until}
        ).json()
        assert body["total"] == 1
        assert [i["id"] for i in body["items"]] == [inside.id]

    def test_combined_filters_intersect(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        base = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        target = _seed_audit_row(
            ts=base,
            event="server.create",
            actor_cn="alice@wg.local",
            resource_type="server",
            resource_id=7,
        )
        # Same actor, different resource
        _seed_audit_row(
            ts=base + timedelta(minutes=1),
            event="client.delete",
            actor_cn="alice@wg.local",
            resource_type="client",
            resource_id=7,
        )
        # Same resource, different actor
        _seed_audit_row(
            ts=base + timedelta(minutes=2),
            event="server.update",
            actor_cn="bob@wg.local",
            resource_type="server",
            resource_id=7,
        )

        body = client.get(
            "/audit",
            params={
                "event": "server.create",
                "actor_cn": "alice@wg.local",
                "resource_type": "server",
                "resource_id": 7,
            },
        ).json()
        assert body["total"] == 1
        assert [i["id"] for i in body["items"]] == [target.id]


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------


class TestPagination:
    """``limit`` + ``offset`` walk the filtered result set."""

    def test_default_limit_is_100(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        body = client.get("/audit").json()
        assert body["limit"] == 100
        assert body["offset"] == 0

    def test_limit_caps_returned_rows_total_stays_full_count(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        base = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        for i in range(5):
            _seed_audit_row(ts=base + timedelta(minutes=i))

        body = client.get("/audit", params={"limit": 2}).json()
        assert body["total"] == 5  # full count
        assert body["limit"] == 2
        assert len(body["items"]) == 2

    def test_offset_walks_pages(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        base = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        rows = [_seed_audit_row(ts=base + timedelta(minutes=i)) for i in range(5)]
        # newest first → rows[4] then rows[3] then rows[2] ...
        page1 = client.get("/audit", params={"limit": 2, "offset": 0}).json()
        page2 = client.get("/audit", params={"limit": 2, "offset": 2}).json()
        page3 = client.get("/audit", params={"limit": 2, "offset": 4}).json()

        assert [i["id"] for i in page1["items"]] == [rows[4].id, rows[3].id]
        assert [i["id"] for i in page2["items"]] == [rows[2].id, rows[1].id]
        assert [i["id"] for i in page3["items"]] == [rows[0].id]
        for p in (page1, page2, page3):
            assert p["total"] == 5

    def test_limit_zero_is_rejected(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        resp = client.get("/audit", params={"limit": 0})
        assert resp.status_code == 422

    def test_limit_above_max_is_rejected(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        """500 is the documented ceiling so a dashboard mistype can't
        materialise the whole table in one shot."""
        client, _ = as_admin
        resp = client.get("/audit", params={"limit": 501})
        assert resp.status_code == 422

    def test_negative_offset_is_rejected(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        resp = client.get("/audit", params={"offset": -1})
        assert resp.status_code == 422
