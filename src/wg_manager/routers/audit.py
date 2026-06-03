"""/audit router — Phase 2e cycle 4 read surface over ``auditevent``.

Cycles 1-3 of Phase 2e shipped the persistence side of the
application audit log: cycle 1 added the
:class:`wg_manager.models.AuditEvent` table, cycle 2 introduced
:func:`wg_manager.audit.persist` as the one seam every mutating
endpoint goes through, and cycle 3 wired the helper into the five
mutating endpoint families called out in the plan. This module is
cycle 4 — the *read* side of the same log, exposed as a single
``GET /audit`` endpoint so the dashboard's audit page (and an
auditor's ``curl`` / ``jq`` session) can render the trail.

Endpoint contract:

* ``GET /audit`` — list audit rows, newest-first. Admin / auditor
  only — same role tier ``GET /certs`` uses, because audit-log access
  is a read role above peer-management. Plain operators get 403.

Query parameters:

* ``event`` — exact match on the event slug
  (``server.create``, ``client.delete``, …).
* ``actor_cn`` — exact match on the actor's CN.
* ``resource_type`` — exact match on the resource bucket
  (``server`` / ``client`` / ``ssh_key`` / ``certificate`` /
  ``crypto``).
* ``resource_id`` — exact match on the affected row id. Combines with
  ``resource_type`` to drive the dashboard's "show me everything that
  happened to server #7" query, which is a single index scan against
  ``ix_auditevent_resource``.
* ``since`` — RFC 3339 lower bound, inclusive (``ts >= since``).
* ``until`` — RFC 3339 upper bound, exclusive (``ts < until``).
* ``limit`` (default 100, max 500) — page size.
* ``offset`` (default 0) — page offset.

The response envelope (:class:`AuditEventListResponse`) carries
``items`` + ``total`` + ``limit`` + ``offset``. ``total`` is the full
count matching the filter — not just the rows in this page — so the
dashboard can render a correct ``Showing X-Y of Z`` line and prev /
next buttons without issuing a second request.

The endpoint is deliberately read-only: the application audit log is
append-only via :func:`wg_manager.audit.persist`. There is no
``POST /audit`` — a mutation that wanted an audit entry would not be
audit at all but bookkeeping.

Module-level deps ``_get_operator`` and ``_RequireAdminOrAuditor`` are
underscored to flag "private to this router + tests"; ``test_audit_api``
overrides them the same way ``test_certs_api`` does.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func as sa_func
from sqlmodel import Session, select

from wg_manager.db import get_session
from wg_manager.models import AuditEvent, Operator, OperatorRole
from wg_manager.schemas import AuditEventListResponse, AuditEventRead

router = APIRouter(prefix="/audit", tags=["audit"])


# Hard ceiling on ``limit`` so a dashboard typo can't materialise the
# entire table in one shot. 500 is generous for an audit page — the
# dashboard reads 100 at a time — and small enough that a single
# response stays under the JSON-render budget.
_MAX_LIMIT = 500


# ---------------------------------------------------------------------------
# Role-gating deps
# ---------------------------------------------------------------------------
#
# Co-located rather than composed against ``wg_manager.auth.require_role``
# so the test suite has one stable per-router override point — same
# pattern :mod:`wg_manager.routers.certs` uses.


def _get_operator(request: Request) -> Operator:
    """Return the :class:`Operator` stashed by ``MTLSAuthMiddleware``.

    A 401 here means the request reached the handler without going
    through the middleware (TLS off and the test forgot to override
    this dep), which is operator/test error rather than a runtime
    auth failure.
    """
    operator = getattr(request.state, "operator", None)
    if operator is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="operator unknown",
        )
    return operator


def _RequireAdminOrAuditor(  # noqa: N802 — capitalised so call sites read like a type
    operator: Annotated[Operator, Depends(_get_operator)],
) -> Operator:
    """Admit :attr:`OperatorRole.admin` or :attr:`OperatorRole.auditor`.

    Plain operators (peer-management role) cannot enumerate the audit
    log — same gate ``GET /certs`` uses.
    """
    if operator.role not in (OperatorRole.admin, OperatorRole.auditor):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="role not permitted",
        )
    return operator


# ---------------------------------------------------------------------------
# Row → schema
# ---------------------------------------------------------------------------


def _row_to_read(row: AuditEvent) -> AuditEventRead:
    """Convert one :class:`AuditEvent` row into the wire-side read shape.

    The one non-trivial step is decoding the ``payload`` column — the
    persistence helper stores it as the compact-JSON string the audit
    logger line also carries, but the dashboard would parse it locally
    on receipt anyway. Doing the parse server-side keeps every consumer
    agreeing on the dict shape and means a downstream SIEM that hits
    the endpoint doesn't need its own JSON-decode pass.
    """
    payload: dict[str, Any] | None = None
    if row.payload is not None:
        payload = json.loads(row.payload)
    return AuditEventRead(
        id=row.id or 0,
        ts=row.ts,
        event=row.event,
        actor_cn=row.actor_cn,
        actor_serial=row.actor_serial,
        actor_role=row.actor_role,
        resource_type=row.resource_type,
        resource_id=row.resource_id,
        action=row.action,
        before_hash=row.before_hash,
        after_hash=row.after_hash,
        payload=payload,
        request_id=row.request_id,
    )


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@router.get("", response_model=AuditEventListResponse)
def list_audit_events(
    _: Annotated[Operator, Depends(_RequireAdminOrAuditor)],
    session: Annotated[Session, Depends(get_session)],
    event: Annotated[str | None, Query(max_length=64)] = None,
    actor_cn: Annotated[str | None, Query(max_length=255)] = None,
    resource_type: Annotated[str | None, Query(max_length=32)] = None,
    resource_id: int | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Annotated[int, Query(gt=0, le=_MAX_LIMIT)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AuditEventListResponse:
    """List audit events matching the supplied filters, newest first.

    All filter parameters are AND-combined: e.g. ``?event=server.create
    &actor_cn=alice@wg.local`` returns rows that match both. The
    ``since`` / ``until`` window is half-open (``ts >= since AND
    ts < until``) so adjacent ``since`` / ``until`` invocations don't
    double-count the boundary row.

    Pagination is offset-based rather than cursor-based — the dashboard
    surface is small enough that the cost of a count + a second select
    is comfortably below the round-trip budget, and an offset is
    easier for an auditor's ``curl`` session to walk by hand. The
    ``total`` field is the count across the whole filter so the
    dashboard can render a real ``Showing X-Y of Z`` line.

    The ordering is ``ts DESC, id DESC``: ``ts`` for the user-visible
    newest-first ordering the dashboard relies on, then ``id`` as a
    deterministic tiebreaker for rows that share the same microsecond
    timestamp (which the audit logger and DB clock can produce on a
    burst of mutations inside one HTTP handler).
    """
    base = select(AuditEvent)
    count_base = select(sa_func.count()).select_from(AuditEvent)

    if event is not None:
        base = base.where(AuditEvent.event == event)
        count_base = count_base.where(AuditEvent.event == event)
    if actor_cn is not None:
        base = base.where(AuditEvent.actor_cn == actor_cn)
        count_base = count_base.where(AuditEvent.actor_cn == actor_cn)
    if resource_type is not None:
        base = base.where(AuditEvent.resource_type == resource_type)
        count_base = count_base.where(AuditEvent.resource_type == resource_type)
    if resource_id is not None:
        base = base.where(AuditEvent.resource_id == resource_id)
        count_base = count_base.where(AuditEvent.resource_id == resource_id)
    if since is not None:
        base = base.where(AuditEvent.ts >= since)
        count_base = count_base.where(AuditEvent.ts >= since)
    if until is not None:
        base = base.where(AuditEvent.ts < until)
        count_base = count_base.where(AuditEvent.ts < until)

    total = int(session.exec(count_base).one())

    page_rows = list(
        session.exec(
            base.order_by(AuditEvent.ts.desc(), AuditEvent.id.desc())
            .limit(limit)
            .offset(offset)
        ).all()
    )

    return AuditEventListResponse(
        items=[_row_to_read(row) for row in page_rows],
        total=total,
        limit=limit,
        offset=offset,
    )


__all__ = ["router"]
