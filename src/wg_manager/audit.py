"""Application audit log — emission helpers + DB persistence.

Phase 2d CP5 introduced the audit *stream*: every admission decision
the mTLS middleware makes (admit / reject) and every host bootstrap
event lands as a one-line JSON record on the ``wg_manager.audit``
named logger. The CP5 acceptance suite reads that stream off a live
uvicorn process's stderr; a production deployment can ship the same
lines off-host without touching this module by attaching a separate
handler (file, syslog, SIEM) to the named logger via
``logging.config``.

Phase 2e cycle 1 added the persisted-mutations counterpart: the
``auditevent`` table backs the upcoming ``/audit`` endpoint and
dashboard page. Cycle 2 — this module — is the single seam every
audit-emitting call site goes through. Three things live here:

* :func:`emit` — log-only. Used by the middleware (every request) and
  by :mod:`wg_manager.bootstrap_ssh` (every install). Identical byte
  output to the CP5 contract — same key order, same ``isoformat``
  precision, same JSON separators.

* :func:`canonical_json_hash` — sorted-key, compact-separator
  rendering of a dict, then SHA-256 hex. ``None`` passes through to
  ``None`` so callers can hand ``before=None`` on a create or
  ``after=None`` on a delete without special-casing.

* :func:`persist` — DB + log. The path mutating endpoints will use in
  cycle 3 onward. Inserts one :class:`AuditEvent` row in the
  caller-supplied session and emits the same identity on the audit
  logger. **Does not commit** — the caller's transaction owns the row
  so an audit failure rolls back the mutation it would have recorded
  (and vice versa).

The module is import-cheap by design: middleware and bootstrap code
in Phase 2d already import :mod:`wg_manager.auth`, and after cycle 2
that module re-exports :data:`_emit_audit` from here so nothing has
to change at the call site. The DB import (``AuditEvent``) is local
to :func:`persist` because the log-only path must not pay the SQLModel
import cost on every middleware call.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover — typing only
    from fastapi import Request
    from sqlmodel import Session

    from wg_manager.models import AuditEvent


# ---------------------------------------------------------------------------
# Logger handle
# ---------------------------------------------------------------------------

# Phase 2d CP5 — dedicated audit logger. Every admission decision the
# middleware makes (admit / reject) emits a one-line JSON record here.
# Logging at WARNING level means the record shows up in default-config
# uvicorn stderr without any extra setup, which is the visible-from-
# outside contract the CP5 acceptance suite relies on. A production
# deployment can attach a separate handler (file, syslog, SIEM) by
# adding a ``logging.config`` entry for the ``wg_manager.audit``
# logger name without touching this module.
audit_logger = logging.getLogger("wg_manager.audit")


# ---------------------------------------------------------------------------
# Log-only emission
# ---------------------------------------------------------------------------


def emit(event: str, **fields: Any) -> None:
    """Emit a structured one-line JSON record on the audit logger.

    The record always carries ``event`` and ``ts`` (RFC 3339 UTC); the
    caller adds the request-shape fields (``cn``, ``serial``,
    ``method``, ``path``, ``reason``, etc.). Serialised with
    ``separators=(",", ":")`` so the line stays on a single newline-
    terminated row — easy for ``grep`` / ``jq`` and easy to assert on
    from the CP5 acceptance tests. Non-JSON-native types (e.g.
    ``datetime``) fall through to ``str`` rather than raising at log
    time; the choice favours observability over strict typing.

    The byte output is **pinned by test** to match the legacy
    ``wg_manager.auth._emit_audit`` so any SIEM rules wired up against
    the CP5 stream keep parsing cleanly when the implementation moves
    here.
    """
    record: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
        "event": event,
        **fields,
    }
    audit_logger.warning(json.dumps(record, separators=(",", ":"), default=str))


# ---------------------------------------------------------------------------
# Canonical-JSON hashing
# ---------------------------------------------------------------------------


def canonical_json_hash(obj: dict[str, Any] | None) -> str | None:
    """Return the SHA-256 hex digest of ``obj`` rendered as canonical JSON.

    "Canonical" here means sorted keys + compact separators + ``str``
    fallback for non-JSON-native values, so two equivalent dicts
    hash identically regardless of insertion order. ``None`` returns
    ``None`` so callers can pass ``before=None`` on a create event or
    ``after=None`` on a delete event without special-casing.

    Used by :func:`persist` to derive :class:`AuditEvent.before_hash`
    and :class:`AuditEvent.after_hash` — the hash-only design keeps
    the audit table safe to ship in backups while still proving "the
    row had these exact contents at this moment" for any future audit
    review.

    :param obj: Dict to hash, or ``None``.
    :return: 64-character lowercase hex SHA-256 digest, or ``None``.
    """
    if obj is None:
        return None
    body = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Actor extraction
# ---------------------------------------------------------------------------


def actor_from_request(request: "Request") -> dict[str, str | None]:
    """Build the ``actor_*`` kwargs for :func:`persist` from a FastAPI request.

    Reads :attr:`MTLSAuthMiddleware`'s two stash points off
    ``request.state`` — ``operator`` (the registry row) and
    ``cert_subject`` (the parsed cert). Both are populated for every
    cert-bearing request in production; both are ``None`` in
    ``TLS_REQUIRED=false`` mode (the default for the test suite),
    which lets endpoints call ``persist(**actor_from_request(request))``
    without branching for the test path.

    The serial is rendered as a decimal string to match
    :attr:`Certificate.serial`'s storage convention — X.509 160-bit
    serials overflow signed-INT64 and Vault's serials regularly do
    too, so the column is :class:`String(64)` everywhere.

    :param request: The incoming FastAPI :class:`Request`.
    :return: ``{"actor_cn", "actor_serial", "actor_role"}`` dict —
        each value is the populated string or ``None``.
    """
    operator = getattr(request.state, "operator", None)
    subject = getattr(request.state, "cert_subject", None)
    return {
        "actor_cn": operator.cn if operator is not None else None,
        "actor_serial": str(subject.serial) if subject is not None else None,
        "actor_role": (
            operator.role.value if operator is not None else None
        ),
    }


# ---------------------------------------------------------------------------
# DB + log persistence
# ---------------------------------------------------------------------------


def persist(
    session: "Session",
    *,
    event: str,
    actor_cn: str | None,
    actor_serial: str | None,
    actor_role: str | None,
    resource_type: str,
    resource_id: int | None,
    action: str,
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
    payload: dict[str, Any] | None = None,
    request_id: str | None = None,
    tenant_id: int | None = None,
) -> "AuditEvent":
    """Insert one :class:`AuditEvent` row + emit the matching log line.

    The caller's session owns the transaction: ``persist`` flushes so
    the row gets an ``id`` for the return value but never commits.
    That way an audit failure rolls back the mutation it would have
    recorded — and a mutation that ultimately fails rolls back the
    audit row alongside it. Endpoints call ``persist`` inside the same
    ``with Session(...) as session`` block they use for the mutation.

    The audit logger line carries the same identity the row does
    (event, actor, resource, action, both hashes, request id), so a
    log-only consumer sees the persistence happen even without
    querying the database.

    :param session: The active SQLModel session.
    :param event: Slug of the form ``<resource>.<action>``
        (``server.create``, ``client.delete``, ``crypto.rotate``).
    :param actor_cn: CN from the operator's mTLS cert, or ``None`` for
        system-origin events.
    :param actor_serial: Cert serial as decimal string; ``None`` for
        system-origin events.
    :param actor_role: :class:`OperatorRole` value at action time;
        ``None`` for system-origin events.
    :param resource_type: Coarse bucket (``server`` / ``client`` /
        ``ssh_key`` / ``certificate`` / ``crypto``).
    :param resource_id: Row id of the affected resource, or ``None``
        for global-scope events.
    :param action: Verb (``create`` / ``update`` / ``delete`` /
        ``revoke`` / ``rotate``).
    :param before: Pre-mutation row as a dict, or ``None`` on create.
    :param after: Post-mutation row as a dict, or ``None`` on delete.
    :param payload: Optional compact summary dict — stripped of
        secret material by the caller before being handed in.
        Persisted as compact JSON (``Text``).
    :param request_id: Correlation ID lifted from the request, or a
        ``uuid4`` for system-origin events.
    :return: The flushed :class:`AuditEvent` row (with ``id``).
    """
    # Local import: keeps the log-only path import-cheap, and avoids
    # a circular import with :mod:`wg_manager.models` once the model
    # imports start pulling more of the package in.
    from wg_manager.models import AuditEvent

    before_hash = canonical_json_hash(before)
    after_hash = canonical_json_hash(after)
    payload_blob: str | None = (
        json.dumps(payload, separators=(",", ":"), default=str)
        if payload is not None
        else None
    )

    row = AuditEvent(
        event=event,
        actor_cn=actor_cn,
        actor_serial=actor_serial,
        actor_role=actor_role,
        resource_type=resource_type,
        resource_id=resource_id,
        action=action,
        before_hash=before_hash,
        after_hash=after_hash,
        payload=payload_blob,
        request_id=request_id,
        tenant_id=tenant_id,
    )
    session.add(row)
    session.flush()

    emit(
        event,
        actor_cn=actor_cn,
        actor_serial=actor_serial,
        actor_role=actor_role,
        resource_type=resource_type,
        resource_id=resource_id,
        action=action,
        before_hash=before_hash,
        after_hash=after_hash,
        request_id=request_id,
        tenant_id=tenant_id,
    )
    return row
