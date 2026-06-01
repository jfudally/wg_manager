"""Tests for Phase 2e cycle 2: ``wg_manager.audit`` module.

Cycle 1 (alembic 0013) landed the ``auditevent`` table; cycle 2
introduces the helper every mutating endpoint will call to populate
it. The module has three responsibilities:

1. ``audit.emit(event, **fields)`` — the existing CP5 log-only path,
   relocated out of :mod:`wg_manager.auth` so middleware,
   :mod:`wg_manager.bootstrap_ssh`, and the new ``persist`` helper all
   share one implementation. The serialised JSON shape must stay
   **byte-identical** to what :func:`wg_manager.auth._emit_audit`
   produces today — the CP5 acceptance suite and any SIEM rules
   already in flight depend on the exact format.

2. ``audit.canonical_json_hash(obj)`` — small helper that renders a
   dict as canonical JSON (sorted keys, compact separators, ``str``
   fallback for non-JSON-native types) and returns the SHA-256 hex
   digest. Returns ``None`` for ``None`` so callers can pass
   ``before=None`` on a create or ``after=None`` on a delete without
   special-casing.

3. ``audit.persist(session, ...)`` — the new write path. Inserts one
   :class:`AuditEvent` row in the caller-supplied session and emits
   the same line on the audit logger. The caller controls the
   transaction; the helper deliberately does **not** commit so the
   audit row lives or dies alongside the mutation it records.

What this module pins down:

* The new ``emit()`` produces the exact byte sequence the old
  ``_emit_audit`` did — same key order, same ``isoformat`` precision,
  same JSON separators.
* :mod:`wg_manager.auth` re-exports the old ``_emit_audit`` name so
  :mod:`wg_manager.bootstrap_ssh` (and any out-of-tree caller) keeps
  importing it unchanged.
* ``persist`` writes a row whose hashes match
  ``canonical_json_hash(before)`` / ``canonical_json_hash(after)``
  and whose other columns mirror the kwargs.
* ``persist`` emits a single audit-logger line that carries the same
  ``event`` slug, actor, resource, and hash fields the row got — so
  log-only readers see the same identity the DB row carries.
* The three legitimate row shapes from cycle 1 (create with ``before
  =None``, delete with ``after=None``, system-origin with
  ``actor_cn=None``) all round-trip cleanly through ``persist``.
* ``persist`` does not commit — the caller's transaction owns the row.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

import pytest
from sqlmodel import Session, select


# ---------------------------------------------------------------------------
# canonical_json_hash
# ---------------------------------------------------------------------------


class TestCanonicalJsonHash:
    """SHA-256 over canonical JSON; ``None`` round-trips as ``None``."""

    def test_returns_none_for_none_input(self) -> None:
        """``before=None`` on create / ``after=None`` on delete pass through."""
        from wg_manager import audit

        assert audit.canonical_json_hash(None) is None

    def test_hash_is_sha256_hex(self) -> None:
        """Output is the 64-char lowercase SHA-256 hex digest."""
        from wg_manager import audit

        h = audit.canonical_json_hash({"name": "hub-1", "address": "1.2.3.4"})
        assert isinstance(h, str)
        assert len(h) == 64
        assert h == h.lower()
        int(h, 16)  # must be valid hex

    def test_hash_is_order_independent(self) -> None:
        """Two dicts with the same content hash identically regardless of key order."""
        from wg_manager import audit

        a = audit.canonical_json_hash({"name": "hub-1", "address": "1.2.3.4"})
        b = audit.canonical_json_hash({"address": "1.2.3.4", "name": "hub-1"})
        assert a == b

    def test_hash_matches_canonical_json_sha256(self) -> None:
        """Exact byte construction: sorted keys, compact separators."""
        from wg_manager import audit

        obj = {"address": "1.2.3.4", "name": "hub-1"}
        expected = hashlib.sha256(
            json.dumps(
                obj, sort_keys=True, separators=(",", ":"), default=str
            ).encode()
        ).hexdigest()
        assert audit.canonical_json_hash(obj) == expected

    def test_handles_non_json_native_types_via_str(self) -> None:
        """``datetime`` values fall through ``default=str`` rather than raising."""
        from wg_manager import audit

        ts = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        # Must not raise.
        h = audit.canonical_json_hash({"created_at": ts, "id": 1})
        assert len(h) == 64


# ---------------------------------------------------------------------------
# emit (log-only path, byte-identical to legacy _emit_audit)
# ---------------------------------------------------------------------------


def _parse_audit_lines(records: list[logging.LogRecord]) -> list[dict]:
    """Extract + decode every ``wg_manager.audit`` JSON line in ``records``."""
    out: list[dict] = []
    for rec in records:
        if rec.name != "wg_manager.audit":
            continue
        out.append(json.loads(rec.getMessage()))
    return out


class TestEmit:
    """``emit`` produces the same JSON shape the CP5 stream already does."""

    def test_emits_one_record_on_named_logger(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """One call → one WARNING record on ``wg_manager.audit``."""
        from wg_manager import audit

        with caplog.at_level(logging.WARNING, logger="wg_manager.audit"):
            audit.emit("server.create", cn="ops@wg.local", resource_id=7)

        lines = _parse_audit_lines(caplog.records)
        assert len(lines) == 1
        assert lines[0]["event"] == "server.create"
        assert lines[0]["cn"] == "ops@wg.local"
        assert lines[0]["resource_id"] == 7
        assert "ts" in lines[0]

    def test_ts_field_is_utc_isoformat_with_microseconds(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """``ts`` is RFC-3339 UTC with microsecond precision (CP5 contract)."""
        from wg_manager import audit

        with caplog.at_level(logging.WARNING, logger="wg_manager.audit"):
            audit.emit("test.event")

        line = _parse_audit_lines(caplog.records)[0]
        # Parseable as ISO with tz, includes microseconds (hh:mm:ss.ffffff).
        parsed = datetime.fromisoformat(line["ts"])
        assert parsed.tzinfo is not None
        assert "." in line["ts"], line["ts"]

    def test_emit_output_byte_identical_to_legacy_auth_emit_audit(
        self,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``wg_manager.auth._emit_audit`` produces the same line as ``audit.emit``.

        Pin the timestamp so the two calls don't disagree on ``ts``;
        then assert the JSON bytes match exactly. Protects every CP5
        acceptance test + any SIEM rule already in flight.
        """
        from wg_manager import audit
        from wg_manager import auth as auth_mod

        fixed = datetime(2026, 6, 1, 12, 0, 0, 123456, tzinfo=timezone.utc)

        class _FrozenDateTime(datetime):
            @classmethod
            def now(cls, tz=None):  # type: ignore[override]
                return fixed if tz is None else fixed.astimezone(tz)

        monkeypatch.setattr(audit, "datetime", _FrozenDateTime)
        monkeypatch.setattr(auth_mod, "datetime", _FrozenDateTime)

        with caplog.at_level(logging.WARNING, logger="wg_manager.audit"):
            audit.emit("auth.admit", cn="ops@wg.local", serial="123")
            auth_mod._emit_audit("auth.admit", cn="ops@wg.local", serial="123")

        msgs = [r.getMessage() for r in caplog.records if r.name == "wg_manager.audit"]
        assert len(msgs) == 2, msgs
        assert msgs[0] == msgs[1], (
            "audit.emit and auth._emit_audit must produce byte-identical lines"
        )

    def test_auth_module_reexports_emit_audit_for_backcompat(self) -> None:
        """``from wg_manager.auth import _emit_audit`` keeps working.

        :mod:`wg_manager.bootstrap_ssh` imports the symbol this way;
        the re-export keeps existing call sites unchanged when the
        implementation moves into :mod:`wg_manager.audit`.
        """
        from wg_manager.auth import _emit_audit

        assert callable(_emit_audit)


# ---------------------------------------------------------------------------
# persist (DB + log)
# ---------------------------------------------------------------------------


def _kwargs(**overrides: Any) -> dict[str, Any]:
    """Default kwargs for ``persist`` — overrides win."""
    base: dict[str, Any] = {
        "event": "server.create",
        "actor_cn": "ops@wg.local",
        "actor_serial": "12345",
        "actor_role": "admin",
        "resource_type": "server",
        "resource_id": 7,
        "action": "create",
        "before": None,
        "after": {"name": "hub-1", "address": "10.9.0.1"},
        "payload": {"name": "hub-1"},
        "request_id": "req-abc",
    }
    base.update(overrides)
    return base


class TestPersist:
    """``persist`` writes one row + emits one matching audit line."""

    def test_writes_audit_event_row(self, session: Session) -> None:
        """Row lands in the session with the kwarg-shaped fields."""
        from wg_manager import audit
        from wg_manager.models import AuditEvent

        audit.persist(session, **_kwargs())
        session.flush()

        rows = session.exec(select(AuditEvent)).all()
        assert len(rows) == 1
        row = rows[0]
        assert row.event == "server.create"
        assert row.actor_cn == "ops@wg.local"
        assert row.actor_serial == "12345"
        assert row.actor_role == "admin"
        assert row.resource_type == "server"
        assert row.resource_id == 7
        assert row.action == "create"
        assert row.request_id == "req-abc"

    def test_hashes_before_and_after_via_canonical_json(
        self, session: Session
    ) -> None:
        """``before_hash`` / ``after_hash`` match ``canonical_json_hash``."""
        from wg_manager import audit
        from wg_manager.models import AuditEvent

        before = {"name": "hub-1", "address": "10.9.0.1"}
        after = {"name": "hub-1", "address": "10.9.0.2"}

        audit.persist(session, **_kwargs(before=before, after=after))
        session.flush()

        row = session.exec(select(AuditEvent)).one()
        assert row.before_hash == audit.canonical_json_hash(before)
        assert row.after_hash == audit.canonical_json_hash(after)

    def test_create_event_leaves_before_hash_null(
        self, session: Session
    ) -> None:
        """``before=None`` (create) → ``before_hash`` column is NULL."""
        from wg_manager import audit
        from wg_manager.models import AuditEvent

        audit.persist(session, **_kwargs(before=None, after={"id": 1}))
        session.flush()

        row = session.exec(select(AuditEvent)).one()
        assert row.before_hash is None
        assert row.after_hash is not None

    def test_delete_event_leaves_after_hash_null(
        self, session: Session
    ) -> None:
        """``after=None`` (delete) → ``after_hash`` column is NULL."""
        from wg_manager import audit
        from wg_manager.models import AuditEvent

        audit.persist(
            session,
            **_kwargs(event="client.delete", action="delete",
                     before={"id": 1}, after=None),
        )
        session.flush()

        row = session.exec(select(AuditEvent)).one()
        assert row.before_hash is not None
        assert row.after_hash is None

    def test_system_origin_event_persists_null_actor(
        self, session: Session
    ) -> None:
        """``actor_cn=None`` (system origin) round-trips as NULL."""
        from wg_manager import audit
        from wg_manager.models import AuditEvent

        audit.persist(
            session,
            **_kwargs(
                event="crypto.rotate",
                actor_cn=None,
                actor_serial=None,
                actor_role=None,
                resource_type="crypto",
                resource_id=None,
                action="rotate",
                before=None,
                after=None,
            ),
        )
        session.flush()

        row = session.exec(select(AuditEvent)).one()
        assert row.actor_cn is None
        assert row.actor_serial is None
        assert row.actor_role is None
        assert row.resource_id is None

    def test_payload_serialised_as_compact_json(
        self, session: Session
    ) -> None:
        """``payload`` lands as a compact JSON string."""
        from wg_manager import audit
        from wg_manager.models import AuditEvent

        audit.persist(session, **_kwargs(payload={"name": "hub-1", "id": 7}))
        session.flush()

        row = session.exec(select(AuditEvent)).one()
        assert row.payload is not None
        decoded = json.loads(row.payload)
        assert decoded == {"name": "hub-1", "id": 7}
        # Compact: no extra whitespace.
        assert ", " not in row.payload
        assert ": " not in row.payload

    def test_payload_none_persists_null(self, session: Session) -> None:
        """``payload=None`` → column is NULL, not the JSON literal ``"null"``."""
        from wg_manager import audit
        from wg_manager.models import AuditEvent

        audit.persist(session, **_kwargs(payload=None))
        session.flush()

        row = session.exec(select(AuditEvent)).one()
        assert row.payload is None

    def test_emits_matching_audit_logger_line(
        self,
        session: Session,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """``persist`` writes a row AND emits one line carrying the same identity."""
        from wg_manager import audit

        with caplog.at_level(logging.WARNING, logger="wg_manager.audit"):
            audit.persist(session, **_kwargs())

        lines = _parse_audit_lines(caplog.records)
        assert len(lines) == 1, lines
        line = lines[0]
        assert line["event"] == "server.create"
        assert line["actor_cn"] == "ops@wg.local"
        assert line["resource_type"] == "server"
        assert line["resource_id"] == 7
        assert line["action"] == "create"
        assert line["request_id"] == "req-abc"
        # The hashes carried in the log line match the row's hashes.
        assert line["after_hash"] == audit.canonical_json_hash(
            {"name": "hub-1", "address": "10.9.0.1"}
        )
        assert "before_hash" in line  # null on create, but the key is present

    def test_does_not_commit(self, session: Session) -> None:
        """The caller's transaction owns the row — ``persist`` only flushes."""
        from wg_manager import audit
        from wg_manager.models import AuditEvent

        audit.persist(session, **_kwargs())
        # Roll back without committing — the row must disappear.
        session.rollback()

        rows = session.exec(select(AuditEvent)).all()
        assert rows == [], (
            "persist must not commit; rollback should drop the audit row"
        )
