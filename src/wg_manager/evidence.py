"""SOC 2-style evidence pack builder for Phase 2e cycle 4.

The pack collects four sources into a single tar.gz an auditor can
verify against:

1. ``audit_events.json`` — the MySQL ``auditevent`` table filtered to
   the last N days, the wg-manager-internal mutation audit trail.
2. ``certificates.json`` — the ``certificate`` table dump, full
   inventory (live + revoked). No date filter because a SOC 2 pack
   wants the current authoritative cert state.
3. ``operators.json`` — the ``operator`` registry dump. Same
   reasoning: an auditor wants the current admins / operators /
   auditors, not a historical slice.
4. ``vault_audit.log`` — the Vault audit log file (default
   ``/vault/logs/audit.log``) sliced to the last N days, alongside
   ``vault_audit_integrity.json`` reporting structural integrity
   (each line valid JSON, has a ``time`` field, ``request`` and
   ``response`` records pair up by ``request.id``).

Plus:

* ``system.json`` — deployment context (wg-manager version, git
  commit, alembic head). The "what was running when these events
  were captured" snapshot.
* ``MANIFEST.md`` — operator-facing index, one line per file.
* ``SHA256SUMS`` — gnu-coreutils-shape file enumerating per-file
  sha256 so the tarball is internally self-verifying.

Vault's audit log is **not cryptographically chained** record-to-
record — the ``hash`` fields inside each record are per-field HMAC
redaction of sensitive values, not a hash chain across lines. The
integrity check this module emits is therefore **structural**:
JSON-parseability, time-field presence, and request/response
pairing. This is documented in ``vault_audit_integrity.json``'s
``method`` field so an auditor reading the pack knows exactly what
guarantee they are looking at.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import tarfile
from collections import Counter
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlmodel import Session, select

from wg_manager.models import AuditEvent, Certificate, Operator

_PACK_VERSION = 1

# The seven files an evidence pack contains. Centralised here so the
# MANIFEST writer + the SHA256SUMS writer + the tests stay in lockstep.
_ARTIFACT_DESCRIPTIONS: dict[str, str] = {
    "audit_events.json": (
        "Application mutation audit log from the MySQL ``auditevent`` "
        "table, filtered to the last N days. One row per "
        "create/update/delete/revoke/rotate event on a managed "
        "resource (server / client / sshkey / certificate / crypto)."
    ),
    "certificates.json": (
        "Full ``certificate`` table dump (live + revoked). Each row "
        "carries serial / CN / SANs / type / validity window / "
        "revocation flag — no PEM material."
    ),
    "operators.json": (
        "Full ``operator`` registry dump (active + disabled). One "
        "row per registered admin / operator / auditor."
    ),
    "vault_audit.log": (
        "Vault audit log file (default ``/vault/logs/audit.log``) "
        "sliced to the last N days by parsing each line's ``time`` "
        "field. One JSON object per line, same shape Vault writes."
    ),
    "vault_audit_integrity.json": (
        "Structural integrity report over the included Vault audit "
        "log slice. Vault does NOT ship cryptographic chain across "
        "records — this report counts lines, malformed JSON, missing "
        "``time`` fields, and unpaired request/response records."
    ),
    "system.json": (
        "Deployment context: wg-manager version, git commit, alembic "
        "head revision, the since-days window applied to the time-"
        "filtered files."
    ),
    "MANIFEST.md": (
        "This file — operator-facing index of the pack."
    ),
    "SHA256SUMS": (
        "GNU coreutils-shape SHA-256 line per other file. Verify with "
        "``sha256sum -c SHA256SUMS`` after extraction."
    ),
}


# ---------------------------------------------------------------------------
# Source dumpers
# ---------------------------------------------------------------------------


def dump_audit_events(session: Session, since_days: int) -> dict[str, Any]:
    """Return the AuditEvent table filtered to ``ts >= now - since_days``."""
    threshold = _utcnow() - timedelta(days=since_days)
    rows = session.exec(
        select(AuditEvent).where(AuditEvent.ts >= threshold).order_by(AuditEvent.ts)
    ).all()
    return {
        "since_days": since_days,
        "generated_at": _utcnow().isoformat(),
        "row_count": len(rows),
        "rows": [
            {
                "id": r.id,
                "ts": r.ts.isoformat() if r.ts else None,
                "event": r.event,
                "actor_cn": r.actor_cn,
                "actor_role": r.actor_role,
                "resource_type": r.resource_type,
                "resource_id": r.resource_id,
                "action": r.action,
                "before_hash": r.before_hash,
                "after_hash": r.after_hash,
                "request_id": r.request_id,
                "payload": r.payload,
            }
            for r in rows
        ],
    }


def dump_certificates(session: Session) -> dict[str, Any]:
    """Return the full Certificate table dump."""
    rows = session.exec(select(Certificate).order_by(Certificate.id)).all()
    return {
        "generated_at": _utcnow().isoformat(),
        "row_count": len(rows),
        "rows": [
            {
                "id": r.id,
                "serial": r.serial,
                "cert_type": r.cert_type.value if r.cert_type else None,
                "common_name": r.common_name,
                "sans": r.sans,
                "operator_id": r.operator_id,
                "not_before": r.not_before.isoformat() if r.not_before else None,
                "not_after": r.not_after.isoformat() if r.not_after else None,
                "revoked": r.revoked,
                "revoked_at": r.revoked_at.isoformat() if r.revoked_at else None,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "out_cert_path": r.out_cert_path,
                "out_key_path": r.out_key_path,
                "out_chain_path": r.out_chain_path,
            }
            for r in rows
        ],
    }


def dump_operators(session: Session) -> dict[str, Any]:
    """Return the full Operator table dump."""
    rows = session.exec(select(Operator).order_by(Operator.id)).all()
    return {
        "generated_at": _utcnow().isoformat(),
        "row_count": len(rows),
        "rows": [
            {
                "id": r.id,
                "cn": r.cn,
                "role": r.role.value if r.role else None,
                "status": r.status.value if r.status else None,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
    }


# ---------------------------------------------------------------------------
# Vault audit log slice + integrity
# ---------------------------------------------------------------------------


def slice_vault_audit_log(
    path: Path, since_days: int
) -> tuple[str, dict[str, Any]]:
    """Return ``(sliced_text, integrity_report)``.

    ``sliced_text`` keeps lines whose ``time`` field parses and falls
    within the last ``since_days`` days. ``integrity_report`` records
    structural integrity counts so an auditor reading the pack knows
    whether the slice is trustworthy.

    Missing file → empty slice + ``ok=False`` with ``reason="missing"``.
    """
    if not path.is_file():
        return "", {
            "ok": False,
            "reason": "missing: vault audit log file not found at the "
            f"configured path ({path})",
            "method": "structural",
            "lines": 0,
            "malformed": 0,
            "unpaired": 0,
            "checked_at": _utcnow().isoformat(),
        }

    threshold = _utcnow() - timedelta(days=since_days)
    kept_lines: list[str] = []
    request_ids: Counter[str] = Counter()
    malformed = 0
    missing_time = 0
    total = 0

    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not raw.strip():
            continue
        total += 1
        try:
            record = json.loads(raw)
        except json.JSONDecodeError:
            malformed += 1
            continue

        time_str = record.get("time")
        if not isinstance(time_str, str):
            missing_time += 1
            continue

        # Vault uses RFC3339 with trailing Z; Python expects either +00:00
        # or no offset. Normalise the trailing Z → +00:00.
        normalised = time_str.replace("Z", "+00:00")
        try:
            line_time = datetime.fromisoformat(normalised)
        except ValueError:
            missing_time += 1
            continue

        if line_time < threshold:
            # Time-filtered out; do *not* count as integrity issue,
            # the line is just outside the window.
            _maybe_track_request_id(record, request_ids)
            continue

        kept_lines.append(raw)
        _maybe_track_request_id(record, request_ids)

    unpaired = sum(1 for count in request_ids.values() if count % 2 != 0)
    ok = malformed == 0 and missing_time == 0 and unpaired == 0
    report: dict[str, Any] = {
        "ok": ok,
        "method": (
            "structural: per-line JSON parseability + ``time`` field "
            "presence + request/response ``request.id`` pairing. Vault "
            "does NOT ship cryptographic chain across records."
        ),
        "lines": total,
        "kept_lines": len(kept_lines),
        "malformed": malformed,
        "missing_time": missing_time,
        "unpaired": unpaired,
        "checked_at": _utcnow().isoformat(),
    }
    return "\n".join(kept_lines), report


def _maybe_track_request_id(record: dict[str, Any], counter: Counter[str]) -> None:
    """Bump the ``request.id`` counter for pairing detection."""
    req = record.get("request")
    if isinstance(req, dict):
        rid = req.get("id")
        if isinstance(rid, str) and rid:
            counter[rid] += 1


# ---------------------------------------------------------------------------
# System info
# ---------------------------------------------------------------------------


def collect_system_info(since_days: int) -> dict[str, Any]:
    """Return deployment context (version, commit, alembic head, ...)."""
    return {
        "generated_at": _utcnow().isoformat(),
        "since_days": since_days,
        "wg_manager_version": _wg_manager_version(),
        "git_commit": _git_commit(),
        "alembic_head": _alembic_head(),
        "pack_version": _PACK_VERSION,
    }


def _wg_manager_version() -> str:
    """Read the installed wg_manager version, fall back to ``unknown``."""
    try:
        from importlib.metadata import version

        return version("wg-manager")
    except Exception:  # noqa: BLE001 — never let version-lookup crash the pack
        return "unknown"


def _git_commit() -> str:
    """Return the short HEAD commit, or ``unknown`` if git isn't available."""
    try:
        result = subprocess.run(  # noqa: S603,S607
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return "unknown"


def _alembic_head() -> str:
    """Read the on-disk alembic head revision, or ``unknown``."""
    # Read by inspecting the migrations directory rather than running
    # alembic — keeps the evidence-pack call hermetic.
    try:
        repo_root = Path(__file__).resolve().parents[2]
        versions_dir = repo_root / "alembic" / "versions"
        if not versions_dir.is_dir():
            return "unknown"
        # The head is whichever revision has no "down_revision" pointing
        # at it. Simplest heuristic: highest-prefixed file (alembic
        # revisions are prefixed by integer in this repo's convention).
        files = sorted(versions_dir.glob("*.py"))
        if not files:
            return "unknown"
        # Filename pattern in this repo: ``NNNN_short_label.py``.
        return files[-1].stem
    except Exception:  # noqa: BLE001
        return "unknown"


# ---------------------------------------------------------------------------
# Pack assembly
# ---------------------------------------------------------------------------


def build_pack(
    output: Path,
    *,
    session: Session,
    since_days: int,
    vault_audit_log: Path,
    pack_dir_name: str | None = None,
) -> Path:
    """Assemble all sources into a tar.gz at ``output``.

    The tarball contains a single top-level directory named
    ``pack_dir_name`` (default: ``evidence-pack-<utc-iso-z>``) holding
    the seven artifact files. Returns the output path for convenience.
    """
    dir_name = pack_dir_name or _default_pack_dir_name()

    audit = dump_audit_events(session, since_days)
    certs = dump_certificates(session)
    ops = dump_operators(session)
    sliced_log, integrity = slice_vault_audit_log(vault_audit_log, since_days)
    system = collect_system_info(since_days)

    files: dict[str, bytes] = {
        "audit_events.json": json.dumps(audit, indent=2, sort_keys=True).encode("utf-8"),
        "certificates.json": json.dumps(certs, indent=2, sort_keys=True).encode("utf-8"),
        "operators.json": json.dumps(ops, indent=2, sort_keys=True).encode("utf-8"),
        "vault_audit.log": sliced_log.encode("utf-8"),
        "vault_audit_integrity.json": json.dumps(
            integrity, indent=2, sort_keys=True
        ).encode("utf-8"),
        "system.json": json.dumps(system, indent=2, sort_keys=True).encode("utf-8"),
    }

    # MANIFEST.md + SHA256SUMS layer on top of the core files. The
    # MANIFEST hashes itself excluded (circular); SHA256SUMS excludes
    # itself for the same reason.
    manifest_body = _build_manifest(files, since_days, dir_name).encode("utf-8")
    files["MANIFEST.md"] = manifest_body

    sha_body = _build_sha256sums(files).encode("utf-8")
    files["SHA256SUMS"] = sha_body

    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output, "w:gz") as tar:
        for name, payload in files.items():
            info = tarfile.TarInfo(name=f"{dir_name}/{name}")
            info.size = len(payload)
            info.mtime = int(_utcnow().timestamp())
            tar.addfile(info, io.BytesIO(payload))

    return output


def _build_manifest(
    files: dict[str, bytes], since_days: int, dir_name: str
) -> str:
    """Operator-facing MANIFEST.md inventory."""
    lines = [
        f"# Evidence pack — {dir_name}",
        "",
        "SOC 2-style evidence pack generated by `wg-manager evidence pack`.",
        f"Last {since_days} days of audit events; full cert + operator "
        "inventory.",
        "",
        "## Files",
        "",
    ]
    for name, desc in _ARTIFACT_DESCRIPTIONS.items():
        if name in files or name in ("MANIFEST.md", "SHA256SUMS"):
            lines.append(f"- **`{name}`** — {desc}")
    lines.extend(
        [
            "",
            "## Verification",
            "",
            "After extracting, verify the contents have not been tampered "
            "with:",
            "",
            "```bash",
            "cd " + dir_name,
            "sha256sum -c SHA256SUMS",
            "```",
            "",
            "Every entry should report `OK`. A mismatch means the pack was "
            "modified after generation.",
            "",
            "## Vault audit-log integrity scope",
            "",
            "`vault_audit_integrity.json` reports **structural** integrity "
            "only (per-line JSON parseability, `time` field presence, "
            "request/response `request.id` pairing). Vault does not ship a "
            "cryptographic chain across audit records — see "
            "[`docs/runbooks/backup-restore.md`](../docs/runbooks/backup-restore.md) "
            "and [`docs/vault-cookbook.md`](../docs/vault-cookbook.md) §6 "
            "for the operator-side guarantees you actually have.",
        ]
    )
    return "\n".join(lines) + "\n"


def _build_sha256sums(files: dict[str, bytes]) -> str:
    """gnu-coreutils-shape SHA256SUMS — one line per file, sorted by name."""
    lines: list[str] = []
    for name in sorted(files):
        if name == "SHA256SUMS":
            continue  # don't hash ourself
        digest = hashlib.sha256(files[name]).hexdigest()
        lines.append(f"{digest}  {name}")
    return "\n".join(lines) + "\n"


def _default_pack_dir_name() -> str:
    """Timestamped pack directory name — ``evidence-pack-<iso-utc-z>``."""
    ts = _utcnow().strftime("%Y%m%dT%H%M%SZ")
    return f"evidence-pack-{ts}"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


__all__ = [
    "build_pack",
    "collect_system_info",
    "dump_audit_events",
    "dump_certificates",
    "dump_operators",
    "slice_vault_audit_log",
]
