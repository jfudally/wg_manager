"""Tests for Phase 2e cycle 4 — `wg-manager evidence pack` SOC 2 tarball.

Cycle 4 closes the ROADMAP Phase 2e stretch acceptance bullet:

    A SOC 2-style "evidence pack" is generatable via `make evidence` —
    pulls last 30 days of audit logs, current cert inventory, and
    Vault audit hash chain into a tarball.

The implementation ships as `wg-manager evidence pack --output PATH
--since-days N --vault-audit-log PATH`. It collects four sources:

1. The MySQL ``auditevent`` table filtered to the last N days.
2. The ``certificate`` table — full, live + revoked, no date filter
   because a SOC 2 pack wants the current authoritative state.
3. The ``operator`` registry — full, same reason.
4. The Vault audit log file (default ``/vault/logs/audit.log``),
   sliced to the last N days by parsing each line's ``time`` field,
   plus an integrity check (each line is valid JSON, has a ``time``
   field, ``request`` and ``response`` records pair up by
   ``request.id``).

Plus a system-info snapshot (alembic head, Transit key version,
PKI/SSH-CA roles, wg-manager version, git commit) and a
``MANIFEST.md`` with per-file SHA-256 so the tarball is internally
self-verifying.

These tests pin the on-disk shape of the tarball, the since-days
filter behaviour, the graceful handling of a missing Vault audit
log, and the integrity verification's failure shape. Hermetic — no
Vault needed because the tests feed a synthetic audit log file via
the ``--vault-audit-log`` flag.
"""

from __future__ import annotations

import hashlib
import json
import tarfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from sqlmodel import Session
from typer.testing import CliRunner

from wg_manager import cli
from wg_manager import db as db_module
from wg_manager.models import (
    AuditEvent,
    Certificate,
    CertificateType,
    Operator,
    OperatorRole,
    OperatorStatus,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def evidence_env(
    engine: Any,  # noqa: ARG001 — installs schema on db_module.engine
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wire ``cli._get_engine`` to the in-memory test engine."""
    monkeypatch.setattr(cli, "_get_engine", lambda url=None: db_module.engine)


def _utc(year: int, month: int, day: int, hour: int = 0, minute: int = 0) -> datetime:
    return datetime(year, month, day, hour, minute, tzinfo=timezone.utc)


def _seed_audit_events(rows: list[tuple[str, datetime]]) -> None:
    """Insert AuditEvent rows; ``rows`` is a list of (event, ts) tuples."""
    with Session(db_module.engine) as session:
        for event, ts in rows:
            session.add(
                AuditEvent(
                    ts=ts,
                    event=event,
                    actor_cn="ops@example.com",
                    actor_role="admin",
                    resource_type="server",
                    resource_id=1,
                    action="update",
                    payload="{}",
                    request_id=f"req-{event}",
                )
            )
        session.commit()


def _seed_certificates(rows: list[tuple[str, str]]) -> None:
    """Insert Certificate rows; ``rows`` is (cn, serial) tuples."""
    with Session(db_module.engine) as session:
        for cn, serial in rows:
            now = datetime.now(timezone.utc)
            session.add(
                Certificate(
                    serial=serial,
                    cert_type=CertificateType.api,
                    common_name=cn,
                    sans=cn,
                    not_before=now,
                    not_after=now + timedelta(days=30),
                )
            )
        session.commit()


def _seed_operators(rows: list[str]) -> None:
    """Insert Operator rows by CN."""
    with Session(db_module.engine) as session:
        for cn in rows:
            session.add(
                Operator(cn=cn, role=OperatorRole.admin, status=OperatorStatus.active)
            )
        session.commit()


def _vault_line(time_iso: str, op: str, req_id: str, type_: str = "request") -> str:
    """Build one Vault-shape audit log line."""
    return json.dumps(
        {
            "time": time_iso,
            "type": type_,
            "request": {"id": req_id, "operation": op, "path": "test"},
        }
    )


def _make_vault_audit_log(path: Path, lines: list[str]) -> None:
    """Write a synthetic Vault audit log to ``path``."""
    path.write_text("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# Tarball shape — the file frame an operator opens up and reads
# ---------------------------------------------------------------------------


class TestTarballShape:
    """Pin the on-disk frame so a future refactor can't quietly drop a
    file an auditor depends on."""

    def test_tarball_is_written_to_output_path(
        self,
        runner: CliRunner,
        evidence_env: None,
        tmp_path: Path,
    ) -> None:
        vault_log = tmp_path / "vault-audit.log"
        _make_vault_audit_log(vault_log, [])
        out = tmp_path / "evidence.tar.gz"

        result = runner.invoke(
            cli.app,
            [
                "evidence",
                "pack",
                "--output",
                str(out),
                "--since-days",
                "30",
                "--vault-audit-log",
                str(vault_log),
            ],
        )
        assert result.exit_code == 0, result.output
        assert out.is_file()
        assert out.stat().st_size > 0

    def test_tarball_contains_required_files(
        self,
        runner: CliRunner,
        evidence_env: None,
        tmp_path: Path,
    ) -> None:
        vault_log = tmp_path / "vault-audit.log"
        _make_vault_audit_log(vault_log, [])
        out = tmp_path / "evidence.tar.gz"

        runner.invoke(
            cli.app,
            [
                "evidence",
                "pack",
                "--output",
                str(out),
                "--since-days",
                "30",
                "--vault-audit-log",
                str(vault_log),
            ],
        )

        with tarfile.open(out, "r:gz") as tar:
            names = {m.name.split("/", 1)[-1] for m in tar.getmembers()}

        assert "audit_events.json" in names
        assert "certificates.json" in names
        assert "operators.json" in names
        assert "vault_audit.log" in names
        assert "vault_audit_integrity.json" in names
        assert "system.json" in names
        assert "MANIFEST.md" in names
        assert "SHA256SUMS" in names


# ---------------------------------------------------------------------------
# Content — what each file holds
# ---------------------------------------------------------------------------


def _extract(tarpath: Path, member: str, tmp: Path) -> str:
    """Extract a single member out of the tarball and return its text."""
    with tarfile.open(tarpath, "r:gz") as tar:
        # The pack uses a top-level dir; resolve to first matching leaf.
        match = next(m for m in tar.getmembers() if m.name.endswith("/" + member))
        f = tar.extractfile(match)
        assert f is not None
        return f.read().decode("utf-8")


class TestContents:
    def test_audit_events_filters_by_since_days(
        self,
        runner: CliRunner,
        evidence_env: None,
        tmp_path: Path,
    ) -> None:
        """Old rows are excluded; recent rows are present."""
        now = datetime.now(timezone.utc)
        _seed_audit_events(
            [
                ("recent-event", now - timedelta(days=5)),
                ("ancient-event", now - timedelta(days=200)),
            ]
        )

        vault_log = tmp_path / "vault-audit.log"
        _make_vault_audit_log(vault_log, [])
        out = tmp_path / "evidence.tar.gz"
        runner.invoke(
            cli.app,
            [
                "evidence",
                "pack",
                "--output",
                str(out),
                "--since-days",
                "30",
                "--vault-audit-log",
                str(vault_log),
            ],
        )

        body = _extract(out, "audit_events.json", tmp_path)
        data = json.loads(body)
        events = [row["event"] for row in data["rows"]]
        assert "recent-event" in events
        assert "ancient-event" not in events
        assert data["since_days"] == 30

    def test_certificates_dump_includes_seeded_rows(
        self,
        runner: CliRunner,
        evidence_env: None,
        tmp_path: Path,
    ) -> None:
        _seed_certificates([("ops@example.com", "111"), ("svc@example.com", "222")])

        vault_log = tmp_path / "vault-audit.log"
        _make_vault_audit_log(vault_log, [])
        out = tmp_path / "evidence.tar.gz"
        runner.invoke(
            cli.app,
            [
                "evidence",
                "pack",
                "--output",
                str(out),
                "--since-days",
                "30",
                "--vault-audit-log",
                str(vault_log),
            ],
        )

        body = _extract(out, "certificates.json", tmp_path)
        data = json.loads(body)
        serials = {row["serial"] for row in data["rows"]}
        assert serials == {"111", "222"}

    def test_operators_dump_includes_seeded_rows(
        self,
        runner: CliRunner,
        evidence_env: None,
        tmp_path: Path,
    ) -> None:
        _seed_operators(["ops@example.com", "auditor@example.com"])

        vault_log = tmp_path / "vault-audit.log"
        _make_vault_audit_log(vault_log, [])
        out = tmp_path / "evidence.tar.gz"
        runner.invoke(
            cli.app,
            [
                "evidence",
                "pack",
                "--output",
                str(out),
                "--since-days",
                "30",
                "--vault-audit-log",
                str(vault_log),
            ],
        )

        body = _extract(out, "operators.json", tmp_path)
        data = json.loads(body)
        cns = {row["cn"] for row in data["rows"]}
        assert cns == {"ops@example.com", "auditor@example.com"}

    def test_system_info_has_known_keys(
        self,
        runner: CliRunner,
        evidence_env: None,
        tmp_path: Path,
    ) -> None:
        vault_log = tmp_path / "vault-audit.log"
        _make_vault_audit_log(vault_log, [])
        out = tmp_path / "evidence.tar.gz"
        runner.invoke(
            cli.app,
            [
                "evidence",
                "pack",
                "--output",
                str(out),
                "--since-days",
                "30",
                "--vault-audit-log",
                str(vault_log),
            ],
        )

        body = _extract(out, "system.json", tmp_path)
        data = json.loads(body)
        # The keys an auditor would expect — pinned by name, not by value
        # because values vary by environment.
        assert "generated_at" in data
        assert "since_days" in data
        assert "wg_manager_version" in data
        assert "alembic_head" in data


# ---------------------------------------------------------------------------
# Vault audit log slice + integrity verification
# ---------------------------------------------------------------------------


class TestVaultAuditSlice:
    def test_audit_log_sliced_to_since_days(
        self,
        runner: CliRunner,
        evidence_env: None,
        tmp_path: Path,
    ) -> None:
        """Lines outside the window are excluded from vault_audit.log."""
        now = datetime.now(timezone.utc)
        recent_t = (now - timedelta(days=2)).isoformat().replace("+00:00", "Z")
        ancient_t = (now - timedelta(days=400)).isoformat().replace("+00:00", "Z")
        vault_log = tmp_path / "vault-audit.log"
        _make_vault_audit_log(
            vault_log,
            [
                _vault_line(ancient_t, "read", "ancient"),
                _vault_line(recent_t, "read", "recent"),
            ],
        )
        out = tmp_path / "evidence.tar.gz"

        runner.invoke(
            cli.app,
            [
                "evidence",
                "pack",
                "--output",
                str(out),
                "--since-days",
                "30",
                "--vault-audit-log",
                str(vault_log),
            ],
        )

        sliced = _extract(out, "vault_audit.log", tmp_path)
        assert "recent" in sliced
        assert "ancient" not in sliced

    def test_integrity_report_passes_on_well_formed_log(
        self,
        runner: CliRunner,
        evidence_env: None,
        tmp_path: Path,
    ) -> None:
        now = datetime.now(timezone.utc)
        t1 = (now - timedelta(minutes=2)).isoformat().replace("+00:00", "Z")
        t2 = (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
        vault_log = tmp_path / "vault-audit.log"
        _make_vault_audit_log(
            vault_log,
            [
                _vault_line(t1, "read", "req-1", "request"),
                _vault_line(t2, "read", "req-1", "response"),
            ],
        )
        out = tmp_path / "evidence.tar.gz"
        runner.invoke(
            cli.app,
            [
                "evidence",
                "pack",
                "--output",
                str(out),
                "--since-days",
                "30",
                "--vault-audit-log",
                str(vault_log),
            ],
        )

        report = json.loads(
            _extract(out, "vault_audit_integrity.json", tmp_path)
        )
        assert report["ok"] is True
        assert report["lines"] == 2
        assert report["malformed"] == 0
        assert report["unpaired"] == 0

    def test_integrity_report_flags_malformed_line(
        self,
        runner: CliRunner,
        evidence_env: None,
        tmp_path: Path,
    ) -> None:
        now = datetime.now(timezone.utc)
        t1 = (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
        vault_log = tmp_path / "vault-audit.log"
        _make_vault_audit_log(
            vault_log,
            [
                _vault_line(t1, "read", "req-1", "request"),
                "this is not json",
            ],
        )
        out = tmp_path / "evidence.tar.gz"
        runner.invoke(
            cli.app,
            [
                "evidence",
                "pack",
                "--output",
                str(out),
                "--since-days",
                "30",
                "--vault-audit-log",
                str(vault_log),
            ],
        )

        report = json.loads(
            _extract(out, "vault_audit_integrity.json", tmp_path)
        )
        assert report["ok"] is False
        assert report["malformed"] >= 1

    def test_missing_vault_audit_log_is_graceful(
        self,
        runner: CliRunner,
        evidence_env: None,
        tmp_path: Path,
    ) -> None:
        """Production deployments may not co-locate the audit log with
        the box running ``make evidence``. Missing → empty vault_audit.log
        + an integrity-report note, not a hard CLI exit."""
        out = tmp_path / "evidence.tar.gz"
        missing = tmp_path / "does-not-exist.log"

        result = runner.invoke(
            cli.app,
            [
                "evidence",
                "pack",
                "--output",
                str(out),
                "--since-days",
                "30",
                "--vault-audit-log",
                str(missing),
            ],
        )
        assert result.exit_code == 0, result.output
        report = json.loads(
            _extract(out, "vault_audit_integrity.json", tmp_path)
        )
        assert report["ok"] is False
        assert "missing" in report.get("reason", "").lower()


# ---------------------------------------------------------------------------
# MANIFEST + SHA256SUMS — internally self-verifying
# ---------------------------------------------------------------------------


class TestManifest:
    def test_sha256sums_lists_every_artifact(
        self,
        runner: CliRunner,
        evidence_env: None,
        tmp_path: Path,
    ) -> None:
        """SHA256SUMS must enumerate every other file so an auditor can
        verify the tarball wasn't tampered with."""
        vault_log = tmp_path / "vault-audit.log"
        _make_vault_audit_log(vault_log, [])
        out = tmp_path / "evidence.tar.gz"
        runner.invoke(
            cli.app,
            [
                "evidence",
                "pack",
                "--output",
                str(out),
                "--since-days",
                "30",
                "--vault-audit-log",
                str(vault_log),
            ],
        )

        sums = _extract(out, "SHA256SUMS", tmp_path).strip().splitlines()
        # SHA256SUMS format: "<64-hex>  <filename>"
        listed = {line.split("  ", 1)[1] for line in sums}
        # MANIFEST excludes itself + SHA256SUMS — circular hash would be
        # a chicken-and-egg.
        assert "audit_events.json" in listed
        assert "certificates.json" in listed
        assert "operators.json" in listed
        assert "vault_audit.log" in listed
        assert "vault_audit_integrity.json" in listed
        assert "system.json" in listed
        assert "MANIFEST.md" in listed

    def test_sha256sums_values_match_actual_file_bytes(
        self,
        runner: CliRunner,
        evidence_env: None,
        tmp_path: Path,
    ) -> None:
        """The recorded hashes must be the *actual* sha256 of the file
        bytes — re-compute on extract and confirm."""
        vault_log = tmp_path / "vault-audit.log"
        _make_vault_audit_log(vault_log, [])
        out = tmp_path / "evidence.tar.gz"
        runner.invoke(
            cli.app,
            [
                "evidence",
                "pack",
                "--output",
                str(out),
                "--since-days",
                "30",
                "--vault-audit-log",
                str(vault_log),
            ],
        )

        sums_text = _extract(out, "SHA256SUMS", tmp_path)
        recorded: dict[str, str] = {}
        for line in sums_text.strip().splitlines():
            digest, name = line.split("  ", 1)
            recorded[name] = digest

        # Recompute sha256 of one file we know the hash of and confirm.
        body = _extract(out, "audit_events.json", tmp_path)
        actual = hashlib.sha256(body.encode("utf-8")).hexdigest()
        assert recorded["audit_events.json"] == actual

    def test_manifest_mentions_every_artifact(
        self,
        runner: CliRunner,
        evidence_env: None,
        tmp_path: Path,
    ) -> None:
        """MANIFEST.md is the operator-facing index — every file must be
        listed by name with a one-line description."""
        vault_log = tmp_path / "vault-audit.log"
        _make_vault_audit_log(vault_log, [])
        out = tmp_path / "evidence.tar.gz"
        runner.invoke(
            cli.app,
            [
                "evidence",
                "pack",
                "--output",
                str(out),
                "--since-days",
                "30",
                "--vault-audit-log",
                str(vault_log),
            ],
        )

        manifest = _extract(out, "MANIFEST.md", tmp_path)
        for f in (
            "audit_events.json",
            "certificates.json",
            "operators.json",
            "vault_audit.log",
            "vault_audit_integrity.json",
            "system.json",
            "SHA256SUMS",
        ):
            assert f in manifest, f"MANIFEST.md must mention {f}"
