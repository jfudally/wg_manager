"""Structural tests for Phase 2e operator runbooks (cycle 1).

Phase 2e's acceptance criterion in ``ROADMAP.md`` calls for two
runbooks an on-call engineer can follow at 3am:

* ``docs/runbooks/key-compromise.md`` — what to do when one of the
  trust roots wg-manager depends on (Vault root token, Transit master
  key, SSH CA private key, PKI root/intermediate, an operator client
  cert, a service cert, a manual-client WireGuard private key) is
  suspected leaked.
* ``docs/runbooks/vault-down.md`` — what to do when the Vault
  dependency is unreachable, sealed, or has lost quorum.

These tests pin the operator-facing contract of those documents — they
exist at the documented paths, contain the incident-response sections
an on-call would reach for, and name the concrete commands the
runbook tells the operator to run. A future rename in the ``cli`` /
``Makefile`` / ``vault_audit`` surface that breaks the runbook's
prescriptions trips the test rather than silently rotting the doc.

Pure parse-and-assert so the fast ``make test`` invocation stays
hermetic — the runbooks themselves are the "live" surface and live
verification is the operator's job during a drill.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNBOOKS_DIR = REPO_ROOT / "docs" / "runbooks"
KEY_COMPROMISE_PATH = RUNBOOKS_DIR / "key-compromise.md"
VAULT_DOWN_PATH = RUNBOOKS_DIR / "vault-down.md"
BACKUP_RESTORE_PATH = RUNBOOKS_DIR / "backup-restore.md"


def _read(path: Path) -> str:
    """Read a runbook file, failing loudly if it is missing.

    Centralised here so every test that depends on a runbook's content
    raises the same ``FileNotFoundError`` shape — makes the RED→GREEN
    transition for cycle 1 unambiguous.
    """
    return path.read_text(encoding="utf-8")


def _headings(body: str) -> list[str]:
    """Return the markdown heading lines (``^#+ ``) in source order.

    Stripped of the leading hashes/whitespace so a section lookup is a
    case-insensitive substring match on the title text.
    """
    return [
        line.lstrip("# ").strip()
        for line in body.splitlines()
        if re.match(r"^#{1,6}\s", line)
    ]


def _has_section(body: str, *needles: str) -> bool:
    """``True`` if any heading contains any of ``needles`` (case-insens)."""
    lowered = [h.lower() for h in _headings(body)]
    return any(any(n.lower() in h for n in needles) for h in lowered)


# ---------------------------------------------------------------------------
# File-existence + top-level frame
# ---------------------------------------------------------------------------


class TestFilesExist:
    """The runbooks live at the paths ``ROADMAP.md`` advertises."""

    def test_runbooks_directory_exists(self) -> None:
        assert RUNBOOKS_DIR.is_dir(), (
            f"{RUNBOOKS_DIR} is missing — cycle 1 hasn't shipped yet"
        )

    def test_key_compromise_runbook_exists(self) -> None:
        assert KEY_COMPROMISE_PATH.is_file(), (
            f"{KEY_COMPROMISE_PATH} is missing — see ROADMAP.md Phase 2e"
        )

    def test_vault_down_runbook_exists(self) -> None:
        assert VAULT_DOWN_PATH.is_file(), (
            f"{VAULT_DOWN_PATH} is missing — see ROADMAP.md Phase 2e"
        )

    def test_key_compromise_runbook_has_h1_title(self) -> None:
        body = _read(KEY_COMPROMISE_PATH)
        first_heading = next(
            (line for line in body.splitlines() if line.startswith("# ")),
            None,
        )
        assert first_heading is not None, "missing H1 title"
        assert "key" in first_heading.lower() and "compromise" in first_heading.lower()

    def test_vault_down_runbook_has_h1_title(self) -> None:
        body = _read(VAULT_DOWN_PATH)
        first_heading = next(
            (line for line in body.splitlines() if line.startswith("# ")),
            None,
        )
        assert first_heading is not None, "missing H1 title"
        assert "vault" in first_heading.lower() and "down" in first_heading.lower()


# ---------------------------------------------------------------------------
# Incident-response section frame
# ---------------------------------------------------------------------------


class TestKeyCompromiseSections:
    """The IR-standard sections an on-call needs in priority order."""

    @pytest.fixture(scope="class")
    def body(self) -> str:
        return _read(KEY_COMPROMISE_PATH)

    def test_scope_section(self, body: str) -> None:
        """Which trust roots this runbook covers — narrows the scope."""
        assert _has_section(body, "scope", "covered keys", "in scope")

    def test_symptoms_or_detection_section(self, body: str) -> None:
        """How an operator knows they're in this scenario."""
        assert _has_section(body, "symptom", "detect", "signal")

    def test_triage_section(self, body: str) -> None:
        """The first 5 minutes — stop the bleed."""
        assert _has_section(body, "triage", "first response", "immediate")

    def test_mitigation_section(self, body: str) -> None:
        """The concrete revoke/rotate steps per key class."""
        assert _has_section(body, "mitigation", "remediation", "rotate", "revoke")

    def test_verification_section(self, body: str) -> None:
        """How to prove the blast radius is contained."""
        assert _has_section(body, "verification", "verify", "confirm")

    def test_postmortem_section(self, body: str) -> None:
        """What to write up after the fire is out."""
        assert _has_section(body, "postmortem", "post-mortem", "follow-up", "followup")


class TestVaultDownSections:
    """Same IR frame, scoped to a Vault outage."""

    @pytest.fixture(scope="class")
    def body(self) -> str:
        return _read(VAULT_DOWN_PATH)

    def test_symptoms_section(self, body: str) -> None:
        assert _has_section(body, "symptom", "detect", "signal")

    def test_triage_section(self, body: str) -> None:
        assert _has_section(body, "triage", "first response", "immediate")

    def test_recovery_section(self, body: str) -> None:
        """Container down vs sealed vs quorum lost branch."""
        assert _has_section(body, "recovery", "recover", "restore")

    def test_verification_section(self, body: str) -> None:
        assert _has_section(body, "verification", "verify", "confirm")

    def test_postmortem_section(self, body: str) -> None:
        assert _has_section(body, "postmortem", "post-mortem", "follow-up", "followup")


# ---------------------------------------------------------------------------
# Key-class coverage — the runbook must name every trust root that
# could plausibly land on it, otherwise an operator looking up "what
# do I do about X?" gets silence at the worst possible moment.
# ---------------------------------------------------------------------------


class TestKeyCompromiseCoverage:
    """Every trust root in the system gets a named section / paragraph."""

    @pytest.fixture(scope="class")
    def body_lower(self) -> str:
        return _read(KEY_COMPROMISE_PATH).lower()

    def test_covers_vault_root_or_unseal(self, body_lower: str) -> None:
        assert "root token" in body_lower or "unseal" in body_lower

    def test_covers_transit_master_key(self, body_lower: str) -> None:
        assert "transit" in body_lower

    def test_covers_ssh_ca(self, body_lower: str) -> None:
        assert "ssh ca" in body_lower or "ssh-ca" in body_lower

    def test_covers_pki_root(self, body_lower: str) -> None:
        assert "pki" in body_lower

    def test_covers_operator_or_service_cert(self, body_lower: str) -> None:
        assert "operator cert" in body_lower or "service cert" in body_lower or "client cert" in body_lower

    def test_covers_manual_client_wireguard_keys(self, body_lower: str) -> None:
        assert "wireguard" in body_lower or "manual client" in body_lower or "manual-client" in body_lower


# ---------------------------------------------------------------------------
# Concrete-command references — a rename in code that breaks the
# runbook's prescriptions trips here.
# ---------------------------------------------------------------------------


KEY_COMPROMISE_REQUIRED_COMMANDS = (
    "wg-manager certs revoke",
    "wg-manager certs list",
    "wg-manager certs renew",
    "wg-manager crypto rewrap",
    "transit/keys/wg-manager/rotate",
    "make ssh-ca-bootstrap",
    "make pki-bootstrap",
)

VAULT_DOWN_REQUIRED_COMMANDS = (
    "vault status",
    "vault operator unseal",
    "vault operator raft snapshot",
    "make vault-up",
    "docker compose",
)


class TestKeyCompromiseCommands:
    @pytest.fixture(scope="class")
    def body(self) -> str:
        return _read(KEY_COMPROMISE_PATH)

    @pytest.mark.parametrize("command", KEY_COMPROMISE_REQUIRED_COMMANDS)
    def test_command_referenced(self, body: str, command: str) -> None:
        assert command in body, (
            f"key-compromise runbook must name `{command}` — see "
            f"src/wg_manager/cli.py / Makefile for the canonical form"
        )


class TestVaultDownCommands:
    @pytest.fixture(scope="class")
    def body(self) -> str:
        return _read(VAULT_DOWN_PATH)

    @pytest.mark.parametrize("command", VAULT_DOWN_REQUIRED_COMMANDS)
    def test_command_referenced(self, body: str, command: str) -> None:
        assert command in body, (
            f"vault-down runbook must name `{command}` — see Makefile + "
            f"docs/vault-cookbook.md §7 for the production-Vault commands"
        )


# ---------------------------------------------------------------------------
# Cross-references — the runbooks should not duplicate facts that
# already live in the cookbook / threat model / SECURITY.md. Pin a
# link to each so the on-call has the breadcrumbs.
# ---------------------------------------------------------------------------


class TestKeyCompromiseCrossReferences:
    @pytest.fixture(scope="class")
    def body(self) -> str:
        return _read(KEY_COMPROMISE_PATH)

    def test_links_vault_cookbook(self, body: str) -> None:
        assert "vault-cookbook.md" in body

    def test_links_threat_model(self, body: str) -> None:
        assert "THREAT_MODEL.md" in body


class TestVaultDownCrossReferences:
    @pytest.fixture(scope="class")
    def body(self) -> str:
        return _read(VAULT_DOWN_PATH)

    def test_links_vault_cookbook(self, body: str) -> None:
        assert "vault-cookbook.md" in body


# ---------------------------------------------------------------------------
# Discoverability — the runbooks are useless if an operator can't find
# them. Pin the entry-point links so a rename trips here.
# ---------------------------------------------------------------------------


class TestDiscoverability:
    """README and SECURITY.md must point at the runbooks."""

    @pytest.fixture(scope="class")
    def readme(self) -> str:
        return (REPO_ROOT / "README.md").read_text(encoding="utf-8")

    @pytest.fixture(scope="class")
    def security(self) -> str:
        return (REPO_ROOT / "SECURITY.md").read_text(encoding="utf-8")

    def test_readme_links_key_compromise_runbook(self, readme: str) -> None:
        assert "runbooks/key-compromise.md" in readme

    def test_readme_links_vault_down_runbook(self, readme: str) -> None:
        assert "runbooks/vault-down.md" in readme

    def test_readme_links_backup_restore_runbook(self, readme: str) -> None:
        assert "runbooks/backup-restore.md" in readme

    def test_security_links_runbooks(self, security: str) -> None:
        assert (
            "runbooks/key-compromise.md" in security
            or "runbooks/vault-down.md" in security
        )


# ---------------------------------------------------------------------------
# Backup / restore runbook (cycle 2)
# ---------------------------------------------------------------------------


class TestBackupRestoreRunbookExists:
    """The cycle 2 runbook lives at the documented path."""

    def test_backup_restore_runbook_exists(self) -> None:
        assert BACKUP_RESTORE_PATH.is_file(), (
            f"{BACKUP_RESTORE_PATH} is missing — see ROADMAP.md Phase 2e "
            "backup story"
        )

    def test_backup_restore_runbook_has_h1_title(self) -> None:
        body = _read(BACKUP_RESTORE_PATH)
        first_heading = next(
            (line for line in body.splitlines() if line.startswith("# ")),
            None,
        )
        assert first_heading is not None
        assert (
            "backup" in first_heading.lower()
            or "restore" in first_heading.lower()
        )


class TestBackupRestoreRunbookSections:
    """The runbook covers both the backup *and* restore halves and the
    standard frame for either."""

    @pytest.fixture(scope="class")
    def body(self) -> str:
        return _read(BACKUP_RESTORE_PATH)

    def test_scope_section(self, body: str) -> None:
        assert _has_section(body, "scope", "what is backed up", "in scope")

    def test_cadence_section(self, body: str) -> None:
        """How often the operator should be running these."""
        assert _has_section(body, "cadence", "schedule", "frequency", "timer")

    def test_backup_section(self, body: str) -> None:
        """The take-a-backup steps."""
        assert _has_section(body, "backup", "take a backup", "snapshot")

    def test_restore_section(self, body: str) -> None:
        """The restore drill."""
        assert _has_section(body, "restore", "recovery", "drill")

    def test_verification_section(self, body: str) -> None:
        """How to confirm the backup is good before you need it."""
        assert _has_section(body, "verification", "verify", "confirm")


BACKUP_RESTORE_REQUIRED_COMMANDS = (
    "wg-manager db backup",
    "wg-manager db restore",
    "--encrypt",
    "--decrypt",
    "make backup-vault",
    "vault operator raft snapshot save",
    "vault operator raft snapshot restore",
)


class TestBackupRestoreRunbookCommands:
    @pytest.fixture(scope="class")
    def body(self) -> str:
        return _read(BACKUP_RESTORE_PATH)

    @pytest.mark.parametrize("command", BACKUP_RESTORE_REQUIRED_COMMANDS)
    def test_command_referenced(self, body: str, command: str) -> None:
        assert command in body, (
            f"backup-restore runbook must name `{command}` — see "
            f"src/wg_manager/cli.py / Makefile for the canonical form"
        )


class TestBackupRestoreCrossReferences:
    @pytest.fixture(scope="class")
    def body(self) -> str:
        return _read(BACKUP_RESTORE_PATH)

    def test_links_vault_cookbook(self, body: str) -> None:
        assert "vault-cookbook.md" in body

    def test_links_systemd_timer(self, body: str) -> None:
        """The cadence section should point at the timer doc so the
        operator doesn't reinvent the timer pattern."""
        assert "deploy/systemd-timer.md" in body


# ---------------------------------------------------------------------------
# systemd-timer.md must grow a backup-timer subsection
# ---------------------------------------------------------------------------


class TestSystemdTimerBackupSubsection:
    """The deploy doc covers cert renewal already; cycle 2 adds a
    parallel backup-timer pattern so an operator gets both timer
    families from one doc."""

    @pytest.fixture(scope="class")
    def body(self) -> str:
        return (REPO_ROOT / "docs" / "deploy" / "systemd-timer.md").read_text(
            encoding="utf-8"
        )

    def test_backup_timer_section_present(self, body: str) -> None:
        # Heading wording is whatever fits; the important bit is that
        # the doc surfaces a backup timer subsection at all.
        assert _has_section(
            body, "backup", "wg-manager-backup", "snapshot timer"
        )

    def test_backup_unit_name_referenced(self, body: str) -> None:
        """The unit-file name must be stable so an operator who reads
        the doc once knows what to `systemctl status` later."""
        assert "wg-manager-backup.service" in body
        assert "wg-manager-backup.timer" in body
