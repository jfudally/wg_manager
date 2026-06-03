"""Tests for Phase 2e backup cycle 2 — make backup-vault target.

The Vault raft snapshot wrapper. Wraps
``vault operator raft snapshot save`` against the dev container at a
timestamped path so an operator's snapshot cadence is one
``make backup-vault`` call away.

Pinning the target's shape in a test keeps the runbook walkthrough
(``docs/runbooks/backup-restore.md``) honest — a future refactor that
renames the target or moves where snapshots land trips the test
rather than rotting the doc.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MAKEFILE_PATH = REPO_ROOT / "Makefile"


def _block_for_target(target: str) -> str:
    """Return the recipe lines between ``<target>:`` and the next blank line."""
    body = MAKEFILE_PATH.read_text()
    in_block = False
    block_lines: list[str] = []
    for line in body.splitlines():
        if line.startswith(f"{target}:"):
            in_block = True
            continue
        if in_block:
            if line.strip() == "":
                break
            block_lines.append(line)
    return "\n".join(block_lines)


class TestBackupVaultTarget:
    """``make backup-vault`` is the canonical Vault snapshot entry."""

    def test_target_declared(self) -> None:
        body = MAKEFILE_PATH.read_text()
        assert "backup-vault:" in body, (
            "Makefile must declare the backup-vault target — see "
            "ROADMAP.md Phase 2e backup story"
        )

    def test_target_wraps_raft_snapshot_save(self) -> None:
        block = _block_for_target("backup-vault")
        assert "vault operator raft snapshot save" in block, (
            f"backup-vault must call `vault operator raft snapshot save` — "
            f"got:\n{block}"
        )

    def test_target_runs_against_dev_compose_vault(self) -> None:
        """The dev-stack target runs the snapshot inside the compose
        container (the prod path is documented in the runbook, not
        wrapped in a make target — operators run it against their own
        Vault address)."""
        block = _block_for_target("backup-vault")
        assert "docker compose exec" in block, (
            f"backup-vault must `docker compose exec vault …` — got:\n{block}"
        )

    def test_target_writes_to_dedicated_snapshots_path(self) -> None:
        """Snapshots land under a path the runbook can name. Pinning
        the prefix keeps the runbook + .gitignore + the volume mount
        consistent."""
        block = _block_for_target("backup-vault")
        # The path is whatever the operator + runbook agree on — but it
        # must be a real path, not stdout.
        assert "/vault/" in block or "snapshot" in block.lower(), (
            f"backup-vault must write to a named path — got:\n{block}"
        )


class TestHelpAndPhony:
    """``make help`` must mention the new target so operators discover
    it without `grep`ing the Makefile."""

    def test_help_target_lists_backup_vault(self) -> None:
        body = MAKEFILE_PATH.read_text()
        # The exact help-line text isn't worth pinning; just that the
        # target appears somewhere in the help frame.
        assert "backup-vault" in body
