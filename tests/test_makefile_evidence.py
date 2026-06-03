"""Tests for Phase 2e cycle 4 — `make evidence` target.

``make evidence`` is the operator-facing entry point that wraps
``wg-manager evidence pack`` with the standard cadence arguments
(30-day window, timestamped output path, default Vault audit log
location). Pinning the target's shape in a test keeps the runbook
walkthrough honest — a future refactor that renames the target or
moves where evidence packs land trips the test rather than rotting
the doc.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MAKEFILE_PATH = REPO_ROOT / "Makefile"


def _block_for_target(target: str) -> str:
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


class TestEvidenceTarget:
    def test_target_declared(self) -> None:
        body = MAKEFILE_PATH.read_text()
        assert "evidence:" in body, (
            "Makefile must declare the evidence target — see ROADMAP "
            "Phase 2e § Acceptance"
        )

    def test_target_calls_wg_manager_evidence_pack(self) -> None:
        block = _block_for_target("evidence")
        assert "evidence pack" in block, (
            f"evidence target must call `wg-manager evidence pack` — got:\n{block}"
        )

    def test_target_passes_since_days(self) -> None:
        """The ROADMAP says \"last 30 days\" — pin it."""
        block = _block_for_target("evidence")
        assert "--since-days" in block, (
            f"evidence target must pass --since-days — got:\n{block}"
        )

    def test_target_writes_to_dedicated_dir(self) -> None:
        """Evidence packs land under a path the runbook can name."""
        block = _block_for_target("evidence")
        assert "evidence" in block.lower()
        # The output should be a real path, not stdout.
        assert "--output" in block

    def test_target_listed_in_help(self) -> None:
        body = MAKEFILE_PATH.read_text()
        assert "evidence" in body
