"""Tests for ``scripts/vault_migrate_raft.sh`` — Vault file → raft storage.

Phase 3d cycle 5 (warm standby) needs raft snapshots to keep the
standby's Vault current, and file storage can't produce them. The
script is the one-shot, offline conversion of an existing prod Vault:

* refuses while the ``vault`` service is running (a torn copy of a
  live storage backend is unrecoverable);
* refuses when the raft volume holds an initialized Vault (never
  clobber a migrated or freshly initialised Vault) — but clears the
  empty, UNINITIALIZED store a premature ``make prod-up`` leaves;
* refuses when there's no file-storage data to migrate;
* otherwise runs ``vault operator migrate`` in a one-off container of
  the ``vault`` service, so both volumes are mounted exactly as the
  server sees them.

The legacy file volume is only read, so rollback is "revert
vault.hcl". These tests stub the compose command with a shell fake
that logs its argv; the live conversion is exercised by the drill in
``docs/runbooks/vault-raft-migration.md``.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "vault_migrate_raft.sh"
MIGRATE_HCL = REPO_ROOT / "docker" / "vault" / "migrate-raft.hcl"
VAULT_HCL = REPO_ROOT / "docker" / "vault" / "vault.hcl"
MAKEFILE = REPO_ROOT / "Makefile"
RUNBOOK = REPO_ROOT / "docs" / "runbooks" / "vault-raft-migration.md"


class Env:
    """Sandbox with a fake compose command and a repo dir.

    Knobs (set before :meth:`run`):

    * ``running`` — what ``compose ps -q vault`` prints.
    * ``raft_contents`` — what ``ls -A /vault/raft`` prints.
    * ``raft_init`` — what the probe server prints
      (``initialized=true|false|unknown``).
    * ``has_source`` — whether ``/vault/file/core`` exists.
    * ``migrate_rc`` — exit code of ``vault operator migrate``.
    """

    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path
        self.log = tmp_path / "calls.log"
        self.repo = tmp_path / "repo"
        (self.repo / "docker" / "vault").mkdir(parents=True)
        (self.repo / ".env.prod").write_text("X=1\n")
        self.running = ""
        self.raft_contents = ""
        self.raft_init = "initialized=unknown"
        self.has_source = True
        self.migrate_rc = 0
        self.compose = tmp_path / "compose"
        self.compose.write_text(
            f"""#!/usr/bin/env bash
echo "compose $*" >> "{self.log}"
[ "$1" = --env-file ] && shift 2
case "$1" in
  ps) printf '%s' "$FAKE_RUNNING"; exit 0 ;;
  run)
    case "$*" in
      *"ls -A /vault/raft"*) printf '%s' "$FAKE_RAFT"; exit 0 ;;
      *"vault status"*) echo "$FAKE_RAFT_INIT"; exit 0 ;;
      *"rm -rf /vault/raft/"*) exit 0 ;;
      *"/vault/file/core"*) [ "$FAKE_HAS_SOURCE" = 1 ]; exit $? ;;
      *"operator migrate"*) exit "$FAKE_MIGRATE_RC" ;;
    esac ;;
esac
exit 0
"""
        )
        self.compose.chmod(self.compose.stat().st_mode | stat.S_IXUSR)

    def run(self) -> subprocess.CompletedProcess:
        env = {
            **os.environ,
            "COMPOSE_BASE": str(self.compose),
            "REPO_DIR": str(self.repo),
            "FAKE_RUNNING": self.running,
            "FAKE_RAFT": self.raft_contents,
            "FAKE_RAFT_INIT": self.raft_init,
            "FAKE_HAS_SOURCE": "1" if self.has_source else "0",
            "FAKE_MIGRATE_RC": str(self.migrate_rc),
        }
        return subprocess.run(
            ["bash", str(SCRIPT)], env=env, capture_output=True, text=True,
            check=False,
        )

    def calls(self) -> str:
        return self.log.read_text() if self.log.exists() else ""


@pytest.fixture
def env(tmp_path: Path) -> Env:
    return Env(tmp_path)


class TestRefusals:
    def test_refuses_while_vault_running(self, env: Env) -> None:
        env.running = "abc123\n"
        proc = env.run()
        assert proc.returncode != 0
        assert "running" in proc.stderr
        assert "operator migrate" not in env.calls()

    def test_refuses_when_raft_volume_holds_initialized_vault(
        self, env: Env
    ) -> None:
        env.raft_contents = "vault.db\nraft\n"
        env.raft_init = "initialized=true"
        proc = env.run()
        assert proc.returncode != 0
        assert "already" in proc.stderr
        assert "operator migrate" not in env.calls()
        assert "rm -rf" not in env.calls()

    def test_refuses_when_raft_state_unknown(self, env: Env) -> None:
        # The probe server never answered: we can't prove the raft data
        # is disposable, so don't touch it.
        env.raft_contents = "vault.db\nraft\n"
        env.raft_init = "initialized=unknown"
        proc = env.run()
        assert proc.returncode != 0
        assert "operator migrate" not in env.calls()
        assert "rm -rf" not in env.calls()

    def test_refuses_without_file_storage_data(self, env: Env) -> None:
        env.has_source = False
        proc = env.run()
        assert proc.returncode != 0
        assert "nothing to migrate" in proc.stderr
        assert "operator migrate" not in env.calls()

    def test_propagates_migrate_failure(self, env: Env) -> None:
        env.migrate_rc = 3
        proc = env.run()
        assert proc.returncode != 0


class TestHappyPath:
    def test_runs_operator_migrate_in_vault_service(self, env: Env) -> None:
        proc = env.run()
        assert proc.returncode == 0, proc.stderr
        migrate = [c for c in env.calls().splitlines() if "operator migrate" in c]
        assert len(migrate) == 1
        call = migrate[0]
        # Uses .env.prod like every other prod target.
        assert f"--env-file {env.repo}/.env.prod" in call
        # One-off container of the vault service, without starting
        # bootstrap-substrate & friends.
        assert " run --rm --no-deps " in call
        # The migrate config is bind-mounted read-only.
        assert f"{env.repo}/docker/vault/migrate-raft.hcl:/vault/config/migrate-raft.hcl:ro" in call
        assert "-config=/vault/config/migrate-raft.hcl" in call

    def test_clears_uninitialized_raft_leftover_then_migrates(
        self, env: Env
    ) -> None:
        # A `make prod-up` before migrating starts Vault on the empty
        # raft volume, which writes vault.db + raft.db for an
        # UNINITIALIZED Vault (no keys, no data). The init guard stops
        # the bootstrap there; the migration must not then be blocked.
        env.raft_contents = "vault.db\nraft\n"
        env.raft_init = "initialized=false"
        proc = env.run()
        assert proc.returncode == 0, proc.stderr
        calls = env.calls()
        assert "rm -rf /vault/raft/" in calls
        assert calls.index("rm -rf /vault/raft/") < calls.index("operator migrate")

    def test_never_deletes_volumes(self, env: Env) -> None:
        env.run()
        assert "down -v" not in env.calls()
        assert "volume rm" not in env.calls()

    def test_prints_next_steps(self, env: Env) -> None:
        proc = env.run()
        assert "make prod-up" in proc.stdout


class TestMigrateConfig:
    """``migrate-raft.hcl`` must agree with ``vault.hcl`` — a mismatch
    produces a raft store the server won't recognise as its own."""

    @pytest.fixture(scope="class")
    def body(self) -> str:
        assert MIGRATE_HCL.is_file(), f"{MIGRATE_HCL} is missing"
        return MIGRATE_HCL.read_text()

    def test_source_is_file_storage(self, body: str) -> None:
        assert re.search(
            r'storage_source\s+"file"\s*\{[^}]*path\s*=\s*"/vault/file"',
            body,
        )

    def test_destination_is_raft_storage(self, body: str) -> None:
        assert re.search(
            r'storage_destination\s+"raft"\s*\{[^}]*path\s*=\s*"/vault/raft"',
            body,
        )

    def test_node_id_and_cluster_addr_match_server(self, body: str) -> None:
        server = VAULT_HCL.read_text()
        for pattern in (r'node_id\s*=\s*"([^"]+)"', r'cluster_addr\s*=\s*"([^"]+)"'):
            mine = re.search(pattern, body)
            theirs = re.search(pattern, server)
            assert mine and theirs, pattern
            assert mine.group(1) == theirs.group(1), pattern


class TestWiring:
    def test_script_is_executable_and_strict(self) -> None:
        assert os.stat(SCRIPT).st_mode & stat.S_IXUSR
        assert "set -euo pipefail" in SCRIPT.read_text()

    def test_make_target(self) -> None:
        mk = MAKEFILE.read_text()
        assert re.search(r"^vault-migrate-raft:", mk, re.MULTILINE)
        phony = next(line for line in mk.splitlines() if line.startswith(".PHONY:"))
        assert "vault-migrate-raft" in phony.split()
        assert "vault-migrate-raft" in mk.split("help:", 1)[1].split("\n\n", 1)[0]

    def test_runbook_covers_migration_and_rollback(self) -> None:
        assert RUNBOOK.is_file(), f"{RUNBOOK} is missing"
        text = RUNBOOK.read_text()
        assert "make vault-migrate-raft" in text
        assert "Rollback" in text
