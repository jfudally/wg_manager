"""Tests for ``make prod-db-backup`` — the production DB backup entry.

``make db-backup`` runs the CLI on the host, where settings come from
the dev ``.env``; against the prod stack it fails with "Access denied".
``prod-db-backup`` instead runs ``wg-manager db backup --encrypt``
inside a one-off ``bootstrap-app`` container (prod ``DATABASE_URL``,
Vault Transit via the entrypoint shim's ``VAULT_TOKEN``) and streams
the envelope to the host over stdout, because the container user
(UID 1001) can't write into the operator's ``backups/`` directory.

These tests run the real recipe with a fake ``docker`` on ``PATH`` that
records its arguments and emits a stand-in envelope, so they pin
behaviour (where the file lands, its mode, failure cleanup) rather than
the recipe's text.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
MAKEFILE_PATH = REPO_ROOT / "Makefile"

FAKE_ENVELOPE = '{"encrypted": true, "ciphertext_b64": "AAAA"}'

# Fake docker: logs argv (one arg per line, runs separated by "--"),
# prints the envelope on stdout and row counts on stderr, and exits
# with $FAKE_DOCKER_EXIT (default 0).
FAKE_DOCKER = f"""#!/bin/sh
for a in "$@"; do echo "$a"; done >> "$FAKE_DOCKER_LOG"
echo -- >> "$FAKE_DOCKER_LOG"
echo '  tenant: 1 row(s)' >&2
if [ "${{FAKE_DOCKER_EXIT:-0}}" != 0 ]; then
    echo 'boom' >&2
    exit "$FAKE_DOCKER_EXIT"
fi
printf '%s' '{FAKE_ENVELOPE}'
"""


@pytest.fixture
def workdir(tmp_path: Path) -> Path:
    """A directory with ``.env.prod`` and a fake ``docker`` on PATH."""
    (tmp_path / ".env.prod").write_text("MYSQL_APP_PASSWORD=x\n")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(FAKE_DOCKER)
    docker.chmod(0o755)
    return tmp_path


def _make(workdir: Path, **env: str) -> subprocess.CompletedProcess[str]:
    """Run ``make prod-db-backup`` from ``workdir`` with the fake docker."""
    full_env = {
        **os.environ,
        "PATH": f"{workdir / 'bin'}:{os.environ['PATH']}",
        "FAKE_DOCKER_LOG": str(workdir / "docker.log"),
        **env,
    }
    return subprocess.run(
        ["make", "--no-print-directory", "-f", str(MAKEFILE_PATH),
         "-C", str(workdir), "prod-db-backup"],
        env=full_env,
        capture_output=True,
        text=True,
        check=False,
    )


def _docker_args(workdir: Path) -> list[str]:
    log = workdir / "docker.log"
    return log.read_text().splitlines() if log.exists() else []


def test_writes_encrypted_backup_to_backups_dir(workdir: Path) -> None:
    result = _make(workdir)
    assert result.returncode == 0, result.stdout + result.stderr

    files = list((workdir / "backups").glob("wg-*.enc.json"))
    assert len(files) == 1, list((workdir / "backups").iterdir())
    backup = files[0]
    assert backup.read_text() == FAKE_ENVELOPE
    # An encrypted dump is still sensitive: owner-only.
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    assert str(backup.relative_to(workdir)) in result.stdout


def test_runs_encrypted_backup_inside_bootstrap_app(workdir: Path) -> None:
    result = _make(workdir)
    assert result.returncode == 0, result.stdout + result.stderr

    args = _docker_args(workdir)
    # Pinned prod project (Makefile PROD_PROJECT), then prod's env file.
    assert args[:5] == ["compose", "-p", "wg_manager", "--env-file", ".env.prod"]
    assert "docker-compose.prod.yml" in args
    run_at = args.index("run")
    assert {"--rm", "-T"} <= set(args[run_at:])
    # The shim entrypoint is what exports VAULT_TOKEN for Transit.
    assert "/usr/local/bin/entrypoint-wg-manager.sh" in args
    assert "bootstrap-app" in args[run_at:]
    command = " ".join(args[args.index("bootstrap-app") + 1:])
    assert "wg-manager db backup" in command
    assert "--encrypt" in command


def test_failed_backup_leaves_no_file(workdir: Path) -> None:
    result = _make(workdir, FAKE_DOCKER_EXIT="3")
    assert result.returncode != 0
    backups = workdir / "backups"
    leftovers = list(backups.iterdir()) if backups.exists() else []
    assert leftovers == [], "a failed run must not leave a partial backup"


def test_refuses_without_env_prod(workdir: Path) -> None:
    (workdir / ".env.prod").unlink()
    result = _make(workdir)
    assert result.returncode == 2
    assert ".env.prod" in result.stdout + result.stderr
    assert _docker_args(workdir) == []


def test_listed_in_help_and_phony() -> None:
    body = MAKEFILE_PATH.read_text()
    phony = next(line for line in body.splitlines() if line.startswith(".PHONY:"))
    assert "prod-db-backup" in phony.split()
    help_out = subprocess.run(
        ["make", "--no-print-directory", "-f", str(MAKEFILE_PATH), "help"],
        capture_output=True, text=True, check=True,
    ).stdout
    assert "prod-db-backup" in help_out
