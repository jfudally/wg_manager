"""Tests for ``scripts/migrate_host.sh`` — moving the prod stack to a new host.

The single-host prod stack keeps its state in three named volumes
(MySQL rows, Vault file storage, Vault audit log) plus three
operator-managed files in the checkout (``.env.prod``,
``vault-init.json``, ``tls/``). Vault uses ``storage "file"``, so a
raft snapshot is not available — the only lossless move is a cold,
byte-for-byte copy of all of it. ``migrate_host.sh`` wraps that copy:

* ``export DIR`` — on the stopped source host, write one tarball per
  volume + ``files.tar`` + ``MANIFEST`` + ``SHA256SUMS`` into ``DIR``.
* ``import DIR`` — on the target host, verify checksums and the git
  commit, refuse to clobber existing state, then recreate the volumes
  (with Compose labels) and unpack the files.
* ``counts`` — exact per-table row counts, run before and after so the
  operator can ``diff`` them.

These tests stub ``docker`` and the compose command with shell fakes
that log their argv, so the suite stays hermetic. The live round trip
is the operator's drill (``docs/runbooks/host-migration.md``).
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "migrate_host.sh"
MAKEFILE = REPO_ROOT / "Makefile"
RUNBOOK = REPO_ROOT / "docs" / "runbooks" / "host-migration.md"

PROJECT = "wg_manager"
STATEFUL_KEYS = (
    "wg_manager_mysql_data",
    "wg_manager_vault_data",
    "wg_manager_vault_audit_logs",
)
ALL_KEYS = (*STATEFUL_KEYS, "wg_manager_valkey_data")


def _compose_config(keys: tuple[str, ...] = ALL_KEYS) -> dict:
    """Minimal ``docker compose config --format json`` output."""
    return {
        "name": PROJECT,
        "services": {
            "mysql": {"image": "mysql:8"},
            "vault": {"image": "hashicorp/vault:1.18"},
            "api": {"image": "wg-manager:prod", "build": {"context": "."}},
        },
        "volumes": {k: {"name": f"{PROJECT}_{k}"} for k in keys},
    }


def _write_exe(path: Path, body: str) -> Path:
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


class Env:
    """A sandbox: fake docker + compose on disk, a git checkout, and helpers.

    Knobs (set before calling :meth:`run`):

    * ``running`` — what ``compose ps -q`` prints (non-empty = stack up).
    * ``existing_volumes`` — names ``docker volume inspect`` succeeds for.
    * ``config`` — the compose config JSON.
    """

    def __init__(self, tmp_path: Path) -> None:
        tmp_path.mkdir(parents=True, exist_ok=True)
        self.tmp = tmp_path
        self.log = tmp_path / "calls.log"
        self.repo = tmp_path / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        (self.repo / "README.md").write_text("x\n")
        subprocess.run(
            ["git", "-C", str(self.repo), "add", "."], check=True
        )
        subprocess.run(
            [
                "git", "-C", str(self.repo),
                "-c", "user.name=t", "-c", "user.email=t@t",
                "commit", "-q", "-m", "init",
            ],
            check=True,
        )
        self.running = ""
        self.existing_volumes: list[str] = []
        self.config = _compose_config()

        # docker fake: `volume inspect` consults FAKE_EXISTING; `run` with
        # tar -c emits a deterministic payload; tar -x swallows stdin.
        self.docker = _write_exe(
            tmp_path / "docker",
            f"""#!/usr/bin/env bash
echo "docker $*" >> "{self.log}"
case "$1 $2" in
  "volume inspect")
    for v in $FAKE_EXISTING; do [ "$v" = "$3" ] && exit 0; done
    exit 1 ;;
  "volume create") echo "$@" | awk '{{print $NF}}'; exit 0 ;;
  "image inspect") [ -n "$FAKE_NO_DIGEST" ] && {{ echo; echo "Error: No such image" >&2; exit 1; }}
    img="${{@: -1}}"; echo "${{img%%:*}}@sha256:deadbeef"; exit 0 ;;
esac
if [ "$1" = run ]; then
  if [[ " $* " == *" -c"* ]]; then echo "payload:$*"; else cat >/dev/null; fi
  exit 0
fi
exit 0
""",
        )
        self.compose = _write_exe(
            tmp_path / "compose",
            f"""#!/usr/bin/env bash
echo "compose $*" >> "{self.log}"
case "$1" in
  ps) printf '%s' "$FAKE_RUNNING"; [ -n "$FAKE_RUNNING" ] && echo; exit 0 ;;
  config) cat "{tmp_path}/config.json"; exit 0 ;;
  exec) echo "users 3"; exit 0 ;;
esac
exit 0
""",
        )

    def seed_state_files(self) -> None:
        """Create the operator files a live prod checkout has."""
        (self.repo / ".env.prod").write_text("MYSQL_ROOT_PASSWORD=x\n")
        (self.repo / "vault-init.json").write_text('{"root_token":"t"}')
        (self.repo / "tls").mkdir()
        (self.repo / "tls" / "server.crt").write_text("cert")

    def run(self, *args: str, **extra_env: str) -> subprocess.CompletedProcess:
        (self.tmp / "config.json").write_text(json.dumps(self.config))
        env = {
            **os.environ,
            "PROD_COMPOSE": str(self.compose),
            "DOCKER": str(self.docker),
            "REPO_DIR": str(self.repo),
            "FAKE_RUNNING": self.running,
            "FAKE_EXISTING": " ".join(self.existing_volumes),
            **extra_env,
        }
        return subprocess.run(
            ["bash", str(SCRIPT), *args],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def calls(self) -> str:
        return self.log.read_text() if self.log.exists() else ""


@pytest.fixture
def env(tmp_path: Path) -> Env:
    return Env(tmp_path)


def _export(env: Env) -> Path:
    """Run a successful export and return the bundle directory."""
    env.seed_state_files()
    env.existing_volumes = [f"{PROJECT}_{k}" for k in STATEFUL_KEYS]
    out = env.tmp / "bundle"
    proc = env.run("export", str(out))
    assert proc.returncode == 0, proc.stderr
    return out


# ---------------------------------------------------------------------------
# Script shape
# ---------------------------------------------------------------------------


class TestScriptShape:
    def test_script_is_executable(self) -> None:
        assert SCRIPT.is_file(), f"{SCRIPT} is missing"
        assert os.stat(SCRIPT).st_mode & stat.S_IXUSR

    def test_script_uses_strict_mode(self) -> None:
        assert "set -euo pipefail" in SCRIPT.read_text()

    def test_unknown_subcommand_fails(self, env: Env) -> None:
        proc = env.run("frobnicate")
        assert proc.returncode != 0
        assert "usage" in (proc.stderr + proc.stdout).lower()


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------


class TestExportGuards:
    def test_refuses_while_stack_running(self, env: Env) -> None:
        """A hot copy of MySQL / Vault file storage can be torn."""
        env.seed_state_files()
        env.running = "abc123"
        proc = env.run("export", str(env.tmp / "bundle"))
        assert proc.returncode != 0
        assert "prod-down" in proc.stderr
        assert "docker run" not in env.calls()

    def test_refuses_non_empty_output_dir(self, env: Env) -> None:
        env.seed_state_files()
        out = env.tmp / "bundle"
        out.mkdir()
        (out / "stale").write_text("x")
        proc = env.run("export", str(out))
        assert proc.returncode != 0
        assert "not empty" in proc.stderr

    def test_refuses_empty_vault_init(self, env: Env) -> None:
        """An empty vault-init.json means Vault was never initialised
        here — exporting it would ship a bundle that can't unseal."""
        env.seed_state_files()
        (env.repo / "vault-init.json").write_text("")
        proc = env.run("export", str(env.tmp / "bundle"))
        assert proc.returncode != 0
        assert "vault-init.json" in proc.stderr

    @pytest.mark.parametrize("missing", [".env.prod", "tls"])
    def test_refuses_missing_state_file(self, env: Env, missing: str) -> None:
        env.seed_state_files()
        target = env.repo / missing
        if target.is_dir():
            for child in target.iterdir():
                child.unlink()
            target.rmdir()
        else:
            target.unlink()
        proc = env.run("export", str(env.tmp / "bundle"))
        assert proc.returncode != 0
        assert missing in proc.stderr

    def test_refuses_missing_volume(self, env: Env) -> None:
        env.seed_state_files()
        env.existing_volumes = [f"{PROJECT}_wg_manager_mysql_data"]
        proc = env.run("export", str(env.tmp / "bundle"))
        assert proc.returncode != 0
        assert "wg_manager_vault_data" in proc.stderr

    def test_refuses_unclassified_volume(self, env: Env) -> None:
        """A volume added to compose later must be classified as migrate
        or skip — never silently left behind."""
        env.seed_state_files()
        env.config = _compose_config((*ALL_KEYS, "wg_manager_new_thing"))
        env.existing_volumes = [f"{PROJECT}_{k}" for k in STATEFUL_KEYS]
        proc = env.run("export", str(env.tmp / "bundle"))
        assert proc.returncode != 0
        assert "wg_manager_new_thing" in proc.stderr


class TestExportBundle:
    def test_writes_one_tar_per_stateful_volume(self, env: Env) -> None:
        out = _export(env)
        for key in STATEFUL_KEYS:
            assert (out / "volumes" / f"{key}.tar").stat().st_size > 0

    def test_skips_valkey(self, env: Env) -> None:
        """Valkey only carries the transient Celery queue."""
        out = _export(env)
        assert not (out / "volumes" / "wg_manager_valkey_data.tar").exists()

    def test_volume_tar_uses_numeric_owner(self, env: Env) -> None:
        """MySQL (999) and Vault (100) own their files by numeric UID;
        mapping by name through the helper image's /etc/passwd would
        scramble ownership."""
        _export(env)
        runs = [line for line in env.calls().splitlines() if "docker run" in line]
        assert runs
        assert all("--numeric-owner" in line for line in runs)

    def test_volumes_mounted_read_only(self, env: Env) -> None:
        _export(env)
        vol = f"{PROJECT}_wg_manager_mysql_data"
        assert f"{vol}:/v:ro" in env.calls()

    def test_files_tar_includes_operator_files(self, env: Env) -> None:
        out = _export(env)
        assert (out / "files.tar").stat().st_size > 0
        files_run = next(
            line for line in env.calls().splitlines()
            if "docker run" in line and str(env.repo) in line
        )
        for name in (".env.prod", "vault-init.json", "tls"):
            assert name in files_run

    def test_files_tar_includes_backups_when_present(self, env: Env) -> None:
        env.seed_state_files()
        (env.repo / "backups").mkdir()
        env.existing_volumes = [f"{PROJECT}_{k}" for k in STATEFUL_KEYS]
        proc = env.run("export", str(env.tmp / "bundle"))
        assert proc.returncode == 0, proc.stderr
        files_run = next(
            line for line in env.calls().splitlines()
            if "docker run" in line and str(env.repo) in line
        )
        assert "backups" in files_run

    def test_manifest_records_commit_and_images(self, env: Env) -> None:
        out = _export(env)
        head = subprocess.run(
            ["git", "-C", str(env.repo), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        manifest = (out / "MANIFEST").read_text()
        assert f"commit={head}" in manifest
        assert f"project={PROJECT}" in manifest
        assert "image mysql:8 mysql@sha256:deadbeef" in manifest
        # Locally-built images have no registry digest worth pinning.
        assert "wg-manager:prod" not in manifest

    def test_manifest_marks_unpulled_image_unknown(self, env: Env) -> None:
        """An image missing locally must yield one well-formed line, not
        a blank digest plus a stray 'unknown' line."""
        env.seed_state_files()
        env.existing_volumes = [f"{PROJECT}_{k}" for k in STATEFUL_KEYS]
        out = env.tmp / "bundle"
        proc = env.run("export", str(out), FAKE_NO_DIGEST="1")
        assert proc.returncode == 0, proc.stderr
        manifest = (out / "MANIFEST").read_text()
        assert "image mysql:8 unknown\n" in manifest
        assert "\nunknown\n" not in manifest

    def test_checksums_verify(self, env: Env) -> None:
        out = _export(env)
        proc = subprocess.run(
            ["sha256sum", "-c", "SHA256SUMS"], cwd=out,
            capture_output=True, text=True, check=False,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        sums = (out / "SHA256SUMS").read_text()
        assert "MANIFEST" in sums and "files.tar" in sums

    def test_bundle_dir_is_private(self, env: Env) -> None:
        """The bundle carries the unseal keys and every password."""
        out = _export(env)
        assert stat.S_IMODE(out.stat().st_mode) == 0o700
        assert stat.S_IMODE((out / "files.tar").stat().st_mode) & 0o077 == 0


# ---------------------------------------------------------------------------
# import
# ---------------------------------------------------------------------------


@pytest.fixture
def bundle_and_target(tmp_path: Path) -> tuple[Path, Env]:
    """Export from a source sandbox, return (bundle, fresh target sandbox)
    whose checkout is at the same commit (a clone of the source repo)."""
    src = Env(tmp_path / "src")
    bundle = _export(src)
    dst = Env(tmp_path / "dst")
    subprocess.run(["rm", "-rf", str(dst.repo)], check=True)
    subprocess.run(
        ["git", "clone", "-q", str(src.repo), str(dst.repo)], check=True
    )
    return bundle, dst


class TestImportGuards:
    def test_refuses_checksum_mismatch(self, bundle_and_target) -> None:
        bundle, dst = bundle_and_target
        with (bundle / "files.tar").open("a") as fh:
            fh.write("tampered")
        proc = dst.run("import", str(bundle))
        assert proc.returncode != 0
        assert "checksum" in proc.stderr.lower()
        assert "volume create" not in dst.calls()

    def test_refuses_commit_mismatch(self, bundle_and_target) -> None:
        bundle, dst = bundle_and_target
        (dst.repo / "new.txt").write_text("y")
        subprocess.run(["git", "-C", str(dst.repo), "add", "."], check=True)
        subprocess.run(
            [
                "git", "-C", str(dst.repo),
                "-c", "user.name=t", "-c", "user.email=t@t",
                "commit", "-q", "-m", "drift",
            ],
            check=True,
        )
        proc = dst.run("import", str(bundle))
        assert proc.returncode != 0
        assert "commit" in proc.stderr.lower()
        assert "volume create" not in dst.calls()

    def test_commit_mismatch_override(self, bundle_and_target) -> None:
        bundle, dst = bundle_and_target
        (dst.repo / "new.txt").write_text("y")
        subprocess.run(["git", "-C", str(dst.repo), "add", "."], check=True)
        subprocess.run(
            [
                "git", "-C", str(dst.repo),
                "-c", "user.name=t", "-c", "user.email=t@t",
                "commit", "-q", "-m", "drift",
            ],
            check=True,
        )
        proc = dst.run("import", str(bundle), MIGRATE_ALLOW_COMMIT_MISMATCH="1")
        assert proc.returncode == 0, proc.stderr

    def test_refuses_existing_target_volume(self, bundle_and_target) -> None:
        """Never merge into, or clobber, state already on the target."""
        bundle, dst = bundle_and_target
        dst.existing_volumes = [f"{PROJECT}_wg_manager_vault_data"]
        proc = dst.run("import", str(bundle))
        assert proc.returncode != 0
        assert "wg_manager_vault_data" in proc.stderr
        assert "volume create" not in dst.calls()

    @pytest.mark.parametrize("name", [".env.prod", "vault-init.json", "tls"])
    def test_refuses_existing_state_file(self, bundle_and_target, name) -> None:
        bundle, dst = bundle_and_target
        (dst.repo / name).write_text("already here")
        proc = dst.run("import", str(bundle))
        assert proc.returncode != 0
        assert name in proc.stderr

    def test_refuses_while_stack_running(self, bundle_and_target) -> None:
        bundle, dst = bundle_and_target
        dst.running = "abc123"
        proc = dst.run("import", str(bundle))
        assert proc.returncode != 0
        assert "volume create" not in dst.calls()

    def test_refuses_project_name_mismatch(self, bundle_and_target) -> None:
        """A different checkout dir name → different volume names →
        prod-up would boot on empty volumes and re-init Vault."""
        bundle, dst = bundle_and_target
        dst.config = {**_compose_config(), "name": "other_dir"}
        proc = dst.run("import", str(bundle))
        assert proc.returncode != 0
        assert "project" in proc.stderr.lower()


class TestImportRestore:
    def test_creates_volumes_with_compose_labels(self, bundle_and_target) -> None:
        """Without the project/volume labels, Compose warns the volume
        'was not created by Docker Compose'."""
        bundle, dst = bundle_and_target
        proc = dst.run("import", str(bundle))
        assert proc.returncode == 0, proc.stderr
        creates = [ln for ln in dst.calls().splitlines() if "volume create" in ln]
        assert len(creates) == len(STATEFUL_KEYS)
        for key in STATEFUL_KEYS:
            line = next(ln for ln in creates if ln.endswith(f"{PROJECT}_{key}"))
            assert f"com.docker.compose.project={PROJECT}" in line
            assert f"com.docker.compose.volume={key}" in line

    def test_extracts_with_numeric_owner(self, bundle_and_target) -> None:
        bundle, dst = bundle_and_target
        proc = dst.run("import", str(bundle))
        assert proc.returncode == 0, proc.stderr
        extracts = [
            ln for ln in dst.calls().splitlines()
            if "docker run" in ln and "-x" in ln
        ]
        # three volumes + the operator files
        assert len(extracts) == len(STATEFUL_KEYS) + 1
        assert all("--numeric-owner" in ln for ln in extracts)
        assert any(str(dst.repo) in ln for ln in extracts)


# ---------------------------------------------------------------------------
# counts
# ---------------------------------------------------------------------------


class TestCounts:
    def test_counts_queries_mysql_via_compose_exec(self, env: Env) -> None:
        proc = env.run("counts")
        assert proc.returncode == 0, proc.stderr
        assert "compose exec -T mysql" in env.calls()
        assert "users 3" in proc.stdout


# ---------------------------------------------------------------------------
# Makefile + runbook wiring
# ---------------------------------------------------------------------------


def _block_for_target(target: str) -> str:
    lines = MAKEFILE.read_text().splitlines()
    out: list[str] = []
    inside = False
    for line in lines:
        if line.startswith(f"{target}:"):
            inside = True
            continue
        if inside:
            if not line.strip():
                break
            out.append(line)
    return "\n".join(out)


class TestMakefile:
    @pytest.mark.parametrize(
        ("target", "arg"),
        [
            ("host-export", "export"),
            ("host-import", "import"),
            ("db-counts", "counts"),
        ],
    )
    def test_target_wires_script(self, target: str, arg: str) -> None:
        body = MAKEFILE.read_text()
        phony = next(ln for ln in body.splitlines() if ln.startswith(".PHONY"))
        assert f" {target}" in phony
        assert f"  {target}" in body  # help line
        block = _block_for_target(target)
        assert "scripts/migrate_host.sh" in block and arg in block
        assert "$(PROD_COMPOSE)" in block


class TestRunbook:
    def test_runbook_exists_and_uses_targets(self) -> None:
        body = RUNBOOK.read_text()
        for needle in (
            "make host-export",
            "make host-import",
            "make db-counts",
            "make prod-down",
            "make prod-up",
            "vault-init.json",
            "rotate-host-cert",
        ):
            assert needle in body, f"runbook must mention {needle}"

    def test_backup_runbook_links_migration(self) -> None:
        body = (REPO_ROOT / "docs" / "runbooks" / "backup-restore.md").read_text()
        assert "host-migration.md" in body
