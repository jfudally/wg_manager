"""Tests for Phase 3d cycle 5e — watching the warm standby, and drilling it.

The standby runs no API, so it has no ``/metrics`` endpoint. Instead:

* ``scripts/standby_metrics.sh`` (``make standby-metrics``, every minute
  from a timer) writes a node_exporter **textfile-collector** file:
  replication state + lag, the installed bundle's creation time and
  commit drift, the last drill's success/failure times, and when the
  file itself was generated. Timestamps, not ages, so Prometheus
  computes staleness even if the timer dies.
* ``scripts/standby_drill.sh`` (``make standby-drill``, weekly) restores
  the latest shipped Vault snapshot into a fully ISOLATED throwaway Vault
  (own internal network, anonymous volume, never the compose project),
  through the same restore → restart → verify path as a real failover,
  and requires healthy replication. It records success/failure for the
  metrics.
* ``make standby-up`` builds the wg-manager image first, so a failover
  never has to build it mid-outage.

The alert rules for these metrics are tested with real ``promtool`` in
``test_prometheus_alerts.py``.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
METRICS_SH = REPO_ROOT / "scripts" / "standby_metrics.sh"
DRILL_SH = REPO_ROOT / "scripts" / "standby_drill.sh"
MAKEFILE = REPO_ROOT / "Makefile"


def _exe(path: Path, body: str) -> Path:
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _git_checkout(path: Path) -> str:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    (path / "README.md").write_text("x\n")
    subprocess.run(["git", "-C", str(path), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(path), "-c", "user.name=t", "-c", "user.email=t@t",
         "commit", "-q", "-m", "init"],
        check=True,
    )
    return subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"], check=True,
        capture_output=True, text=True,
    ).stdout.strip()


STATUS_OK = (
    "Source_Host:           rv.vpn\n"
    "Replica_IO_Running:    Yes\n"
    "Replica_SQL_Running:   Yes\n"
    "Seconds_Behind_Source: 3\n"
    "OK\n"
)


class Box:
    """A standby checkout plus fakes for the replication script and docker."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.log = tmp / "calls.log"
        self.bin = tmp / "bin"
        self.bin.mkdir()
        self.repo = tmp / "wg_manager"
        self.head = _git_checkout(self.repo)
        (self.repo / "standby").mkdir()
        (self.repo / "standby" / "vault.snap").write_bytes(b"SNAP")
        (self.repo / "vault-init.json").write_text('{"root_token":"r"}')
        (self.repo / ".env.host").write_text("WG_MANAGER_ROLE=standby\n")
        self.metrics_file = tmp / "textfile" / "wg_manager_standby.prom"
        self.metrics_file.parent.mkdir()
        self.status = STATUS_OK
        self.status_rc = 0
        self.fail = ""  # substring of a docker call that should exit 1
        self.image_present = True
        log = self.log
        _exe(
            self.bin / "repl",
            f"""#!/usr/bin/env bash
echo "repl $*" >> "{log}"
printf '%b' "$FAKE_STATUS"; exit "$FAKE_STATUS_RC"
""",
        )
        _exe(
            self.bin / "compose",
            f"""#!/usr/bin/env bash
echo "compose $*" >> "{log}"
while [ "$1" = --env-file ] || [ "$1" = -f ]; do shift 2; done
if [ "$1" = config ]; then
  echo '{{"services": {{"vault": {{"image": "hashicorp/vault:1.18"}},
         "bootstrap-app": {{"image": "wg-manager:prod"}}}}}}'
fi
exit 0
""",
        )
        _exe(
            self.bin / "docker",
            f"""#!/usr/bin/env bash
if [[ "$*" == *vault_restore.py* && " $* " != *" --verify "* ]]; then
  echo "docker $* stdin=$(cat)" >> "{log}"
else
  echo "docker $*" >> "{log}"
fi
[ -n "$FAKE_FAIL" ] && [[ "docker $*" == *"$FAKE_FAIL"* ]] && exit 1
case "$1 $2" in
  "image inspect") [ "$FAKE_IMAGE" = 1 ]; exit $? ;;
esac
if [[ "$*" == *"test -s /src/vault-init.json"* ]]; then
  [ -s "{self.repo}/vault-init.json" ]; exit $?
fi
[[ "$*" == *"vault status"* ]] && exit 2      # listening, sealed
[[ "$*" == *"--verify"* ]] && echo "==> Vault verified. Mounts: pki/ ssh/ sys/ transit/"
exit 0
""",
        )

    def manifest(self, created: int, commit: str | None = None) -> None:
        (self.repo / "standby" / "MANIFEST").write_text(
            f"format=1\ncommit={commit or self.head}\ncreated_epoch={created}\n"
            "created=2026-10-06T00:00:00Z\nsource_host=rv\n"
        )

    def env(self, **extra: str) -> dict:
        return {
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "HOME": str(self.tmp),
            "REPO_DIR": str(self.repo),
            "COMPOSE": str(self.bin / "compose"),
            "DOCKER": str(self.bin / "docker"),
            "MYSQL_REPL_SCRIPT": str(self.bin / "repl"),
            "STANDBY_METRICS_FILE": str(self.metrics_file),
            "FAKE_STATUS": self.status,
            "FAKE_STATUS_RC": str(self.status_rc),
            "FAKE_FAIL": self.fail,
            "FAKE_IMAGE": "1" if self.image_present else "0",
            "DRILL_READY_TIMEOUT_SECONDS": "3",
            **extra,
        }

    def metrics(self, **extra: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["bash", str(METRICS_SH)], env=self.env(**extra), capture_output=True,
            text=True, check=False,
        )

    def drill(self, **extra: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["bash", str(DRILL_SH)], env=self.env(**extra), capture_output=True,
            text=True, check=False,
        )

    def calls(self) -> str:
        return self.log.read_text() if self.log.exists() else ""

    def samples(self) -> dict[str, float]:
        out: dict[str, float] = {}
        for line in self.metrics_file.read_text().splitlines():
            if line and not line.startswith("#"):
                name, value = line.rsplit(" ", 1)
                out[name] = float(value)
        return out


@pytest.fixture
def box(tmp_path: Path) -> Box:
    return Box(tmp_path)


# ---------------------------------------------------------------------------
# standby_metrics.sh
# ---------------------------------------------------------------------------

P = "wg_manager_standby_"


class TestMetrics:
    def test_healthy(self, box: Box) -> None:
        box.manifest(created=1_791_000_000)
        proc = box.metrics()
        assert proc.returncode == 0, proc.stderr
        s = box.samples()
        assert s[P + "replication_configured"] == 1
        assert s[P + "replication_io_running"] == 1
        assert s[P + "replication_sql_running"] == 1
        assert s[P + "replication_lag_seconds"] == 3
        assert s[P + "bundle_present"] == 1
        assert s[P + "bundle_created_timestamp_seconds"] == 1_791_000_000
        assert s[P + "bundle_commit_drift"] == 0
        assert abs(s[P + "metrics_generated_timestamp_seconds"] - time.time()) < 60

    def test_every_sample_has_help_and_type(self, box: Box) -> None:
        box.manifest(created=1)
        box.metrics()
        text = box.metrics_file.read_text()
        for name in box.samples():
            assert f"# HELP {name} " in text, name
            assert f"# TYPE {name} gauge" in text, name

    def test_broken_replication(self, box: Box) -> None:
        box.status = (
            "Replica_IO_Running:    Connecting\nReplica_SQL_Running:   Yes\n"
            "Seconds_Behind_Source: NULL\nUNHEALTHY: replication is not running.\n"
        )
        box.status_rc = 1
        proc = box.metrics()
        assert proc.returncode == 0, proc.stderr  # unhealthy is data, not an error
        s = box.samples()
        assert s[P + "replication_io_running"] == 0
        assert P + "replication_lag_seconds" not in s  # NULL: omit, don't fake 0

    def test_not_configured(self, box: Box) -> None:
        box.status = "Replication is not configured on this host (see make standby-seed).\n"
        box.status_rc = 1
        box.metrics()
        s = box.samples()
        assert s[P + "replication_configured"] == 0
        assert s[P + "replication_io_running"] == 0

    def test_no_bundle_yet(self, box: Box) -> None:
        box.metrics()
        s = box.samples()
        assert s[P + "bundle_present"] == 0
        assert P + "bundle_created_timestamp_seconds" not in s

    def test_commit_drift(self, box: Box) -> None:
        box.manifest(created=1, commit="deadbeef")
        box.metrics()
        assert box.samples()[P + "bundle_commit_drift"] == 1

    def test_drill_results(self, box: Box) -> None:
        (box.repo / "standby" / "drill.last_success").write_text("1791000000\n")
        (box.repo / "standby" / "drill.last_failure").write_text("1791000500\n")
        box.metrics()
        s = box.samples()
        assert s[P + "drill_last_success_timestamp_seconds"] == 1_791_000_000
        assert s[P + "drill_last_failure_timestamp_seconds"] == 1_791_000_500

    def test_atomic_write_leaves_no_temp_files(self, box: Box) -> None:
        box.metrics()
        box.metrics()
        assert sorted(p.name for p in box.metrics_file.parent.iterdir()) == [
            "wg_manager_standby.prom"
        ]

    def test_file_from_env_host(self, box: Box) -> None:
        target = box.tmp / "textfile" / "custom.prom"
        with (box.repo / ".env.host").open("a") as f:
            f.write(f"STANDBY_METRICS_FILE={target}\n")
        env = box.env()
        del env["STANDBY_METRICS_FILE"]
        subprocess.run(["bash", str(METRICS_SH)], env=env, check=True, capture_output=True)
        assert target.is_file()

    def test_unwritable_target_fails(self, box: Box) -> None:
        proc = box.metrics(STANDBY_METRICS_FILE=str(box.tmp / "missing-dir" / "x.prom"))
        assert proc.returncode != 0
        assert "missing-dir" in proc.stderr


# ---------------------------------------------------------------------------
# standby_drill.sh
# ---------------------------------------------------------------------------


def _order(calls: str, *needles: str) -> None:
    pos = [calls.index(n) for n in needles]
    assert pos == sorted(pos), calls


class TestDrill:
    def test_success_sequence(self, box: Box) -> None:
        proc = box.drill()
        assert proc.returncode == 0, proc.stdout + proc.stderr
        calls = box.calls()
        _order(
            calls,
            "docker network create --internal",
            "docker run -d --name wg-manager-drill-",
            "vault_restore.py stdin=SNAP",
            "docker restart wg-manager-drill-",
            "vault_restore.py --verify",
            "repl status",
            "docker rm -f -v wg-manager-drill-",
            "docker network rm wg-manager-drill-",
        )
        last = (box.repo / "standby" / "drill.last_success").read_text().strip()
        assert abs(int(last) - time.time()) < 60
        assert "Mounts:" in proc.stdout

    def test_isolated_from_the_real_stack(self, box: Box) -> None:
        box.drill()
        calls = box.calls()
        # The standby's own compose project is only READ (to find images).
        compose_calls = [c for c in calls.splitlines() if c.startswith("compose ")]
        assert compose_calls and all(" config " in c for c in compose_calls), compose_calls
        run = next(c for c in calls.splitlines() if "docker run -d --name wg-manager-drill-" in c)
        assert "--network wg-manager-drill-" in run
        # Anonymous volume: never one of the real named volumes.
        assert "wg_manager_vault_raft" not in calls
        assert "type=volume,dst=/vault/raft" in run
        assert "docker/vault/vault.hcl:/vault/config/vault.hcl:ro" in run
        # The app container sees vault-init.json read-only.
        restore = next(c for c in calls.splitlines() if "vault_restore.py stdin=" in c)
        assert "vault-init.json:/app/vault-init.json:ro" in restore
        assert "VAULT_ADDR=http://vault:8200" in restore

    def test_restore_failure_records_and_cleans_up(self, box: Box) -> None:
        box.fail = "vault_restore.py"
        proc = box.drill()
        assert proc.returncode != 0
        assert "docker rm -f -v wg-manager-drill-" in box.calls()
        assert "docker network rm wg-manager-drill-" in box.calls()
        assert (box.repo / "standby" / "drill.last_failure").is_file()
        assert not (box.repo / "standby" / "drill.last_success").exists()

    def test_unhealthy_replication_fails_the_drill(self, box: Box) -> None:
        box.status, box.status_rc = "UNHEALTHY: replication is not running.\n", 1
        proc = box.drill()
        assert proc.returncode != 0
        assert "replication" in proc.stderr.lower()
        assert (box.repo / "standby" / "drill.last_failure").is_file()

    def test_missing_image_is_a_clear_error(self, box: Box) -> None:
        box.image_present = False
        proc = box.drill()
        assert proc.returncode != 0
        assert "make standby-up" in proc.stderr
        assert "network create" not in box.calls()

    def test_needs_snapshot(self, box: Box) -> None:
        (box.repo / "standby" / "vault.snap").unlink()
        proc = box.drill()
        assert proc.returncode != 0
        assert "standby-pull" in proc.stderr
        assert "network create" not in box.calls()


# ---------------------------------------------------------------------------
# Makefile + docs
# ---------------------------------------------------------------------------


class TestMakefile:
    def test_targets_documented(self) -> None:
        mk = MAKEFILE.read_text()
        phony = next(line for line in mk.splitlines() if line.startswith(".PHONY:"))
        help_block = mk.split("help:", 1)[1].split("\n\n", 1)[0]
        for target in ("standby-metrics", "standby-drill", "alerts-check"):
            assert re.search(rf"^{target}:", mk, re.MULTILINE), target
            assert target in phony.split(), target
            assert target in help_block, target

    def test_standby_up_builds_the_app_image_first(self, tmp_path: Path) -> None:
        shutil.copy(MAKEFILE, tmp_path / "Makefile")
        (tmp_path / ".env.prod").write_text("X=1\n")
        (tmp_path / ".env.host").write_text("WG_MANAGER_ROLE=standby\n")
        proc = subprocess.run(
            ["make", "--no-print-directory", "-C", str(tmp_path), "standby-up",
             "PROD_COMPOSE=echo compose"],
            capture_output=True, text=True, check=False,
        )
        assert proc.returncode == 0, proc.stderr
        out = proc.stdout
        assert "build bootstrap-app" in out
        assert out.index("build bootstrap-app") < out.index("up -d --no-deps --wait mysql")


class TestDocs:
    def test_timers_documented(self) -> None:
        text = (REPO_ROOT / "docs" / "deploy" / "systemd-timer.md").read_text()
        assert "wg-manager-standby-metrics.timer" in text
        assert "wg-manager-standby-drill.timer" in text

    def test_observability_doc(self) -> None:
        text = (REPO_ROOT / "docs" / "observability.md").read_text()
        assert "textfile" in text
        assert "wg_manager_standby_" in text

    def test_env_host_example(self) -> None:
        assert "STANDBY_METRICS_FILE=" in (REPO_ROOT / ".env.host.example").read_text()

