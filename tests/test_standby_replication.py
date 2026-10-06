"""Tests for Phase 3d cycle 5b — MySQL replication primary → standby.

The warm standby (``general``) keeps a read-only MySQL replica of the
primary (``rv``) so ``make failover`` (cycle 5d) can promote it. The
pieces under test:

* ``docker-compose.prod.yml`` — the primary's mysqld runs with GTIDs on
  and server-id 1, publishes on a per-host bind address, and gets the
  replication password in its env.
* ``docker-compose.standby.yml`` — layered on the prod files on the
  standby: mysqld with server-id 2 and crash-safe relay log recovery.
  Read-only is persisted into the datadir by ``seed``, not a flag.
* ``.env.host`` — per-host, gitignored. ``WG_MANAGER_ROLE`` gates the
  Makefile so a standby never runs ``prod-up`` (two beats racing
  host-cert renewals) and a primary never runs ``standby-up`` (its
  mysqld would restart read-only: an outage).
* ``scripts/mysql_replication.sh`` — ``primary-setup`` / ``seed HOST``
  / ``status``. Each subcommand ships a POSIX ``sh`` snippet into the
  mysql container via ``compose exec``. The fake compose here runs
  that snippet for real on the host, against fake ``mysql`` /
  ``mysqldump`` binaries that log their argv + stdin, so the snippet's
  own logic (guards, SQL, ordering) is what's exercised.
* MySQL server cert SANs — ``MYSQL_SERVER_EXTRA_SANS`` lets one cert
  verify on either host, so the replica can use VERIFY_IDENTITY.

The live round trip (two real mysqld's over TLS) is the drill in
``docs/runbooks/standby-replication.md``.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "mysql_replication.sh"
MAKEFILE = REPO_ROOT / "Makefile"
PROD_OVERLAY = REPO_ROOT / "docker-compose.prod.yml"
STANDBY_OVERLAY = REPO_ROOT / "docker-compose.standby.yml"
RUNBOOK = REPO_ROOT / "docs" / "runbooks" / "standby-replication.md"


class _ComposeLoader(yaml.SafeLoader):
    """SafeLoader that passes Compose's ``!override`` / ``!reset`` through."""


def _passthrough(loader: yaml.Loader, node: yaml.Node) -> object:
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_scalar(node)


_ComposeLoader.add_constructor("!override", _passthrough)
_ComposeLoader.add_constructor("!reset", _passthrough)


def _load(path: Path) -> dict:
    return yaml.load(path.read_text(), Loader=_ComposeLoader)


def _flags(cmd: list[str]) -> dict[str, str]:
    """``["mysqld", "--a=1", "--b=ON"]`` → ``{"a": "1", "b": "ON"}``."""
    out = {}
    for arg in cmd:
        if arg.startswith("--") and "=" in arg:
            k, v = arg[2:].split("=", 1)
            out[k.replace("_", "-")] = v
    return out


# ---------------------------------------------------------------------------
# Compose config
# ---------------------------------------------------------------------------


class TestPrimaryMysql:
    @pytest.fixture(scope="class")
    def mysql(self) -> dict:
        return _load(PROD_OVERLAY)["services"]["mysql"]

    def test_gtids_and_server_id(self, mysql: dict) -> None:
        cmd = mysql.get("command") or []
        assert cmd and cmd[0] == "mysqld"
        f = _flags(cmd)
        assert f.get("server-id") == "1"
        assert f.get("gtid-mode") == "ON"
        assert f.get("enforce-gtid-consistency") == "ON"
        # Binlogs must outlive a standby outage long enough to catch up.
        assert int(f.get("binlog-expire-logs-seconds", "0")) >= 3 * 86400

    def test_bind_address_is_per_host_and_defaults_to_loopback(
        self, mysql: dict
    ) -> None:
        assert mysql["ports"] == ["${MYSQL_BIND_ADDR:-127.0.0.1}:3306:3306"]

    def test_replication_password_reaches_container(self, mysql: dict) -> None:
        # The scripts build the replication SQL inside the container so
        # the host shell never handles the secret.
        env = mysql.get("environment") or {}
        assert "MYSQL_REPL_PASSWORD" in env


class TestStandbyOverlay:
    @pytest.fixture(scope="class")
    def doc(self) -> dict:
        assert STANDBY_OVERLAY.is_file(), f"{STANDBY_OVERLAY} is missing"
        return _load(STANDBY_OVERLAY)

    def test_only_overrides_mysql(self, doc: dict) -> None:
        assert set(doc["services"]) == {"mysql"}

    def test_replica_flags(self, doc: dict) -> None:
        f = _flags(doc["services"]["mysql"]["command"])
        assert f.get("server-id") == "2"
        assert f.get("gtid-mode") == "ON"
        assert f.get("enforce-gtid-consistency") == "ON"
        # NOT a startup flag: with super-read-only on, the image's
        # first-boot init can't set the root password or create the
        # database (ERROR 1290) and crash-loops — found in the live
        # drill. Read-only is persisted into the datadir by
        # `standby-seed` instead (TestSeed.test_persists_read_only).
        assert "super-read-only" not in f
        assert "read-only" not in f
        # Crash-safe: discard a possibly-torn relay log on restart and
        # re-fetch from the source.
        assert f.get("relay-log-recovery") == "ON"
        # Fixed relay-log name. The default derives from the hostname,
        # i.e. the container ID, so a recreated container can't find its
        # relay logs and mysqld fails to start (5d live drill).
        assert f.get("relay-log") == "relay-bin"

    def test_primary_and_standby_share_binlog_retention(self, doc: dict) -> None:
        # After failover the standby IS the primary; its binlogs must be
        # kept as long so the rebuilt old primary can catch up.
        prod = _flags(_load(PROD_OVERLAY)["services"]["mysql"]["command"])
        mine = _flags(doc["services"]["mysql"]["command"])
        assert mine.get("binlog-expire-logs-seconds") == prod.get(
            "binlog-expire-logs-seconds"
        )


# ---------------------------------------------------------------------------
# Makefile + role guard
# ---------------------------------------------------------------------------


@pytest.fixture
def mk_dir(tmp_path: Path) -> Path:
    """A scratch checkout with the real Makefile and a dummy .env.prod."""
    shutil.copy(MAKEFILE, tmp_path / "Makefile")
    (tmp_path / ".env.prod").write_text("X=1\n")
    return tmp_path


def _make(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    # PROD_COMPOSE=echo turns every compose call into a printout, so a
    # target that gets past its guard just prints the command.
    return subprocess.run(
        ["make", "--no-print-directory", "-C", str(cwd), *args],
        capture_output=True,
        text=True,
        check=False,
    )


class TestRoleGuard:
    def test_prod_up_refuses_on_standby(self, mk_dir: Path) -> None:
        (mk_dir / ".env.host").write_text("WG_MANAGER_ROLE=standby\n")
        proc = _make(mk_dir, "prod-up", "PROD_COMPOSE=echo compose")
        assert proc.returncode != 0
        assert "standby" in proc.stdout + proc.stderr
        assert "compose up" not in proc.stdout

    def test_prod_up_allowed_on_primary(self, mk_dir: Path) -> None:
        (mk_dir / ".env.host").write_text("WG_MANAGER_ROLE=primary\n")
        proc = _make(mk_dir, "prod-up", "PROD_COMPOSE=echo compose")
        assert proc.returncode == 0, proc.stderr
        assert "compose up" in proc.stdout

    def test_prod_up_allowed_without_env_host(self, mk_dir: Path) -> None:
        # Single-host installs have no .env.host and must keep working.
        proc = _make(mk_dir, "prod-up", "PROD_COMPOSE=echo compose")
        assert proc.returncode == 0, proc.stderr

    @pytest.mark.parametrize("content", ["WG_MANAGER_ROLE=primary\n", None])
    def test_standby_up_requires_standby_role(
        self, mk_dir: Path, content: str | None
    ) -> None:
        if content:
            (mk_dir / ".env.host").write_text(content)
        proc = _make(mk_dir, "standby-up", "PROD_COMPOSE=echo compose")
        assert proc.returncode != 0
        assert "compose" not in proc.stdout

    def test_standby_up_runs_mysql_only_without_deps(self, mk_dir: Path) -> None:
        (mk_dir / ".env.host").write_text("WG_MANAGER_ROLE=standby\n")
        proc = _make(mk_dir, "standby-up", "PROD_COMPOSE=echo compose")
        assert proc.returncode == 0, proc.stderr
        assert "-f docker-compose.standby.yml" in proc.stdout
        assert re.search(r"up -d --no-deps --wait mysql\s*$", proc.stdout.strip())

    def test_standby_seed_requires_primary_arg(self, mk_dir: Path) -> None:
        (mk_dir / ".env.host").write_text("WG_MANAGER_ROLE=standby\n")
        proc = _make(mk_dir, "standby-seed")
        assert proc.returncode != 0
        assert "primary=" in proc.stdout + proc.stderr

    def test_prod_compose_layers_env_host_when_present(self, mk_dir: Path) -> None:
        (mk_dir / ".env.host").write_text("WG_MANAGER_ROLE=primary\n")
        proc = _make(mk_dir, "-pn")
        assert "--env-file .env.prod --env-file .env.host" in proc.stdout

    def test_targets_documented(self) -> None:
        mk = MAKEFILE.read_text()
        phony = next(line for line in mk.splitlines() if line.startswith(".PHONY:"))
        help_block = mk.split("help:", 1)[1].split("\n\n", 1)[0]
        for target in (
            "repl-primary-setup",
            "standby-up",
            "standby-down",
            "standby-seed",
            "standby-status",
        ):
            assert re.search(rf"^{target}:", mk, re.MULTILINE), target
            assert target in phony.split(), target
            assert target in help_block, target


# ---------------------------------------------------------------------------
# Env templates
# ---------------------------------------------------------------------------


class TestEnvTemplates:
    def test_env_host_example(self) -> None:
        text = (REPO_ROOT / ".env.host.example").read_text()
        assert "WG_MANAGER_ROLE=" in text
        assert "MYSQL_BIND_ADDR=" in text

    def test_env_host_is_gitignored(self) -> None:
        proc = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "check-ignore", "-q", ".env.host"],
            check=False,
        )
        assert proc.returncode == 0, ".env.host must be gitignored"

    def test_env_prod_example_has_replication_vars(self) -> None:
        text = (REPO_ROOT / ".env.prod.example").read_text()
        assert "MYSQL_REPL_PASSWORD=" in text
        assert "MYSQL_SERVER_EXTRA_SANS=" in text


# ---------------------------------------------------------------------------
# MySQL server cert SANs
# ---------------------------------------------------------------------------


class TestMysqlServerSans:
    def test_substrate_mint_appends_extra_sans(self) -> None:
        body = (REPO_ROOT / "scripts" / "prod_bootstrap_substrate.sh").read_text()
        assert "MYSQL_SERVER_EXTRA_SANS" in body

    def test_rotation_appends_extra_sans(self, monkeypatch) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "bootstrap_mysql_tls_files",
            REPO_ROOT / "scripts" / "bootstrap_mysql_tls_files.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        monkeypatch.setenv("MYSQL_SERVER_EXTRA_SANS", " rv.vpn , general.vpn,")
        sans = mod.server_sans()
        assert sans[:4] == ["localhost", "127.0.0.1", "mysql", "wg_manager_mysql"]
        assert sans[4:] == ["rv.vpn", "general.vpn"]
        monkeypatch.delenv("MYSQL_SERVER_EXTRA_SANS")
        assert mod.server_sans() == ["localhost", "127.0.0.1", "mysql", "wg_manager_mysql"]

    @pytest.mark.parametrize("service", ["bootstrap-substrate", "bootstrap-app"])
    def test_extra_sans_forwarded_to_minting_containers(self, service: str) -> None:
        # bootstrap-substrate mints at first boot; bootstrap-app runs
        # `make certs-rotate`. Both must see the setting.
        env = _load(PROD_OVERLAY)["services"][service]["environment"]
        assert "MYSQL_SERVER_EXTRA_SANS" in env


# ---------------------------------------------------------------------------
# scripts/mysql_replication.sh
# ---------------------------------------------------------------------------


class Sandbox:
    """Fake compose that runs ``exec ... sh -c SNIPPET`` locally.

    Knobs (environment the in-container snippet sees, plus fake mysql
    answers) are plain attributes; :meth:`run` wires them up.
    """

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.log = tmp / "calls.log"
        self.bin = tmp / "bin"
        self.bin.mkdir()
        # What the fake mysql answers.
        self.server_id = "2"
        self.gtid_mode = "ON"
        self.replica_status = ""  # `SHOW REPLICA STATUS` (-N -B) output
        self.replica_status_g = ""  # `SHOW REPLICA STATUS\G` output
        self.tables = "0"
        self.dump_rc = 0
        self.running_services = "mysql\n"
        self.mysql_fail = ""  # mysql exits 1 when its argv contains this
        self.ready_after = 0  # the first N `SELECT 1` probes fail
        # Container env.
        self.repl_password = "abc123def"
        self._write_fakes()

    def _exe(self, name: str, body: str) -> None:
        p = self.bin / name
        p.write_text(body)
        p.chmod(p.stat().st_mode | stat.S_IXUSR)

    def _write_fakes(self) -> None:
        log = self.log
        self._exe(
            "mysql",
            f"""#!/bin/sh
stdin=""
# One log line per call: multi-line SQL would otherwise spill onto
# lines the tests read as argv.
[ -t 0 ] || stdin="$(tr '\\n' ' ')"
echo "mysql $* <<< $stdin" >> "{log}"
if [ -n "$FAKE_MYSQL_FAIL" ]; then
  case "$*" in *"$FAKE_MYSQL_FAIL"*) echo "ERROR 1045 (28000): Access denied" >&2; exit 1 ;; esac
fi
case "$*" in
  *"SELECT 1"*)
    n=$(cat "{self.tmp}/probes" 2>/dev/null || echo 0); echo $((n + 1)) > "{self.tmp}/probes"
    [ "$n" -ge "$FAKE_READY_AFTER" ] || {{ echo "ERROR 2002: Can't connect" >&2; exit 1; }}
    echo 1 ;;
  *"SELECT @@server_id"*) echo "$FAKE_SERVER_ID" ;;
  *"SELECT @@gtid_mode"*) echo "$FAKE_GTID_MODE" ;;
  *"COUNT(*)"*) echo "$FAKE_TABLES" ;;
  *"SHOW REPLICA STATUS\\G"*) printf '%s\\n' "$FAKE_REPLICA_STATUS_G" ;;
  *"SHOW REPLICA STATUS"*) printf '%s' "$FAKE_REPLICA_STATUS" ;;
esac
exit 0
""",
        )
        self._exe(
            "mysqldump",
            f"""#!/bin/sh
echo "mysqldump $* pwd=$MYSQL_PWD" >> "{log}"
[ "$FAKE_DUMP_RC" = 0 ] || exit "$FAKE_DUMP_RC"
echo "-- fake dump"
""",
        )
        # compose fake: `exec -T [-e K=V]... mysql sh -c SNIPPET` runs
        # SNIPPET locally with the -e vars exported. `ps` lists services.
        self._exe(
            "compose",
            f"""#!/usr/bin/env bash
# Log everything except the snippet itself (the last arg of an exec):
# its SOURCE mentions CREATE USER, mysqldump, ... and would satisfy
# every "was X run?" assertion. What ran shows up via the fakes below.
if [[ " $* " == *" exec "* ]]; then
  echo "compose ${{*:1:$#-1}} <snippet>" >> "{log}"
else
  echo "compose $*" >> "{log}"
fi
while [ "$1" = --env-file ] || [ "$1" = -f ]; do shift 2; done
case "$1" in
  ps) printf '%s' "$FAKE_RUNNING"; exit 0 ;;
  exec)
    shift
    while [ "$#" -gt 0 ]; do
      case "$1" in
        -T) shift ;;
        -e) export "${{2?}}"; shift 2 ;;
        mysql) shift; break ;;
        *) shift ;;
      esac
    done
    exec "$@" ;;
esac
exit 0
""",
        )

    def run(self, *args: str) -> subprocess.CompletedProcess:
        env = {
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "HOME": str(self.tmp),
            "COMPOSE": str(self.bin / "compose"),
            # Container env (what the mysql service carries).
            "MYSQL_ROOT_PASSWORD": "rootpw",
            "MYSQL_DATABASE": "wg_manager",
            "MYSQL_REPL_PASSWORD": self.repl_password,
            # Fake answers.
            "FAKE_SERVER_ID": self.server_id,
            "FAKE_GTID_MODE": self.gtid_mode,
            "FAKE_REPLICA_STATUS": self.replica_status,
            "FAKE_REPLICA_STATUS_G": self.replica_status_g,
            "FAKE_TABLES": self.tables,
            "FAKE_DUMP_RC": str(self.dump_rc),
            "FAKE_RUNNING": self.running_services,
            "FAKE_MYSQL_FAIL": self.mysql_fail,
            "FAKE_READY_AFTER": str(self.ready_after),
            # Keep the readiness wait fast and bounded in tests.
            "REPL_READY_TIMEOUT_SECONDS": "3",
            "REPL_READY_INTERVAL_SECONDS": "0",
            # The snippet writes its dump under TMPDIR.
            "TMPDIR": str(self.tmp),
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
def box(tmp_path: Path) -> Sandbox:
    return Sandbox(tmp_path)


class TestScriptWiring:
    def test_executable_and_strict(self) -> None:
        assert os.stat(SCRIPT).st_mode & stat.S_IXUSR
        assert "set -euo pipefail" in SCRIPT.read_text()

    def test_usage_on_unknown_subcommand(self, box: Sandbox) -> None:
        proc = box.run("bogus")
        assert proc.returncode == 2

    def test_secrets_never_on_a_command_line(self, box: Sandbox) -> None:
        # Passwords travel via MYSQL_PWD / stdin, never argv (visible
        # in `ps` to every user on the host).
        box.run("primary-setup")
        box.run("seed", "rv.vpn")
        for line in box.calls().splitlines():
            argv = line.split(" <<< ")[0].split(" pwd=")[0]
            assert "abc123def" not in argv, line
            assert "rootpw" not in argv, line


class TestPrimarySetup:
    def test_creates_x509_replication_user(self, box: Sandbox) -> None:
        box.server_id = "1"
        proc = box.run("primary-setup")
        assert proc.returncode == 0, proc.stderr
        sql = box.calls()
        assert "CREATE USER IF NOT EXISTS 'wg_repl'@'%'" in sql
        assert "ALTER USER 'wg_repl'@'%' IDENTIFIED BY 'abc123def' REQUIRE X509" in sql
        assert "GRANT REPLICATION SLAVE" in sql

    def test_refuses_when_gtids_off(self, box: Sandbox) -> None:
        box.server_id = "1"
        box.gtid_mode = "OFF"
        proc = box.run("primary-setup")
        assert proc.returncode != 0
        assert "gtid" in proc.stderr.lower()
        assert "CREATE USER" not in box.calls()

    def test_refuses_without_password(self, box: Sandbox) -> None:
        box.server_id = "1"
        box.repl_password = ""
        proc = box.run("primary-setup")
        assert proc.returncode != 0
        assert "MYSQL_REPL_PASSWORD" in proc.stderr
        assert "CREATE USER" not in box.calls()

    @pytest.mark.parametrize("bad", ["it's", "back\\slash"])
    def test_refuses_password_that_breaks_sql_quoting(
        self, box: Sandbox, bad: str
    ) -> None:
        box.server_id = "1"
        box.repl_password = bad
        proc = box.run("primary-setup")
        assert proc.returncode != 0
        assert "CREATE USER" not in box.calls()


class TestSeed:
    def test_happy_path_order(self, box: Sandbox) -> None:
        proc = box.run("seed", "rv.vpn")
        assert proc.returncode == 0, proc.stderr
        calls = box.calls()
        steps = [
            "super_read_only=OFF",
            "RESET BINARY LOGS AND GTIDS",
            "mysqldump",
            "-- fake dump",  # the dump is loaded
            "CHANGE REPLICATION SOURCE TO",
            "START REPLICA",
            "super_read_only=ON",
        ]
        positions = [calls.index(s) for s in steps]
        assert positions == sorted(positions), calls

    def test_persists_read_only(self, box: Sandbox) -> None:
        # SET PERSIST lands in the datadir's mysqld-auto.cnf, so the
        # replica comes back read-only after every restart.
        box.run("seed", "rv.vpn")
        calls = box.calls()
        assert "SET PERSIST super_read_only=ON" in calls
        assert calls.index("SET PERSIST super_read_only=ON") > calls.index("START REPLICA")

    def test_dump_is_consistent_and_verifies_primary_identity(
        self, box: Sandbox
    ) -> None:
        box.run("seed", "rv.vpn")
        dump = next(c for c in box.calls().splitlines() if c.startswith("mysqldump"))
        for flag in (
            "-h rv.vpn",
            "-u wg_repl",
            "--ssl-mode=VERIFY_IDENTITY",
            "--ssl-ca=/etc/mysql/certs/ca.crt",
            "--ssl-cert=/etc/mysql/certs/client.crt",
            "--ssl-key=/etc/mysql/certs/client.key",
            "--single-transaction",
            "--set-gtid-purged=ON",
            "--databases wg_manager",
        ):
            assert flag in dump, flag
        assert "pwd=abc123def" in dump  # via MYSQL_PWD, not argv

    def test_replication_source_settings(self, box: Sandbox) -> None:
        box.run("seed", "rv.vpn")
        change = next(
            c for c in box.calls().splitlines() if "CHANGE REPLICATION SOURCE TO" in c
        )
        for frag in (
            "SOURCE_HOST='rv.vpn'",
            "SOURCE_USER='wg_repl'",
            "SOURCE_PASSWORD='abc123def'",
            "SOURCE_AUTO_POSITION=1",
            "SOURCE_SSL=1",
            "SOURCE_SSL_VERIFY_SERVER_CERT=1",
            "SOURCE_SSL_CA='/etc/mysql/certs/ca.crt'",
            "SOURCE_SSL_CERT='/etc/mysql/certs/client.crt'",
            # MySQL's defaults (10 tries, 60s apart) make the replica give
            # up for good once the primary has been down ~10 minutes, and
            # it never resumes on its own — found in the live drill. Retry
            # every 10s for as long as the binlogs are kept.
            "SOURCE_CONNECT_RETRY=10",
            "SOURCE_RETRY_COUNT=86400",
        ):
            assert frag in change, frag

    def test_refuses_on_primary(self, box: Sandbox) -> None:
        box.server_id = "1"
        proc = box.run("seed", "rv.vpn")
        assert proc.returncode != 0
        assert "standby-up" in proc.stderr
        assert "mysqldump" not in box.calls()

    def test_refuses_when_already_replicating(self, box: Sandbox) -> None:
        box.replica_status = "rv.vpn\twg_repl\t3306\n"
        proc = box.run("seed", "rv.vpn")
        assert proc.returncode != 0
        assert "already" in proc.stderr
        assert "mysqldump" not in box.calls()

    def test_refuses_when_local_db_not_empty(self, box: Sandbox) -> None:
        box.tables = "12"
        proc = box.run("seed", "rv.vpn")
        assert proc.returncode != 0
        assert "mysqldump" not in box.calls()

    def test_refuses_while_app_services_run(self, box: Sandbox) -> None:
        box.running_services = "mysql\napi\nworker\n"
        proc = box.run("seed", "rv.vpn")
        assert proc.returncode != 0
        assert "mysqldump" not in box.calls()

    @pytest.mark.parametrize("host", ["", "rv.vpn;DROP", "rv vpn", "-hx"])
    def test_rejects_bad_primary_host(self, box: Sandbox, host: str) -> None:
        proc = box.run("seed", host)
        assert proc.returncode != 0
        assert "mysqldump" not in box.calls()

    def test_query_failure_aborts_before_any_change(self, box: Sandbox) -> None:
        # Regression (found in the live drill): a guard written as
        # `[ "$(q ...)" != 1 ]` swallows q's failure under `set -e`, so
        # a mysql that rejects root (first-boot init still running, or a
        # wrong password) read as "not the primary / not configured /
        # empty" and the seed carried on.
        box.mysql_fail = "SELECT @@server_id"
        proc = box.run("seed", "rv.vpn")
        assert proc.returncode != 0
        calls = box.calls()
        assert "SHOW REPLICA STATUS" not in calls, "must stop at the failed guard"
        assert "super_read_only" not in calls
        assert "mysqldump" not in calls

    def test_waits_for_server_to_accept_root(self, box: Sandbox) -> None:
        # `up --wait` can return while the image's first-boot init is
        # still swapping its temporary server for the real one.
        box.ready_after = 2
        proc = box.run("seed", "rv.vpn")
        assert proc.returncode == 0, proc.stderr
        calls = box.calls()
        assert calls.count("SELECT 1 ") == 3  # two failed probes, one ok
        assert calls.rindex("SELECT 1 ") < calls.index("SELECT @@server_id")
        assert "CHANGE REPLICATION SOURCE TO" in calls

    def test_gives_up_when_server_never_ready(self, box: Sandbox) -> None:
        box.ready_after = 999
        proc = box.run("seed", "rv.vpn")
        assert proc.returncode != 0
        assert "not accepting" in proc.stderr
        assert "SELECT @@server_id" not in box.calls()

    def test_failed_dump_restores_read_only(self, box: Sandbox) -> None:
        box.dump_rc = 2
        proc = box.run("seed", "rv.vpn")
        assert proc.returncode != 0
        calls = box.calls()
        assert "CHANGE REPLICATION SOURCE TO" not in calls
        # The trap puts super_read_only back even on failure.
        assert calls.rindex("SET PERSIST super_read_only=ON") > calls.index(
            "super_read_only=OFF"
        )
        # And points at the usual cause.
        assert "MYSQL_SERVER_EXTRA_SANS" in proc.stderr


def _status_g(io: str = "Yes", sql: str = "Yes", lag: str = "0", err: str = "") -> str:
    return (
        "*************************** 1. row ***************************\n"
        f"             Source_Host: rv.vpn\n"
        f"      Replica_IO_Running: {io}\n"
        f"     Replica_SQL_Running: {sql}\n"
        f"   Seconds_Behind_Source: {lag}\n"
        f"           Last_IO_Error: {err}\n"
        f"          Last_SQL_Error: \n"
    )


class TestStatus:
    def test_healthy(self, box: Sandbox) -> None:
        box.replica_status_g = _status_g()
        proc = box.run("status")
        assert proc.returncode == 0, proc.stderr
        assert "Seconds_Behind_Source: 0" in proc.stdout

    def test_not_configured(self, box: Sandbox) -> None:
        proc = box.run("status")
        assert proc.returncode == 1
        assert "not configured" in proc.stdout + proc.stderr

    def test_io_thread_down(self, box: Sandbox) -> None:
        box.replica_status_g = _status_g(
            io="Connecting", lag="NULL", err="error connecting to source"
        )
        proc = box.run("status")
        assert proc.returncode == 1
        assert "error connecting to source" in proc.stdout

    def test_lagging(self, box: Sandbox) -> None:
        box.replica_status_g = _status_g(lag="900")
        proc = box.run("status")
        assert proc.returncode == 2


class TestRunbook:
    def test_runbook_exists_and_covers_both_hosts(self) -> None:
        assert RUNBOOK.is_file(), f"{RUNBOOK} is missing"
        text = RUNBOOK.read_text()
        for needle in (
            "make repl-primary-setup",
            "make standby-seed primary=",
            "make standby-status",
            ".env.host",
            "MYSQL_SERVER_EXTRA_SANS",
        ):
            assert needle in text, needle
