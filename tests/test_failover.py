"""Tests for Phase 3d cycle 5d — promotion: demote / failover / rejoin.

A switchover is three commands, each re-runnable:

* ``make demote`` (current primary) — remove app containers, make MySQL
  read-only; MySQL + Vault stay up for the standby's final catch-up.
* ``make failover`` (standby) — probe the primary over the replication
  channel and fence: writable → refuse; read-only (demoted) → final
  bundle pull, wait for every primary GTID, promote (zero loss);
  unreachable → only with ``confirm=primary-is-down``, then promote what
  was received. Restore Vault from ``standby/vault.snap``, flip the role,
  ``prod-up``, ``repl-primary-setup``.
* ``make rejoin primary=HOST`` (old primary) — become a replica of HOST
  without re-seeding, only if this host has no transactions HOST lacks.

Layers under test:

* ``scripts/mysql_replication.sh`` — ``primary-state`` / ``promote`` /
  ``demote`` / ``rejoin``. Its in-container ``sh`` snippets run for real
  against a rule-driven fake ``mysql``.
* ``scripts/vault_restore.py`` — init a throwaway Vault if needed (keys
  kept in memory only), restore the snapshot, unseal with the shipped
  keys, verify. Against a stateful fake Vault HTTP API.
* ``scripts/failover.sh`` — the orchestration, with the MySQL script,
  make, compose and docker all faked.

The live round trip (rv → general → rv with real MySQL and Vault) is
the drill in ``docs/runbooks/failover.md``.
"""

from __future__ import annotations

import http.server
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
REPL_SH = REPO_ROOT / "scripts" / "mysql_replication.sh"
RESTORE_PY = REPO_ROOT / "scripts" / "vault_restore.py"
FAILOVER_SH = REPO_ROOT / "scripts" / "failover.sh"
MAKEFILE = REPO_ROOT / "Makefile"


def _exe(path: Path, body: str) -> Path:
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


# ---------------------------------------------------------------------------
# mysql_replication.sh: primary-state / promote / demote / rejoin
# ---------------------------------------------------------------------------


class MysqlBox:
    """Fake compose + rule-driven fake mysql.

    ``rules`` is an ordered list of ``(substring, output, rc)``. The fake
    mysql matches each against its argv + stdin; the first hit prints
    ``output`` (``\\n`` / ``\\t`` escapes honoured) and exits ``rc``. No
    hit → empty output, rc 0. Every call is logged (one line each).
    """

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.log = tmp / "calls.log"
        self.bin = tmp / "bin"
        self.bin.mkdir()
        self.rules: list[tuple[str, str, int]] = []
        log = self.log
        _exe(
            self.bin / "mysql",
            f"""#!/usr/bin/env bash
stdin=""
[ -t 0 ] || stdin="$(tr '\\n' ' ')"
all="$* <<< $stdin"
echo "mysql $all" >> "{log}"
# Fields are \x1f-separated: tab is IFS whitespace, so empty fields
# would collapse; outputs carry tabs as "\\t" escapes for printf %b.
while IFS=$'\\x1f' read -r pat out rc; do
  [ -n "$pat" ] || continue
  case "$all" in *"$pat"*) printf '%b' "$out"; exit "$rc" ;; esac
done < "{tmp}/rules.txt"
exit 0
""",
        )
        _exe(
            self.bin / "compose",
            f"""#!/usr/bin/env bash
if [[ " $* " == *" exec "* || " $* " == *" run "* ]]; then
  echo "compose ${{*:1:$#-1}} <snippet>" >> "{log}"
else echo "compose $*" >> "{log}"; fi
while [ "$1" = --env-file ] || [ "$1" = -f ]; do shift 2; done
case "$1" in
  ps) exit 0 ;;
  exec|run)
    echo "compose-mode $1" >> "{log}"
    shift
    while [ "$#" -gt 0 ]; do
      case "$1" in
        -T|--rm|--no-deps) shift ;;
        --entrypoint) shift 2 ;;
        -e) export "${{2?}}"; shift 2 ;;
        mysql) shift; break ;;
        *) shift ;;
      esac
    done
    # `run --entrypoint sh mysql -c SNIPPET` → "-c SNIPPET"; `exec mysql sh -c ...` → "sh -c ..."
    [ "$1" = -c ] && exec sh "$@"
    exec "$@" ;;
esac
exit 0
""",
        )

    def rule(self, pat: str, out: str = "", rc: int = 0) -> None:
        self.rules.append((pat, out, rc))

    def run(self, *args: str, **extra: str) -> subprocess.CompletedProcess:
        # Readiness probe always succeeds unless a test overrides it.
        rules = [*self.rules, ("SELECT 1 ", "1", 0)]
        def esc(out: str) -> str:
            return out.replace("\t", "\\t").replace("\n", "\\n")

        (self.tmp / "rules.txt").write_text(
            "".join(f"{p}\x1f{esc(o)}\x1f{rc}\n" for p, o, rc in rules)
        )
        env = {
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "HOME": str(self.tmp),
            "COMPOSE": str(self.bin / "compose"),
            "MYSQL_ROOT_PASSWORD": "rootpw",
            "MYSQL_DATABASE": "wg_manager",
            "MYSQL_REPL_PASSWORD": "abc123def",
            "REPL_READY_TIMEOUT_SECONDS": "2",
            "REPL_READY_INTERVAL_SECONDS": "0",
            **extra,
        }
        return subprocess.run(
            ["bash", str(REPL_SH), *args], env=env, capture_output=True,
            text=True, check=False,
        )

    def calls(self) -> str:
        return self.log.read_text() if self.log.exists() else ""


@pytest.fixture
def mb(tmp_path: Path) -> MysqlBox:
    return MysqlBox(tmp_path)


SOURCE_CFG = "replication_connection_configuration"


class TestPrimaryState:
    def test_not_a_replica(self, mb: MysqlBox) -> None:
        mb.rule(SOURCE_CFG, "")
        mb.rule("@@super_read_only", "0")
        mb.rule("COUNT(*)", "12")
        proc = mb.run("primary-state")
        assert proc.returncode == 0, proc.stderr
        assert "state=not-a-replica" in proc.stdout
        assert "local_read_only=0" in proc.stdout
        assert "local_tables=12" in proc.stdout

    def test_unreachable(self, mb: MysqlBox) -> None:
        mb.rule(SOURCE_CFG, "rv.vpn")
        mb.rule("-h rv.vpn", "", 1)
        proc = mb.run("primary-state")
        assert proc.returncode == 0, proc.stderr
        assert "state=unreachable" in proc.stdout
        assert "host=rv.vpn" in proc.stdout

    def test_writable(self, mb: MysqlBox) -> None:
        mb.rule(SOURCE_CFG, "rv.vpn")
        mb.rule("-h rv.vpn", "0\tu1:1-10")
        proc = mb.run("primary-state")
        assert "state=writable" in proc.stdout
        assert "gtid=u1:1-10" in proc.stdout

    def test_readonly_with_multi_uuid_gtid_set(self, mb: MysqlBox) -> None:
        # mysql -B prints the newline inside @@gtid_executed as a literal \n.
        mb.rule(SOURCE_CFG, "rv.vpn")
        mb.rule("-h rv.vpn", "1\tu1:1-5,\\\\nu2:1-3")
        proc = mb.run("primary-state")
        assert "state=readonly" in proc.stdout
        assert "gtid=u1:1-5,u2:1-3" in proc.stdout

    def test_probe_is_mutual_tls_with_timeout(self, mb: MysqlBox) -> None:
        mb.rule(SOURCE_CFG, "rv.vpn")
        mb.run("primary-state")
        probe = next(c for c in mb.calls().splitlines() if "-h rv.vpn" in c)
        for frag in ("-u wg_repl", "--ssl-mode=VERIFY_IDENTITY",
                     "--ssl-cert=/etc/mysql/certs/client.crt", "--connect-timeout="):
            assert frag in probe, frag
        assert "abc123def" not in probe  # password via MYSQL_PWD


class TestProbe:
    """`probe HOST`: is HOST a writable primary? Runs in a ONE-OFF mysql
    container, so it works even when this host's own mysqld is down."""

    def test_writable(self, mb: MysqlBox) -> None:
        mb.rule("-h general.vpn", "0\tu1:1-20")
        proc = mb.run("probe", "general.vpn")
        assert proc.returncode == 0, proc.stderr
        assert "state=writable" in proc.stdout
        assert "compose-mode run" in mb.calls()
        assert "compose-mode exec" not in mb.calls()

    def test_readonly(self, mb: MysqlBox) -> None:
        mb.rule("-h general.vpn", "1\tu1:1-20")
        assert "state=readonly" in mb.run("probe", "general.vpn").stdout

    def test_unreachable(self, mb: MysqlBox) -> None:
        mb.rule("-h general.vpn", "", 1)
        assert "state=unreachable" in mb.run("probe", "general.vpn").stdout

    def test_rejects_bad_host(self, mb: MysqlBox) -> None:
        assert mb.run("probe", "a b").returncode != 0
        assert "mysql" not in mb.calls()


class TestPromote:
    def _replica(self, mb: MysqlBox) -> None:
        mb.rule("COUNT(*)", "12")
        mb.rule("SHOW REPLICA STATUS", "rv.vpn\twg_repl")
        mb.rule("RECEIVED_TRANSACTION_SET", "u1:1-9")
        mb.rule("WAIT_FOR_EXECUTED_GTID_SET", "0")

    def test_planned_waits_for_primary_gtids_then_promotes(self, mb: MysqlBox) -> None:
        self._replica(mb)
        proc = mb.run("promote", WAIT_GTID="u1:1-10")
        assert proc.returncode == 0, proc.stderr
        calls = mb.calls()
        order = [
            "WAIT_FOR_EXECUTED_GTID_SET('u1:1-10'",
            "STOP REPLICA IO_THREAD",
            "STOP REPLICA ",
            "RESET REPLICA ALL",
            "SET PERSIST super_read_only=OFF",
            "SET PERSIST read_only=OFF",
        ]
        pos = [calls.index(s) for s in order]
        assert pos == sorted(pos), calls

    def test_planned_wait_timeout_aborts(self, mb: MysqlBox) -> None:
        self._replica(mb)
        mb.rules.insert(0, ("WAIT_FOR_EXECUTED_GTID_SET('u1:1-10'", "1", 0))
        proc = mb.run("promote", WAIT_GTID="u1:1-10")
        assert proc.returncode != 0
        assert "STOP REPLICA" not in mb.calls()

    def test_unplanned_applies_everything_received(self, mb: MysqlBox) -> None:
        self._replica(mb)
        proc = mb.run("promote")
        assert proc.returncode == 0, proc.stderr
        calls = mb.calls()
        assert calls.index("STOP REPLICA IO_THREAD") < calls.index(
            "WAIT_FOR_EXECUTED_GTID_SET('u1:1-9'"
        ) < calls.index("RESET REPLICA ALL")

    def test_resumes_when_already_promoted(self, mb: MysqlBox) -> None:
        mb.rule("COUNT(*)", "12")
        mb.rule("SHOW REPLICA STATUS", "")
        mb.rule("@@super_read_only", "0")
        proc = mb.run("promote")
        assert proc.returncode == 0, proc.stderr
        assert "already promoted" in proc.stdout
        assert "RESET REPLICA" not in mb.calls()

    def test_refuses_empty_database(self, mb: MysqlBox) -> None:
        # A never-seeded standby is "not a replica, writable" too — it
        # must never be mistaken for an already-promoted one.
        mb.rule("SHOW REPLICA STATUS", "")
        mb.rule("@@super_read_only", "0")
        mb.rule("COUNT(*)", "0")
        proc = mb.run("promote")
        assert proc.returncode != 0
        assert "SET PERSIST" not in mb.calls()

    def test_promotes_a_configured_replica_even_if_empty(self, mb: MysqlBox) -> None:
        # Whether it was seeded is the replication config's call, not the
        # table count: a primary with an empty database is legitimate.
        self._replica(mb)
        mb.rules.insert(0, ("COUNT(*)", "0", 0))
        proc = mb.run("promote")
        assert proc.returncode == 0, proc.stderr
        assert "RESET REPLICA ALL" in mb.calls()

    @pytest.mark.parametrize("bad", ["u1:1-5'; DROP", "u1 1"])
    def test_rejects_malformed_gtid(self, mb: MysqlBox, bad: str) -> None:
        self._replica(mb)
        proc = mb.run("promote", WAIT_GTID=bad)
        assert proc.returncode != 0
        assert "WAIT_FOR" not in mb.calls()


class TestDemoteDb:
    def test_persists_read_only(self, mb: MysqlBox) -> None:
        mb.rule("@@gtid_executed", "u1:1-10")
        proc = mb.run("demote")
        assert proc.returncode == 0, proc.stderr
        assert "SET PERSIST super_read_only=ON" in mb.calls()
        assert "gtid=u1:1-10" in proc.stdout


class TestRejoin:
    def _standby_mode(self, mb: MysqlBox) -> None:
        mb.rule("@@server_id", "2")
        mb.rule("SHOW REPLICA STATUS", "")
        mb.rule("@@super_read_only", "1")
        mb.rule("-h general.vpn", "u1:1-20,u2:1-4")
        mb.rule("SELECT @@gtid_executed", "u1:1-20")

    def test_rejoins_when_subset(self, mb: MysqlBox) -> None:
        self._standby_mode(mb)
        mb.rule("GTID_SUBSET", "1")
        proc = mb.run("rejoin", "general.vpn")
        assert proc.returncode == 0, proc.stderr
        calls = mb.calls()
        assert "GTID_SUBSET('u1:1-20', 'u1:1-20,u2:1-4')" in calls
        assert "SOURCE_HOST='general.vpn'" in calls
        assert calls.index("SET PERSIST super_read_only=ON") < calls.index("START REPLICA")

    def test_refuses_errant_transactions(self, mb: MysqlBox) -> None:
        self._standby_mode(mb)
        mb.rule("GTID_SUBSET", "0")
        mb.rule("GTID_SUBTRACT", "u1:21-22")
        proc = mb.run("rejoin", "general.vpn")
        assert proc.returncode != 0
        assert "u1:21-22" in proc.stderr
        assert "Re-seeding" in proc.stderr
        assert "CHANGE REPLICATION" not in mb.calls()
        # Left read-only: it's a standby now, just not replicating.
        assert "SET PERSIST super_read_only=ON" in mb.calls()

    def test_makes_a_writable_host_read_only_first(self, mb: MysqlBox) -> None:
        # After an UNPLANNED failover the old primary was never demoted:
        # its MySQL comes back writable. Rejoin must handle that itself
        # (live-drill design finding), read-only before anything else.
        mb.rule("@@server_id", "2")
        mb.rule("SHOW REPLICA STATUS", "")
        mb.rule("@@super_read_only", "0")
        mb.rule("-h general.vpn", "u1:1-20")
        mb.rule("SELECT @@gtid_executed", "u1:1-20")
        mb.rule("GTID_SUBSET", "1")
        proc = mb.run("rejoin", "general.vpn")
        assert proc.returncode == 0, proc.stderr
        calls = mb.calls()
        assert calls.index("SET PERSIST super_read_only=ON") < calls.index("GTID_SUBSET")
        assert "START REPLICA" in calls

    def test_refuses_primary_flags(self, mb: MysqlBox) -> None:
        mb.rule("@@server_id", "1")
        proc = mb.run("rejoin", "general.vpn")
        assert proc.returncode != 0
        assert "standby-up" in proc.stderr

    def test_noop_when_already_following_host(self, mb: MysqlBox) -> None:
        mb.rule("@@server_id", "2")
        mb.rule("@@super_read_only", "1")
        mb.rule("SHOW REPLICA STATUS", "general.vpn\twg_repl")
        mb.rule(SOURCE_CFG, "general.vpn")
        proc = mb.run("rejoin", "general.vpn")
        assert proc.returncode == 0, proc.stderr
        assert "already" in proc.stdout.lower()
        assert "CHANGE REPLICATION" not in mb.calls()

    def test_rejects_bad_host(self, mb: MysqlBox) -> None:
        proc = mb.run("rejoin", "general.vpn;x")
        assert proc.returncode != 0
        assert "mysql" not in mb.calls()


# ---------------------------------------------------------------------------
# vault_restore.py
# ---------------------------------------------------------------------------


class FakeVault:
    """Stateful fake of the endpoints vault_restore.py uses.

    Keys: the "shipped" Vault (the snapshot's lineage) unseals with
    ``shipped-key`` and answers ``shipped-root``. A throwaway init yields
    ``tmp-key`` / ``tmp-root``. A restore switches the keyring to the
    shipped one and seals (``seal_after_restore``).
    """

    def __init__(self, initialized: bool, sealed: bool) -> None:
        self.initialized = initialized
        self.sealed = sealed
        self.keyring = "shipped" if initialized else None
        self.seal_after_restore = True
        self.restore_status = 204
        self.mounts = {"ssh/": {}, "pki/": {}, "transit/": {}}
        self.restored: bytes | None = None
        self.log: list[str] = []
        # Raft needs a moment after an unseal to elect itself leader:
        # sys/health answers 429 (standby) this many times first, and a
        # restore posted meanwhile fails with HTTP 500 (5d live drill).
        self.activation_polls = 0
        self._pending = 0
        # A real restore re-seals Vault ASYNCHRONOUSLY: for this many
        # status polls after the restore it still looks unsealed, then it
        # seals (5d live drill: the script saw "unsealed", moved on, and
        # waited forever on a sealed Vault).
        self.seal_lag_polls = 0
        self._seal_in = -1
        # A restored-but-not-restarted Vault keeps the throwaway's seal
        # config in memory: the shipped (Shamir) keys are rejected with
        # "invalid key size 33" until the server restarts (5d live drill).
        self.stale_seal_config = False
        fv = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_a) -> None:
                pass

            def _json(self, code: int, body: dict | None = None) -> None:
                data = json.dumps(body or {}).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _tok(self) -> str:
                return self.headers.get("X-Vault-Token", "")

            def _body(self) -> bytes:
                return self.rfile.read(int(self.headers.get("Content-Length", 0)))

            def do_GET(self) -> None:
                fv.log.append(f"GET {self.path} tok={self._tok()}")
                if fv._seal_in > 0:
                    fv._seal_in -= 1
                elif fv._seal_in == 0:
                    fv.sealed, fv._seal_in = True, -1
                if self.path.startswith("/v1/sys/health"):
                    if not fv.initialized:
                        self._json(501)
                    elif fv.sealed:
                        self._json(503)
                    elif fv._pending > 0:
                        fv._pending -= 1
                        self._json(429)
                    else:
                        self._json(200, {"initialized": True, "sealed": False})
                elif self.path == "/v1/sys/init":
                    self._json(200, {"initialized": fv.initialized})
                elif self.path == "/v1/sys/seal-status":
                    self._json(200, {"sealed": fv.sealed, "initialized": fv.initialized})
                elif self.path == "/v1/sys/mounts":
                    if fv.sealed:
                        self._json(503)
                    elif self._tok() != f"{fv.keyring}-root":
                        self._json(403)
                    else:
                        self._json(200, {"data": fv.mounts})
                else:
                    self._json(404)

            def do_PUT(self) -> None:
                body = self._body()
                fv.log.append(f"PUT {self.path} tok={self._tok()} body={body[:60]!r}")
                if self.path == "/v1/sys/init":
                    fv.initialized, fv.keyring = True, "tmp"
                    self._json(200, {"keys_base64": ["tmp-key"], "root_token": "tmp-root"})
                elif self.path == "/v1/sys/unseal":
                    key = json.loads(body)["key"]
                    if fv.stale_seal_config:
                        msg = (
                            "invalid key: failed to setup unseal key: "
                            "crypto/aes: invalid key size 33"
                        )
                        self._json(400, {"errors": [msg]})
                        return
                    if key == f"{fv.keyring}-key" and fv.sealed:
                        fv.sealed = False
                        fv._pending = fv.activation_polls
                    self._json(200, {"sealed": fv.sealed})
                else:
                    self._json(404)

            def do_POST(self) -> None:
                body = self._body()
                fv.log.append(f"POST {self.path} tok={self._tok()} len={len(body)}")
                if self.path != "/v1/sys/storage/raft/snapshot-force":
                    self._json(404)
                elif fv.sealed or self._tok() != f"{fv.keyring}-root":
                    self._json(403)
                elif fv._pending > 0:
                    msg = "local node not active but active cluster node not found"
                    self._json(500, {"errors": [msg]})
                elif fv.restore_status != 204:
                    self._json(fv.restore_status)
                else:
                    fv.restored = body
                    fv.keyring = "shipped"
                    fv.stale_seal_config = True
                    if fv.seal_after_restore and fv.seal_lag_polls:
                        fv._seal_in = fv.seal_lag_polls
                    else:
                        fv.sealed = fv.seal_after_restore
                    self.send_response(204)
                    self.end_headers()

        self.server = http.server.HTTPServer(("127.0.0.1", 0), H)
        self.addr = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def restart(self) -> None:
        """What `compose restart vault` does: sealed, seal config reloaded."""
        self.sealed, self.stale_seal_config, self._seal_in = True, False, -1

    def close(self) -> None:
        self.server.shutdown()


@pytest.fixture
def init_file(tmp_path: Path) -> Path:
    f = tmp_path / "vault-init.json"
    f.write_text(json.dumps({"unseal_keys_b64": ["shipped-key"], "root_token": "shipped-root"}))
    return f


def _restore(
    fv: FakeVault, init_file: Path, snap: bytes, cwd: Path, *args: str
) -> subprocess.CompletedProcess:
    env = {
        **os.environ,
        "VAULT_ADDR": fv.addr,
        "VAULT_INIT_FILE": str(init_file),
        # What the entrypoint shim exports from the (shipped) init file.
        "VAULT_TOKEN": "shipped-root",
    }
    return subprocess.run(
        [sys.executable, str(RESTORE_PY), *args], input=snap, env=env, cwd=cwd,
        capture_output=True, check=False,
    )


class TestVaultRestore:
    @pytest.mark.parametrize(
        ("initialized", "sealed"), [(False, True), (True, True), (True, False)]
    )
    def test_restore_then_restart_then_verify(
        self, initialized: bool, sealed: bool, init_file: Path, tmp_path: Path
    ) -> None:
        fv = FakeVault(initialized, sealed)
        try:
            proc = _restore(fv, init_file, b"SNAP" * 1000, tmp_path)
            assert proc.returncode == 0, proc.stderr
            assert fv.restored == b"SNAP" * 1000
            # Phase 1 must NOT try to unseal against the stale seal config.
            after = fv.log[fv.log.index(next(e for e in fv.log if "snapshot-force" in e)):]
            assert not any("/v1/sys/unseal" in e for e in after)
            assert b"restart" in (proc.stdout + proc.stderr).lower()

            fv.restart()
            proc = _restore(fv, init_file, b"", tmp_path, "--verify")
        finally:
            fv.close()
        assert proc.returncode == 0, proc.stderr
        assert not fv.sealed and fv.keyring == "shipped"
        assert b"ssh/" in proc.stdout

    def test_waits_for_raft_to_become_active(self, init_file: Path, tmp_path: Path) -> None:
        fv = FakeVault(initialized=False, sealed=True)
        fv.activation_polls = 3
        try:
            proc = _restore(fv, init_file, b"S", tmp_path)
        finally:
            fv.close()
        assert proc.returncode == 0, proc.stderr
        assert fv.restored == b"S"
        health = [e for e in fv.log if e.startswith("GET /v1/sys/health")]
        assert len(health) >= 4  # waited through the 429s

    @pytest.mark.parametrize("lag", [1, 2, 3])
    def test_verify_handles_late_sealing(
        self, init_file: Path, tmp_path: Path, lag: int
    ) -> None:
        fv = FakeVault(initialized=True, sealed=False)
        fv.seal_lag_polls = lag
        fv._seal_in = lag
        try:
            proc = _restore(fv, init_file, b"", tmp_path, "--verify")
        finally:
            fv.close()
        assert proc.returncode == 0, proc.stderr

    def test_throwaway_only_for_uninitialized(self, init_file: Path, tmp_path: Path) -> None:
        fv = FakeVault(initialized=True, sealed=True)
        try:
            _restore(fv, init_file, b"S", tmp_path)
        finally:
            fv.close()
        assert not any(e.startswith("PUT /v1/sys/init") for e in fv.log)

    def test_throwaway_keys_never_touch_disk(self, init_file: Path, tmp_path: Path) -> None:
        work = tmp_path / "w"
        work.mkdir()
        before = init_file.read_text()
        fv = FakeVault(initialized=False, sealed=True)
        try:
            proc = _restore(fv, init_file, b"S", work)
        finally:
            fv.close()
        assert proc.returncode == 0, proc.stderr
        assert init_file.read_text() == before
        assert list(work.iterdir()) == []
        assert b"tmp-root" not in proc.stdout + proc.stderr
        assert b"tmp-key" not in proc.stdout + proc.stderr

    def test_empty_snapshot_refused_before_touching_vault(
        self, init_file: Path, tmp_path: Path
    ) -> None:
        fv = FakeVault(initialized=False, sealed=True)
        try:
            proc = _restore(fv, init_file, b"", tmp_path)
        finally:
            fv.close()
        assert proc.returncode != 0
        assert fv.log == []

    def test_restore_error_fails(self, init_file: Path, tmp_path: Path) -> None:
        fv = FakeVault(initialized=True, sealed=False)
        fv.restore_status = 400
        try:
            proc = _restore(fv, init_file, b"S", tmp_path)
        finally:
            fv.close()
        assert proc.returncode != 0

    def test_verification_needs_the_engines(self, init_file: Path, tmp_path: Path) -> None:
        fv = FakeVault(initialized=True, sealed=False)
        fv.mounts = {"sys/": {}}
        try:
            proc = _restore(fv, init_file, b"", tmp_path, "--verify")
        finally:
            fv.close()
        assert proc.returncode != 0
        assert b"ssh/" in proc.stderr


# ---------------------------------------------------------------------------
# failover.sh orchestration
# ---------------------------------------------------------------------------


class Host:
    """A checkout with fakes for the MySQL script, make, compose, docker."""

    def __init__(self, tmp: Path, role: str = "standby") -> None:
        self.tmp = tmp
        self.log = tmp / "calls.log"
        self.bin = tmp / "bin"
        self.bin.mkdir()
        self.repo = tmp / "wg_manager"
        (self.repo / "standby").mkdir(parents=True)
        (self.repo / "standby" / "vault.snap").write_bytes(b"SNAP")
        (self.repo / "standby" / "MANIFEST").write_text("format=1\n")
        (self.repo / "vault-init.json").write_text('{"root_token":"r"}')
        (self.repo / ".env.host").write_text(
            f"WG_MANAGER_ROLE={role}\nMYSQL_BIND_ADDR=10.0.0.2\n"
            "STANDBY_PRIMARY_SSH=ops@rv.vpn\n"
        )
        self.state = "state=unreachable\nhost=rv.vpn\n"
        self.probe = "state=writable\ngtid=u1:1-20\n"
        self.fail: str = ""  # a call substring that should exit 1
        log = self.log
        _exe(
            self.bin / "repl",
            f"""#!/usr/bin/env bash
echo "repl $* WAIT_GTID=${{WAIT_GTID:-}}" >> "{log}"
[ -n "$FAKE_FAIL" ] && [[ "repl $*" == *"$FAKE_FAIL"* ]] && exit 1
[ "$1" = primary-state ] && printf '%b' "$FAKE_STATE"
[ "$1" = probe ] && printf '%b' "$FAKE_PROBE"
exit 0
""",
        )
        for name in ("make", "compose"):
            _exe(
                self.bin / name,
                f"""#!/usr/bin/env bash
if [ "{name}" = compose ] && [[ "$*" == *vault_restore.py* ]]; then
  echo "{name} $* stdin=$(cat)" >> "{log}"
else
  echo "{name} $*" >> "{log}"
fi
[ -n "$FAKE_FAIL" ] && [[ "{name} $*" == *"$FAKE_FAIL"* ]] && exit 1
exit 0
""",
            )
        # docker fake: helper `test -s` on vault-init.json succeeds iff non-empty.
        _exe(
            self.bin / "docker",
            f"""#!/usr/bin/env bash
echo "docker $*" >> "{log}"
if [[ "$*" == *"test -s /src/vault-init.json"* ]]; then
  [ -s "{self.repo}/vault-init.json" ]; exit $?
fi
exit 0
""",
        )

    def run(self, *args: str, **extra: str) -> subprocess.CompletedProcess:
        env = {
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "HOME": str(self.tmp),
            "REPO_DIR": str(self.repo),
            "COMPOSE": str(self.bin / "compose"),
            "MAKE": str(self.bin / "make"),
            "DOCKER": str(self.bin / "docker"),
            "MYSQL_REPL_SCRIPT": str(self.bin / "repl"),
            "FAKE_STATE": self.state,
            "FAKE_PROBE": self.probe,
            "FAKE_FAIL": self.fail,
            **extra,
        }
        return subprocess.run(
            ["bash", str(FAILOVER_SH), *args], env=env, capture_output=True,
            text=True, check=False,
        )

    def calls(self) -> str:
        return self.log.read_text() if self.log.exists() else ""

    def role(self) -> str:
        m = re.search(r"^WG_MANAGER_ROLE=(\w+)", (self.repo / ".env.host").read_text(), re.M)
        return m.group(1) if m else ""


@pytest.fixture
def host(tmp_path: Path) -> Host:
    return Host(tmp_path)


def _order(calls: str, *needles: str) -> None:
    pos = [calls.index(n) for n in needles]
    assert pos == sorted(pos), calls


class TestFailover:
    def test_refuses_writable_primary(self, host: Host) -> None:
        host.state = "state=writable\nhost=rv.vpn\ngtid=u1:1-9\n"
        proc = host.run("failover", CONFIRM="primary-is-down")
        assert proc.returncode != 0
        assert "make demote" in proc.stderr
        assert "promote" not in host.calls()
        assert host.role() == "standby"

    def test_unplanned_needs_confirmation(self, host: Host) -> None:
        proc = host.run("failover")
        assert proc.returncode != 0
        assert "confirm=primary-is-down" in proc.stderr
        assert "promote" not in host.calls()

    def test_unplanned_full_sequence(self, host: Host) -> None:
        proc = host.run("failover", CONFIRM="primary-is-down")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        calls = host.calls()
        _order(
            calls,
            "repl primary-state",
            "repl promote WAIT_GTID=\n",
            "up -d --no-deps --wait vault",
            "vault_restore.py stdin=SNAP",
            "compose restart vault",
            "vault_restore.py --verify",
            "make prod-up",
            "make repl-primary-setup",
        )
        assert "standby-pull" not in calls  # primary is down: nothing to pull
        assert host.role() == "primary"
        env_host = (host.repo / ".env.host").read_text()
        assert "MYSQL_BIND_ADDR=10.0.0.2" in env_host  # other keys kept
        assert "DNS" in proc.stdout  # tells the operator to move the name

    def test_planned_pulls_then_waits_for_gtids(self, host: Host) -> None:
        host.state = "state=readonly\nhost=rv.vpn\ngtid=u1:1-10\n"
        proc = host.run("failover")  # no confirmation needed
        assert proc.returncode == 0, proc.stdout + proc.stderr
        _order(host.calls(), "make standby-pull", "repl promote WAIT_GTID=u1:1-10",
               "vault_restore.py", "make prod-up")

    def test_planned_aborts_if_final_pull_fails(self, host: Host) -> None:
        host.state = "state=readonly\nhost=rv.vpn\ngtid=u1:1-10\n"
        host.fail = "make standby-pull"
        proc = host.run("failover")
        assert proc.returncode != 0
        assert "promote" not in host.calls()
        assert host.role() == "standby"

    def test_resumes_after_promotion(self, host: Host) -> None:
        host.state = "state=not-a-replica\nlocal_read_only=0\nlocal_tables=12\n"
        proc = host.run("failover")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "resuming" in proc.stdout
        assert "vault_restore.py" in host.calls()

    def test_refuses_never_seeded_standby(self, host: Host) -> None:
        host.state = "state=not-a-replica\nlocal_read_only=0\nlocal_tables=0\n"
        proc = host.run("failover", CONFIRM="primary-is-down")
        assert proc.returncode != 0
        assert "vault_restore" not in host.calls()

    def test_needs_snapshot(self, host: Host) -> None:
        (host.repo / "standby" / "vault.snap").unlink()
        proc = host.run("failover", CONFIRM="primary-is-down")
        assert proc.returncode != 0
        assert "standby-pull" in proc.stderr
        assert "primary-state" not in host.calls()

    def test_needs_vault_init(self, host: Host) -> None:
        (host.repo / "vault-init.json").write_text("")
        proc = host.run("failover", CONFIRM="primary-is-down")
        assert proc.returncode != 0
        assert "promote" not in host.calls()

    def test_vault_restore_failure_keeps_standby_role(self, host: Host) -> None:
        host.fail = "vault_restore.py"
        proc = host.run("failover", CONFIRM="primary-is-down")
        assert proc.returncode != 0
        assert host.role() == "standby"
        assert "make prod-up" not in host.calls()
        assert "make failover" in proc.stderr  # re-run resumes

    def test_prod_up_failure_says_how_to_finish(self, host: Host) -> None:
        host.fail = "make prod-up"
        proc = host.run("failover", CONFIRM="primary-is-down")
        assert proc.returncode != 0
        assert host.role() == "primary"
        assert "make prod-up && make repl-primary-setup" in proc.stderr


@pytest.fixture
def primary(tmp_path: Path) -> Host:
    return Host(tmp_path, role="primary")


class TestDemoteHost:
    def test_sequence(self, primary: Host) -> None:
        proc = primary.run("demote")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        calls = primary.calls()
        # rm -s -f, not stop: a stopped `restart: always` container comes
        # back when the Docker daemon restarts (e.g. a reboot).
        _order(calls, "compose rm -s -f api worker beat web enroll", "repl demote")
        assert "stop mysql" not in calls and "stop vault" not in calls
        assert primary.role() == "primary"  # flipped by rejoin, not here
        assert "make failover" in proc.stdout


class TestRejoinHost:
    def test_sequence(self, primary: Host) -> None:
        proc = primary.run("rejoin", "general.vpn")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        calls = primary.calls()
        _order(
            calls,
            "repl probe general.vpn",
            "compose rm -s -f api worker beat web enroll vault",
            "make standby-up",
            "repl rejoin general.vpn",
        )
        assert primary.role() == "standby"

    @pytest.mark.parametrize("state", ["state=readonly\n", "state=unreachable\n"])
    def test_refuses_unless_host_is_a_writable_primary(
        self, primary: Host, state: str
    ) -> None:
        # Guards running rejoin on the wrong host or with a typo'd name:
        # nothing is torn down unless HOST really is the new primary.
        primary.probe = state
        proc = primary.run("rejoin", "general.vpn")
        assert proc.returncode != 0
        assert "compose rm" not in primary.calls()
        assert primary.role() == "primary"

    def test_warns_when_pull_source_differs(self, primary: Host) -> None:
        proc = primary.run("rejoin", "general.vpn")
        # .env.host still pulls from rv.vpn — it must now pull from general.
        assert "STANDBY_PRIMARY_SSH" in proc.stdout + proc.stderr

    def test_no_warning_when_pull_source_is_the_new_primary(self, primary: Host) -> None:
        # The SSH name and the MySQL name can differ (`general` vs
        # `general.vpn`): compare the first DNS label (5d live drill).
        env_host = primary.repo / ".env.host"
        env_host.write_text(env_host.read_text().replace("ops@rv.vpn", "ops@general"))
        proc = primary.run("rejoin", "general.vpn")
        assert proc.returncode == 0, proc.stderr
        assert "WARNING" not in proc.stdout + proc.stderr

    def test_rejects_bad_host(self, primary: Host) -> None:
        proc = primary.run("rejoin", "general vpn")
        assert proc.returncode != 0
        assert primary.calls() == ""


# ---------------------------------------------------------------------------
# Makefile + docs
# ---------------------------------------------------------------------------


class TestMakefile:
    def _mk(self, tmp: Path, role: str, *args: str) -> subprocess.CompletedProcess:
        shutil.copy(MAKEFILE, tmp / "Makefile")
        (tmp / ".env.host").write_text(f"WG_MANAGER_ROLE={role}\n")
        (tmp / "scripts").mkdir(exist_ok=True)
        _exe(tmp / "scripts" / "failover.sh", '#!/bin/sh\necho "failover.sh $* CONFIRM=$CONFIRM"\n')
        return subprocess.run(
            ["make", "--no-print-directory", "-C", str(tmp), *args],
            capture_output=True, text=True, check=False,
        )

    def test_targets_documented(self) -> None:
        mk = MAKEFILE.read_text()
        phony = next(line for line in mk.splitlines() if line.startswith(".PHONY:"))
        help_block = mk.split("help:", 1)[1].split("\n\n", 1)[0]
        for target in ("failover", "demote", "rejoin"):
            assert re.search(rf"^{target}:", mk, re.MULTILINE), target
            assert target in phony.split(), target
            assert target in help_block, target

    def test_failover_only_on_standby(self, tmp_path: Path) -> None:
        assert self._mk(tmp_path, "primary", "failover").returncode != 0

    def test_failover_passes_confirmation(self, tmp_path: Path) -> None:
        proc = self._mk(tmp_path, "standby", "failover", "confirm=primary-is-down")
        assert proc.returncode == 0, proc.stderr
        assert "failover.sh failover CONFIRM=primary-is-down" in proc.stdout

    def test_demote_only_on_primary(self, tmp_path: Path) -> None:
        assert self._mk(tmp_path, "standby", "demote").returncode != 0
        proc = self._mk(tmp_path, "primary", "demote")
        assert "failover.sh demote" in proc.stdout

    def test_rejoin_needs_primary_arg(self, tmp_path: Path) -> None:
        proc = self._mk(tmp_path, "primary", "rejoin")
        assert proc.returncode != 0
        assert "primary=" in proc.stdout + proc.stderr
        proc = self._mk(tmp_path, "primary", "rejoin", "primary=general.vpn")
        assert "failover.sh rejoin general.vpn" in proc.stdout


class TestDocs:
    def test_planned_switchover_covers_the_drill_findings(self) -> None:
        # The first rv <-> general drill (2026-10-09) needed four steps the
        # runbook didn't list. Each one breaks or stalls a switchover.
        text = (REPO_ROOT / "docs" / "runbooks" / "failover.md").read_text()
        start, end = text.index("## Planned switchover"), text.index("## Unplanned failover")
        section = text[start:end].lower()
        for needle in (
            "configuration management",  # Chef/Ansible rewriting .env.host mid-failover
            "pull key",                  # the failback needs the reverse pull path
            "silence",                   # the standby alerts fire while roles are swapped
            "ttl",                       # the DNS move takes effect only as fast as caches expire
        ):
            assert needle in section, needle

    def test_failover_runbook(self) -> None:
        text = (REPO_ROOT / "docs" / "runbooks" / "failover.md").read_text()
        for needle in (
            "make demote",
            "make failover",
            "confirm=primary-is-down",
            "make rejoin primary=",
            "API_SERVER_SANS",
            "split-brain",
        ):
            assert needle in text, needle
