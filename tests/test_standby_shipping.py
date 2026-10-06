"""Tests for Phase 3d cycle 5c — shipping state from the primary to the standby.

The warm standby needs more than the MySQL replica (5b) to take over:
the primary's Vault (as a raft snapshot) plus the files that unlock and
talk to it — ``vault-init.json``, ``.env.prod``, ``tls/``. Pieces under
test:

* ``scripts/vault_snapshot.py`` — streams ``GET
  /v1/sys/storage/raft/snapshot`` to stdout. Runs in a throwaway
  ``bootstrap-app`` container on the primary, where the entrypoint shim
  exports the root token, so the token never reaches the host.
* ``scripts/standby_bundle.sh`` (``make standby-bundle``, primary) —
  snapshot + ``files.tar`` + ``MANIFEST`` + ``SHA256SUMS``, as one tar.
* ``scripts/standby_pull.sh`` (``make standby-pull``, standby) — fetch
  the bundle over SSH, verify, refuse stale/replayed bundles, install,
  restart the replica only when ``tls/mysql`` changed; ``status``
  reports bundle age and code drift.

The SSH fake runs the REAL bundle script in a sandboxed "primary"
checkout, so pull tests exercise the full producer → consumer path.
Docker/compose fakes run helper ``tar`` invocations for real on the
host (bind-mount paths swapped), as in ``test_migrate_host.py``. The
live round trip (real Vault, real snapshot restore) is the drill in
``docs/runbooks/standby-replication.md``.
"""

from __future__ import annotations

import hashlib
import http.server
import io
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import threading
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_PY = REPO_ROOT / "scripts" / "vault_snapshot.py"
BUNDLE_SH = REPO_ROOT / "scripts" / "standby_bundle.sh"
PULL_SH = REPO_ROOT / "scripts" / "standby_pull.sh"
MAKEFILE = REPO_ROOT / "Makefile"


def _exe(path: Path, body: str) -> Path:
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _git_checkout(path: Path) -> str:
    """Make ``path`` a git checkout with one commit; return its HEAD."""
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
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()


# ---------------------------------------------------------------------------
# vault_snapshot.py
# ---------------------------------------------------------------------------


class _FakeVault:
    """Serves GET /v1/sys/storage/raft/snapshot."""

    def __init__(self, status: int = 200, body: bytes = b"") -> None:
        fake = self
        self.status = status
        self.body = body
        self.seen_token: str | None = None

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_a) -> None:
                pass

            def do_GET(self) -> None:
                fake.seen_token = self.headers.get("X-Vault-Token")
                if self.path != "/v1/sys/storage/raft/snapshot":
                    self.send_response(404)
                    self.end_headers()
                    return
                data = fake.body if fake.status == 200 else b'{"errors":["permission denied"]}'
                self.send_response(fake.status)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.addr = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()


def _snapshot(addr: str, token: str | None) -> subprocess.CompletedProcess:
    env = {**os.environ, "VAULT_ADDR": addr}
    env.pop("VAULT_TOKEN", None)
    if token is not None:
        env["VAULT_TOKEN"] = token
    return subprocess.run(
        [sys.executable, str(SNAPSHOT_PY)], env=env, capture_output=True, check=False
    )


class TestVaultSnapshot:
    def test_streams_snapshot_bytes_with_token(self) -> None:
        body = os.urandom(300_000)  # bigger than one read chunk
        fv = _FakeVault(body=body)
        try:
            proc = _snapshot(fv.addr, "root-tok")
        finally:
            fv.close()
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout == body
        assert fv.seen_token == "root-tok"

    def test_fails_loudly_on_http_error(self) -> None:
        fv = _FakeVault(status=403)
        try:
            proc = _snapshot(fv.addr, "bad")
        finally:
            fv.close()
        assert proc.returncode != 0
        assert proc.stdout == b""
        assert b"403" in proc.stderr

    def test_fails_on_empty_snapshot(self) -> None:
        fv = _FakeVault(body=b"")
        try:
            proc = _snapshot(fv.addr, "tok")
        finally:
            fv.close()
        assert proc.returncode != 0

    def test_requires_token(self) -> None:
        proc = _snapshot("http://127.0.0.1:1", None)
        assert proc.returncode != 0
        assert b"VAULT_TOKEN" in proc.stderr


# ---------------------------------------------------------------------------
# Shared sandbox: a "primary" checkout and a "standby" checkout.
# ---------------------------------------------------------------------------


class Pair:
    """Two checkouts plus fakes for docker, compose and ssh.

    * docker fake — ``run ... -v SRC:DST[:ro] IMAGE CMD...`` runs CMD on
      the host with DST swapped for SRC in every argument (so helper
      ``tar``/``sh`` really read and write the checkout).
    * compose fake — ``run ... bootstrap-app python
      /app/scripts/vault_snapshot.py`` prints ``$FAKE_SNAPSHOT``;
      ``ps --services --status running`` prints ``$FAKE_RUNNING``;
      everything is logged.
    * ssh fake — runs the remote command with bash inside the primary
      checkout, i.e. the REAL ``make standby-bundle`` path; set
      ``corrupt`` to flip a byte of the bundle in transit.
    """

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.log = tmp / "calls.log"
        self.bin = tmp / "bin"
        self.bin.mkdir()
        self.primary = tmp / "home" / "wg_manager"
        self.standby = tmp / "standby" / "wg_manager"
        self.primary_head = _git_checkout(self.primary)
        self.standby_head = _git_checkout(self.standby)
        # The standby must run the same commit; copy the primary's .git.
        shutil.rmtree(self.standby / ".git")
        shutil.copytree(self.primary / ".git", self.standby / ".git")
        self.standby_head = self.primary_head
        shutil.copy(MAKEFILE, self.primary / "Makefile")
        (self.primary / "scripts").mkdir()
        shutil.copy(BUNDLE_SH, self.primary / "scripts" / "standby_bundle.sh")
        self.seed_primary_files()
        (self.primary / ".env.host").write_text("WG_MANAGER_ROLE=primary\n")
        (self.standby / ".env.host").write_text(
            "WG_MANAGER_ROLE=standby\n"
            "STANDBY_PRIMARY_SSH=ops@rv.vpn\n"
            "STANDBY_PRIMARY_DIR=wg_manager\n"
        )
        self.snapshot = "SNAPSHOT-v1"
        self.running = "mysql\n"
        self.corrupt = False
        self._fakes()

    def seed_primary_files(self, tls_mysql: str = "cert-v1") -> None:
        p = self.primary
        (p / ".env.prod").write_text("MYSQL_ROOT_PASSWORD=x\n")
        (p / "vault-init.json").write_text('{"root_token":"rv-root","unseal_keys_b64":["k"]}')
        (p / "tls" / "mysql").mkdir(parents=True, exist_ok=True)
        (p / "tls" / "mysql" / "client.crt").write_text(tls_mysql)
        (p / "tls" / "server.crt").write_text("api-cert")

    def _fakes(self) -> None:
        log = self.log
        _exe(
            self.bin / "docker",
            f"""#!/usr/bin/env bash
echo "docker $*" >> "{log}"
[ "$1" = run ] || exit 0
shift; src=""; dst=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -v) IFS=: read -r src dst _ <<< "$2"; shift 2 ;;
    -*) shift ;;
    *) shift; break ;;   # the image; the rest is the command
  esac
done
cmd=(); for a in "$@"; do cmd+=("${{a//$dst/$src}}"); done
exec "${{cmd[@]}}"
""",
        )
        _exe(
            self.bin / "compose",
            f"""#!/usr/bin/env bash
echo "compose $*" >> "{log}"
while [ "$1" = --env-file ] || [ "$1" = -f ]; do shift 2; done
case "$*" in
  *"vault_snapshot.py"*) printf '%s' "$FAKE_SNAPSHOT"; exit 0 ;;
  "ps --services --status running") printf '%s' "$FAKE_RUNNING"; exit 0 ;;
esac
exit 0
""",
        )
        # ssh fake: last arg is the remote command; run it in $HOME of
        # the primary (the home dir holding wg_manager/).
        _exe(
            self.bin / "ssh",
            f"""#!/usr/bin/env bash
echo "ssh $*" >> "{log}"
remote="${{@: -1}}"
cd "{self.primary.parent}" || exit 1
# Real ssh doesn't forward the caller's environment.
unset REPO_DIR COMPOSE
if [ "$FAKE_CORRUPT" = 1 ]; then
  bash -c "$remote" | python3 -c '
import sys
d = bytearray(sys.stdin.buffer.read())
d[len(d) // 2] ^= 0xFF
sys.stdout.buffer.write(d)'
else
  bash -c "$remote"
fi
""",
        )

    def env(self, **extra: str) -> dict:
        return {
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "HOME": str(self.tmp),
            "DOCKER": str(self.bin / "docker"),
            "SSH": str(self.bin / "ssh"),
            # Override the Makefile's PROD_COMPOSE for every make in the
            # chain (including the one ssh runs on the "primary"):
            # MAKEFLAGS assignments act as command-line overrides, which
            # beat the Makefile's own `:=`.
            "MAKEFLAGS": f"PROD_COMPOSE={self.bin / 'compose'}",
            "COMPOSE": str(self.bin / "compose"),
            "FAKE_SNAPSHOT": self.snapshot,
            "FAKE_RUNNING": self.running,
            "FAKE_CORRUPT": "1" if self.corrupt else "0",
            **extra,
        }

    def bundle(self, *args: str, **extra: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["bash", str(self.primary / "scripts" / "standby_bundle.sh"), *args],
            cwd=self.primary,
            env={**self.env(**extra), "REPO_DIR": str(self.primary)},
            capture_output=True,
            check=False,
        )

    def pull(self, *args: str, **extra: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["bash", str(PULL_SH), *(args or ("pull",))],
            cwd=self.standby,
            env={**self.env(**extra), "REPO_DIR": str(self.standby)},
            capture_output=True,
            text=True,
            check=False,
        )

    def calls(self) -> str:
        return self.log.read_text() if self.log.exists() else ""


@pytest.fixture
def pair(tmp_path: Path) -> Pair:
    return Pair(tmp_path)


def _members(data: bytes) -> dict[str, bytes]:
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        return {
            m.name.removeprefix("./"): tf.extractfile(m).read()
            for m in tf.getmembers()
            if m.isfile()
        }


def _manifest(text: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


# ---------------------------------------------------------------------------
# standby_bundle.sh
# ---------------------------------------------------------------------------


class TestBundle:
    def test_stdout_bundle_contents(self, pair: Pair) -> None:
        proc = pair.bundle("-")
        assert proc.returncode == 0, proc.stderr
        m = _members(proc.stdout)
        assert set(m) == {"MANIFEST", "SHA256SUMS", "vault.snap", "files.tar"}
        assert m["vault.snap"] == b"SNAPSHOT-v1"
        files = _members(m["files.tar"])
        assert files[".env.prod"].startswith(b"MYSQL_ROOT_PASSWORD")
        assert b"rv-root" in files["vault-init.json"]
        assert files["tls/mysql/client.crt"] == b"cert-v1"

    def test_manifest_and_checksums(self, pair: Pair) -> None:
        m = _members(pair.bundle("-").stdout)
        man = _manifest(m["MANIFEST"].decode())
        assert man["format"] == "1"
        assert man["commit"] == pair.primary_head
        assert abs(int(man["created_epoch"]) - time.time()) < 60
        assert man["source_host"]
        for line in m["SHA256SUMS"].decode().splitlines():
            digest, name = line.split()
            assert hashlib.sha256(m[name]).hexdigest() == digest, name

    def test_snapshot_runs_in_bootstrap_app_with_token_shim(self, pair: Pair) -> None:
        pair.bundle("-")
        snap = next(c for c in pair.calls().splitlines() if "vault_snapshot.py" in c)
        assert " run --rm --no-deps -T " in snap
        assert "--entrypoint /usr/local/bin/entrypoint-wg-manager.sh bootstrap-app" in snap

    def test_stdout_carries_only_the_tar(self, pair: Pair) -> None:
        # Progress goes to stderr; anything else on stdout corrupts the
        # stream the standby reads over SSH.
        proc = pair.bundle("-")
        assert proc.stdout[:512].count(b"==>") == 0
        assert b"==>" in proc.stderr

    def test_refuses_empty_snapshot(self, pair: Pair) -> None:
        pair.snapshot = ""
        proc = pair.bundle("-")
        assert proc.returncode != 0
        assert proc.stdout == b""

    def test_refuses_without_vault_init(self, pair: Pair) -> None:
        (pair.primary / "vault-init.json").write_text("")
        proc = pair.bundle("-")
        assert proc.returncode != 0
        assert proc.stdout == b""

    def test_writes_private_file(self, pair: Pair, tmp_path: Path) -> None:
        out = tmp_path / "b.tar"
        proc = pair.bundle(str(out))
        assert proc.returncode == 0, proc.stderr
        assert stat.S_IMODE(out.stat().st_mode) == 0o600
        assert "vault.snap" in _members(out.read_bytes())

    def test_leaves_no_temp_dirs(self, pair: Pair, tmp_path: Path) -> None:
        tmpdir = tmp_path / "t"
        tmpdir.mkdir()
        pair.bundle("-", TMPDIR=str(tmpdir))
        pair.snapshot = ""
        pair.bundle("-", TMPDIR=str(tmpdir))
        assert list(tmpdir.iterdir()) == []


# ---------------------------------------------------------------------------
# standby_pull.sh pull
# ---------------------------------------------------------------------------


class TestPull:
    def test_installs_everything(self, pair: Pair) -> None:
        proc = pair.pull()
        assert proc.returncode == 0, proc.stderr
        s = pair.standby
        assert (s / "standby" / "vault.snap").read_text() == "SNAPSHOT-v1"
        assert "rv-root" in (s / "vault-init.json").read_text()
        assert (s / ".env.prod").read_text().startswith("MYSQL_ROOT_PASSWORD")
        assert (s / "tls" / "mysql" / "client.crt").read_text() == "cert-v1"
        man = _manifest((s / "standby" / "MANIFEST").read_text())
        assert man["commit"] == pair.primary_head
        assert stat.S_IMODE((s / "standby").stat().st_mode) == 0o700
        # The snapshot + the shipped vault-init.json ARE the Vault; don't
        # rely on the directory mode alone (live drill found 0664 here).
        for name in ("vault.snap", "MANIFEST"):
            mode = stat.S_IMODE((s / "standby" / name).stat().st_mode)
            assert mode == 0o600, (name, oct(mode))

    def test_ssh_is_batch_mode_and_runs_bundle(self, pair: Pair) -> None:
        pair.pull()
        ssh = next(c for c in pair.calls().splitlines() if c.startswith("ssh "))
        assert "-o BatchMode=yes" in ssh
        assert "ops@rv.vpn" in ssh
        assert "cd wg_manager && make -s standby-bundle o=-" in ssh

    def test_ssh_key_from_env_host(self, pair: Pair) -> None:
        with (pair.standby / ".env.host").open("a") as f:
            f.write("STANDBY_SSH_KEY=/home/ops/.ssh/wg-standby\n")
        pair.pull()
        ssh = next(c for c in pair.calls().splitlines() if c.startswith("ssh "))
        assert "-i /home/ops/.ssh/wg-standby" in ssh

    def test_keeps_previous_snapshot(self, pair: Pair) -> None:
        pair.pull()
        pair.snapshot = "SNAPSHOT-v2"
        time.sleep(1.1)  # created_epoch has 1s resolution
        assert pair.pull().returncode == 0
        d = pair.standby / "standby"
        assert (d / "vault.snap").read_text() == "SNAPSHOT-v2"
        assert (d / "vault.snap.prev").read_text() == "SNAPSHOT-v1"

    def test_restarts_replica_only_when_mysql_tls_changes(self, pair: Pair) -> None:
        pair.pull()  # first install: tls/mysql appears → restart
        first = pair.calls()
        assert "up -d --no-deps --wait mysql" in first
        pair.log.unlink()
        time.sleep(1.1)
        pair.pull()  # nothing changed
        assert "--wait mysql" not in pair.calls()
        pair.log.unlink()
        pair.seed_primary_files(tls_mysql="cert-v2")  # rotation on the primary
        time.sleep(1.1)
        pair.pull()
        assert "up -d --no-deps --wait mysql" in pair.calls()
        assert (pair.standby / "tls" / "mysql" / "client.crt").read_text() == "cert-v2"

    def test_no_restart_when_replica_not_running(self, pair: Pair) -> None:
        pair.running = ""
        pair.pull()
        assert "--wait mysql" not in pair.calls()

    def test_rejects_corrupted_bundle_and_keeps_old_state(self, pair: Pair) -> None:
        pair.pull()
        before = (pair.standby / "standby" / "MANIFEST").read_text()
        pair.corrupt = True
        pair.snapshot = "SNAPSHOT-v2"
        time.sleep(1.1)
        proc = pair.pull()
        assert proc.returncode != 0
        assert (pair.standby / "standby" / "MANIFEST").read_text() == before
        assert (pair.standby / "standby" / "vault.snap").read_text() == "SNAPSHOT-v1"

    def test_refuses_bundle_older_than_installed(self, pair: Pair) -> None:
        pair.pull()
        man = pair.standby / "standby" / "MANIFEST"
        text = man.read_text()
        future = int(time.time()) + 3600
        man.write_text(re.sub(r"created_epoch=\d+", f"created_epoch={future}", text))
        proc = pair.pull()
        assert proc.returncode != 0
        assert "not newer than the installed one" in proc.stderr

    def test_ssh_failure_is_loud_and_harmless(self, pair: Pair) -> None:
        pair.pull()
        before = (pair.standby / "standby" / "MANIFEST").read_text()
        (pair.primary / "vault-init.json").write_text("")  # bundle will fail
        time.sleep(1.1)
        proc = pair.pull()
        assert proc.returncode != 0
        assert (pair.standby / "standby" / "MANIFEST").read_text() == before

    def test_warns_on_commit_mismatch(self, pair: Pair) -> None:
        (pair.primary / "x").write_text("y")
        subprocess.run(["git", "-C", str(pair.primary), "add", "x"], check=True)
        subprocess.run(
            ["git", "-C", str(pair.primary), "-c", "user.name=t", "-c",
             "user.email=t@t", "commit", "-q", "-m", "upgrade"],
            check=True,
        )
        proc = pair.pull()
        assert proc.returncode == 0, proc.stderr  # data still installed
        assert "WARNING" in proc.stderr and "commit" in proc.stderr

    def test_requires_primary_ssh(self, pair: Pair) -> None:
        (pair.standby / ".env.host").write_text("WG_MANAGER_ROLE=standby\n")
        proc = pair.pull()
        assert proc.returncode != 0
        assert "STANDBY_PRIMARY_SSH" in proc.stderr

    def test_no_incoming_leftovers(self, pair: Pair) -> None:
        pair.pull()
        pair.corrupt = True
        time.sleep(1.1)
        pair.pull()
        leftovers = [p.name for p in (pair.standby / "standby").iterdir()]
        assert sorted(leftovers) == ["MANIFEST", "vault.snap"]


# ---------------------------------------------------------------------------
# standby_pull.sh status
# ---------------------------------------------------------------------------


class TestBundleStatus:
    def test_none_yet(self, pair: Pair) -> None:
        proc = pair.pull("status")
        assert proc.returncode == 1
        assert "No bundle" in proc.stdout

    def test_fresh(self, pair: Pair) -> None:
        pair.pull()
        proc = pair.pull("status")
        assert proc.returncode == 0, proc.stdout
        assert "OK" in proc.stdout

    def test_stale(self, pair: Pair) -> None:
        pair.pull()
        proc = pair.pull("status", STANDBY_MAX_BUNDLE_AGE_SECONDS="0")
        time.sleep(1.1)
        proc = pair.pull("status", STANDBY_MAX_BUNDLE_AGE_SECONDS="0")
        assert proc.returncode == 2
        assert "STALE" in proc.stdout

    def test_code_drift(self, pair: Pair) -> None:
        pair.pull()
        man = pair.standby / "standby" / "MANIFEST"
        man.write_text(re.sub(r"commit=\w+", "commit=deadbeef", man.read_text()))
        proc = pair.pull("status")
        assert proc.returncode == 2
        assert "commit" in proc.stdout


# ---------------------------------------------------------------------------
# Makefile wiring
# ---------------------------------------------------------------------------


def _make(cwd: Path, env: dict, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["make", "--no-print-directory", "-C", str(cwd), *args],
        env=env, capture_output=True, text=True, check=False,
    )


class TestMakefile:
    def test_targets_documented(self) -> None:
        mk = MAKEFILE.read_text()
        phony = next(line for line in mk.splitlines() if line.startswith(".PHONY:"))
        help_block = mk.split("help:", 1)[1].split("\n\n", 1)[0]
        for target in ("standby-bundle", "standby-pull"):
            assert re.search(rf"^{target}:", mk, re.MULTILINE), target
            assert target in phony.split(), target
            assert target in help_block, target

    def test_bundle_refuses_on_standby(self, pair: Pair) -> None:
        shutil.copy(MAKEFILE, pair.standby / "Makefile")
        proc = _make(pair.standby, pair.env(), "-s", "standby-bundle", "o=-")
        assert proc.returncode != 0
        assert "standby" in proc.stdout + proc.stderr

    def test_pull_refuses_off_standby(self, pair: Pair) -> None:
        proc = _make(pair.primary, pair.env(), "standby-pull")
        assert proc.returncode != 0

    def test_end_to_end_through_make(self, pair: Pair) -> None:
        # standby: `make standby-pull` → ssh → primary: `make -s
        # standby-bundle o=-`. Proves the primary's make prints nothing
        # but the tar on stdout.
        shutil.copy(MAKEFILE, pair.standby / "Makefile")
        (pair.standby / "scripts").mkdir()
        shutil.copy(PULL_SH, pair.standby / "scripts" / "standby_pull.sh")
        proc = _make(pair.standby, pair.env(), "standby-pull")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert (pair.standby / "standby" / "vault.snap").read_text() == "SNAPSHOT-v1"

    def test_status_combines_replication_and_bundle(self) -> None:
        mk = MAKEFILE.read_text()
        block = mk.split("\nstandby-status:", 1)[1].split("\n\n", 1)[0]
        assert "mysql_replication.sh status" in block
        assert "standby_pull.sh status" in block


def test_bootstrap_app_mounts_scripts() -> None:
    # The bundle runs /app/scripts/vault_snapshot.py in bootstrap-app.
    # The image doesn't bake scripts/; this bind mount is what makes the
    # script present without an image rebuild.
    import yaml

    class Loader(yaml.SafeLoader):
        pass

    Loader.add_constructor("!override", lambda ld, n: ld.construct_sequence(n))
    Loader.add_constructor("!reset", lambda ld, n: None)
    doc = yaml.load((REPO_ROOT / "docker-compose.prod.yml").read_text(), Loader=Loader)
    assert "./scripts:/app/scripts:ro" in doc["services"]["bootstrap-app"]["volumes"]


class TestDocs:
    def test_runbook_covers_shipping(self) -> None:
        text = (REPO_ROOT / "docs" / "runbooks" / "standby-replication.md").read_text()
        for needle in ("make standby-pull", "STANDBY_PRIMARY_SSH", 'command="'):
            assert needle in text, needle

    def test_timer_documented(self) -> None:
        text = (REPO_ROOT / "docs" / "deploy" / "systemd-timer.md").read_text()
        assert "wg-manager-standby-pull.timer" in text

    def test_env_host_example(self) -> None:
        text = (REPO_ROOT / ".env.host.example").read_text()
        assert "STANDBY_PRIMARY_SSH=" in text

    def test_standby_dir_gitignored(self) -> None:
        proc = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "check-ignore", "-q", "standby/vault.snap"],
            check=False,
        )
        assert proc.returncode == 0

