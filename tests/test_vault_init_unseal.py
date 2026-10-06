"""Tests for ``scripts/vault_init_unseal.sh``.

The script is the operator's seam between "Vault is a sealed
production server with persistent state" and "the rest of the
self-bootstrap can authenticate against it". Three idempotent
states it handles:

  1. **Uninitialized**: runs ``vault operator init -format=json -key-
     shares=5 -key-threshold=3``, writes the output to
     ``${VAULT_INIT_FILE}`` with mode 0600, then unseals.
  2. **Initialized + sealed**: reads ``${VAULT_INIT_FILE}``, calls
     ``vault operator unseal`` for each of the 3 keys.
  3. **Initialized + unsealed** (re-run): no-ops.

Substrate bootstrap calls this BEFORE pki/ssh-ca/transit/audit
bootstraps so those run against an authenticated, unsealed Vault.

Shape-only tests. Live execution lives in the rv.vpn end-to-end
smoke (initial init writes ``vault-init.json``; restart-then-prod-
up uses the existing keys to unseal).
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "vault_init_unseal.sh"


@pytest.fixture(scope="module")
def body() -> str:
    assert SCRIPT.is_file(), (
        f"{SCRIPT} is missing — the prod stack's self-bootstrap "
        "needs a scripted seam between a sealed production Vault "
        "and the PKI / SSH-CA / Transit / audit bootstraps that "
        "depend on an authenticated client."
    )
    return SCRIPT.read_text()


class TestScriptShape:
    def test_executable(self) -> None:
        assert bool(os.stat(SCRIPT).st_mode & stat.S_IXUSR), (
            "vault_init_unseal.sh must be chmod +x — substrate "
            "bootstrap execs it directly."
        )

    def test_strict_mode(self, body: str) -> None:
        first = body.splitlines()[0] if body else ""
        assert "bash" in first, f"need bash shebang; got {first!r}"
        assert "set -euo pipefail" in body, (
            "vault_init_unseal.sh must `set -euo pipefail` so an init "
            "or unseal failure halts bootstrap rather than continuing "
            "into a half-applied state."
        )


class TestInitFile:
    """The script reads/writes a single JSON file with the
    operator-facing generated secrets (5 unseal keys + the root
    token). Location is env-configurable for testability but
    defaults to ``/app/vault-init.json`` — the same path the
    compose bind-mount uses inside the wg-manager containers."""

    def test_references_vault_init_file_env(self, body: str) -> None:
        # Either `${VAULT_INIT_FILE}` or `$VAULT_INIT_FILE` is
        # acceptable. The point is that the location is not
        # hard-coded so the integration tests can point it at a
        # tmpdir.
        assert "VAULT_INIT_FILE" in body, (
            "vault_init_unseal.sh must read the init-file path from "
            "${VAULT_INIT_FILE} so the path is operator/test "
            "configurable, not baked in."
        )

    def test_default_path_under_app_dir(self, body: str) -> None:
        # The wg-manager image's /app is the bind-mount target the
        # compose overlay uses for the init file. The default
        # (when ${VAULT_INIT_FILE} is unset) must point there so
        # the operator's compose invocation doesn't have to set
        # the env var.
        assert "/app/vault-init.json" in body, (
            "vault_init_unseal.sh must default ${VAULT_INIT_FILE} "
            "to /app/vault-init.json so the prod compose's bind-"
            "mount lines up without extra env wiring."
        )

    def test_writes_init_file_with_mode_0600(self, body: str) -> None:
        # Vault's init output includes 5 unseal keys + a root
        # token. The file MUST be 0600 (owner read/write only) —
        # 0644 would let any UID inside the container read it on
        # a re-mount.
        has_chmod = "chmod 600" in body or "chmod 0600" in body
        has_umask = "umask 077" in body or "umask 0077" in body
        assert has_chmod or has_umask, (
            "vault_init_unseal.sh must set mode 0600 (or `umask 077`) "
            "on the init file. Any wider permission leaks the unseal "
            "keys to any UID with /app read access."
        )


class TestStateDetection:
    """The script must distinguish between the three possible
    Vault states and act appropriately on each."""

    def test_checks_initialized_state(self, body: str) -> None:
        # `vault status` / `vault operator init -status` / a query
        # against `/v1/sys/health` or `/v1/sys/init` — any of those
        # gives the initialized state. The grep is loose.
        markers = ("operator init", "sys/init", "sys/health", "vault status")
        assert any(m in body for m in markers), (
            "vault_init_unseal.sh must probe Vault's initialized "
            "state (e.g. via `vault operator init -status` or "
            "`/v1/sys/init`) so first-run vs re-run is detectable."
        )

    def test_checks_sealed_state(self, body: str) -> None:
        # Similarly: `vault status`, or `/v1/sys/seal-status`.
        markers = ("vault status", "sys/seal-status", "sealed", "operator unseal")
        assert any(m in body for m in markers), (
            "vault_init_unseal.sh must probe Vault's sealed state "
            "so an initialized-but-sealed restart (the most common "
            "post-bootstrap shape) is handled without re-initializing."
        )


class TestInitOnFirstRun:
    """When Vault is uninitialized, the script runs `vault operator
    init` with 5 shares / 3 threshold (matching the runbook's
    documented backup story)."""

    def test_invokes_operator_init(self, body: str) -> None:
        assert "operator init" in body, (
            "vault_init_unseal.sh must call `vault operator init` "
            "when Vault is in an uninitialized state."
        )

    def test_init_requests_json_output(self, body: str) -> None:
        # `-format=json` makes the output machine-parseable so the
        # script can extract unseal keys / root token without
        # regexing CLI text. Without it, the parser layer is
        # brittle.
        assert "-format=json" in body or "--format=json" in body or "format json" in body, (
            "vault_init_unseal.sh must request `-format=json` on "
            "the init call so the unseal-key + root-token extraction "
            "doesn't have to grep CLI prose."
        )

    def test_default_key_shares_and_threshold(self, body: str) -> None:
        # 5 shares / 3 threshold is Vault's documented prod default
        # and what `single-host-prod.md` documents for the backup
        # story. Different values are fine if env-configurable —
        # what's NOT fine is a hard-coded 1/1 (trivial unseal).
        assert (
            "key-shares=5" in body
            or "key_shares=5" in body
            or "VAULT_KEY_SHARES" in body
        ), (
            "vault_init_unseal.sh must request 5 key shares (or "
            "honour ${VAULT_KEY_SHARES}) — not the default 1-of-1 "
            "trivial unseal."
        )
        assert (
            "key-threshold=3" in body
            or "key_threshold=3" in body
            or "VAULT_KEY_THRESHOLD" in body
        ), (
            "vault_init_unseal.sh must request a key threshold of 3 "
            "(or honour ${VAULT_KEY_THRESHOLD})."
        )


class TestUnsealStep:
    """When Vault is initialized + sealed, the script reads the
    keys from the init file and runs `vault operator unseal` once
    per key until the threshold is reached."""

    def test_calls_unseal_api(self, body: str) -> None:
        # The CLI `vault operator unseal` and the HTTP API
        # `/v1/sys/unseal` are equivalent — either is fine. The
        # point is that the script EXERCISES one of them on the
        # sealed path.
        assert "operator unseal" in body or "sys/unseal" in body, (
            "vault_init_unseal.sh must call `vault operator unseal` "
            "(or the equivalent /v1/sys/unseal HTTP API) when Vault "
            "is initialized but sealed."
        )

    def test_reads_unseal_keys_from_init_file(self, body: str) -> None:
        # The init JSON has `unseal_keys_b64` (array) and
        # `unseal_keys_hex` — either works. The grep is loose:
        # any reference to the key fields counts as "reads them".
        markers = ("unseal_keys_b64", "unseal_keys_hex")
        assert any(m in body for m in markers), (
            "vault_init_unseal.sh must read unseal keys from "
            "${VAULT_INIT_FILE} (the `unseal_keys_b64` or "
            "`unseal_keys_hex` field) on a sealed restart."
        )


# ---------------------------------------------------------------------------
# Behavioural tests against a fake Vault HTTP API.
# ---------------------------------------------------------------------------


class _FakeVault:
    """Tiny in-thread HTTP server speaking the four Vault endpoints the
    script touches (sys/health, sys/init, sys/seal-status, sys/unseal).

    It starts uninitialized + sealed. ``puts`` records every PUT path
    so tests can assert whether ``sys/init`` was called.
    """

    def __init__(self) -> None:
        import http.server
        import threading

        self.initialized = False
        self.sealed = True
        self.puts: list[str] = []
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args) -> None:  # silence test output
                pass

            def _json(self, code: int, body: dict) -> None:
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:
                if self.path.startswith("/v1/sys/health"):
                    self._json(501 if not fake.initialized else 503, {})
                elif self.path == "/v1/sys/init":
                    self._json(200, {"initialized": fake.initialized})
                elif self.path == "/v1/sys/seal-status":
                    self._json(200, {"sealed": fake.sealed, "t": 3, "progress": 0})
                else:
                    self._json(404, {})

            def do_PUT(self) -> None:
                length = int(self.headers.get("Content-Length", 0))
                self.rfile.read(length)
                fake.puts.append(self.path)
                if self.path == "/v1/sys/init":
                    fake.initialized = True
                    self._json(200, {"keys_base64": ["k1", "k2", "k3"], "root_token": "new-root"})
                elif self.path == "/v1/sys/unseal":
                    fake.sealed = False
                    self._json(200, {"sealed": False, "progress": 0})
                else:
                    self._json(404, {})

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.addr = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()


@pytest.fixture
def fake_vault():
    fv = _FakeVault()
    yield fv
    fv.close()


def _run_script(fake_vault: _FakeVault, init_file: Path) -> subprocess.CompletedProcess:
    env = {
        **os.environ,
        "VAULT_ADDR": fake_vault.addr,
        "VAULT_INIT_FILE": str(init_file),
        "PYTHON": sys.executable,
    }
    return subprocess.run(
        ["bash", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=30
    )


class TestRefusesToReinitialize:
    """An uninitialized Vault next to a non-empty vault-init.json means
    the storage went missing (skipped raft migration, wrong volume,
    `down -v`), not a first boot. Initializing would overwrite the only
    copy of the real Vault's unseal keys + root token and mint a new
    SSH CA that no managed host trusts. The script must stop instead.
    """

    def test_refuses_when_init_file_has_keys(
        self, fake_vault: _FakeVault, tmp_path: Path
    ) -> None:
        init_file = tmp_path / "vault-init.json"
        original = '{"unseal_keys_b64": ["old"], "root_token": "old-root"}'
        init_file.write_text(original)

        proc = _run_script(fake_vault, init_file)

        assert proc.returncode != 0, proc.stdout + proc.stderr
        assert "/v1/sys/init" not in fake_vault.puts, "must not call sys/init"
        assert init_file.read_text() == original, "init file was overwritten"
        assert "vault-migrate-raft" in proc.stderr, (
            "the refusal must point the operator at the raft migration"
        )

    def test_initializes_when_init_file_is_empty(
        self, fake_vault: _FakeVault, tmp_path: Path
    ) -> None:
        # First-ever prod-up: the Makefile touches an empty file so the
        # bind mount is a file, not a directory. That must still init.
        init_file = tmp_path / "vault-init.json"
        init_file.write_text("")

        proc = _run_script(fake_vault, init_file)

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "/v1/sys/init" in fake_vault.puts
        assert json.loads(init_file.read_text())["root_token"] == "new-root"
