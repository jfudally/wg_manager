"""Tests for ``scripts/certs_due.py`` and ``scripts/certs_rotate_if_due.sh``.

The prod stack's TLS leaves (MySQL server/client, API server, operator
CLI client) only rotate via ``make certs-rotate``, which also restarts
the containers that load them at startup. ``make certs-rotate-if-due``
lets a host-side systemd timer run that hourly but only act when a
leaf has burned past ``--threshold-pct`` of its lifetime.

``certs_due.py`` is the check; its exit codes are the contract the
wrapper branches on:

* ``0`` — nothing due
* ``10`` — at least one leaf due (distinct from docker/compose's own
  failure codes, so a broken ``compose run`` is never read as "due")
* ``2`` — the check itself couldn't run (missing file, no leaf found)
"""

from __future__ import annotations

import importlib.util
import os
import stat
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

REPO_ROOT = Path(__file__).resolve().parents[1]
CHECK_SCRIPT = REPO_ROOT / "scripts" / "certs_due.py"
WRAPPER_SCRIPT = REPO_ROOT / "scripts" / "certs_rotate_if_due.sh"


def _load_check() -> ModuleType:
    """Import ``scripts/certs_due.py`` (not a package) as a module."""
    spec = importlib.util.spec_from_file_location("certs_due", CHECK_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _pem(
    *, days_ago: float, days_left: float, is_ca: bool = False, cn: str = "leaf"
) -> bytes:
    """Self-signed cert PEM issued ``days_ago`` and expiring in ``days_left``."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=days_ago))
        .not_valid_after(now + timedelta(days=days_left))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def check() -> ModuleType:
    return _load_check()


class TestCheck:
    def test_fresh_leaves_are_not_due(self, check: ModuleType, tmp_path: Path) -> None:
        a = tmp_path / "a.crt"
        a.write_bytes(_pem(days_ago=1, days_left=29))
        assert check.main([str(a)]) == check.EXIT_OK

    def test_leaf_past_threshold_is_due(
        self, check: ModuleType, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        fresh = tmp_path / "fresh.crt"
        fresh.write_bytes(_pem(days_ago=1, days_left=29))
        stale = tmp_path / "stale.crt"
        stale.write_bytes(_pem(days_ago=20, days_left=10))
        assert check.main([str(fresh), str(stale)]) == check.EXIT_DUE
        assert "stale.crt" in caplog.text

    def test_expired_leaf_is_due(self, check: ModuleType, tmp_path: Path) -> None:
        f = tmp_path / "expired.crt"
        f.write_bytes(_pem(days_ago=40, days_left=-10))
        assert check.main([str(f)]) == check.EXIT_DUE

    def test_threshold_is_configurable(self, check: ModuleType, tmp_path: Path) -> None:
        # ~33% elapsed: not due at the default 50, due at 25.
        f = tmp_path / "a.crt"
        f.write_bytes(_pem(days_ago=10, days_left=20))
        assert check.main([str(f)]) == check.EXIT_OK
        assert check.main(["--threshold-pct", "25", str(f)]) == check.EXIT_DUE

    def test_ca_certs_in_a_bundle_are_ignored(
        self, check: ModuleType, tmp_path: Path
    ) -> None:
        """Rotating leaves doesn't renew the CA, so an ageing CA must not
        trigger a rotate-and-restart every hour forever."""
        f = tmp_path / "chain.crt"
        f.write_bytes(
            _pem(days_ago=1, days_left=29)
            + _pem(days_ago=3000, days_left=100, is_ca=True, cn="ca")
        )
        assert check.main([str(f)]) == check.EXIT_OK

    def test_missing_file_is_an_error(self, check: ModuleType, tmp_path: Path) -> None:
        assert check.main([str(tmp_path / "nope.crt")]) == check.EXIT_ERROR

    def test_file_without_a_leaf_is_an_error(
        self, check: ModuleType, tmp_path: Path
    ) -> None:
        f = tmp_path / "ca-only.crt"
        f.write_bytes(_pem(days_ago=1, days_left=3650, is_ca=True))
        assert check.main([str(f)]) == check.EXIT_ERROR

    def test_garbage_file_is_an_error(self, check: ModuleType, tmp_path: Path) -> None:
        f = tmp_path / "junk.crt"
        f.write_text("not a cert")
        assert check.main([str(f)]) == check.EXIT_ERROR

    def test_default_files_match_what_certs_rotate_writes(
        self, check: ModuleType
    ) -> None:
        """Checking a file certs-rotate doesn't rewrite would loop:
        due → rotate → still due. Pin the list to the rotate outputs."""
        rotate = (REPO_ROOT / "scripts" / "prod_rotate_certs.sh").read_text()
        assert "bootstrap_mysql_tls_files.py" in rotate
        for rel in check.DEFAULT_LEAVES:
            name = Path(rel).name
            if rel.startswith("mysql/"):
                assert name in (
                    REPO_ROOT / "scripts" / "bootstrap_mysql_tls_files.py"
                ).read_text()
            else:
                assert f'"${{TLS_DIR}}/{name}"' in rotate


def _fake_bin(tmp_path: Path, name: str, body: str) -> Path:
    """Write an executable shell stub that logs its argv to ``calls.log``."""
    path = tmp_path / name
    path.write_text(
        f'#!/usr/bin/env bash\necho "{name} $*" >> "{tmp_path}/calls.log"\n{body}\n'
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _run_wrapper(tmp_path: Path, check_exit: int) -> tuple[int, str]:
    """Run the wrapper with a stubbed compose (check result) and make."""
    compose = _fake_bin(tmp_path, "compose", f"exit {check_exit}")
    make = _fake_bin(tmp_path, "make", "exit 0")
    env = {**os.environ, "PROD_COMPOSE": str(compose), "MAKE": str(make)}
    # check=False: callers assert on the wrapper's exit code themselves.
    proc = subprocess.run(
        ["bash", str(WRAPPER_SCRIPT)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    log = tmp_path / "calls.log"
    return proc.returncode, log.read_text() if log.exists() else ""


class TestWrapper:
    def test_nothing_due_does_not_rotate(self, tmp_path: Path) -> None:
        code, calls = _run_wrapper(tmp_path, 0)
        assert code == 0
        assert "compose run --rm --no-deps" in calls
        assert "make" not in calls.replace("compose", "")

    def test_due_runs_certs_rotate(self, tmp_path: Path) -> None:
        code, calls = _run_wrapper(tmp_path, 10)
        assert code == 0
        assert "make certs-rotate" in calls

    @pytest.mark.parametrize("check_exit", [1, 2, 125])
    def test_check_failure_fails_loudly_without_rotating(
        self, tmp_path: Path, check_exit: int
    ) -> None:
        code, calls = _run_wrapper(tmp_path, check_exit)
        assert code != 0
        assert "make certs-rotate" not in calls


class TestMakefile:
    def test_target_declared_phony_and_in_help(self) -> None:
        body = (REPO_ROOT / "Makefile").read_text()
        assert "\ncerts-rotate-if-due:" in body
        phony = " ".join(
            line for line in body.splitlines() if line.startswith(".PHONY:")
        )
        assert "certs-rotate-if-due" in phony.split()
        assert '@echo "  certs-rotate-if-due' in body

    def test_target_runs_wrapper_with_prod_compose(self) -> None:
        body = (REPO_ROOT / "Makefile").read_text()
        block = body.split("\ncerts-rotate-if-due:", 1)[1].split("\n\n", 1)[0]
        assert "scripts/certs_rotate_if_due.sh" in block
        assert "PROD_COMPOSE=" in block
