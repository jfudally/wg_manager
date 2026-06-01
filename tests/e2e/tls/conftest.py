"""Shared fixtures for the Phase 2d CP5 mTLS acceptance suite.

The fixture stack mirrors the Phase 2c CP5 sshd suite's shape:

* :func:`pki_backend` (session) — fresh in-process :class:`LocalDevPKI`
  hierarchy used as the trust anchor on both ends. The same instance
  signs the API listener's server cert *and* every client cert the
  tests later mint, so the API trusts what the tests present without
  having to thread a separate trust bundle.

* :func:`tls_materials` (session) — server cert + key + CA bundle
  written to a tmp dir. The bundle is the file the API process feeds
  to uvicorn's ``ssl_ca_certs`` so its TLS layer validates client
  certs against the same root.

* :func:`live_api_server` (session) — a real ``uvicorn`` subprocess
  bound to a free loopback port with ``ssl_cert_reqs=CERT_REQUIRED``.
  Yields a :class:`LiveAPIEnv` handle exposing the bind coords + the
  PEM paths the tests reuse. Teardown SIGTERMs the child.

Subprocess (not in-process ``uvicorn.Server``) because the four CP5
acceptance criteria are about behaviour at the *real* socket: how a
plain-HTTP byte stream is handled, how an expired client cert is
handled at the OpenSSL handshake, how the MySQL TLS layer behaves
across a cert hot-swap. None of that is exercised by Starlette's
``TestClient``.

The conftest auto-applies the ``e2e_tls`` pytest marker to every test
under this package — see :func:`pytest_collection_modifyitems`. The
``pyproject.toml`` ``addopts`` keeps ``e2e_tls`` deselected from the
fast ``make test`` invocation; ``make test-e2e-tls`` overrides.
"""

from __future__ import annotations

import os
import socket
import ssl
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import pytest

from wg_manager.pki import Cert, LocalDevPKI

# ---------------------------------------------------------------------------
# Module-level marker auto-application
# ---------------------------------------------------------------------------


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Auto-tag every test under ``tests/e2e/tls/`` with the ``e2e_tls`` marker.

    The outer ``tests/e2e/conftest.py`` only marks tests that are
    *direct* children of ``tests/e2e/`` (Phase 2c CP5 sshd suite);
    tests under this subdir get the distinct ``e2e_tls`` marker so
    operators can run the two acceptance buckets independently.
    """
    tls_dir = Path(__file__).parent.resolve()
    for item in items:
        try:
            test_path = Path(item.fspath).resolve()
        except (TypeError, OSError):  # pragma: no cover — defensive
            continue
        if tls_dir in test_path.parents or test_path == tls_dir:
            item.add_marker(pytest.mark.e2e_tls)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


# Loopback only — the CP5 suite never reaches out beyond the host.
_BIND_HOST = "127.0.0.1"
# Common Name on the API server's leaf cert. Matches the bind host so
# any client-side TLS verification with ``check_hostname=True`` passes.
_API_CN = "127.0.0.1"
# Long enough that a single ``make test-e2e-tls`` invocation never
# trips on the server cert expiring mid-run. CP5.2 (expired-cert
# acceptance) flips the *client* cert's TTL, not this one.
_SERVER_TTL_SECONDS = 60 * 60
# Cold-start budget for uvicorn + the wg-manager import graph. The
# heaviest imports are pymysql + cryptography; on a warm laptop the
# subprocess is up in ~2 s, on a cold cache it's closer to 8 s. 30 s
# leaves plenty of headroom for CI runners without making the failure
# mode hang the suite.
_API_STARTUP_TIMEOUT = 30.0
_TCP_PROBE_TIMEOUT = 1.0
# Canonical published-in-repo Fernet key used by the fast suite. Safe
# to repeat here because the live subprocess is local-only; production
# is Vault Transit (`CRYPTO_BACKEND=vault`).
_DEV_FERNET_KEY = "6BR-12U4QDta_TTnZnieCyvMU5VzRSnUqbH6hA80Ihw="
# CN the bootstrap path self-registers on the first cert-bearing
# request. CP5.2 + CP5.3 mint *their own* operator certs against this
# CN so the registry has an active admin row to validate against.
_BOOTSTRAP_OPERATOR_CN = "cp5-bootstrap"


# ---------------------------------------------------------------------------
# Value object
# ---------------------------------------------------------------------------


@dataclass(slots=True, frozen=True)
class LiveAPIEnv:
    """Handle returned by :func:`live_api_server`.

    :ivar host: Loopback IP the listener bound to.
    :ivar port: Free TCP port the test selected at fixture-setup time.
    :ivar server_cert_pem_path: Path to the mTLS listener's leaf cert
        — handy for the operator-perspective tests that connect with
        ``ssl.create_default_context(cafile=...)``.
    :ivar server_key_pem_path: Path to the matching private key.
    :ivar ca_bundle_pem_path: Path to the chain a client must trust to
        verify the server. Same trust anchor the API uses to verify
        client certs — by design, since the suite shares one
        :class:`LocalDevPKI` between the test process and the API
        subprocess.
    :ivar pki: The shared :class:`LocalDevPKI` instance. Tests use this
        to mint operator client certs (CP5.2 / CP5.3).
    :ivar bootstrap_operator_cn: CN the API self-registers on first
        cert-bearing request — CP5.2 / CP5.3 mint client certs whose
        subject CN matches so the request lands as an active admin
        row.
    :ivar tmp_dir: The session tmp dir the harness wrote PEM files
        under. Acceptance tests use this to drop per-cert PEM files
        so the on-disk paths httpx wants are valid.
    :ivar stderr_path: Path to the file the API subprocess's stderr is
        redirected to. CP5.2 / CP5.3 read this to assert audit lines
        emitted by :func:`wg_manager.auth._emit_audit` show up in the
        listener's stream — which is the visible-to-operator signal
        the acceptance criteria call out.
    """

    host: str
    port: int
    server_cert_pem_path: Path
    server_key_pem_path: Path
    ca_bundle_pem_path: Path
    pki: LocalDevPKI
    bootstrap_operator_cn: str
    tmp_dir: Path
    stderr_path: Path

    @property
    def base_url(self) -> str:
        """``https://host:port`` form for httpx callers."""
        return f"https://{self.host}:{self.port}"

    def read_stderr(self) -> str:
        """Snapshot the API subprocess's stderr file.

        Returns the *entire* file contents — the acceptance tests
        substring-search for audit-line markers (``"auth.admit"``,
        ``"operator-cert-revoked"``, …) rather than parsing line by
        line. Each test that depends on a clean stderr slate calls
        :meth:`reset_stderr` before driving traffic.
        """
        try:
            return self.stderr_path.read_text(errors="replace")
        except FileNotFoundError:  # pragma: no cover — defensive
            return ""

    def reset_stderr(self) -> None:
        """Truncate the stderr file so the next assertion is local in time.

        Without this, a test reading ``read_stderr()`` would see audit
        lines accumulated across previous tests in the session. Calling
        ``truncate(0)`` on the bind-mounted file is safe because we
        opened the file in append mode on the subprocess side — the
        next write extends from the new EOF.
        """
        try:
            with self.stderr_path.open("r+") as fh:
                fh.truncate(0)
        except FileNotFoundError:  # pragma: no cover — defensive
            pass

    def mint_client_cert(self, cn: str, *, ttl_seconds: int) -> Cert:
        """Issue a clientAuth leaf signed by the shared PKI.

        Wraps :meth:`LocalDevPKI.issue_client_cert` so tests don't have
        to thread the PKI handle through. The cert is *not* written to
        disk by this method — callers pair it with
        :meth:`write_pem_files` when they need on-disk paths for
        httpx's ``cert=`` kwarg.
        """
        return self.pki.issue_client_cert(
            common_name=cn,
            sans=[cn],
            ttl_seconds=ttl_seconds,
        )

    def write_pem_files(self, cert: Cert, label: str) -> tuple[Path, Path]:
        """Persist ``cert``'s leaf + key under ``tmp_dir/<label>.{crt,key}``.

        Returns the (cert_path, key_path) pair httpx expects on its
        ``cert=`` kwarg. ``label`` lets the caller scope the filenames
        — useful when one test mints two different identities (e.g.
        a bootstrap admin + a target leaf).
        """
        cert_path = self.tmp_dir / f"{label}.crt"
        key_path = self.tmp_dir / f"{label}.key"
        cert_path.write_text(cert.cert_pem)
        key_path.write_text(cert.private_pem)
        key_path.chmod(0o600)
        return cert_path, key_path

    def make_client_ssl_context(
        self, cert_path: Path, key_path: Path
    ) -> ssl.SSLContext:
        """Build an :class:`ssl.SSLContext` for an mTLS call into the live API.

        Loads the listener's CA bundle as the trust anchor, attaches
        the supplied client cert + key, and **disables**
        :data:`ssl.VERIFY_X509_STRICT`.

        Why strict mode is off: Python 3.13's OpenSSL strict
        verification requires every non-self-signed cert to carry an
        ``AuthorityKeyIdentifier`` extension and every CA to carry
        ``SubjectKeyIdentifier`` — :class:`LocalDevPKI` (the dev /
        test PKI) doesn't emit either. Vault PKI (the production
        backend) does, so production traffic passes strict mode just
        fine. Disabling the flag here is *test-only* scaffolding so
        the acceptance suite can keep using ``LocalDevPKI`` without
        having to spin Vault. The production listener configuration
        is unaffected.

        Each call returns a fresh context — :meth:`ssl.SSLContext.load_cert_chain`
        is one-shot per context, and we mint different client certs
        across the CP5 tests.
        """
        ctx = ssl.create_default_context(
            cafile=str(self.ca_bundle_pem_path)
        )
        ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
        ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        return ctx


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pick_free_port() -> int:
    """Ask the OS for a free TCP port on loopback.

    TOCTOU-prone (the port can be claimed between ``close()`` and the
    subprocess ``bind()``) but that race is rare on a developer laptop
    and acceptable for a session-scoped fixture. A retry loop wouldn't
    materially improve flakiness.
    """
    with socket.socket() as sock:
        sock.bind((_BIND_HOST, 0))
        return int(sock.getsockname()[1])


def _wait_for_tcp(host: str, port: int, timeout: float) -> None:
    """Poll TCP-connect until ``host:port`` accepts or we time out.

    Used as the "listener is up" gate. We don't try to handshake TLS
    here — a successful TCP connect is enough proof uvicorn bound; the
    individual tests then drive the TLS layer themselves.
    """
    deadline = time.monotonic() + timeout
    last_exc: OSError | None = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(
                (host, port), timeout=_TCP_PROBE_TIMEOUT
            ):
                return
        except OSError as exc:
            last_exc = exc
            time.sleep(0.25)
    raise RuntimeError(
        f"live API listener at {host}:{port} did not accept TCP within "
        f"{timeout}s; last error: {last_exc}"
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def pki_backend() -> LocalDevPKI:
    """One :class:`LocalDevPKI` shared across the whole CP5 suite.

    Session-scoped so the live API's trust anchor — set up exactly
    once in :func:`tls_materials` — keeps validating client certs the
    later tests mint, without having to thread a separate bundle.
    """
    return LocalDevPKI.generate()


@pytest.fixture(scope="session")
def tls_materials(
    pki_backend: LocalDevPKI, tmp_path_factory: pytest.TempPathFactory
) -> dict[str, Path]:
    """Mint the API server's leaf + write all PEMs to disk.

    Returns a dict the live-API fixture threads into the subprocess's
    env vars. ``ca_bundle_pem`` is reused as the trust anchor in CP5.2
    / CP5.3 when the test process verifies the server cert it sees.
    """
    tmp = tmp_path_factory.mktemp("cp5-tls")
    server = pki_backend.issue_server_cert(
        common_name=_API_CN,
        sans=[_API_CN, "localhost"],
        ttl_seconds=_SERVER_TTL_SECONDS,
    )
    server_cert = tmp / "server.crt"
    server_key = tmp / "server.key"
    ca_bundle = tmp / "ca-bundle.crt"
    server_cert.write_text(server.cert_pem)
    server_key.write_text(server.private_pem)
    ca_bundle.write_text(pki_backend.ca_bundle_pem)
    # Match the production-shape permissions for the private key. The
    # subprocess inherits the test process's uid so 0o600 is enough.
    server_key.chmod(0o600)
    return {
        "server_cert_pem": server_cert,
        "server_key_pem": server_key,
        "ca_bundle_pem": ca_bundle,
        "tmp": tmp,
    }


@pytest.fixture(scope="session")
def live_api_server(
    pki_backend: LocalDevPKI,
    tls_materials: dict[str, Path],
) -> Iterator[LiveAPIEnv]:
    """Spin up a real uvicorn subprocess bound to a free port with mTLS on.

    The subprocess inherits the test process's interpreter + path so
    the entire ``wg_manager`` module graph is reachable. The runner
    code passes the same SSL kwargs ``python -m wg_manager`` uses,
    minus ``reload`` — uvicorn's autoreload spawns a watcher + worker
    pair which makes process-group teardown brittle, and reload is a
    dev ergonomic, not a Phase 2d acceptance criterion. The
    ``__main__.py`` startup-validation logic is covered by
    ``tests/test_main_tls_wiring.py``; this fixture deliberately
    bypasses it to focus on listener behaviour.

    Pinning the four ``PKI_LOCAL_DEV_*`` PEMs in the env is what makes
    the test process + API process trust the *same* root — without
    the pin each process generates its own hierarchy and the client
    certs the tests mint would be untrusted by the API.

    The SQLite schema is initialised by a one-shot subprocess call to
    ``SQLModel.metadata.create_all`` before uvicorn starts. Faster
    than spinning alembic for every ``make test-e2e-tls`` invocation;
    the CP5 acceptance suite is not the place to validate migration
    ordering (the alembic-* unit tests already pin that contract).
    """
    port = _pick_free_port()
    tmp = tls_materials["tmp"]

    db_path = tmp / "cp5.db"
    env = os.environ.copy()
    env.update(
        {
            "DATABASE_URL": f"sqlite:///{db_path}",
            # API listener TLS
            "TLS_REQUIRED": "true",
            "TLS_CERT_PEM": str(tls_materials["server_cert_pem"]),
            "TLS_KEY_PEM": str(tls_materials["server_key_pem"]),
            "TLS_CA_BUNDLE_PEM": str(tls_materials["ca_bundle_pem"]),
            "BIND_HOST": _BIND_HOST,
            "BIND_PORT": str(port),
            # PKI hierarchy — pinned so test + subprocess share one root
            "PKI_BACKEND": "local",
            "PKI_LOCAL_DEV_ROOT_PEM": pki_backend.root_pem,
            "PKI_LOCAL_DEV_ROOT_KEY_PEM": pki_backend.root_key_pem,
            "PKI_LOCAL_DEV_INT_PEM": pki_backend.intermediate_pem,
            "PKI_LOCAL_DEV_INT_KEY_PEM": pki_backend.intermediate_key_pem,
            # Encryption-at-rest backend — same shape as the fast suite.
            "CRYPTO_BACKEND": "local",
            "CRYPTO_LOCAL_DEV_KEY": _DEV_FERNET_KEY,
            "SSH_CA_BACKEND": "local",
            # Bootstrap path — CP5.2 / CP5.3 ride this to land an admin
            # row on the first cert-bearing request.
            "AUTH_BOOTSTRAP_OPERATOR_CN": _BOOTSTRAP_OPERATOR_CN,
            "AUTH_BOOTSTRAP_OPERATOR_ROLE": "admin",
            # No broker / backend wiring needed — the CP5 acceptance
            # surface doesn't enqueue work.
            "CELERY_BROKER_URL": "memory://",
            "CELERY_RESULT_BACKEND": "cache+memory://",
        }
    )

    # Schema bootstrap: SQLModel.metadata.create_all runs in a one-shot
    # subprocess so the engine it touches honours the env above. Using
    # the same interpreter the live API will run under guarantees
    # SQLite dialect parity.
    subprocess.run(
        [
            sys.executable,
            "-c",
            "import wg_manager.models  # noqa: F401\n"
            "from wg_manager.db import engine\n"
            "from sqlmodel import SQLModel\n"
            "SQLModel.metadata.create_all(engine)\n",
        ],
        env=env,
        check=True,
        capture_output=True,
    )

    # uvicorn.run is invoked here with reload=False on purpose — see
    # the fixture docstring. log_level=warning silences the per-request
    # INFO line so the CP5 acceptance suite's stderr stays readable
    # when an operator runs it locally.
    runner_code = (
        "import ssl\n"
        "import uvicorn\n"
        "from wg_manager.main import app\n"
        "uvicorn.run(\n"
        "    app,\n"
        f"    host={_BIND_HOST!r},\n"
        f"    port={port},\n"
        f"    ssl_certfile={str(tls_materials['server_cert_pem'])!r},\n"
        f"    ssl_keyfile={str(tls_materials['server_key_pem'])!r},\n"
        f"    ssl_ca_certs={str(tls_materials['ca_bundle_pem'])!r},\n"
        "    ssl_cert_reqs=ssl.CERT_REQUIRED,\n"
        "    log_level='warning',\n"
        ")\n"
    )

    # Stderr goes to a file rather than a pipe so the buffer can't
    # back up and block uvicorn after enough audit lines accumulate.
    # CP5.2 / CP5.3 also need on-demand snapshots of this stream to
    # verify their audit-line assertions, which a pipe doesn't allow
    # without a reader thread.
    stderr_path = tmp / "api.stderr.log"
    stdout_path = tmp / "api.stdout.log"
    stderr_fh = stderr_path.open("ab")
    stdout_fh = stdout_path.open("ab")

    proc = subprocess.Popen(  # noqa: S603 — controlled args, dev-only fixture
        [sys.executable, "-c", runner_code],
        env=env,
        stdout=stdout_fh,
        stderr=stderr_fh,
    )

    try:
        try:
            _wait_for_tcp(_BIND_HOST, port, _API_STARTUP_TIMEOUT)
        except RuntimeError as wait_exc:
            # Surface uvicorn's startup error so the developer sees a
            # readable failure instead of just "didn't bind."
            proc.kill()
            proc.wait(timeout=5.0)
            stderr_text = ""
            stdout_text = ""
            try:
                stderr_text = stderr_path.read_text(errors="replace")
                stdout_text = stdout_path.read_text(errors="replace")
            except FileNotFoundError:  # pragma: no cover
                pass
            raise RuntimeError(
                f"{wait_exc}\n"
                f"--- subprocess stderr ---\n{stderr_text}\n"
                f"--- subprocess stdout ---\n{stdout_text}"
            ) from wait_exc

        yield LiveAPIEnv(
            host=_BIND_HOST,
            port=port,
            server_cert_pem_path=tls_materials["server_cert_pem"],
            server_key_pem_path=tls_materials["server_key_pem"],
            ca_bundle_pem_path=tls_materials["ca_bundle_pem"],
            pki=pki_backend,
            bootstrap_operator_cn=_BOOTSTRAP_OPERATOR_CN,
            tmp_dir=tmp,
            stderr_path=stderr_path,
        )
    finally:
        # SIGTERM gives uvicorn a chance to close listening sockets
        # cleanly. The 10 s grace covers a worker that's mid-handshake;
        # SIGKILL is the unconditional fallback so a hung child doesn't
        # block the pytest exit.
        proc.terminate()
        try:
            proc.wait(timeout=10.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        stderr_fh.close()
        stdout_fh.close()
