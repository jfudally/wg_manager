"""Shared pytest fixtures: in-memory SQLite engine + FakeSSHRunner."""

from __future__ import annotations

import os
from collections.abc import Generator
from typing import Any

# Force SQLite + in-memory Celery transports before any wg_manager module
# is imported, so the engine and Celery app pick them up at construction time.
# DEFAULT_SUBNET is pinned to the legacy default so tests stay hermetic even
# when the operator's ``.env`` overrides it (or contains a stub value while
# they're mid-edit).
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["CELERY_BROKER_URL"] = "memory://"
os.environ["CELERY_RESULT_BACKEND"] = "cache+memory://"
os.environ["DEFAULT_SUBNET"] = "10.9.0.0/24"

# Crypto backend defaults for the test suite. Use a fixed Fernet key so
# encrypt() output is reproducible between test runs (useful for `vcr`-style
# fixtures) and the suite is hermetic — no `.env` file is consulted. The
# value is published in the repo, so do NOT use it outside tests.
os.environ.setdefault("CRYPTO_BACKEND", "local")
os.environ.setdefault(
    "CRYPTO_LOCAL_DEV_KEY",
    "6BR-12U4QDta_TTnZnieCyvMU5VzRSnUqbH6hA80Ihw=",
)

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

import wg_manager.db as db_module
import wg_manager.tasks as tasks_module  # noqa: F401  — register tasks
from wg_manager.celery_app import celery_app
from wg_manager.db import get_session
from wg_manager.main import app
from wg_manager.ssh import CommandResult

# Run tasks synchronously inside the calling process so tests don't need a
# real broker. ``task_eager_propagates`` makes task exceptions surface as
# normal Python exceptions in the caller.
celery_app.conf.task_always_eager = True
celery_app.conf.task_eager_propagates = True
celery_app.conf.task_store_eager_result = True


# ---------------------------------------------------------------------------
# Fake SSH runner
# ---------------------------------------------------------------------------


class FakeSSHRunner:
    """In-process stand-in for :class:`wg_manager.ssh.SSHRunner`.

    Records every command invocation into a class-level ``COMMANDS`` list so
    tests can assert on provisioning behaviour. The ``cat /etc/wireguard/publickey``
    probe returns a canned pubkey unique per host.
    """

    COMMANDS: list[tuple[str, str]] = []  # (host, cmd)
    PUBKEYS: dict[str, str] = {}
    # Tests can register canned stdout for a given (host, command-substring) so
    # FakeSSHRunner emulates remote tools (e.g. ``wg show wg0 dump``) without
    # needing a real SSH session. The first match wins.
    OUTPUTS: dict[tuple[str, str], str] = {}
    # Tests can register an exception to raise from ``__enter__`` for a given
    # host, simulating connection-time failures (timeout, auth, refused, ...).
    RAISE_ON_ENTER: dict[str, BaseException] = {}
    # Every SSHRunner construction records (host, pkey_pem, passphrase) so
    # the encryption-at-rest tests (Phase 2b) can assert the *decrypted*
    # plaintext is what flows through to paramiko. The list is reset in the
    # ``client`` fixture between tests.
    KEYS_USED: list[tuple[str, str, str | None]] = []
    # Phase 2c CP2: the task layer constructs the runner with
    # ``cert_pem`` / ``ca_public_key`` when ``SSH_AUTH_MODE=ca``. We record
    # them on a separate list so the legacy 3-tuple shape of ``KEYS_USED``
    # stays intact for Phase 2b's regression tests.
    CERTS_USED: list[tuple[str, str | None, str | None, str]] = []

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        pkey_pem: str,
        passphrase: str | None = None,
        *,
        cert_pem: str | None = None,
        ca_public_key: str | None = None,
        connect_timeout: float = 15.0,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.pkey_pem = pkey_pem
        self.passphrase = passphrase
        self.cert_pem = cert_pem
        self.ca_public_key = ca_public_key
        self.connect_timeout = connect_timeout
        FakeSSHRunner.KEYS_USED.append((host, pkey_pem, passphrase))
        FakeSSHRunner.CERTS_USED.append((host, cert_pem, ca_public_key, username))

    def __enter__(self) -> FakeSSHRunner:
        exc = FakeSSHRunner.RAISE_ON_ENTER.get(self.host)
        if exc is not None:
            raise exc
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        return None

    def _record(self, cmd: str) -> None:
        FakeSSHRunner.COMMANDS.append((self.host, cmd))

    def _canned_pubkey(self) -> str:
        if self.host not in FakeSSHRunner.PUBKEYS:
            FakeSSHRunner.PUBKEYS[self.host] = f"PUBKEY::{self.host}"
        return FakeSSHRunner.PUBKEYS[self.host]

    def run(self, cmd: str, check: bool = True) -> CommandResult:
        self._record(cmd)
        stdout = ""
        # Honour any test-registered canned output first; this lets tests
        # emulate the response of arbitrary remote commands such as
        # ``wg show wg0 dump`` on a per-host basis.
        for (host, needle), canned in FakeSSHRunner.OUTPUTS.items():
            if host == self.host and needle in cmd:
                stdout = canned
                return CommandResult(cmd=cmd, rc=0, stdout=stdout, stderr="")
        if "cat /etc/wireguard/publickey" in cmd:
            stdout = self._canned_pubkey() + "\n"
        elif cmd.startswith("grep -q"):
            # Report "not found" so the [Peer] append branch runs.
            return CommandResult(cmd=cmd, rc=1, stdout="", stderr="")
        return CommandResult(cmd=cmd, rc=0, stdout=stdout, stderr="")

    def sudo(self, cmd: str, check: bool = True) -> CommandResult:
        return self.run(f"sudo -n {cmd}", check=check)

    def write_file(
        self,
        path: str,
        content: str,
        mode: str = "644",
        sudo: bool = True,
    ) -> CommandResult:
        prefix = "sudo -n " if sudo else ""
        self._record(f"{prefix}tee {path}")
        return CommandResult(cmd=f"tee {path}", rc=0, stdout="", stderr="")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine() -> Generator[Any, None, None]:
    """Create a fresh in-memory SQLite engine shared across the test."""
    test_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    # Import models to populate metadata before create_all.
    import wg_manager.models  # noqa: F401

    SQLModel.metadata.create_all(test_engine)
    # Swap the module-level engine so any code that reaches for it directly
    # sees the test engine.
    original = db_module.engine
    db_module.engine = test_engine
    try:
        yield test_engine
    finally:
        db_module.engine = original
        SQLModel.metadata.drop_all(test_engine)


@pytest.fixture()
def session(engine: Any) -> Generator[Session, None, None]:
    """Yield a SQLModel session bound to the test engine."""
    with Session(engine) as db_session:
        yield db_session


def promote_all_keys_to_ca(session: Session) -> None:
    """Flip every :class:`SSHKey` row to ``mode=ca`` in the test engine.

    Phase 2c CP4.1 made the task layer's auth routing per-row: a key
    must have ``mode='ca'`` before the task layer will mint a user
    cert for it. The production migration path is
    ``wg-manager ssh migrate-to-ca <id>`` (CP4.2), which installs the
    CA trust anchor on every host using the key before flipping the
    column.

    Tests that exercise the CA-mode runner / host-cert / rotation
    paths don't want to drive that whole CLI for every case; they
    just need the column flipped so the routing seam picks the cert
    branch. This helper is the test-only shortcut — call it after any
    SSH-key rows have been created (typically right after
    ``POST /ssh-keys`` or :func:`_bootstrap_ready_server`).
    """
    from sqlmodel import select

    from wg_manager.models import SSHKey, SSHKeyMode

    for row in session.exec(select(SSHKey)).all():
        row.mode = SSHKeyMode.ca
        session.add(row)
    session.commit()


@pytest.fixture()
def client(
    engine: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[TestClient, None, None]:
    """Yield a TestClient with overridden DB dependency and fake SSH runner.

    Each request opens a fresh ``Session`` against the shared in-memory
    engine. This mirrors production behaviour and — importantly — prevents
    identity-map staleness between the router's session and the session
    opened inside an eagerly-executed Celery task.
    """
    FakeSSHRunner.COMMANDS = []
    FakeSSHRunner.PUBKEYS = {}
    FakeSSHRunner.OUTPUTS = {}
    FakeSSHRunner.RAISE_ON_ENTER = {}
    FakeSSHRunner.KEYS_USED = []
    FakeSSHRunner.CERTS_USED = []

    # Swap SSHRunner as used inside the Celery tasks (import-time binding).
    monkeypatch.setattr(tasks_module, "SSHRunner", FakeSSHRunner)

    def _override_session() -> Generator[Session, Any, None]:
        with Session(engine) as request_session:
            yield request_session

    app.dependency_overrides[get_session] = _override_session
    try:
        with TestClient(app) as c:
            yield c
    finally:
        app.dependency_overrides.clear()
