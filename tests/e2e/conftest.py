"""Shared fixtures for the Phase 2c CP5 dockerised-sshd e2e suite.

The fixture stack:

* :func:`vault_client` — module-level (session-scoped) ``hvac.Client``
  pointed at the dev Vault declared in ``docker-compose.yml``. Skips
  the suite if Vault is not reachable so an operator who hasn't run
  ``make vault-up`` gets a clear message instead of a stack trace.

* :func:`vault_ssh_ca` — session-scoped :class:`VaultSSHCA`
  bootstrapped against a dedicated mount path (``ssh-e2e``) so the
  e2e suite doesn't trample on any in-progress production-shape CA
  the operator has at the default ``ssh`` mount. The bootstrap is
  idempotent (the wrapped Vault APIs are upsert-shaped); repeated
  runs against the same dev Vault are no-ops.

* :func:`sshd_container` — session-scoped; brings up the
  ``sshd-e2e`` compose service if it's not already running, waits
  for sshd to accept TCP, installs the Vault CA pubkey into the
  bind-mounted ``/wg-manager-e2e/`` volume (``TrustedUserCAKeys``),
  and yields a small container handle the tests use. Does *not*
  tear down at session end — leaving the container running between
  runs makes the suite fast to re-execute. ``make e2e-down`` (or
  ``docker compose --profile e2e down``) clears it explicitly.

* :func:`installed_host_cert` — function-scoped; installs a fresh
  Vault-signed host cert into the container before the test runs
  and reloads sshd. Tests that need a *different* host-cert state
  (e.g. the attacker-CA scenario) call the
  :func:`E2EEnv.write_host_cert` helper directly to override.

A module-level ``pytestmark = pytest.mark.e2e`` hook auto-tags
every test in ``tests/e2e/`` with the ``e2e`` marker so individual
test functions don't have to repeat it. ``pyproject.toml``'s
``addopts = "-m 'not e2e'"`` deselects the bucket from the default
``pytest`` invocation; ``make test-e2e`` overrides with ``-m e2e``.
"""

from __future__ import annotations

import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import hvac
import pytest

from wg_manager.ssh_ca import VaultSSHCA


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Auto-tag every test under ``tests/e2e/`` with the ``e2e`` marker.

    ``pytestmark`` in a conftest doesn't propagate to tests (only the
    module/class-level form does), so the hook is the canonical
    pytest seam for "every test under this directory wears this
    marker." Keeps individual test files free of repeated
    ``@pytest.mark.e2e`` decorators.
    """
    e2e_dir = Path(__file__).parent.resolve()
    for item in items:
        try:
            test_path = Path(item.fspath).resolve()
        except (TypeError, OSError):  # pragma: no cover — defensive
            continue
        if e2e_dir in test_path.parents or test_path == e2e_dir:
            item.add_marker(pytest.mark.e2e)


# ---------------------------------------------------------------------------
# Connection constants — match docker-compose.yml's ``sshd-e2e`` service
# ---------------------------------------------------------------------------

VAULT_ADDR = "http://127.0.0.1:8200"
VAULT_TOKEN = "dev-only-root"

E2E_MOUNT = "ssh-e2e"
E2E_USER_ROLE = "wg-manager-e2e-user"
E2E_HOST_ROLE = "wg-manager-e2e-host"
# Auxiliary roles bootstrapped alongside the main pair so the
# behavioural tests can mint certs Vault *will* sign but sshd should
# still reject:
#
# * ``E2E_USER_ROLE_SHORT_TTL`` — 5-second TTL so the TTL-expiry
#   test can mint, sleep past expiry, and assert sshd refuses.
# * ``E2E_USER_ROLE_MULTI_USER`` — adds ``otheruser`` to the allow
#   list so the principal-mismatch test can mint a cert whose
#   ``valid_principals`` doesn't include the ``wguser`` username
#   the runner will try to connect with. The username never exists
#   on the container; the role is just the Vault-side gate Vault
#   uses to decide whether to sign at all.
E2E_USER_ROLE_SHORT_TTL = "wg-manager-e2e-user-short"
E2E_USER_ROLE_MULTI_USER = "wg-manager-e2e-user-multi"
E2E_OTHER_PRINCIPAL = "otheruser"

E2E_CONTAINER = "wg_manager_sshd_e2e"
E2E_HOST = "127.0.0.1"
E2E_PORT = 2222
E2E_USERNAME = "wguser"
E2E_HOSTNAME_PRINCIPAL = "e2e-sshd.local"

E2E_CA_PATH = "/wg-manager-e2e/user-ca.pub"
E2E_HOST_CERT_PATH = "/wg-manager-e2e/ssh_host_ed25519_key-cert.pub"
E2E_HOST_PUBKEY_PATH = "/etc/ssh/ssh_host_ed25519_key.pub"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _vault_reachable() -> bool:
    """Return ``True`` iff the dev Vault TCP port accepts a connection.

    Used by the skipper on :func:`vault_client` so the suite degrades
    gracefully when an operator hasn't run ``make vault-up``.
    """
    try:
        with socket.create_connection(("127.0.0.1", 8200), timeout=1.0):
            return True
    except OSError:
        return False


def _docker_exec(container: str, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run ``docker exec <container> <args...>`` and return the completed process.

    Centralised so failure modes (docker not on PATH, container not
    running) surface with a consistent error in the fixtures.
    """
    return subprocess.run(
        ["docker", "exec", container, *args],
        capture_output=True,
        text=True,
        check=check,
    )


def _docker_write(container: str, path: str, content: str) -> None:
    """Write ``content`` to ``path`` inside ``container`` via ``docker exec``.

    Piped through ``tee`` because ``docker exec`` doesn't run a shell
    by default and we want shell-side redirection. ``tee`` also
    avoids the ``sh -c`` quoting tarpit when ``content`` contains
    quotes or newlines.
    """
    proc = subprocess.run(
        ["docker", "exec", "-i", container, "tee", path],
        input=content,
        capture_output=True,
        text=True,
        check=True,
    )
    assert proc.returncode == 0, proc.stderr


def _wait_for_ssh(host: str, port: int, timeout: float = 30.0) -> None:
    """Poll TCP-connect to ``host:port`` until sshd answers or we time out.

    sshd is the only thing in the container, so a successful TCP
    connect is a strong signal it's ready. Real connection / auth
    timing happens on top of paramiko's own banner_timeout.
    """
    deadline = time.monotonic() + timeout
    last_exc: OSError | None = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return
        except OSError as exc:
            last_exc = exc
            time.sleep(0.5)
    raise RuntimeError(
        f"sshd at {host}:{port} did not accept connections within "
        f"{timeout}s; last error: {last_exc}"
    )


# ---------------------------------------------------------------------------
# Vault fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def vault_client() -> hvac.Client:
    """Authenticate to the dev Vault. Skip the suite if it's not up."""
    if not _vault_reachable():
        pytest.skip(
            f"Vault not reachable at {VAULT_ADDR} — run `make vault-up` first"
        )
    client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)
    if not client.is_authenticated():
        pytest.skip(
            f"Vault at {VAULT_ADDR} rejected the dev root token — "
            f"is the container in dev mode?"
        )
    return client


@pytest.fixture(scope="session")
def vault_ssh_ca(vault_client: hvac.Client) -> VaultSSHCA:
    """Bootstrap a dedicated SSH CA mount for the e2e suite.

    Dedicated mount path (``ssh-e2e``) so the suite doesn't collide
    with any production-shape CA the operator has at the default
    ``ssh`` mount. ``bootstrap()`` is idempotent — repeated runs
    against the same dev Vault are no-ops.

    User role TTL is left at 5m (the production default) so the
    happy-path tests don't trip on it; the TTL-expiry test mints
    against a different short-TTL role it bootstraps itself.
    """
    ca = VaultSSHCA.bootstrap(
        client=vault_client,
        mount_point=E2E_MOUNT,
        user_role=E2E_USER_ROLE,
        host_role=E2E_HOST_ROLE,
        # Tight allow-list — the happy-path role only signs certs
        # for the actual connect username.
        allowed_users=E2E_USERNAME,
        # No DNS constraint: the host cert principal is a synthetic
        # ``e2e-sshd.local`` string we plug into the runner's known-
        # hosts equivalent via :class:`KnownHostsCAPolicy`.
        allowed_host_domains="",
    )

    # Auxiliary roles for the behavioural tests. ``create_role`` is
    # upsert-shaped so re-running the suite against an already-
    # bootstrapped dev Vault is a no-op.
    vault_client.secrets.ssh.create_role(
        name=E2E_USER_ROLE_SHORT_TTL,
        key_type="ca",
        allow_user_certificates=True,
        allow_host_certificates=False,
        default_user=E2E_USERNAME,
        allowed_users=E2E_USERNAME,
        default_extensions={"permit-pty": ""},
        allowed_extensions="permit-pty",
        ttl="5s",
        max_ttl="5s",
        mount_point=E2E_MOUNT,
    )
    vault_client.secrets.ssh.create_role(
        name=E2E_USER_ROLE_MULTI_USER,
        key_type="ca",
        allow_user_certificates=True,
        allow_host_certificates=False,
        default_user=E2E_USERNAME,
        # Both principals are legal Vault-side so we can mint with
        # either; the test asserts sshd rejects the one that doesn't
        # match the connect username.
        allowed_users=f"{E2E_USERNAME},{E2E_OTHER_PRINCIPAL}",
        default_extensions={"permit-pty": ""},
        allowed_extensions="permit-pty",
        ttl="5m",
        max_ttl="5m",
        mount_point=E2E_MOUNT,
    )

    return ca


@pytest.fixture(scope="session")
def vault_ssh_ca_short_ttl(
    vault_client: hvac.Client, vault_ssh_ca: VaultSSHCA
) -> VaultSSHCA:
    """``VaultSSHCA`` bound to the 5-second-TTL user role.

    Shares the bootstrapped CA pubkey with :func:`vault_ssh_ca` —
    same Vault mount, same signing key, different role policy.
    """
    return VaultSSHCA(
        client=vault_client,
        mount_point=E2E_MOUNT,
        user_role=E2E_USER_ROLE_SHORT_TTL,
        host_role=E2E_HOST_ROLE,
        ca_public_key=vault_ssh_ca.ca_public_key,
    )


@pytest.fixture(scope="session")
def vault_ssh_ca_multi_user(
    vault_client: hvac.Client, vault_ssh_ca: VaultSSHCA
) -> VaultSSHCA:
    """``VaultSSHCA`` bound to the multi-user role.

    Lets the principal-mismatch test mint a cert Vault is willing
    to sign for a *different* principal than the connect username.
    """
    return VaultSSHCA(
        client=vault_client,
        mount_point=E2E_MOUNT,
        user_role=E2E_USER_ROLE_MULTI_USER,
        host_role=E2E_HOST_ROLE,
        ca_public_key=vault_ssh_ca.ca_public_key,
    )


# ---------------------------------------------------------------------------
# sshd container fixture
# ---------------------------------------------------------------------------


@dataclass(slots=True, frozen=True)
class E2EEnv:
    """Handle returned by :func:`sshd_container` — connection coords + helpers.

    :ivar host: TCP host the test connects to (loopback).
    :ivar port: TCP port the test connects to (compose-published 2222).
    :ivar username: SSH username (``wguser``); also the only legal
        user-cert principal under the bootstrap above.
    :ivar hostname_principal: Synthetic principal the fixture signs
        the host cert with — passed to the CA's ``mint_host_cert``.
    :ivar container: Docker container name. Tests use this to call
        :func:`write_host_cert` / :func:`write_user_ca` directly.
    :ivar host_pubkey_openssh: The container's freshly-generated
        ed25519 host pubkey, read once at startup. Used by tests
        that mint host certs.
    :ivar ca_public_key: The Vault CA's OpenSSH-formatted public
        key. Mirrors ``vault_ssh_ca.ca_public_key`` — surfaced on
        the env so test code doesn't have to thread two fixtures.
    """

    host: str
    port: int
    username: str
    hostname_principal: str
    container: str
    host_pubkey_openssh: str
    ca_public_key: str

    def write_host_cert(self, cert_pem: str) -> None:
        """Install ``cert_pem`` as the sshd host cert + SIGHUP sshd."""
        _docker_write(self.container, E2E_HOST_CERT_PATH, cert_pem + "\n")
        _docker_exec(self.container, "sh", "-c", "kill -HUP 1")

    def write_user_ca(self, ca_public_key: str) -> None:
        """Overwrite the ``TrustedUserCAKeys`` file inside the container.

        sshd parses ``TrustedUserCAKeys`` at every connection (no
        reload needed), but we SIGHUP anyway to keep the semantics
        consistent with :meth:`write_host_cert`.
        """
        _docker_write(self.container, E2E_CA_PATH, ca_public_key + "\n")
        _docker_exec(self.container, "sh", "-c", "kill -HUP 1")


def _ensure_container_up() -> None:
    """Make sure the ``sshd-e2e`` compose service is running.

    Idempotent: if it's already up, ``docker compose up -d`` is a
    no-op. If the image hasn't been built, it builds it.
    """
    compose_dir = Path(__file__).resolve().parents[2]
    subprocess.run(
        [
            "docker",
            "compose",
            "--profile",
            "e2e",
            "up",
            "-d",
            "--build",
            "sshd-e2e",
        ],
        cwd=compose_dir,
        capture_output=True,
        text=True,
        check=True,
    )


@pytest.fixture(scope="session")
def sshd_container(vault_ssh_ca: VaultSSHCA) -> Iterator[E2EEnv]:
    """Boot the ``sshd-e2e`` container and install the Vault CA pubkey.

    Session-scoped because spinning up the container is the
    expensive part. The fixture does *not* tear down at end of
    session — operators stay in tight iteration loops; explicit
    ``make e2e-down`` clears state when they're ready.
    """
    _ensure_container_up()
    _wait_for_ssh(E2E_HOST, E2E_PORT)

    # Pull the container's freshly-generated ed25519 host pubkey so
    # tests can mint host certs against it.
    pubkey_result = _docker_exec(E2E_CONTAINER, "cat", E2E_HOST_PUBKEY_PATH)
    host_pubkey = pubkey_result.stdout.strip()

    env = E2EEnv(
        host=E2E_HOST,
        port=E2E_PORT,
        username=E2E_USERNAME,
        hostname_principal=E2E_HOSTNAME_PRINCIPAL,
        container=E2E_CONTAINER,
        host_pubkey_openssh=host_pubkey,
        ca_public_key=vault_ssh_ca.ca_public_key,
    )

    # Default user-CA: trust the Vault e2e CA. Tests that want a
    # different ``TrustedUserCAKeys`` value call ``write_user_ca``
    # explicitly.
    env.write_user_ca(vault_ssh_ca.ca_public_key)

    yield env


# ---------------------------------------------------------------------------
# Default host cert — most tests want a vault-signed cert in place
# ---------------------------------------------------------------------------


@pytest.fixture
def installed_host_cert(
    sshd_container: E2EEnv, vault_ssh_ca: VaultSSHCA
) -> None:
    """Install a fresh vault-signed host cert into the container.

    Function-scoped so each test starts from the same known-good
    state. Tests that want a *different* host cert (attacker CA,
    expired, mis-principal'd) install their own via
    :meth:`E2EEnv.write_host_cert` after this fixture has run.
    """
    cert = vault_ssh_ca.mint_host_cert(
        public_key_openssh=sshd_container.host_pubkey_openssh,
        principals=[sshd_container.hostname_principal],
        ttl_seconds=300,
    )
    sshd_container.write_host_cert(cert.cert_pem)
