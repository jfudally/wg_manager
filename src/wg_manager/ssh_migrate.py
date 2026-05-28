"""Phase 2c CP4.2 — bootstrap an :class:`SSHKey` row from legacy to CA mode.

The migration helper closes the chicken-and-egg gap CP4.1 left behind:
a row that is on ``mode=ca`` (or was running on the deprecated
``SSH_AUTH_MODE=ca`` env var before CP4.1) cannot reach a host that
hasn't yet been bootstrapped with a CA-signed host cert, because the
client-side :class:`wg_manager.ssh.KnownHostsCAPolicy` refuses to TOFU.
But you can't install the host cert without first SSH-ing in. The way
out is to take a one-shot legacy SSH key (the same one the operator
historically used to log into the host) and use it to open a
TOFU-allowed session — install the cert — and *then* flip the row to
``mode=ca`` so future sessions take the CA path.

:func:`migrate_key_to_ca` is the entry point. It:

1. Walks every :class:`wg_manager.models.Server` row that references
   the SSH key.
2. For each: constructs a *legacy* :class:`wg_manager.ssh.SSHRunner`
   (no ``cert_pem`` / ``ca_public_key``) using the operator-supplied
   private key, then drives
   :func:`wg_manager.host_ssh.install_host_cert` to push the CA trust
   anchor + signed host cert, and persists the cert metadata onto
   the server row's ``host_cert_*`` columns.
3. After every server succeeds: flips the SSH key row to
   :attr:`~wg_manager.models.SSHKeyMode.ca` and nulls the
   ``private_key_ct`` / ``passphrase_ct`` columns so no plaintext SSH
   material remains at rest. If *any* server failed, the row's mode
   stays unchanged so the operator has a clean retry path against
   the fixed host(s).

The helper is HTTP-agnostic: the router layer in
:mod:`wg_manager.routers.ssh_keys` (CP4.2 endpoint) and the CLI in
:mod:`wg_manager.cli` (CP4.2 subcommand) both call this. The return
value is a list of :class:`SSHKeyMigrateToCAServerResult` objects
ready to drop into the response envelope.
"""

from __future__ import annotations

from sqlmodel import Session, select

from wg_manager.config import Settings
from wg_manager.host_ssh import HostCertInstallError, install_host_cert
from wg_manager.models import SSHKey, SSHKeyMode, Server
from wg_manager.schemas import SSHKeyMigrateToCAServerResult
from wg_manager.ssh import SSHCommandError, SSHConnectionError, SSHRunner
from wg_manager.ssh_ca import SSHCAError, make_ssh_ca_backend
from wg_manager.tasks import _persist_host_cert


# Errors we expect during a bootstrap session — anything in this
# tuple gets recorded as a per-server ``ssh_failed`` rather than
# propagating up and aborting the whole migration. Same shape as
# :data:`wg_manager.tasks._SSH_EXPECTED_ERRORS` but kept local so the
# task layer's set can evolve independently.
_BOOTSTRAP_EXPECTED_ERRORS: tuple[type[BaseException], ...] = (
    SSHConnectionError,
    SSHCommandError,
    SSHCAError,
    HostCertInstallError,
    TimeoutError,
    OSError,
)


def _bootstrap_one(
    *,
    server: Server,
    private_key_pem: str,
    passphrase: str | None,
    settings: Settings,
) -> SSHKeyMigrateToCAServerResult:
    """Bootstrap a single server's CA trust anchor and host cert.

    The session is *always* legacy (no cert / no CA pubkey passed to
    :class:`SSHRunner`) — the whole point is to reach a host that does
    not yet trust the CA. Errors in
    :data:`_BOOTSTRAP_EXPECTED_ERRORS` are caught and reported as
    ``ssh_failed`` in the result. Anything else (Vault permission
    denied, programmer error, …) propagates so the operator sees the
    full failure rather than a silently-swallowed bootstrap.

    :param server: The server row whose host should be bootstrapped.
        Mutated in-place on success to populate the ``host_cert_*``
        columns; the caller is responsible for committing the change.
    :param private_key_pem: PEM body of the one-shot legacy SSH key.
    :param passphrase: Optional passphrase unlocking ``private_key_pem``.
    :param settings: Live :class:`Settings` for the CA backend factory
        and host-cert TTL.
    :return: A :class:`SSHKeyMigrateToCAServerResult` with ``status``
        set to ``"ok"`` (server mutated, cert metadata populated)
        or ``"ssh_failed"`` (server untouched, ``error`` populated).
    """
    try:
        with SSHRunner(
            host=server.hostname,
            port=server.ssh_port,
            username=server.ssh_username,
            pkey_pem=private_key_pem,
            passphrase=passphrase,
        ) as runner:
            ca = make_ssh_ca_backend(settings)
            cert = install_host_cert(
                runner=runner,
                server=server,
                ca=ca,
                ttl_seconds=settings.ssh_host_cert_ttl_seconds,
            )
            _persist_host_cert(server, cert, ca.ca_public_key)
    except _BOOTSTRAP_EXPECTED_ERRORS as exc:
        return SSHKeyMigrateToCAServerResult(
            server_id=server.id or -1,
            hostname=server.hostname,
            status="ssh_failed",
            error=str(exc),
        )

    return SSHKeyMigrateToCAServerResult(
        server_id=server.id or -1,
        hostname=server.hostname,
        status="ok",
        cert_serial=cert.serial,
        valid_before=cert.valid_before,
        error=None,
    )


def migrate_key_to_ca(
    *,
    session: Session,
    key: SSHKey,
    private_key_pem: str,
    passphrase: str | None,
    settings: Settings,
) -> list[SSHKeyMigrateToCAServerResult]:
    """Bootstrap every server using ``key`` and conditionally flip the row.

    See the module docstring for the full lifecycle. The mutation
    contract on the row:

    * **All servers succeed** (or there are zero servers) →
      ``key.mode = SSHKeyMode.ca``, ``key.private_key_ct = None``,
      ``key.passphrase_ct = None``. The row carries no plaintext SSH
      material after this point.
    * **Any server fails** → ``key`` is *not* touched. The operator
      can re-run after fixing the failed host(s); the bootstrap is
      idempotent on the servers that already succeeded (their
      ``host_cert_*`` columns get rewritten with a fresh cert).

    The function commits once at the end so the per-server cert
    persistence and the row's mode flip ship atomically.

    :param session: Open SQLModel session; the function commits before
        returning.
    :param key: The SSH key row to migrate. May be ``mode=legacy``
        (standard path) or ``mode=ca`` with NULL pk_ct (the 2026-05-27
        broken-but-labelled-ca shape — also supported; the helper
        runs the bootstrap and leaves the mode at ``ca``).
    :param private_key_pem: One-shot legacy SSH key used to reach each
        host. Never stored.
    :param passphrase: Optional passphrase unlocking ``private_key_pem``.
    :param settings: Live :class:`Settings` (CA backend + TTL).
    :return: One :class:`SSHKeyMigrateToCAServerResult` per server.
    """
    servers = list(
        session.exec(select(Server).where(Server.ssh_key_id == key.id)).all()
    )

    results: list[SSHKeyMigrateToCAServerResult] = []
    for server in servers:
        result = _bootstrap_one(
            server=server,
            private_key_pem=private_key_pem,
            passphrase=passphrase,
            settings=settings,
        )
        results.append(result)
        if result.status == "ok":
            session.add(server)

    all_ok = all(r.status == "ok" for r in results)
    if all_ok:
        key.mode = SSHKeyMode.ca
        # Drop the at-rest plaintext now that the row is on the
        # CA-mint codepath. Operators flipping back to legacy after
        # this point need to PATCH a fresh key body in — there is no
        # un-flip helper, by design (CP4.4 will drop the columns
        # entirely once every row is ca).
        key.private_key_ct = None
        key.passphrase_ct = None
        session.add(key)

    session.commit()
    return results
