"""Celery tasks that perform WireGuard provisioning over SSH.

Tasks operate on row IDs (never ORM instances) so they survive a hop through
the broker. They open their own session against ``wg_manager.db.engine`` and
update the row's ``status`` to ``ready`` or ``error`` before returning.

Phase 2c CP4.4 closed the CA migration arc: every ``SSHKey`` row is
now in :attr:`~wg_manager.models.SSHKeyMode.ca`, and every connection
mints a fresh ephemeral Ed25519 keypair + short-lived user
certificate from :func:`wg_manager.ssh_ca.make_ssh_ca_backend`. The
runner is constructed with ``cert_pem`` and ``ca_public_key`` so
client auth presents the cert and host trust comes from the SSH CA
— there is no stored-key fallback path.

:func:`_open_runner` is the single seam through which every task
constructs a runner.
"""

from __future__ import annotations

import socket
from datetime import datetime, timedelta, timezone
from typing import Any

from celery.utils.log import get_task_logger
from sqlmodel import Session, col, or_, select

from wg_manager.bootstrap_ssh import BootstrapSSHRunner, bootstrap_host
from wg_manager.celery_app import celery_app
from wg_manager.config import Settings
from wg_manager.crypto import make_backend as make_crypto_backend
from wg_manager.host_ssh import HostCertInstallError, install_host_cert
from wg_manager.locks import task_row_lock
from wg_manager.models import (
    Client,
    DiscoveredPeer,
    NodeStatus,
    Server,
    SSHKey,
)
from wg_manager.ssh import SSHCommandError, SSHConnectionError, SSHRunner
from wg_manager.ssh_ca import HostCert, SSHCAError, make_ssh_ca_backend
from wg_manager.wireguard import (
    discover_peers,
    provision_client,
    provision_server,
    reconfigure_server,
)

logger = get_task_logger(__name__)


def _mark_error(session: Session, row: Server | Client) -> None:
    """Persist a node row in the ``error`` state."""
    row.status = NodeStatus.error
    session.add(row)
    session.commit()


# Network and command-level errors we consider "expected failure modes"
# that should be logged tidily (no stack trace) and converted into a clean
# :class:`RuntimeError`. ``SSHRunner`` normalises connect-time errors into
# :class:`SSHConnectionError`, but raw ``socket.timeout`` / ``TimeoutError``
# / ``OSError`` can still leak from paramiko channel I/O during ``run()``;
# we catch those defensively too so a flaky read never produces a
# 30-frame traceback in the worker log. Anything outside this set is a
# true bug and keeps the existing :func:`logger.exception` treatment so
# we don't lose signal.
_SSH_EXPECTED_ERRORS: tuple[type[BaseException], ...] = (
    SSHConnectionError,
    SSHCommandError,
    SSHCAError,
    HostCertInstallError,
    socket.timeout,
    TimeoutError,
    OSError,
)


def _open_runner(
    *,
    host: str,
    port: int,
    username: str,
    ssh_key: SSHKey,  # noqa: ARG001 — kept for call-site symmetry and future routing
    known_principals: str | None = None,
) -> SSHRunner:
    """Construct an :class:`SSHRunner` against the SSH CA.

    Phase 2c CP4.4 retired the legacy stored-key path: every
    connection mints a per-session Ed25519 keypair + short-lived user
    cert from the SSH CA backend, configured with the same CA's
    public key for host trust (so
    :class:`wg_manager.ssh.KnownHostsCAPolicy` rejects anything not
    signed by it). The ``ssh_key`` argument is kept on the signature
    so call sites that look up the row up-front don't have to change
    shape, but its only remaining job is to participate in the
    eventual per-row routing decision a future mode might
    re-introduce.

    :param host: Target SSH host (used for cert minting principals and
        the runner constructor).
    :param port: Target SSH port.
    :param username: Remote username. Becomes the cert principal —
        sshd will reject the cert unless this principal is in the
        cert's ``valid_principals`` list.
    :param ssh_key: The SSH role row; unused today, retained for
        forwards compatibility.
    :param known_principals: The row's ``host_cert_principals`` — the
        comma-separated names on the host cert this control plane last
        issued. Accepted by :class:`~wg_manager.ssh.KnownHostsCAPolicy`
        in addition to ``host``, so a row whose hostname was edited can
        still be reached (and re-certified for its new name).
    :return: An unentered :class:`SSHRunner`. The caller is responsible
        for entering it as a context manager.
    :raises SSHCAError: If the CA backend cannot be constructed
        (Vault unreachable, malformed PEM, …).
    """
    settings = Settings()
    ca = make_ssh_ca_backend(settings)
    user_cert = ca.mint_user_cert(
        principals=[username],
        ttl_seconds=settings.ssh_user_cert_ttl_seconds,
    )
    return SSHRunner(
        host=host,
        port=port,
        username=username,
        pkey_pem=user_cert.private_pem,
        cert_pem=user_cert.cert_pem,
        ca_public_key=ca.ca_public_key,
        accepted_principals=tuple(
            name.strip() for name in (known_principals or "").split(",") if name.strip()
        ),
    )


def _persist_host_cert(
    server: Server | Client, cert: HostCert, ca_public_key: str
) -> None:
    """Copy ``cert`` and the signing CA pubkey onto the row's ``host_cert_*`` columns.

    Works for both hubs and SSH-provisioned clients — the two models
    carry identical ``host_cert_*`` columns (Alembic 0006 / 0017).

    Pure data assignment — does not commit. The caller (a Celery task
    inside its open session) owns the commit so the host-cert update
    and the row's ``status=ready`` flip ship atomically.

    The principals tuple is flattened to a comma-separated string to
    match the column shape (see :class:`wg_manager.models.Server`).
    """
    server.host_cert_pem = cert.cert_pem
    server.host_cert_serial = cert.serial
    server.host_cert_principals = ",".join(cert.principals)
    server.host_cert_valid_after = cert.valid_after
    server.host_cert_valid_before = cert.valid_before
    server.host_cert_ca_public_key = ca_public_key


def _install_host_cert(
    *,
    runner: SSHRunner,
    server: Server | Client,
    settings: Settings,
) -> None:
    """Mint + install a host cert for ``server`` and persist its metadata.

    ``server`` may be a hub or an SSH-provisioned client row.

    Phase 2c CP4.4 made this unconditional — every connection is
    CA-mode now, so the matching CA trust anchor + host cert always
    need to be present on the host for the *next* session to
    handshake successfully under
    :class:`wg_manager.ssh.KnownHostsCAPolicy`.

    1. Resolves the CA backend (same factory the runner mint uses).
    2. Calls :func:`wg_manager.host_ssh.install_host_cert` to push the
       drop-in + cert + CA pubkey to the host and reload sshd.
    3. Mutates the ``server`` row in-place via
       :func:`_persist_host_cert` so the caller's session commit
       captures the new column values alongside the
       ``status=ready`` flip.

    The TTL comes from ``settings.ssh_host_cert_ttl_seconds`` (24 h
    by default; an explicit setting so an operator can tighten it
    for high-security deployments without code changes).
    """
    ca = make_ssh_ca_backend(settings)
    cert = install_host_cert(
        runner=runner,
        server=server,
        ca=ca,
        ttl_seconds=settings.ssh_host_cert_ttl_seconds,
    )
    _persist_host_cert(server, cert, ca.ca_public_key)


def _fail_clean(message: str) -> RuntimeError:
    """Return a :class:`RuntimeError` with the chained traceback suppressed.

    Use as ``raise _fail_clean(msg) from None`` inside a Celery task — the
    resulting failure carries the concise ``message`` instead of dragging
    along the underlying paramiko / socket traceback. Celery still records
    the task as ``FAILURE`` so callers polling ``GET /tasks/{id}`` see the
    correct terminal state.
    """
    return RuntimeError(message)


def _ready_clients_for(session: Session, server_id: int) -> list[Client]:
    """Return all ``ready`` clients attached to ``server_id``."""
    return list(
        session.exec(
            select(Client).where(
                Client.server_id == server_id,
                Client.status == NodeStatus.ready,
            )
        ).all()
    )


def _run_bootstrap_if_supplied(
    *,
    node: Server | Client,
    bootstrap_pem_ciphertext: str | None,
    bootstrap_pem_context: str | None,
    bootstrap_passphrase_ciphertext: str | None,
    bootstrap_passphrase_context: str | None,
    bootstrap_connect_timeout: float,
) -> None:
    """Optionally do the operator-driven SSH-CA bootstrap on ``node``.

    ``node`` is either a hub (:class:`Server`) or an SSH-provisioned
    spoke (:class:`Client`); only its ``hostname`` / ``ssh_port`` /
    ``ssh_username`` are read, so both share this one code path.

    When ``bootstrap_pem_ciphertext`` is present, opens **one**
    TOFU-permitted :class:`BootstrapSSHRunner` session against the
    target with the decrypted operator key and lays down the CA
    trust + signed host cert + sshd drop-in via
    :func:`wg_manager.bootstrap_ssh.bootstrap_host`. After this
    returns, the host trusts the CA so the production CA-mode
    runner can handshake without TOFU.

    No-op when ``bootstrap_pem_ciphertext`` is ``None`` — the
    caller assumed the host was already bootstrapped (CLI flow,
    earlier dashboard run, baked AMI).

    The decrypted PEM and passphrase live only inside this function
    frame: dropped at return, never written to disk, never persisted
    to the DB. The runner is constructed with ``key_pem=`` so
    nothing touches the filesystem.

    :raises SSHConnectionError, SSHCommandError, HostCertInstallError,
        SSHCAError: propagated unwrapped so the surrounding
        ``except _SSH_EXPECTED_ERRORS`` in
        :func:`provision_server_task` / :func:`provision_client_task`
        catches them with the rest of the SSH error family.
    """
    if bootstrap_pem_ciphertext is None:
        return
    if bootstrap_pem_context is None:
        raise ValueError(
            "bootstrap_pem_context is required when "
            "bootstrap_pem_ciphertext is supplied"
        )

    crypto = make_crypto_backend()
    pem = crypto.decrypt(
        bootstrap_pem_ciphertext, context=bootstrap_pem_context
    ).decode("utf-8")
    passphrase: str | None = None
    if bootstrap_passphrase_ciphertext is not None:
        if bootstrap_passphrase_context is None:
            raise ValueError(
                "bootstrap_passphrase_context is required when "
                "bootstrap_passphrase_ciphertext is supplied"
            )
        passphrase = crypto.decrypt(
            bootstrap_passphrase_ciphertext,
            context=bootstrap_passphrase_context,
        ).decode("utf-8")

    settings = Settings()
    ca = make_ssh_ca_backend(settings)
    runner = BootstrapSSHRunner(
        host=node.hostname,
        port=node.ssh_port,
        username=node.ssh_username,
        key_pem=pem,
        passphrase=passphrase,
        connect_timeout=bootstrap_connect_timeout,
    )
    with runner as session:
        bootstrap_host(
            runner=session,
            hostname=node.hostname,
            # Phase 2c: the cert principal defaults to the SSH dial
            # name. Operators who need a different principal use the
            # CLI or the (deprecated) standalone bootstrap path —
            # the merged registration flow is intentionally narrow
            # so the form stays one page.
            principal=node.hostname,
            ca=ca,
            ttl_seconds=settings.ssh_host_cert_ttl_seconds,
            cn=node.ssh_username,
        )


@celery_app.task(name="wg_manager.tasks.provision_server", bind=True)
def provision_server_task(
    self,
    server_id: int,
    *,
    bootstrap_pem_ciphertext: str | None = None,
    bootstrap_pem_context: str | None = None,
    bootstrap_passphrase_ciphertext: str | None = None,
    bootstrap_passphrase_context: str | None = None,
    bootstrap_connect_timeout: float = 15.0,
) -> dict[str, Any]:
    """Provision (or re-provision) a WireGuard hub identified by ``server_id``.

    The remote ``wg0.conf`` is rewritten from scratch and includes every
    currently-``ready`` client for this server, so repeated invocations are
    safe even when the node was left half-configured.

    **Optional bootstrap step (this cycle).** When the operator
    submits ``POST /servers`` with the bootstrap fields populated,
    the router encrypts the PEM + passphrase and passes the
    ciphertext through to this task as the ``bootstrap_*`` kwargs.
    The task opens a one-shot :class:`BootstrapSSHRunner` session
    (TOFU + operator's OOB key) and lays down the SSH CA trust +
    signed host cert + sshd drop-in BEFORE opening the regular
    CA-mode session. Bootstrap is idempotent — re-running rotates
    the host cert in place — so this is safe to send even when the
    box was already bootstrapped, but the dashboard form only
    surfaces the section for fresh hosts to keep the common case
    simple.

    Skipped entirely when ``bootstrap_pem_ciphertext`` is ``None``;
    the production CA-mode runner runs as it did before and fails
    cleanly with ``host cert signed by an untrusted CA`` if the
    box really isn't ready yet.

    Phase 3d cycle 2 idempotency: **GUARDED_BY_ROW_LOCK** (cycle 3
    upgraded from BENIGN_OVERWRITE). Acquires
    :func:`wg_manager.locks.task_row_lock` on ``wgm:server:<id>``
    before any SSH or DB-mutation work. A second worker that races
    the same ``server_id`` is held off at the lock (or, if the lock
    is held already, returns ``{"status": "skipped"}`` and lets
    the broker re-deliver later). Remote SSH commands remain
    guarded for re-run safety (``apt-get install`` is idempotent;
    ``_ensure_keypair`` runs ``test -s … || generate``); the lock
    is the cycle 3 belt to cycle 2's suspenders.

    :param server_id: Primary key of the :class:`Server` row to provision.
    :type server_id: int
    :param bootstrap_pem_ciphertext: Crypto-backend ciphertext of the
        operator's OOB SSH private key. Decrypted in-memory and used
        for one bootstrap session. ``None`` disables the bootstrap step.
    :param bootstrap_pem_context: Encryption context used at encrypt
        time. Required when ``bootstrap_pem_ciphertext`` is supplied.
    :param bootstrap_passphrase_ciphertext: Optional ciphertext of
        the passphrase protecting the bootstrap PEM.
    :param bootstrap_passphrase_context: Context for the passphrase
        ciphertext. Pairs with ``bootstrap_passphrase_ciphertext``.
    :param bootstrap_connect_timeout: Seconds the bootstrap SSH
        session waits for TCP / banner / auth before giving up.
    :return: Summary of the final state.
    :rtype: dict[str, Any]
    :raises ValueError: If the server or its SSH key cannot be loaded.
    """
    from wg_manager.db import engine

    with Session(engine) as session:
        # Phase 3d cycle 3 — advisory lock keyed on the server row.
        # Another worker concurrently provisioning the same server
        # makes us skip rather than race; broker re-delivery picks
        # us back up once the holding worker finishes.
        with task_row_lock(session, "server", server_id) as acquired:
            if not acquired:
                return {
                    "status": "skipped",
                    "reason": "concurrent_run",
                    "server_id": server_id,
                }
            server = session.get(Server, server_id)
            if server is None:
                raise ValueError(f"Server {server_id} not found")
            ssh_key = session.get(SSHKey, server.ssh_key_id)
            if ssh_key is None:
                _mark_error(session, server)
                raise ValueError(f"SSH key {server.ssh_key_id} not found")

            clients = _ready_clients_for(session, server_id)

            try:
                # Optional first hop — only when the operator supplied
                # bootstrap material at registration time. Lives inside
                # the same try/except so a bootstrap failure marks the
                # row error + surfaces a single tidy line, exactly like
                # a provision-side SSH failure.
                _run_bootstrap_if_supplied(
                    node=server,
                    bootstrap_pem_ciphertext=bootstrap_pem_ciphertext,
                    bootstrap_pem_context=bootstrap_pem_context,
                    bootstrap_passphrase_ciphertext=bootstrap_passphrase_ciphertext,
                    bootstrap_passphrase_context=bootstrap_passphrase_context,
                    bootstrap_connect_timeout=bootstrap_connect_timeout,
                )

                with _open_runner(
                    host=server.hostname,
                    known_principals=server.host_cert_principals,
                    port=server.ssh_port,
                    username=server.ssh_username,
                    ssh_key=ssh_key,
                ) as runner:
                    public_key = provision_server(runner, server, clients)
                    # CP3: mint + install the host cert on the same SSH
                    # session — CP4.4 made this unconditional, so every
                    # successful provision lands a fresh cert on the host
                    # and the matching ``host_cert_*`` columns on the row.
                    _install_host_cert(
                        runner=runner,
                        server=server,
                        settings=Settings(),
                    )
            except _SSH_EXPECTED_ERRORS as exc:
                # Expected: timeout / auth / refused / non-zero remote command.
                # Log a single tidy line and convert to a clean failure.
                logger.error(
                    "server %s provisioning failed for %s: %s",
                    server_id,
                    server.hostname,
                    exc,
                )
                _mark_error(session, server)
                raise _fail_clean(
                    f"server {server_id} ({server.hostname}) provisioning failed: {exc}"
                ) from None
            except Exception:
                # Unexpected: keep the traceback so we don't paper over bugs.
                logger.exception("server %s provisioning failed", server_id)
                _mark_error(session, server)
                raise

            server.public_key = public_key
            server.status = NodeStatus.ready
            session.add(server)
            session.commit()
            session.refresh(server)
            return {
                "server_id": server.id,
                "status": server.status.value,
                "public_key": server.public_key,
                "address": server.address,
                "peer_count": len(clients),
            }


@celery_app.task(name="wg_manager.tasks.rotate_host_cert", bind=True)
def rotate_host_cert_task(self, server_id: int) -> dict[str, Any]:
    """Re-mint and install the host certificate for ``server_id``.

    The operator-facing rotation flow (Phase 2c CP3.3): open an SSH
    session to the host, drive
    :func:`wg_manager.host_ssh.install_host_cert` end-to-end (which is
    idempotent — it overwrites every file in place and reloads sshd),
    then update the CP3.1 host-cert columns on the row with the
    freshly-minted cert.

    Phase 2c CP4.4 dropped the legacy-mode precondition that earlier
    versions guarded with — every ``SSHKey`` row is now CA-mode by
    construction, so the task can dial unconditionally.

    Phase 3d cycle 2 idempotency: **GUARDED_BY_ROW_LOCK** (cycle 3
    upgraded from BENIGN_OVERWRITE). Acquires
    :func:`wg_manager.locks.task_row_lock` on ``wgm:server:<id>``
    before minting the cert. Concurrent rotations on the same
    ``server_id`` see one workflow finish before the other
    proceeds (no wasted Vault signatures from racing workers).

    :param server_id: Primary key of the :class:`Server` whose host
        cert should be rotated.
    :return: ``{"status", "server_id", "serial", "valid_before"}``.
        ``valid_before`` is an ISO-8601 string so the result dict is
        JSON-safe for the ``GET /tasks/{id}`` response.
    :raises ValueError: If the server (or its SSH key) cannot be loaded.
    """
    from wg_manager.db import engine

    settings = Settings()

    with Session(engine) as session:
        # Phase 3d cycle 3 — advisory lock keyed on the server row.
        with task_row_lock(session, "server", server_id) as acquired:
            if not acquired:
                return {
                    "status": "skipped",
                    "reason": "concurrent_run",
                    "server_id": server_id,
                }
            server = session.get(Server, server_id)
            if server is None:
                raise ValueError(f"Server {server_id} not found")
            ssh_key = session.get(SSHKey, server.ssh_key_id)
            if ssh_key is None:
                raise ValueError(f"SSH key {server.ssh_key_id} not found")

            try:
                with _open_runner(
                    host=server.hostname,
                    known_principals=server.host_cert_principals,
                    port=server.ssh_port,
                    username=server.ssh_username,
                    ssh_key=ssh_key,
                ) as runner:
                    ca = make_ssh_ca_backend(settings)
                    cert = install_host_cert(
                        runner=runner,
                        server=server,
                        ca=ca,
                        ttl_seconds=settings.ssh_host_cert_ttl_seconds,
                    )
                    _persist_host_cert(server, cert, ca.ca_public_key)
            except _SSH_EXPECTED_ERRORS as exc:
                logger.error(
                    "host-cert rotation failed for server %s (%s): %s",
                    server_id,
                    server.hostname,
                    exc,
                )
                raise _fail_clean(
                    f"host-cert rotation failed for server {server_id} "
                    f"({server.hostname}): {exc}"
                ) from None

            session.add(server)
            session.commit()
            session.refresh(server)
            return {
                "status": "ok",
                "server_id": server_id,
                "serial": server.host_cert_serial,
                # ISO-8601 string keeps the dict JSON-serialisable for the
                # ``GET /tasks/{id}`` response. The DB-side datetime is
                # already UTC.
                "valid_before": (
                    server.host_cert_valid_before.isoformat()
                    if server.host_cert_valid_before
                    else None
                ),
            }


@celery_app.task(name="wg_manager.tasks.rotate_client_host_cert", bind=True)
def rotate_client_host_cert_task(self, client_id: int) -> dict[str, Any]:
    """Re-mint and install the SSH host certificate for client ``client_id``.

    Client twin of :func:`rotate_host_cert_task`: opens a CA-mode SSH
    session to the client, re-runs the idempotent host-side install
    (:func:`wg_manager.host_ssh.install_host_cert`), and overwrites the
    row's ``host_cert_*`` columns with the fresh cert. Lets operators
    renew a client's cert before ``SSH_HOST_CERT_TTL_SECONDS`` expires
    without re-running ``bootstrap-host``.

    A failed rotation does NOT flip the row to ``error`` — the client's
    WireGuard config is untouched and still working; only the cert
    renewal failed, which the task result reports.

    Phase 3d cycle 2 idempotency: **GUARDED_BY_ROW_LOCK**. Acquires
    :func:`wg_manager.locks.task_row_lock` on ``wgm:client:<id>`` before
    minting, so it also serializes against a concurrent
    ``provision_client_task`` on the same row. On contention returns
    ``{"status": "skipped", ...}`` without any SSH or DB work.

    :param client_id: Primary key of the :class:`Client` to rotate.
    :return: ``{"status", "client_id", "serial", "valid_before"}`` with
        ``valid_before`` as an ISO-8601 string (JSON-safe for
        ``GET /tasks/{id}``).
    :raises ValueError: If the client is missing, manual, or its SSH
        key is gone.
    :raises RuntimeError: One clean line when the SSH / CA work fails.
    """
    from wg_manager.db import engine

    settings = Settings()

    with Session(engine) as session:
        with task_row_lock(session, "client", client_id) as acquired:
            if not acquired:
                return {
                    "status": "skipped",
                    "reason": "concurrent_run",
                    "client_id": client_id,
                }
            client = session.get(Client, client_id)
            if client is None:
                raise ValueError(f"Client {client_id} not found")
            if client.is_manual or client.hostname is None:
                raise ValueError(
                    f"Client {client_id} is a manual client; no SSH access "
                    "to rotate a host cert on"
                )
            if client.ssh_key_id is None or client.ssh_username is None:
                raise ValueError(f"Client {client_id} has no SSH credentials")
            ssh_key = session.get(SSHKey, client.ssh_key_id)
            if ssh_key is None:
                raise ValueError(f"SSH key {client.ssh_key_id} not found")

            try:
                with _open_runner(
                    host=client.hostname,
                    known_principals=client.host_cert_principals,
                    port=client.ssh_port,
                    username=client.ssh_username,
                    ssh_key=ssh_key,
                ) as runner:
                    _install_host_cert(runner=runner, server=client, settings=settings)
            except _SSH_EXPECTED_ERRORS as exc:
                logger.error(
                    "host-cert rotation failed for client %s (%s): %s",
                    client_id,
                    client.hostname,
                    exc,
                )
                raise _fail_clean(
                    f"host-cert rotation failed for client {client_id} "
                    f"({client.hostname}): {exc}"
                ) from None

            session.add(client)
            session.commit()
            session.refresh(client)
            return {
                "status": "ok",
                "client_id": client_id,
                "serial": client.host_cert_serial,
                "valid_before": (
                    client.host_cert_valid_before.isoformat()
                    if client.host_cert_valid_before
                    else None
                ),
            }


@celery_app.task(name="wg_manager.tasks.rotate_expiring_host_certs", bind=True)
def rotate_expiring_host_certs_task(self) -> dict[str, Any]:
    """Dispatch host-cert rotation for every host whose cert is about to lapse.

    Run by Celery beat every ``SSH_HOST_CERT_ROTATION_INTERVAL_SECONDS``
    (see ``beat_schedule`` in :mod:`wg_manager.celery_app`). Needed
    because :class:`wg_manager.ssh.KnownHostsCAPolicy` rejects expired
    host certs, and an expired host can't be rotated (rotation itself
    needs a trusted session) — only re-bootstrapped by hand.

    Selects rows that are ``ready`` and whose ``host_cert_valid_before``
    is either within ``SSH_HOST_CERT_RENEW_BEFORE_SECONDS`` of now
    (including already expired — the dispatch fails cleanly and the
    failure is visible in the task result / logs) or ``NULL`` (cert
    state unknown, e.g. rows provisioned before host-cert tracking):

    * servers → :func:`rotate_host_cert_task`
    * SSH-provisioned clients (``is_manual=False``) →
      :func:`rotate_client_host_cert_task`

    Non-ready rows are skipped: a pending row is mid-provision (which
    installs a fresh cert anyway) and an error row needs an operator.

    Each rotation is its own task so one unreachable host can't block
    the rest, and a dispatch failure (broker hiccup) is logged and
    reported without aborting the sweep.

    Phase 3d cycle 2 idempotency: **BENIGN_OVERWRITE**. The sweep holds
    no lock and mutates nothing itself; the dispatched rotation tasks
    each take their row lock, so a duplicate sweep (two beats, or a
    manual trigger racing beat) only costs redundant Vault signatures.

    :return: ``{"servers": [ids], "clients": [ids], "failed": [...]}``
        where ``failed`` lists ``{"kind", "id", "error"}`` for dispatches
        that raised.
    """
    from wg_manager.db import engine

    settings = Settings()
    # Stored datetimes are naive UTC (SQLite / MySQL DATETIME drop tzinfo).
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(
        seconds=settings.ssh_host_cert_renew_before_seconds
    )

    with Session(engine) as session:
        server_ids = list(
            session.exec(
                select(Server.id).where(
                    Server.status == NodeStatus.ready,
                    or_(
                        col(Server.host_cert_valid_before).is_(None),
                        col(Server.host_cert_valid_before) < cutoff,
                    ),
                )
            ).all()
        )
        client_ids = list(
            session.exec(
                select(Client.id).where(
                    Client.status == NodeStatus.ready,
                    col(Client.is_manual).is_(False),
                    or_(
                        col(Client.host_cert_valid_before).is_(None),
                        col(Client.host_cert_valid_before) < cutoff,
                    ),
                )
            ).all()
        )

    failed: list[dict[str, Any]] = []
    dispatched: dict[str, list[int]] = {"servers": [], "clients": []}
    for kind, ids, task in (
        ("server", server_ids, rotate_host_cert_task),
        ("client", client_ids, rotate_client_host_cert_task),
    ):
        for row_id in ids:
            try:
                task.delay(row_id)
            except Exception as exc:  # noqa: BLE001 — isolate per-row dispatch
                # Log with context and keep going: one bad dispatch must
                # not strand every other host's renewal until next sweep.
                logger.exception(
                    "host-cert rotation dispatch failed for %s %s", kind, row_id
                )
                failed.append({"kind": kind, "id": row_id, "error": str(exc)})
            else:
                dispatched[f"{kind}s"].append(row_id)

    logger.info(
        "host-cert sweep: %d server(s), %d client(s) dispatched, %d failed",
        len(dispatched["servers"]),
        len(dispatched["clients"]),
        len(failed),
    )
    return {**dispatched, "failed": failed}


# How a reconfigure that finds the hub lock held backs off. 30 x 10 s
# covers five minutes of continuous contention, far longer than any
# healthy SSH reconfigure, before the task fails loudly.
RECONFIGURE_RETRY_SECONDS = 10
RECONFIGURE_MAX_RETRIES = 30


def request_reconfigure(server_id: int) -> Any:
    """Ask for the hub's peer list to catch up with the DB, then dispatch.

    **The only sanctioned way to dispatch** :func:`reconfigure_server_task`.
    Call it *after* committing the change the hub must learn about. It
    bumps ``server.reconfig_requested_gen`` in its own transaction and
    queues the task with that generation, which lets the task:

    * skip work a newer run already covered (coalescing), and
    * never mark a generation applied unless its client list was read
      after the change that requested it.

    The bump is a single ``UPDATE … SET gen = gen + 1``, so concurrent
    callers each get a distinct increment.

    :param server_id: Hub to reconfigure.
    :return: The Celery ``AsyncResult`` of the queued task.
    :raises ValueError: If the server doesn't exist.
    """
    from sqlalchemy import update

    from wg_manager.db import engine

    with Session(engine) as session:
        bumped = session.exec(  # type: ignore[call-overload]
            update(Server)
            .where(Server.id == server_id)
            .values(reconfig_requested_gen=Server.reconfig_requested_gen + 1)
        )
        if bumped.rowcount != 1:
            session.rollback()
            raise ValueError(f"Server {server_id} not found")
        session.commit()
        generation = session.exec(
            select(Server.reconfig_requested_gen).where(Server.id == server_id)
        ).one()
    return reconfigure_server_task.apply_async(
        args=(server_id,), kwargs={"generation": int(generation)}
    )


@celery_app.task(
    name="wg_manager.tasks.reconfigure_server",
    bind=True,
    max_retries=RECONFIGURE_MAX_RETRIES,
)
def reconfigure_server_task(
    self, server_id: int, generation: int | None = None
) -> dict[str, Any]:
    """Regenerate the server's ``wg0.conf`` from DB state and restart the interface.

    This is the fast path: no package install, no keygen. Dispatch it
    through :func:`request_reconfigure`, never ``.delay()`` directly.

    Phase 3d cycle 2 idempotency: **GUARDED_BY_ROW_LOCK**, and since
    Phase 3f hardening also **GENERATION_COALESCED**. It holds
    :func:`wg_manager.locks.task_row_lock` on ``wgm:server:<id>`` so
    concurrent reconfigures can't flap the interface, and re-running it
    renders the same ``wg0.conf`` from DB state.

    Concurrency (see Alembic 0019 for the full story):

    * **Lock contention retries.** It used to skip, which lost updates:
      the lock holder may have read the client list before this task's
      change was committed. Now it retries every
      :data:`RECONFIGURE_RETRY_SECONDS`, up to
      :data:`RECONFIGURE_MAX_RETRIES` times, then fails.
    * **Coalescing.** If ``server.reconfig_applied_gen`` already covers
      ``generation``, a newer run already wrote a client list that
      includes this change, so the task returns ``coalesced`` with no
      SSH session and no interface restart.
    * **Ordering.** Inside the lock, ``reconfig_requested_gen`` is read
      *before* the client list, from a session opened after the lock
      was acquired. That guarantees every generation up to the one read
      is reflected in the list, so it's safe to mark it applied once the
      hub has the config.

    :param server_id: Primary key of the :class:`Server` row to reconfigure.
    :param generation: Requested generation this run must cover. ``None``
        (messages queued before Alembic 0019) always applies.
    :return: ``{"status": "applied", ...}`` or ``{"status": "coalesced", ...}``.
    :raises ValueError: If the server or its SSH key cannot be loaded.
    :raises celery.exceptions.Retry: When the hub lock is held.
    """
    from sqlalchemy import update

    from wg_manager.db import engine

    with Session(engine) as lock_session:
        with task_row_lock(lock_session, "server", server_id) as acquired:
            if not acquired:
                raise self.retry(countdown=RECONFIGURE_RETRY_SECONDS)

            # Fresh session opened after the lock is held, so its reads
            # can't come from a snapshot taken while we were waiting.
            with Session(engine) as session:
                server = session.get(Server, server_id)
                if server is None:
                    raise ValueError(f"Server {server_id} not found")
                if (
                    generation is not None
                    and server.reconfig_applied_gen >= generation
                ):
                    return {
                        "status": "coalesced",
                        "server_id": server_id,
                        "generation": generation,
                        "applied_generation": server.reconfig_applied_gen,
                    }
                ssh_key = session.get(SSHKey, server.ssh_key_id)
                if ssh_key is None:
                    raise ValueError(f"SSH key {server.ssh_key_id} not found")

                # Order matters: target first, then the clients it covers.
                target = server.reconfig_requested_gen
                clients = _ready_clients_for(session, server_id)

                try:
                    with _open_runner(
                        host=server.hostname,
                        known_principals=server.host_cert_principals,
                        port=server.ssh_port,
                        username=server.ssh_username,
                        ssh_key=ssh_key,
                    ) as runner:
                        reconfigure_server(runner, server, clients)
                except _SSH_EXPECTED_ERRORS as exc:
                    logger.error(
                        "server %s reconfigure failed for %s: %s",
                        server_id,
                        server.hostname,
                        exc,
                    )
                    raise _fail_clean(
                        f"server {server_id} ({server.hostname}) reconfigure failed: {exc}"
                    ) from None

                # Only ever moves forward: a guarded UPDATE, so a slower
                # run can't roll back a newer run's applied generation.
                session.exec(  # type: ignore[call-overload]
                    update(Server)
                    .where(Server.id == server_id)
                    .where(Server.reconfig_applied_gen < target)
                    .values(reconfig_applied_gen=target)
                )
                session.commit()

                return {
                    "status": "applied",
                    "server_id": server_id,
                    "generation": target,
                    "peer_count": len(clients),
                    "peers": [c.name for c in clients],
                }


@celery_app.task(name="wg_manager.tasks.provision_client", bind=True)
def provision_client_task(
    self,
    client_id: int,
    *,
    bootstrap_pem_ciphertext: str | None = None,
    bootstrap_pem_context: str | None = None,
    bootstrap_passphrase_ciphertext: str | None = None,
    bootstrap_passphrase_context: str | None = None,
    bootstrap_connect_timeout: float = 15.0,
) -> dict[str, Any]:
    """Provision (or re-provision) a WireGuard spoke.

    On success the task commits the client in ``ready`` state and dispatches
    :func:`reconfigure_server_task` so the hub picks up the new peer.

    **Optional bootstrap step.** Same contract as
    :func:`provision_server_task`: when ``POST /clients`` carried the
    operator's OOB key, the router passes its ciphertext here and the
    task runs :func:`_run_bootstrap_if_supplied` against the client
    BEFORE opening the CA-mode session. A bootstrap failure marks the
    client ``error`` and skips provisioning. Omitted → no bootstrap.

    Phase 3d cycle 2 idempotency: **GUARDED_BY_ROW_LOCK** (cycle 3
    upgraded from BENIGN_OVERWRITE). Acquires
    :func:`wg_manager.locks.task_row_lock` on ``wgm:client:<id>``
    before any SSH work. The follow-up ``reconfigure_server_task``
    dispatch takes its own lock on ``wgm:server:<server_id>``.
    Concurrent provisions on the same client serialize at the
    lock; on contention the second worker skips and lets the
    broker re-deliver.

    :param client_id: Primary key of the :class:`Client` row to provision.
    :type client_id: int
    :param bootstrap_pem_ciphertext: Crypto-backend ciphertext of the
        operator's OOB SSH private key. ``None`` disables bootstrap.
    :param bootstrap_pem_context: Encryption context for the PEM
        ciphertext. Required when ``bootstrap_pem_ciphertext`` is set.
    :param bootstrap_passphrase_ciphertext: Optional ciphertext of the
        passphrase protecting the bootstrap PEM.
    :param bootstrap_passphrase_context: Context for the passphrase
        ciphertext.
    :param bootstrap_connect_timeout: Seconds the bootstrap SSH session
        waits for TCP / banner / auth before giving up.
    :return: Summary of the final state.
    :rtype: dict[str, Any]
    :raises ValueError: If any required row cannot be loaded.
    """
    from wg_manager.db import engine

    with Session(engine) as session:
        # Phase 3d cycle 3 — advisory lock on the client row.
        with task_row_lock(session, "client", client_id) as acquired:
            if not acquired:
                return {
                    "status": "skipped",
                    "reason": "concurrent_run",
                    "client_id": client_id,
                }
            client = session.get(Client, client_id)
            if client is None:
                raise ValueError(f"Client {client_id} not found")
            server = session.get(Server, client.server_id)
            if server is None:
                _mark_error(session, client)
                raise ValueError(f"Server {client.server_id} not found")
            client_key = session.get(SSHKey, client.ssh_key_id)
            if client_key is None:
                _mark_error(session, client)
                raise ValueError("SSH key for client is missing")

            try:
                # Optional first hop, inside the same try so a bootstrap
                # failure marks the client error with one tidy line.
                _run_bootstrap_if_supplied(
                    node=client,
                    bootstrap_pem_ciphertext=bootstrap_pem_ciphertext,
                    bootstrap_pem_context=bootstrap_pem_context,
                    bootstrap_passphrase_ciphertext=bootstrap_passphrase_ciphertext,
                    bootstrap_passphrase_context=bootstrap_passphrase_context,
                    bootstrap_connect_timeout=bootstrap_connect_timeout,
                )

                with _open_runner(
                    host=client.hostname,
                    known_principals=client.host_cert_principals,
                    port=client.ssh_port,
                    username=client.ssh_username,
                    ssh_key=client_key,
                ) as client_runner:
                    client_pubkey = provision_client(client_runner, client, server)
                    # Parity with provision_server_task: refresh the
                    # client's host cert on every successful provision so
                    # its ``host_cert_*`` columns are populated and the
                    # TTL clock restarts.
                    _install_host_cert(
                        runner=client_runner,
                        server=client,
                        settings=Settings(),
                    )
            except _SSH_EXPECTED_ERRORS as exc:
                logger.error(
                    "client %s provisioning failed for %s: %s",
                    client_id,
                    client.hostname,
                    exc,
                )
                _mark_error(session, client)
                raise _fail_clean(
                    f"client {client_id} ({client.hostname}) provisioning failed: {exc}"
                ) from None
            except Exception:
                logger.exception("client %s provisioning failed", client_id)
                _mark_error(session, client)
                raise

            client.public_key = client_pubkey
            client.status = NodeStatus.ready
            session.add(client)
            session.commit()
            session.refresh(client)
            server_id = server.id
            result = {
                "client_id": client.id,
                "status": client.status.value,
                "address": client.address,
                "public_key": client.public_key,
                "server_id": server_id,
            }

    # Dispatch the follow-up server reconfigure outside the session so the
    # hub task opens its own clean session / connection.
    reconfigure_task = request_reconfigure(server_id)
    result["reconfigure_task_id"] = reconfigure_task.id
    return result


@celery_app.task(name="wg_manager.tasks.discover_peers", bind=True)
def discover_peers_task(self, server_id: int) -> dict[str, Any]:
    """Discover WireGuard peers configured on a server and persist them.

    Connects to ``server_id`` over SSH, runs ``wg show <interface> dump``,
    and upserts a :class:`DiscoveredPeer` row per peer keyed on
    ``(server_id, public_key)``. Re-running is safe — existing rows are
    refreshed in place. Peers whose public key already matches a managed
    :class:`Client` on the same server are flagged ``is_managed=True`` so
    the operator can tell observed peers apart from wg-manager-controlled
    ones.

    Each successful pass is **authoritative** for the server: any existing
    ``DiscoveredPeer`` row whose public key is *not* observed in this pass
    is pruned, so a peer removed from the server's running config clears
    from the table instead of lingering as stale data. Pruning runs only
    after a successful ``wg show`` — an SSH failure returns early (below)
    and never wipes the known peer set for a host that was merely
    unreachable.

    Phase 3d cycle 2 idempotency: **NATURALLY_IDEMPOTENT**. Read-only
    SSH + upsert keyed on ``(server_id, public_key)``. Two workers
    racing the same ``server_id`` converge to the same row set with
    the later writer winning ``last_seen_at`` — no operator-visible
    inconsistency. Safe at-least-once.

    Discovery is a read operation, so an SSH-level failure for this
    server is **not** treated as a task failure: the error is logged and
    the result contains ``status="ssh_failed"`` with the error message.
    This lets a batch discovery walking multiple servers continue past
    unreachable hosts without aborting (see :func:`discover_all_peers_task`).

    :param server_id: Primary key of the :class:`Server` to query.
    :type server_id: int
    :return: A summary of the discovery result with one of two shapes:
        ``{"status": "ok", "server_id", "peer_count", "new", "updated",
        "pruned"}`` on success, or
        ``{"status": "ssh_failed", "server_id", "peer_count": 0, "error"}``
        when the server could not be reached.
    :rtype: dict[str, Any]
    :raises ValueError: If the server or its SSH key cannot be loaded.
    """
    from wg_manager.db import engine

    with Session(engine) as session:
        server = session.get(Server, server_id)
        if server is None:
            raise ValueError(f"Server {server_id} not found")
        ssh_key = session.get(SSHKey, server.ssh_key_id)
        if ssh_key is None:
            raise ValueError(f"SSH key {server.ssh_key_id} not found")

        try:
            with _open_runner(
                host=server.hostname,
                known_principals=server.host_cert_principals,
                port=server.ssh_port,
                username=server.ssh_username,
                ssh_key=ssh_key,
            ) as runner:
                _interface, peers = discover_peers(runner, server)
        except _SSH_EXPECTED_ERRORS as exc:
            # Fail-soft: log and return — do NOT raise. Callers (notably
            # the batch task) need to continue past unreachable hosts.
            logger.error(
                "discovery on server %s (%s) failed: %s",
                server_id,
                server.hostname,
                exc,
            )
            return {
                "status": "ssh_failed",
                "server_id": server_id,
                "hostname": server.hostname,
                "peer_count": 0,
                "error": (
                    f"discovery on server {server_id} "
                    f"({server.hostname}) failed: {exc}"
                ),
            }

        managed_keys: set[str] = {
            row.public_key
            for row in session.exec(
                select(Client).where(Client.server_id == server_id)
            ).all()
            if row.public_key
        }

        now = datetime.now(tz=timezone.utc)
        new_count = 0
        updated_count = 0
        observed_keys = {peer.public_key for peer in peers}
        for peer in peers:
            existing = session.exec(
                select(DiscoveredPeer).where(
                    DiscoveredPeer.server_id == server_id,
                    DiscoveredPeer.public_key == peer.public_key,
                )
            ).first()
            handshake_at: datetime | None = (
                datetime.fromtimestamp(peer.last_handshake_epoch, tz=timezone.utc)
                if peer.last_handshake_epoch > 0
                else None
            )
            is_managed = peer.public_key in managed_keys
            if existing is None:
                row = DiscoveredPeer(
                    server_id=server_id,
                    public_key=peer.public_key,
                    allowed_ips=peer.allowed_ips,
                    endpoint=peer.endpoint,
                    last_handshake_at=handshake_at,
                    rx_bytes=peer.rx_bytes,
                    tx_bytes=peer.tx_bytes,
                    persistent_keepalive=peer.persistent_keepalive,
                    is_managed=is_managed,
                    first_seen_at=now,
                    last_seen_at=now,
                )
                session.add(row)
                new_count += 1
            else:
                existing.allowed_ips = peer.allowed_ips
                existing.endpoint = peer.endpoint
                existing.last_handshake_at = handshake_at
                existing.rx_bytes = peer.rx_bytes
                existing.tx_bytes = peer.tx_bytes
                existing.persistent_keepalive = peer.persistent_keepalive
                existing.is_managed = is_managed
                existing.last_seen_at = now
                session.add(existing)
                updated_count += 1

        # Prune stale rows: any DiscoveredPeer for this server whose public
        # key was *not* observed in this pass has been removed from the
        # server's running config and must not linger as a ghost. This only
        # runs on a successful pass — an SSH failure returns early above, so
        # an unreachable host never wipes the known peer set (see
        # ``test_ssh_failure_does_not_prune``).
        stale_query = select(DiscoveredPeer).where(
            DiscoveredPeer.server_id == server_id
        )
        if observed_keys:
            # When the server reported peers, keep only those; otherwise the
            # ``notin_`` below would short-circuit and the bare server-scope
            # filter already selects every row to prune.
            stale_query = stale_query.where(
                DiscoveredPeer.public_key.notin_(observed_keys)  # type: ignore[attr-defined]
            )
        stale_rows = session.exec(stale_query).all()
        pruned_count = 0
        for row in stale_rows:
            session.delete(row)
            pruned_count += 1
        session.commit()

        return {
            "status": "ok",
            "server_id": server_id,
            "hostname": server.hostname,
            "peer_count": len(peers),
            "new": new_count,
            "updated": updated_count,
            "pruned": pruned_count,
        }


@celery_app.task(name="wg_manager.tasks.discover_all_peers", bind=True)
def discover_all_peers_task(self) -> dict[str, Any]:
    """Run peer discovery against every registered server in sequence.

    Per-server SSH failures are logged and skipped — they do **not** abort
    the batch. The aggregated result counts successful and failed servers

    Phase 3d cycle 2 idempotency: **NATURALLY_IDEMPOTENT** (inherits
    from :func:`discover_peers_task` which it calls per-server as a
    plain Python invocation — not ``.delay()``, so the whole batch
    runs on whichever worker picked up the parent). Safe at-least-once.
    and includes the per-server result payload so the operator can drill
    into individual failures.

    :return: ``{"servers_total", "servers_ok", "servers_failed",
        "peers_total", "results": [...]}``
    :rtype: dict[str, Any]
    """
    from wg_manager.db import engine

    with Session(engine) as session:
        server_ids: list[int] = [
            row_id for row_id in session.exec(select(Server.id)).all() if row_id
        ]

    results: list[dict[str, Any]] = []
    peers_total = 0
    ok = 0
    failed = 0
    for sid in server_ids:
        # Each server gets its own task call so a hung SSH session can't
        # take the whole batch down — the inner task already swallows SSH
        # errors and returns a result dict.
        try:
            result = discover_peers_task(sid)
        except Exception as exc:
            # Truly unexpected (not an SSH error): record it and move on
            # rather than aborting the batch.
            logger.error(
                "unexpected error during discovery on server %s: %s", sid, exc
            )
            result = {
                "status": "error",
                "server_id": sid,
                "peer_count": 0,
                "error": str(exc),
            }
        results.append(result)
        if result.get("status") == "ok":
            ok += 1
            peers_total += int(result.get("peer_count", 0))
        else:
            failed += 1

    return {
        "servers_total": len(server_ids),
        "servers_ok": ok,
        "servers_failed": failed,
        "peers_total": peers_total,
        "results": results,
    }




@celery_app.task(name="wg_manager.tasks.sweep_enrollment_tokens", bind=True)
def sweep_enrollment_tokens_task(self) -> dict[str, Any]:
    """Delete enrollment tokens that have been dead longer than the retention.

    Run by Celery beat every ``ENROLL_TOKEN_SWEEP_INTERVAL_SECONDS`` (see
    ``beat_schedule`` in :mod:`wg_manager.celery_app`). A token is dead
    once it has expired or been revoked; it's deleted once it has been
    dead for ``ENROLL_TOKEN_RETENTION_SECONDS``, so recently dead tokens
    stay visible in ``GET /v1/enrollment-tokens``. The rows hold only a
    hash, so this is housekeeping rather than secret hygiene; the
    ``enrollment_token.*`` and ``client.enroll`` audit rows keep the
    history.

    Phase 3d cycle 2 idempotency: **NATURALLY_IDEMPOTENT**. A dead
    token can't become live again, so a duplicate or overlapping sweep
    just deletes nothing the second time.

    :return: ``{"deleted": [ids]}``.
    """
    from wg_manager.db import engine
    from wg_manager.enrollment import delete_dead_tokens

    settings = Settings()
    with Session(engine) as session:
        deleted = delete_dead_tokens(
            session, retention_seconds=settings.enroll_token_retention_seconds
        )
        session.commit()
    logger.info(
        "enrollment-token sweep: deleted %d token(s) dead for over %d s",
        len(deleted),
        settings.enroll_token_retention_seconds,
    )
    return {"deleted": deleted}
