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
from datetime import datetime, timezone
from typing import Any

from celery.utils.log import get_task_logger
from sqlmodel import Session, select

from wg_manager.celery_app import celery_app
from wg_manager.config import Settings
from wg_manager.host_ssh import HostCertInstallError, install_host_cert
from wg_manager.models import (
    Client,
    DiscoveredPeer,
    NodeStatus,
    SSHKey,
    Server,
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
    )


def _persist_host_cert(server: Server, cert: HostCert, ca_public_key: str) -> None:
    """Copy ``cert`` and the signing CA pubkey onto ``server``'s CP3.1 columns.

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
    server: Server,
    settings: Settings,
) -> None:
    """Mint + install a host cert for ``server`` and persist its metadata.

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


@celery_app.task(name="wg_manager.tasks.provision_server", bind=True)
def provision_server_task(self, server_id: int) -> dict[str, Any]:
    """Provision (or re-provision) a WireGuard hub identified by ``server_id``.

    The remote ``wg0.conf`` is rewritten from scratch and includes every
    currently-``ready`` client for this server, so repeated invocations are
    safe even when the node was left half-configured.

    :param server_id: Primary key of the :class:`Server` row to provision.
    :type server_id: int
    :return: Summary of the final state.
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
            _mark_error(session, server)
            raise ValueError(f"SSH key {server.ssh_key_id} not found")

        clients = _ready_clients_for(session, server_id)

        try:
            with _open_runner(
                host=server.hostname,
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
        server = session.get(Server, server_id)
        if server is None:
            raise ValueError(f"Server {server_id} not found")
        ssh_key = session.get(SSHKey, server.ssh_key_id)
        if ssh_key is None:
            raise ValueError(f"SSH key {server.ssh_key_id} not found")

        try:
            with _open_runner(
                host=server.hostname,
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


@celery_app.task(name="wg_manager.tasks.reconfigure_server", bind=True)
def reconfigure_server_task(self, server_id: int) -> dict[str, Any]:
    """Regenerate the server's ``wg0.conf`` from DB state and restart the interface.

    This is the fast path: no package install, no keygen. It is dispatched
    automatically after a successful client provision so new peers are
    picked up without a full re-provision of the hub.

    :param server_id: Primary key of the :class:`Server` row to reconfigure.
    :type server_id: int
    :return: Summary of the reconfigure result.
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

        clients = _ready_clients_for(session, server_id)

        try:
            with _open_runner(
                host=server.hostname,
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

        return {
            "server_id": server_id,
            "peer_count": len(clients),
            "peers": [c.name for c in clients],
        }


@celery_app.task(name="wg_manager.tasks.provision_client", bind=True)
def provision_client_task(self, client_id: int) -> dict[str, Any]:
    """Provision (or re-provision) a WireGuard spoke.

    On success the task commits the client in ``ready`` state and dispatches
    :func:`reconfigure_server_task` so the hub picks up the new peer.

    :param client_id: Primary key of the :class:`Client` row to provision.
    :type client_id: int
    :return: Summary of the final state.
    :rtype: dict[str, Any]
    :raises ValueError: If any required row cannot be loaded.
    """
    from wg_manager.db import engine

    with Session(engine) as session:
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
            with _open_runner(
                host=client.hostname,
                port=client.ssh_port,
                username=client.ssh_username,
                ssh_key=client_key,
            ) as client_runner:
                client_pubkey = provision_client(client_runner, client, server)
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
    reconfigure_task = reconfigure_server_task.delay(server_id)
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

    Discovery is a read operation, so an SSH-level failure for this
    server is **not** treated as a task failure: the error is logged and
    the result contains ``status="ssh_failed"`` with the error message.
    This lets a batch discovery walking multiple servers continue past
    unreachable hosts without aborting (see :func:`discover_all_peers_task`).

    :param server_id: Primary key of the :class:`Server` to query.
    :type server_id: int
    :return: A summary of the discovery result with one of two shapes:
        ``{"status": "ok", "server_id", "peer_count", "new", "updated"}``
        on success, or
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
        session.commit()

        return {
            "status": "ok",
            "server_id": server_id,
            "hostname": server.hostname,
            "peer_count": len(peers),
            "new": new_count,
            "updated": updated_count,
        }


@celery_app.task(name="wg_manager.tasks.discover_all_peers", bind=True)
def discover_all_peers_task(self) -> dict[str, Any]:
    """Run peer discovery against every registered server in sequence.

    Per-server SSH failures are logged and skipped — they do **not** abort
    the batch. The aggregated result counts successful and failed servers
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
