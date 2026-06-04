"""/servers router — register and query WireGuard hub nodes."""

from __future__ import annotations

from ipaddress import IPv4Network
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlmodel import Session, select

from wg_manager import audit
from wg_manager.config import settings
from wg_manager.db import get_session
from wg_manager.models import (
    Client,
    DiscoveredPeer,
    NodeStatus,
    SSHKey,
    Server,
)
from wg_manager.schemas import (
    DiscoverAllResponse,
    DiscoveredPeerRead,
    DiscoverResponse,
    HostCertRotateResponse,
    ServerCreate,
    ServerRead,
    ServerRegisterResponse,
    ServerUpdate,
)
from wg_manager.tasks import (
    discover_all_peers_task,
    discover_peers_task,
    provision_server_task,
    rotate_host_cert_task,
)
from wg_manager.models import OperatorRole
from wg_manager.tenant_scope import (
    ScopeDep,
    require_tenant_role,
    scope_filter,
)

router = APIRouter(prefix="/servers", tags=["servers"])

_SessionDep = Annotated[Session, Depends(get_session)]


@router.post(
    "",
    response_model=ServerRegisterResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def register_server(
    payload: ServerCreate, request: Request, session: _SessionDep
) -> ServerRegisterResponse:
    """Register a server and dispatch its provisioning task.

    The row is persisted in **pending** state and a Celery task is enqueued
    to perform the actual SSH-driven install. The response includes both the
    row and a ``task_id`` the caller can poll at ``GET /tasks/{task_id}``.

    Phase 2e cycle 3 wires :func:`wg_manager.audit.persist` into the
    same transaction as the row insert so a successful register lands
    one ``server.create`` audit row and a failure leaves none.
    """
    ssh_key = session.get(SSHKey, payload.ssh_key_id)
    if ssh_key is None:
        raise HTTPException(status_code=404, detail="SSH key not found")

    # ``ServerCreate`` has already validated the subnet shape; strict=False
    # here is harmless because pydantic re-emitted a network-aligned CIDR.
    subnet_cidr = payload.subnet or settings.default_subnet
    network = IPv4Network(subnet_cidr, strict=False)
    server_host = list(network.hosts())[0]
    address = f"{server_host}/{network.prefixlen}"

    row = Server(
        hostname=payload.hostname,
        ssh_port=payload.ssh_port,
        ssh_username=payload.ssh_username,
        ssh_key_id=payload.ssh_key_id,
        endpoint_host=payload.endpoint_host,
        endpoint_port=payload.endpoint_port,
        interface=payload.interface,
        subnet=str(network),
        address=address,
        public_key="",
        status=NodeStatus.pending,
    )
    session.add(row)
    session.flush()
    session.refresh(row)
    audit.persist(
        session,
        event="server.create",
        **audit.actor_from_request(request),
        resource_type="server",
        resource_id=row.id,
        action="create",
        before=None,
        after=row.model_dump(mode="json"),
        payload={"hostname": row.hostname},
        tenant_id=row.tenant_id,
    )
    session.commit()
    session.refresh(row)

    async_result = provision_server_task.delay(row.id)
    return ServerRegisterResponse(
        task_id=async_result.id,
        server=ServerRead.model_validate(row),
    )


@router.post(
    "/{server_id}/reprovision",
    response_model=ServerRegisterResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def reprovision_server(server_id: int, session: _SessionDep) -> ServerRegisterResponse:
    """Re-run provisioning against an existing server row.

    Use this to overwrite the WireGuard configuration on a server that is
    half-installed or in an ``error`` state. The keypair is preserved so
    existing clients remain valid; ``wg0.conf`` is regenerated from scratch
    (including all currently-``ready`` peers) and ``wg-quick`` is restarted.
    """
    row = session.get(Server, server_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Server not found")

    row.status = NodeStatus.pending
    session.add(row)
    session.commit()
    session.refresh(row)

    async_result = provision_server_task.delay(row.id)
    return ServerRegisterResponse(
        task_id=async_result.id,
        server=ServerRead.model_validate(row),
    )


@router.get("", response_model=list[ServerRead])
def list_servers(session: _SessionDep, scope: ScopeDep) -> list[Server]:
    """Return all registered servers visible to the calling operator.

    Phase 3b cycle 3 narrows the result set to the operator's tenant
    join set. Super-admin (global ``Operator.role = admin``) sees
    every row; non-super-admin operators see only the rows whose
    ``tenant_id`` is in their :class:`OperatorTenant` joins. An
    operator with no joins gets an empty list rather than a 403 — a
    fresh install can still hit the endpoint without locking itself
    out before the attach action runs.
    """
    query = select(Server)
    where_expr = scope_filter(scope, Server)
    if where_expr is not None:
        query = query.where(where_expr)
    return list(session.exec(query).all())


@router.get("/{server_id}", response_model=ServerRead)
def get_server(
    server_id: int, session: _SessionDep, scope: ScopeDep
) -> Server:
    """Return a single server by ID.

    Phase 3b cycle 3 returns 404 (not 403) to an operator whose
    scope doesn't include the row's tenant — the existence of the
    row in another tenant must not be leaked to a probing operator.
    """
    row = session.get(Server, server_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Server not found")
    if not scope.is_super_admin and row.tenant_id not in scope.tenant_ids:
        raise HTTPException(status_code=404, detail="Server not found")
    return row


@router.patch("/{server_id}", response_model=ServerRead)
def update_server(
    server_id: int,
    payload: ServerUpdate,
    request: Request,
    session: _SessionDep,
    scope: ScopeDep,
) -> Server:
    """Partially update operator-supplied fields on a server.

    Only the fields listed in :class:`ServerUpdate` are editable; everything
    else (subnet, address, public key, status, interface name) is treated
    as provisioning-managed state and ignored. Reassigning ``ssh_key_id``
    to a non-existent key is rejected with 404.

    Changing ``endpoint_host`` / ``endpoint_port`` does **not** rewrite
    already-deployed client configs — they will keep pointing at the old
    endpoint until each client is reprovisioned.

    Phase 2e cycle 3 captures the pre-mutation row dict for the audit
    log's ``before_hash`` and emits a ``server.update`` row inside the
    same transaction as the mutation.

    :return: The updated server row.
    :rtype: Server
    :raises HTTPException: 404 if the server (or a newly-referenced SSH
        key) does not exist.
    """
    row = session.get(Server, server_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Server not found")

    # Phase 3b cycle 3 — non-super-admin operators see 404 (not 403)
    # for rows in tenants they aren't joined to so the row's
    # existence isn't leaked. Per-tenant role check happens next:
    # ``admin`` and ``operator`` admit; ``auditor`` 403s.
    if not scope.is_super_admin and row.tenant_id not in scope.tenant_ids:
        raise HTTPException(status_code=404, detail="Server not found")
    require_tenant_role(
        scope, row.tenant_id, OperatorRole.admin, OperatorRole.operator
    )

    updates = payload.model_dump(exclude_unset=True, exclude_none=True)

    new_key_id = updates.get("ssh_key_id")
    if new_key_id is not None and session.get(SSHKey, new_key_id) is None:
        raise HTTPException(status_code=404, detail="SSH key not found")

    before = row.model_dump(mode="json")
    for field, value in updates.items():
        setattr(row, field, value)

    session.add(row)
    session.flush()
    session.refresh(row)
    audit.persist(
        session,
        event="server.update",
        **audit.actor_from_request(request),
        resource_type="server",
        resource_id=row.id,
        action="update",
        before=before,
        after=row.model_dump(mode="json"),
        payload={"hostname": row.hostname, "fields": sorted(updates.keys())},
        tenant_id=row.tenant_id,
    )
    session.commit()
    session.refresh(row)
    return row


@router.delete("/{server_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_server(
    server_id: int,
    session: _SessionDep,
    scope: ScopeDep,
    force: bool = False,
) -> None:
    """Delete a server row.

    DB-only: wg-manager does **not** SSH in to tear down ``wg-quick`` on the
    remote host. Operators are responsible for stopping the WireGuard
    service themselves if they want the box fully decommissioned.

    Refuses with 409 if any managed :class:`Client` rows still reference
    the server. Pass ``?force=true`` to cascade — every attached client and
    every discovered peer for the server is deleted along with the row.

    :param force: When true, cascade-delete dependent rows instead of
        refusing.
    :raises HTTPException: 404 if the server does not exist, 409 if it has
        attached managed clients and ``force`` is false.
    """
    row = session.get(Server, server_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Server not found")

    # Phase 3b cycle 3 — same 404-on-out-of-scope / 403-on-wrong-role
    # shape as PATCH so existence isn't leaked and auditors can't
    # delete.
    if not scope.is_super_admin and row.tenant_id not in scope.tenant_ids:
        raise HTTPException(status_code=404, detail="Server not found")
    require_tenant_role(
        scope, row.tenant_id, OperatorRole.admin, OperatorRole.operator
    )

    attached_clients = list(
        session.exec(select(Client).where(Client.server_id == server_id)).all()
    )

    if attached_clients and not force:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Server still has {len(attached_clients)} managed client(s); "
                "pass ?force=true to cascade-delete them."
            ),
        )

    if force:
        for managed_client in attached_clients:
            session.delete(managed_client)
        discovered = list(
            session.exec(
                select(DiscoveredPeer).where(DiscoveredPeer.server_id == server_id)
            ).all()
        )
        for peer in discovered:
            session.delete(peer)

    session.delete(row)
    session.commit()
    return None


@router.post(
    "/{server_id}/discover",
    response_model=DiscoverResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def discover_server_peers(server_id: int, session: _SessionDep) -> DiscoverResponse:
    """Kick off an asynchronous discovery scan of the server's WireGuard peers.

    The Celery task SSHes into the server, runs ``wg show <interface> dump``,
    and upserts a row into the ``discoveredpeer`` table for every peer
    observed. Re-running the endpoint is safe — existing rows are refreshed
    in place, never duplicated.

    :return: The server row and a ``task_id`` callers can poll at
        ``GET /tasks/{task_id}``.
    :rtype: DiscoverResponse
    """
    row = session.get(Server, server_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Server not found")

    async_result = discover_peers_task.delay(row.id)
    return DiscoverResponse(
        task_id=async_result.id,
        server=ServerRead.model_validate(row),
    )


@router.get(
    "/{server_id}/discovered-peers",
    response_model=list[DiscoveredPeerRead],
)
def list_server_discovered_peers(
    server_id: int, session: _SessionDep
) -> list[DiscoveredPeer]:
    """List every peer that has been discovered on ``server_id``.

    Returns an empty list if no discovery has run yet. The server must exist;
    a 404 is returned otherwise so callers can tell "no peers" apart from
    "no such server".
    """
    if session.get(Server, server_id) is None:
        raise HTTPException(status_code=404, detail="Server not found")
    return list(
        session.exec(
            select(DiscoveredPeer).where(DiscoveredPeer.server_id == server_id)
        ).all()
    )


@router.get("/discovered-peers/all", response_model=list[DiscoveredPeerRead])
def list_all_discovered_peers(session: _SessionDep) -> list[DiscoveredPeer]:
    """List discovered peers across every server."""
    return list(session.exec(select(DiscoveredPeer)).all())


@router.post(
    "/{server_id}/rotate-host-cert",
    response_model=HostCertRotateResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def rotate_server_host_cert(
    server_id: int, session: _SessionDep
) -> HostCertRotateResponse:
    """Re-mint and install the server's SSH host certificate.

    Phase 2c CP3.3 — operator-driven rotation of the cert the SSH CA
    last signed for this host. Dispatches
    :func:`wg_manager.tasks.rotate_host_cert_task` which SSHes into
    the host, re-runs the host-side install (idempotent), and
    overwrites the row's ``host_cert_*`` columns with the freshly-
    minted cert (new serial, new validity window).

    Phase 2c CP4.4 dropped the legacy-mode precondition: every
    ``SSHKey`` row is CA-mode now by construction, so the only
    pre-flight check left is "does the row exist".

    :return: ``{task_id, server}`` — task to poll, plus the row as it
        was at dispatch time. The row's columns update once the task
        completes; the dashboard re-queries to pick up the new cert.
    :raises HTTPException: 404 when ``server_id`` doesn't exist; 409
        when the row's referenced SSH key has been deleted out from
        under it.
    """
    row = session.get(Server, server_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Server not found")

    ssh_key = session.get(SSHKey, row.ssh_key_id)
    if ssh_key is None:
        # The FK is non-nullable so this shouldn't happen, but a 409 is
        # more honest than a 500 if a row's referenced key got deleted
        # behind a broken constraint.
        raise HTTPException(
            status_code=409,
            detail=(
                f"server {row.id} references SSHKey {row.ssh_key_id} "
                f"which no longer exists; reassign before rotating"
            ),
        )

    async_result = rotate_host_cert_task.delay(row.id)
    return HostCertRotateResponse(
        task_id=async_result.id,
        server=ServerRead.model_validate(row),
    )


@router.post(
    "/discover-all",
    response_model=DiscoverAllResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def discover_all_servers(session: _SessionDep) -> DiscoverAllResponse:
    """Kick off a batch discovery against every registered server.

    The Celery task walks each server in turn. Per-host SSH failures are
    logged and skipped — they do not abort the batch, so a single
    unreachable node never blocks discovery of the rest of the fleet. The
    final aggregated result (with per-server outcomes) is available via
    ``GET /tasks/{task_id}``.
    """
    count = len(list(session.exec(select(Server.id)).all()))
    async_result = discover_all_peers_task.delay()
    return DiscoverAllResponse(task_id=async_result.id, server_count=count)
