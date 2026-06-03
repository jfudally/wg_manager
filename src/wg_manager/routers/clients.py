"""/clients router — register and query WireGuard spoke nodes."""

from __future__ import annotations

from ipaddress import ip_interface
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import PlainTextResponse
from sqlmodel import Session, select

from wg_manager import audit
from wg_manager.db import get_session
from wg_manager.ipam import IPPoolExhausted, allocate_client_ip
from wg_manager.models import Client, NodeStatus, SSHKey, Server
from wg_manager.schemas import (
    ClientCreate,
    ClientDeleteResponse,
    ClientManualCreate,
    ClientManualRegisterResponse,
    ClientRead,
    ClientRegisterResponse,
    ClientUpdate,
)
from wg_manager.tasks import provision_client_task, reconfigure_server_task
from wg_manager.wireguard import (
    generate_wireguard_keypair,
    render_manual_client_config,
)

router = APIRouter(prefix="/clients", tags=["clients"])

_SessionDep = Annotated[Session, Depends(get_session)]


@router.post(
    "",
    response_model=ClientRegisterResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def register_client(payload: ClientCreate, session: _SessionDep) -> ClientRegisterResponse:
    """Register a client and dispatch its provisioning task.

    The row is persisted in **pending** state with an auto-allocated IP, then
    a Celery task is enqueued to install WireGuard on the client and add it
    as a peer on the server. The response includes a ``task_id`` the caller
    can poll at ``GET /tasks/{task_id}``.
    """
    existing = session.exec(select(Client).where(Client.name == payload.name)).first()
    if existing is not None:
        raise HTTPException(status_code=409, detail=f"Client named {payload.name!r} already exists")

    ssh_key = session.get(SSHKey, payload.ssh_key_id)
    if ssh_key is None:
        raise HTTPException(status_code=404, detail="SSH key not found")

    server = session.get(Server, payload.server_id)
    if server is None:
        raise HTTPException(status_code=404, detail="Server not found")
    if server.status != NodeStatus.ready:
        raise HTTPException(
            status_code=400,
            detail=f"Server is not ready (status={server.status.value})",
        )

    try:
        allocated = allocate_client_ip(session, server)
    except IPPoolExhausted as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    row = Client(
        name=payload.name,
        hostname=payload.hostname,
        ssh_port=payload.ssh_port,
        ssh_username=payload.ssh_username,
        ssh_key_id=payload.ssh_key_id,
        server_id=payload.server_id,
        address=f"{allocated}/32",
        public_key="",
        status=NodeStatus.pending,
    )
    session.add(row)
    session.commit()
    session.refresh(row)

    async_result = provision_client_task.delay(row.id)
    return ClientRegisterResponse(
        task_id=async_result.id,
        client=ClientRead.model_validate(row),
    )


@router.post(
    "/manual",
    response_model=ClientManualRegisterResponse,
    status_code=status.HTTP_201_CREATED,
)
def register_manual_client(
    payload: ClientManualCreate,
    session: _SessionDep,
) -> ClientManualRegisterResponse:
    """Register a client we will install by hand instead of over SSH.

    Use this for devices wg-manager can't reach (phones, IoT, locked-down
    embedded boxes). The flow is:

    1. Generate an X25519 keypair on the control plane (the device side
       never runs ``wg genkey``).
    2. Allocate the next free host address out of the parent server's
       subnet, sharing the IPAM pool with SSH-provisioned clients.
    3. Persist a :class:`Client` row in ``ready`` state with the
       **public** key and ``is_manual=True``. The private key is
       returned to the caller in this response and is never stored —
       wg-manager has no operational use for it (the device is one we
       can't log into), so persisting it would be pure liability.
    4. Render the WireGuard config (with the private key inline) and
       return it as ``wg_config`` on the response.
    5. Dispatch :func:`wg_manager.tasks.reconfigure_server_task` so the
       hub's ``wg0.conf`` is rewritten to admit the new peer.

    Because the private key is dropped after this call, the operator
    **must** capture ``wg_config`` from this response — there is no
    way to re-render it later. Losing the config means deleting the
    row and re-registering (which generates a fresh keypair and
    reconfigures the hub).

    :raises HTTPException: 409 if ``name`` collides with an existing
        client; 404 if ``server_id`` does not exist; 400 if the parent
        server is not in ``ready`` state (its public key is required to
        render the manual config); 409 if the subnet is exhausted.
    """
    existing = session.exec(select(Client).where(Client.name == payload.name)).first()
    if existing is not None:
        raise HTTPException(
            status_code=409, detail=f"Client named {payload.name!r} already exists"
        )

    server = session.get(Server, payload.server_id)
    if server is None:
        raise HTTPException(status_code=404, detail="Server not found")
    if server.status != NodeStatus.ready:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Server is not ready (status={server.status.value}); "
                "manual clients require a server whose public key is known"
            ),
        )

    try:
        allocated = allocate_client_ip(session, server)
    except IPPoolExhausted as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    private_key, public_key = generate_wireguard_keypair()
    row = Client(
        name=payload.name,
        # SSH fields stay NULL — there's no device-side login for manual rows.
        hostname=None,
        ssh_username=None,
        ssh_key_id=None,
        server_id=payload.server_id,
        address=f"{allocated}/32",
        public_key=public_key,
        is_manual=True,
        status=NodeStatus.ready,
    )
    session.add(row)
    session.commit()
    session.refresh(row)

    # Render the wg0.conf body with the freshly-generated private key
    # inline. The plaintext lives only in the local ``private_key``
    # and the response payload — both vanish when this function returns
    # and the response is serialized over the wire.
    wg_config = render_manual_client_config(
        row, server, private_key=private_key
    )

    # Push the new peer into the hub's running config so the device can
    # actually connect once the operator installs the rendered .conf.
    async_result = reconfigure_server_task.delay(payload.server_id)
    return ClientManualRegisterResponse(
        task_id=async_result.id,
        client=ClientRead.model_validate(row),
        wg_config=wg_config,
    )


@router.post(
    "/{client_id}/reprovision",
    response_model=ClientRegisterResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def reprovision_client(client_id: int, session: _SessionDep) -> ClientRegisterResponse:
    """Re-run provisioning against an existing client row.

    Use this to overwrite the WireGuard configuration on a client that is
    half-installed or in an ``error`` state. The keypair is preserved; the
    client's ``wg0.conf`` is regenerated and the service restarted, after
    which the hub is automatically reconfigured so the peer list is in sync.

    :raises HTTPException: 404 if the client does not exist; 400 if the
        client is a manual row (no SSH credentials to dial in with).
    """
    row = session.get(Client, client_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Client not found")
    if row.is_manual:
        # Manual rows have no SSH credentials — reprovision (which SSHes
        # in to rewrite /etc/wireguard/wg0.conf) can't reach the device.
        # Fail fast at the router instead of letting the Celery task
        # blow up later with a confusing "no SSH key" stack trace.
        raise HTTPException(
            status_code=400,
            detail=(
                "Cannot reprovision a manual client — delete and re-register "
                "to mint a fresh keypair and config"
            ),
        )

    row.status = NodeStatus.pending
    session.add(row)
    session.commit()
    session.refresh(row)

    async_result = provision_client_task.delay(row.id)
    return ClientRegisterResponse(
        task_id=async_result.id,
        client=ClientRead.model_validate(row),
    )


@router.get("", response_model=list[ClientRead])
def list_clients(session: _SessionDep) -> list[Client]:
    """Return all registered clients."""
    return list(session.exec(select(Client)).all())


@router.get(
    "/export/ssh-config",
    response_class=PlainTextResponse,
    responses={200: {"content": {"text/plain": {}}}},
)
def export_ssh_config(session: _SessionDep) -> str:
    """Render a ready-to-append ``~/.ssh/config`` block for every client.

    Each managed client produces one entry:

    .. code-block:: text

        Host <name>.vpn
            HostName <wg-ip>
            User <ssh_username>
            IdentityFile ~/.ssh/<key-name>

    The ``Host`` alias is the client's ``name`` with a ``.vpn`` suffix so
    operators can type ``ssh <name>.vpn`` after they've connected to the
    VPN. ``HostName`` is the wg-assigned host address — the ``/32``
    netmask stored on the row is stripped so the value is a bare IPv4
    address. ``User`` is the client's per-row ``ssh_username``.
    ``IdentityFile`` points at ``~/.ssh/<key-name>`` where ``<key-name>``
    is the SSHKey row's ``name`` column; wg-manager assumes the operator
    has placed that key under their own ``$HOME/.ssh/`` directory.

    Entries are separated by a blank line and ordered by client ID
    (insertion order in practice) so the export is stable across calls.
    The response is ``text/plain`` so the body can be piped directly
    into a file, e.g. ``curl ... > ~/.ssh/wg-manager.conf``.

    :return: Newline-terminated SSH config text. Empty string if no
        clients are registered.
    :rtype: str
    """
    # Manual clients have no SSH credentials, so they can't appear in an
    # SSH-config export. Skip them rather than emit broken ``Host`` blocks
    # with empty User / IdentityFile lines.
    clients = [
        c
        for c in session.exec(select(Client).order_by(Client.id)).all()
        if not c.is_manual
    ]
    if not clients:
        return ""

    key_ids = {c.ssh_key_id for c in clients if c.ssh_key_id is not None}
    key_names: dict[int, str] = {
        k.id: k.name
        for k in session.exec(select(SSHKey).where(SSHKey.id.in_(key_ids))).all()
        if k.id is not None
    }

    blocks: list[str] = []
    for c in clients:
        host_ip = str(ip_interface(c.address).ip) if c.address else ""
        identity = key_names.get(c.ssh_key_id, "") if c.ssh_key_id is not None else ""
        blocks.append(
            f"Host {c.name}.vpn\n"
            f"    HostName {host_ip}\n"
            f"    User {c.ssh_username}\n"
            f"    IdentityFile ~/.ssh/{identity}\n"
        )
    return "\n".join(blocks)


@router.get("/{client_id}", response_model=ClientRead)
def get_client(client_id: int, session: _SessionDep) -> Client:
    """Return a single client by ID."""
    row = session.get(Client, client_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Client not found")
    return row


@router.patch("/{client_id}", response_model=ClientRead)
def update_client(
    client_id: int, payload: ClientUpdate, session: _SessionDep
) -> Client:
    """Partially update operator-supplied fields on a client.

    Only the fields enumerated in :class:`ClientUpdate` are editable. The
    parent ``server_id``, the auto-allocated ``address``, the remote
    ``public_key`` and the ``status`` are all provisioning artefacts and
    cannot be changed here — pydantic silently drops them.

    :raises HTTPException: 404 if the client (or a newly-referenced SSH
        key) does not exist; 409 if renaming would collide with an
        existing client name.
    """
    row = session.get(Client, client_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Client not found")

    updates = payload.model_dump(exclude_unset=True, exclude_none=True)

    new_key_id = updates.get("ssh_key_id")
    if new_key_id is not None and session.get(SSHKey, new_key_id) is None:
        raise HTTPException(status_code=404, detail="SSH key not found")

    new_name = updates.get("name")
    if new_name is not None and new_name != row.name:
        collision = session.exec(
            select(Client).where(Client.name == new_name)
        ).first()
        if collision is not None:
            raise HTTPException(
                status_code=409,
                detail=f"Client named {new_name!r} already exists",
            )

    for field, value in updates.items():
        setattr(row, field, value)

    session.add(row)
    session.commit()
    session.refresh(row)
    return row


@router.delete(
    "/{client_id}",
    response_model=ClientDeleteResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def delete_client(
    client_id: int, request: Request, session: _SessionDep
) -> ClientDeleteResponse:
    """Delete a client and dispatch a hub reconfigure to drop the peer.

    The row is removed from the database immediately. A follow-up
    :func:`wg_manager.tasks.reconfigure_server_task` is enqueued against
    the parent server so the hub's ``wg0.conf`` is rewritten without the
    deleted peer — meaning the deleted client's public key can no longer
    be used to connect. Poll ``GET /tasks/{task_id}`` to confirm the hub
    picked up the change.

    Phase 2e cycle 3 captures the row dict for the audit log's
    ``before_hash`` and emits a ``client.delete`` row inside the same
    transaction as the row removal.

    :raises HTTPException: 404 if the client does not exist.
    """
    row = session.get(Client, client_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Client not found")

    server_id = row.server_id
    before = row.model_dump(mode="json")
    session.delete(row)
    audit.persist(
        session,
        event="client.delete",
        **audit.actor_from_request(request),
        resource_type="client",
        resource_id=client_id,
        action="delete",
        before=before,
        after=None,
        payload={"name": before.get("name"), "server_id": server_id},
    )
    session.commit()

    async_result = reconfigure_server_task.delay(server_id)
    return ClientDeleteResponse(
        task_id=async_result.id,
        client_id=client_id,
        server_id=server_id,
    )
