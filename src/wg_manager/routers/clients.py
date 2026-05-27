"""/clients router — register and query WireGuard spoke nodes."""

from __future__ import annotations

from ipaddress import ip_interface
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import PlainTextResponse
from sqlmodel import Session, select

from wg_manager.crypto import (
    CryptoBackend,
    encrypt_client_private_key,
    resolve_client_private_key,
)
from wg_manager.db import get_session
from wg_manager.deps import get_crypto_backend
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
_CryptoDep = Annotated[CryptoBackend, Depends(get_crypto_backend)]


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
    crypto: _CryptoDep,
) -> ClientManualRegisterResponse:
    """Register a client we will install by hand instead of over SSH.

    Use this for devices wg-manager can't reach (phones, IoT, locked-down
    embedded boxes). The flow is:

    1. Generate an X25519 keypair on the control plane (the device side
       never runs ``wg genkey``).
    2. Allocate the next free host address out of the parent server's
       subnet, sharing the IPAM pool with SSH-provisioned clients.
    3. Persist a :class:`Client` row in ``ready`` state with the
       generated keys and ``is_manual=True``.
    4. Dispatch :func:`wg_manager.tasks.reconfigure_server_task` so the
       hub's ``wg0.conf`` is rewritten to admit the new peer.

    The operator then fetches the rendered ``wg0.conf`` via
    ``GET /clients/{id}/config`` and installs it on the device by hand.

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
    # The row now has an ID; bind the per-row context and encrypt the
    # freshly-generated WireGuard private key straight into the
    # ciphertext column. The plaintext lives only in the local variable
    # ``private_key`` and is dropped when this function returns.
    encrypt_client_private_key(crypto, row, private_key=private_key)
    session.add(row)
    session.commit()
    session.refresh(row)

    # Push the new peer into the hub's running config so the device can
    # actually connect once the operator installs the rendered .conf.
    async_result = reconfigure_server_task.delay(payload.server_id)
    return ClientManualRegisterResponse(
        task_id=async_result.id,
        client=ClientRead.model_validate(row),
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
            detail="Cannot reprovision a manual client — re-export the config instead",
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


@router.get(
    "/{client_id}/config",
    response_class=PlainTextResponse,
    responses={200: {"content": {"text/plain": {}}}},
)
def export_client_config(
    client_id: int, session: _SessionDep, crypto: _CryptoDep
) -> str:
    """Render a manual client's ``wg0.conf`` so the operator can install it.

    Only valid for clients created via ``POST /clients/manual`` — the
    SSH-provisioned flow leaves the private key on the device and the
    control plane never sees it, so there's nothing meaningful to render
    here for managed rows.

    The output is the full body of a WireGuard config file, including
    the device's private key. Save it as ``/etc/wireguard/wg0.conf`` on
    Linux, or import it into the WireGuard app on phones / desktops.

    :raises HTTPException: 404 if the client does not exist; 400 if the
        row is an SSH-provisioned client (no server-side private key to
        render).
    """
    row = session.get(Client, client_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Client not found")
    if not row.is_manual:
        raise HTTPException(
            status_code=400,
            detail=(
                "Config export is only available for manual clients; "
                "SSH-provisioned clients keep their private key on the device"
            ),
        )

    server = session.get(Server, row.server_id)
    if server is None:
        # Defensive: the FK guarantees this normally, but if the parent
        # server was somehow deleted the config can't be rendered.
        raise HTTPException(status_code=404, detail="Parent server not found")

    # Decrypt-at-render — pulls from ``private_key_ct`` if populated,
    # falls back to the legacy plaintext column otherwise. The actual
    # render function stays oblivious to the storage layer.
    private_key = resolve_client_private_key(crypto, row)
    return render_manual_client_config(row, server, private_key=private_key)


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
def delete_client(client_id: int, session: _SessionDep) -> ClientDeleteResponse:
    """Delete a client and dispatch a hub reconfigure to drop the peer.

    The row is removed from the database immediately. A follow-up
    :func:`wg_manager.tasks.reconfigure_server_task` is enqueued against
    the parent server so the hub's ``wg0.conf`` is rewritten without the
    deleted peer — meaning the deleted client's public key can no longer
    be used to connect. Poll ``GET /tasks/{task_id}`` to confirm the hub
    picked up the change.

    :raises HTTPException: 404 if the client does not exist.
    """
    row = session.get(Client, client_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Client not found")

    server_id = row.server_id
    session.delete(row)
    session.commit()

    async_result = reconfigure_server_task.delay(server_id)
    return ClientDeleteResponse(
        task_id=async_result.id,
        client_id=client_id,
        server_id=server_id,
    )
