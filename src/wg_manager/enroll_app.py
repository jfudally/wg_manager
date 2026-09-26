"""Phase 3f: ASGI app served on the enrollment-only listener.

This is a **separate** FastAPI application from
:func:`wg_manager.main.create_app`, not a filtered view of it. The
enrollment listener accepts TLS clients without a certificate (see
:func:`wg_manager.tls_listeners.enroll_ssl_kwargs`), so the safety
property "an anonymous caller can reach only enrollment" is enforced
by construction: no operator router is ever imported into this app.
``tests/test_enroll_listener.py`` checks that every route on the main
app 404s here.

Mounted surface:

* ``POST /v1/enroll``: redeem an enrollment token (see :func:`enroll`).
* ``/healthz`` + ``/readyz`` (and their ``/v1/`` twins): the same probes
  as the operator app, so a load balancer can health-check this port
  too.

OpenAPI docs are disabled: this is a public listener and the schema
would only serve as a map for scanners.
"""

from __future__ import annotations

import logging
from typing import Annotated, NoReturn

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Request, status
from sqlmodel import Session, select

from wg_manager import audit
from wg_manager.config import settings
from wg_manager.db import get_session
from wg_manager.enrollment import consume_token, find_token, is_expired
from wg_manager.ipam import IPPoolExhausted, allocate_client_ip
from wg_manager.locks import task_row_lock
from wg_manager.models import Client, EnrollmentToken, NodeStatus, Server
from wg_manager.routers import health
from wg_manager.schemas import EnrollRequest, EnrollResponse
from wg_manager.ssh_ca import HostCert, SSHCAError, make_ssh_ca_backend
from wg_manager.tasks import _persist_host_cert, reconfigure_server_task
from wg_manager.wireguard import render_enrolled_client_config

logger = logging.getLogger(__name__)

ENROLL_PATH = "/v1/enroll"

# How long a redemption waits for another redemption on the same hub to
# finish allocating its address. Bursts from an autoscaling group queue
# behind each other briefly instead of failing.
_IPAM_LOCK_TIMEOUT_SECONDS = 10

_router = APIRouter(tags=["enroll"])

_SessionDep = Annotated[Session, Depends(get_session)]


def _reject(request: Request, reason: str, token_id: int | None = None) -> NoReturn:
    """Log a failed redemption and raise the uniform 401.

    Every token failure produces the same status, body and header, so a
    caller can't tell a wrong token from an expired or used-up one. The
    real reason goes to the audit log only. The plaintext token is never
    logged.

    :param request: Incoming request (for the peer address).
    :param reason: Machine-readable reason for the audit line.
    :param token_id: Row id when the token was recognised.
    :raises HTTPException: Always; 401 with ``WWW-Authenticate: Bearer``.
    """
    audit.emit(
        "enroll.reject",
        reason=reason,
        token_id=token_id,
        peer=request.client.host if request.client else None,
    )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="invalid enrollment token",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _bearer(authorization: str | None) -> str | None:
    """Extract the token from an ``Authorization: Bearer <token>`` header."""
    if not authorization:
        return None
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()


@_router.post(
    ENROLL_PATH,
    response_model=EnrollResponse,
    status_code=status.HTTP_201_CREATED,
)
def enroll(
    payload: EnrollRequest,
    request: Request,
    session: _SessionDep,
    authorization: Annotated[str | None, Header()] = None,
) -> EnrollResponse:
    """Redeem an enrollment token and admit the calling host as a managed client.

    Runs as one transaction, serialised per hub by an advisory lock so
    concurrent redemptions can't be handed the same address:

    1. Find the token by hash; reject if unknown or expired.
    2. Consume one use (guarded ``UPDATE``); reject if none are left.
    3. Check the hub is ready and the name and WireGuard key are free.
    4. Allocate the next address and have the SSH CA sign the host key.
       The **only** principal is that address: the host-reported
       hostname never becomes a principal, so a token holder can't get
       a cert for another machine's name.
    5. Insert the client row (managed, ``ready``, dialled at its VPN
       address) and the audit row, then commit.

    Any failure after step 2 rolls back the whole transaction,
    including the token use. A hub reconfigure is queued after commit so
    the hub admits the new peer.

    :raises HTTPException: 401 for any token problem; 409 for a name or
        key clash or an exhausted subnet; 503 if the hub isn't ready or
        the lock is contended; 502 if the SSH CA refuses to sign.
    """
    token = _bearer(authorization)
    if token is None:
        _reject(request, "missing_token")
    row = find_token(session, token)
    if row is None:
        _reject(request, "unknown_token")
    if is_expired(row):
        _reject(request, "expired", row.id)

    token_id = int(row.id or 0)
    server_id = row.server_id
    with task_row_lock(
        session, "ipam", server_id, timeout_seconds=_IPAM_LOCK_TIMEOUT_SECONDS
    ) as acquired:
        if not acquired:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="enrollment busy; retry",
                headers={"Retry-After": "5"},
            )
        try:
            if not consume_token(session, row):
                _reject(request, "exhausted", token_id)
            client, server, cert, ca_public_key = _admit(session, row, payload)
            audit.persist(
                session,
                event="client.enroll",
                actor_cn=None,
                actor_serial=None,
                actor_role=None,
                resource_type="client",
                resource_id=client.id,
                action="create",
                before=None,
                after=client.model_dump(mode="json"),
                payload={
                    "token_id": token_id,
                    "hostname": payload.hostname,
                    "server_id": server_id,
                    "peer": request.client.host if request.client else None,
                },
                tenant_id=client.tenant_id,
            )
            session.commit()
        except BaseException:
            # Covers our own HTTPExceptions too: nothing, including the
            # token use, survives a failed enrollment.
            session.rollback()
            raise
        session.refresh(client)

    task = reconfigure_server_task.delay(server_id)
    return EnrollResponse(
        client_id=int(client.id or 0),
        name=client.name,
        address=client.address,
        wg_config=render_enrolled_client_config(client, server),
        ssh_username=client.ssh_username or "",
        user_ca_public_key=ca_public_key,
        host_certificate=cert.cert_pem,
        host_cert_principals=list(cert.principals),
        task_id=str(task.id),
    )


def _admit(
    session: Session, row: EnrollmentToken, payload: EnrollRequest
) -> tuple[Client, Server, HostCert, str]:
    """Steps 3 to 5 of :func:`enroll`: validate, allocate, sign, insert.

    Split out so :func:`enroll` reads as the transaction outline. Flushes
    but doesn't commit.

    :return: ``(client, server, host_cert, ca_public_key)``.
    :raises HTTPException: 503 / 409 / 502, as documented on
        :func:`enroll`.
    """
    server = session.get(Server, row.server_id)
    if server is None or server.status != NodeStatus.ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="hub not ready; retry later",
            headers={"Retry-After": "30"},
        )

    name = f"{row.name_prefix}-{payload.hostname}"
    if session.exec(select(Client).where(Client.name == name)).first() is not None:
        raise HTTPException(status_code=409, detail=f"client {name!r} already exists")
    if session.exec(
        select(Client).where(Client.public_key == payload.wg_public_key)
    ).first() is not None:
        raise HTTPException(status_code=409, detail="wg_public_key already enrolled")

    try:
        address = allocate_client_ip(session, server)
    except IPPoolExhausted as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    ca = make_ssh_ca_backend(settings)
    try:
        cert = ca.mint_host_cert(
            public_key_openssh=payload.ssh_host_public_key,
            principals=[str(address)],
            ttl_seconds=settings.ssh_host_cert_ttl_seconds,
        )
    except SSHCAError:
        # Details stay server-side: the caller is unauthenticated.
        logger.exception("SSH CA refused host cert during enrollment")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="certificate authority unavailable; retry later",
        ) from None

    client = Client(
        tenant_id=row.tenant_id,
        name=name,
        # The worker dials the VPN address: it's the one name the host
        # cert vouches for, and the host may have no reachable public IP.
        hostname=str(address),
        ssh_username=row.ssh_username,
        ssh_key_id=row.ssh_key_id,
        server_id=server.id,
        address=f"{address}/32",
        public_key=payload.wg_public_key,
        is_manual=False,
        status=NodeStatus.ready,
    )
    _persist_host_cert(client, cert, ca.ca_public_key)
    session.add(client)
    session.flush()
    return client, server, cert, ca.ca_public_key


def create_enroll_app() -> FastAPI:
    """Build the enrollment-listener application.

    :return: A FastAPI app exposing only the enrollment route and the
        health probes, with docs / OpenAPI disabled.
    :rtype: FastAPI
    """
    application = FastAPI(
        title="wg-manager-enroll",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    application.include_router(_router)
    # Same dual mount as the operator app (Phase 3c contract) so an LB
    # probe config can be shared between the two listeners.
    application.include_router(health.router)
    application.include_router(health.router, prefix="/v1")
    return application
