"""/enrollment-tokens router: mint Phase 3f enrollment tokens.

Operator-side half of zero-touch enrollment. It's mounted on the mTLS
operator app only, never on the enrollment listener. An admin mints a
token here and bakes it into a new host's userdata, and the host
redeems it at ``POST /v1/enroll`` on the enrollment port.

Only admins can mint: a per-tenant admin on the hub's tenant, or a
super-admin. A token is effectively a pre-authorised "add a managed
host to this hub" action, so it's gated like the most sensitive
mutations rather than like ordinary client registration.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlmodel import Session

from wg_manager import audit
from wg_manager.db import get_session
from wg_manager.enrollment import mint_token
from wg_manager.models import NodeStatus, OperatorRole, Server, SSHKey
from wg_manager.schemas import EnrollmentTokenCreate, EnrollmentTokenCreateResponse
from wg_manager.tenant_scope import ScopeDep, require_tenant_role

router = APIRouter(prefix="/enrollment-tokens", tags=["enrollment"])

_SessionDep = Annotated[Session, Depends(get_session)]


@router.post(
    "",
    response_model=EnrollmentTokenCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_enrollment_token(
    payload: EnrollmentTokenCreate,
    request: Request,
    session: _SessionDep,
    scope: ScopeDep,
) -> EnrollmentTokenCreateResponse:
    """Mint an enrollment token for ``payload.server_id``.

    :raises HTTPException: 404 if the hub or SSH key doesn't exist;
        403 unless the caller is admin on the hub's tenant; 400 if the
        hub isn't ``ready`` or the SSH key belongs to another tenant.
    :return: The token row summary plus the plaintext token. This is
        the only time the plaintext is available.
    """
    server = session.get(Server, payload.server_id)
    if server is None:
        raise HTTPException(status_code=404, detail="Server not found")
    require_tenant_role(scope, server.tenant_id, OperatorRole.admin)

    ssh_key = session.get(SSHKey, payload.ssh_key_id)
    if ssh_key is None:
        raise HTTPException(status_code=404, detail="SSH key not found")
    if ssh_key.tenant_id != server.tenant_id:
        # Otherwise a tenant-A admin could have tenant-B's SSH role
        # manage hosts in tenant A.
        raise HTTPException(
            status_code=400,
            detail="SSH key must belong to the same tenant as the server",
        )
    if server.status != NodeStatus.ready:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Server is not ready (status={server.status.value}); "
                "enrollment needs the hub's public key"
            ),
        )

    actor = audit.actor_from_request(request)
    row, token = mint_token(
        session,
        server=server,
        ssh_key=ssh_key,
        ssh_username=payload.ssh_username,
        name_prefix=payload.name_prefix,
        ttl_seconds=payload.ttl_seconds,
        max_uses=payload.max_uses,
        created_by_cn=actor["actor_cn"],
    )
    audit.persist(
        session,
        event="enrollment_token.create",
        **actor,
        resource_type="enrollment_token",
        resource_id=row.id,
        action="create",
        before=None,
        # token_hash excluded from both the hashed snapshot and the
        # payload: the audit trail never needs it.
        after=row.model_dump(mode="json", exclude={"token_hash"}),
        payload={
            "server_id": row.server_id,
            "max_uses": row.max_uses,
            "ttl_seconds": payload.ttl_seconds,
        },
        tenant_id=row.tenant_id,
    )
    session.commit()
    session.refresh(row)
    return EnrollmentTokenCreateResponse(
        id=int(row.id or 0),
        token=token,
        server_id=row.server_id,
        tenant_id=row.tenant_id,
        max_uses=row.max_uses,
        expires_at=row.expires_at,
    )
