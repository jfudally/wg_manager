"""/enrollment-tokens router: mint, list and revoke Phase 3f enrollment tokens.

Operator-side half of zero-touch enrollment. It's mounted on the mTLS
operator app only, never on the enrollment listener. An admin mints a
token here and bakes it into a new host's userdata, and the host
redeems it at ``POST /v1/enroll`` on the enrollment port.

* ``POST /enrollment-tokens``: mint; returns the plaintext once.
* ``GET /enrollment-tokens``: list, newest first, with a derived
  ``status``. Never returns the token or its hash.
* ``POST /enrollment-tokens/{id}/revoke``: soft revoke; idempotent.

Everything here is admin-only: a per-tenant admin on the token's (hub's)
tenant, or a super-admin. A token is effectively a pre-authorised "add a
managed host to this hub" action, so it's gated like the most sensitive
mutations rather than like ordinary client registration. Listing
follows suit: a non-admin gets an empty list, the way list endpoints
treat tenants outside the caller's scope.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlmodel import Session, col, select

from wg_manager import audit
from wg_manager.db import get_session
from wg_manager.enrollment import active_filter, mint_token, revoke_token, token_status
from wg_manager.models import (
    EnrollmentToken,
    NodeStatus,
    OperatorRole,
    Server,
    SSHKey,
)
from wg_manager.schemas import (
    EnrollmentTokenCreate,
    EnrollmentTokenCreateResponse,
    EnrollmentTokenRead,
)
from wg_manager.tenant_scope import ScopeDep, TenantScope, require_tenant_role

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


def _read(row: EnrollmentToken) -> EnrollmentTokenRead:
    """Build the API view of ``row``, with its derived status."""
    return EnrollmentTokenRead.model_validate(
        {**row.model_dump(exclude={"token_hash"}), "status": token_status(row)}
    )


def _admin_tenant_ids(scope: TenantScope) -> list[int]:
    """Tenants whose tokens a non-super-admin caller may list."""
    return [t for t, role in scope.tenant_roles.items() if role == OperatorRole.admin]


@router.get("", response_model=list[EnrollmentTokenRead])
def list_enrollment_tokens(
    session: _SessionDep,
    scope: ScopeDep,
    server_id: int | None = None,
    active: bool = False,
) -> list[EnrollmentTokenRead]:
    """List enrollment tokens the caller administers, newest first.

    :param server_id: Only tokens for this hub.
    :param active: Only tokens that are redeemable right now (not
        revoked, expired or used up).
    :return: Token summaries without the token or its hash.
    """
    query = select(EnrollmentToken).order_by(col(EnrollmentToken.id).desc())
    if not scope.is_super_admin:
        query = query.where(col(EnrollmentToken.tenant_id).in_(_admin_tenant_ids(scope)))
    if server_id is not None:
        query = query.where(EnrollmentToken.server_id == server_id)
    if active:
        query = query.where(active_filter())
    return [_read(row) for row in session.exec(query).all()]


@router.post("/{token_id}/revoke", response_model=EnrollmentTokenRead)
def revoke_enrollment_token(
    token_id: int,
    request: Request,
    session: _SessionDep,
    scope: ScopeDep,
) -> EnrollmentTokenRead:
    """Revoke a token so it can't be redeemed again.

    Soft: the row stays, with ``revoked_at`` / ``revoked_by_cn`` set.
    Idempotent: revoking an already-revoked token returns it unchanged
    and writes no second audit row. Hosts already enrolled with the
    token are unaffected; delete their clients to remove them.

    :raises HTTPException: 404 if the token doesn't exist; 403 unless
        the caller is admin on its tenant.
    """
    row = session.get(EnrollmentToken, token_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Enrollment token not found")
    require_tenant_role(scope, row.tenant_id, OperatorRole.admin)

    actor = audit.actor_from_request(request)
    before = row.model_dump(mode="json", exclude={"token_hash"})
    if revoke_token(session, row, revoked_by_cn=actor["actor_cn"]):
        audit.persist(
            session,
            event="enrollment_token.revoke",
            **actor,
            resource_type="enrollment_token",
            resource_id=row.id,
            action="revoke",
            before=before,
            after=row.model_dump(mode="json", exclude={"token_hash"}),
            payload={"server_id": row.server_id, "use_count": row.use_count},
            tenant_id=row.tenant_id,
        )
        session.commit()
        session.refresh(row)
    return _read(row)
