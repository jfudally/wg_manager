"""/ssh-keys router — CRUD over named SSH roles.

Phase 2c CP4.4 closed the migration arc that started in CP2: every
``sshkey`` row is now a *name-and-mode label* with no persisted SSH
material. The router exposes the bare minimum surface — register a
name, rename it, look it up, delete it. The task layer mints a
short-lived user cert from the SSH CA on every connection
(:mod:`wg_manager.ssh_ca`); the credential binding lives in Vault's
SSH role configuration, not on this row.

Pre-CP4.4 the router accepted a base64 PEM body on create and PATCH
for in-place credential rotation, plus a ``POST .../migrate-to-ca``
endpoint. Those are gone; the schema layer rejects the obsolete
fields with 422 (``extra="forbid"``) so an upgrader still sending
them sees a clear error instead of silently losing material.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlmodel import Session, select

from wg_manager import audit
from wg_manager.db import get_session
from wg_manager.models import Client, OperatorRole, SSHKey, Server
from wg_manager.schemas import SSHKeyCreate, SSHKeyRead, SSHKeyUpdate
from wg_manager.tenant_scope import (
    ScopeDep,
    require_tenant_role,
    resolve_create_tenant,
    scope_filter,
)

router = APIRouter(prefix="/ssh-keys", tags=["ssh-keys"])

_SessionDep = Annotated[Session, Depends(get_session)]


@router.post("", response_model=SSHKeyRead, status_code=status.HTTP_201_CREATED)
def create_ssh_key(
    payload: SSHKeyCreate,
    request: Request,
    session: _SessionDep,
    scope: ScopeDep,
) -> SSHKey:
    """Register a new SSH role.

    Post-CP4.4 the role carries no private-key material — the row is
    a name-and-mode label only. The default mode (set on the model)
    is ``ca``; every connection at task time mints a fresh user cert
    from the SSH CA.

    Phase 2e cycle 3 emits one ``ssh_key.create`` audit row inside the
    same transaction as the insert. Phase 3b cycle 5 resolves the
    tenant the row lands in via
    :func:`wg_manager.tenant_scope.resolve_create_tenant`.

    :raises HTTPException: 409 if the role name is already taken.
    """
    # Phase 3b cycle 5 — resolve tenant first so a misconfigured
    # caller fails before the uniqueness check (cleaner error story).
    tenant = resolve_create_tenant(scope, session, payload.tenant_id)

    existing = session.exec(
        select(SSHKey).where(SSHKey.name == payload.name)
    ).first()
    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail=f"SSH key named {payload.name!r} already exists",
        )
    row = SSHKey(name=payload.name, tenant_id=tenant.id)
    session.add(row)
    session.flush()
    session.refresh(row)
    audit.persist(
        session,
        event="ssh_key.create",
        **audit.actor_from_request(request),
        resource_type="ssh_key",
        resource_id=row.id,
        action="create",
        before=None,
        after=row.model_dump(mode="json"),
        payload={"name": row.name},
        tenant_id=row.tenant_id,
    )
    session.commit()
    session.refresh(row)
    return row


@router.get("", response_model=list[SSHKeyRead])
def list_ssh_keys(
    session: _SessionDep, scope: ScopeDep
) -> list[SSHKey]:
    """List all registered SSH roles (metadata only), scoped to the
    operator's tenants. Super-admin sees every row."""
    query = select(SSHKey)
    where_expr = scope_filter(scope, SSHKey)
    if where_expr is not None:
        query = query.where(where_expr)
    return list(session.exec(query).all())


@router.get("/{key_id}", response_model=SSHKeyRead)
def get_ssh_key(
    key_id: int, session: _SessionDep, scope: ScopeDep
) -> SSHKey:
    """Return metadata for a single SSH role; 404 to out-of-scope operators."""
    row = session.get(SSHKey, key_id)
    if row is None:
        raise HTTPException(status_code=404, detail="SSH key not found")
    if not scope.is_super_admin and row.tenant_id not in scope.tenant_ids:
        raise HTTPException(status_code=404, detail="SSH key not found")
    return row


@router.patch("/{key_id}", response_model=SSHKeyRead)
def update_ssh_key(
    key_id: int,
    payload: SSHKeyUpdate,
    session: _SessionDep,
    scope: ScopeDep,
) -> SSHKey:
    """Partially update an SSH role.

    Post-CP4.4 the only mutable field is ``name`` — the row carries
    no key material to rotate. Behaviour mirrors :func:`update_server`
    / :func:`update_client`:

    * **404** if no row with ``key_id`` exists.
    * **409** if ``name`` collides with a *different* role's name
      (renaming a role onto its own existing name is a no-op and
      returns 200).
    * **422** for any other field on the wire — the schema layer
      forbids them (see :class:`SSHKeyUpdate`).
    """
    row = session.get(SSHKey, key_id)
    if row is None:
        raise HTTPException(status_code=404, detail="SSH key not found")
    if not scope.is_super_admin and row.tenant_id not in scope.tenant_ids:
        raise HTTPException(status_code=404, detail="SSH key not found")
    require_tenant_role(
        scope, row.tenant_id, OperatorRole.admin, OperatorRole.operator
    )

    updates = payload.model_dump(exclude_unset=True, exclude_none=True)

    new_name = updates.get("name")
    if new_name is not None and new_name != row.name:
        collision = session.exec(
            select(SSHKey).where(SSHKey.name == new_name)
        ).first()
        if collision is not None:
            raise HTTPException(
                status_code=409,
                detail=f"SSH key named {new_name!r} already exists",
            )

    for field, value in updates.items():
        setattr(row, field, value)

    session.add(row)
    session.commit()
    session.refresh(row)
    return row


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_ssh_key(
    key_id: int, session: _SessionDep, scope: ScopeDep
) -> None:
    """Delete an SSH role. Returns 409 if still referenced by a server or client."""
    row = session.get(SSHKey, key_id)
    if row is None:
        raise HTTPException(status_code=404, detail="SSH key not found")
    if not scope.is_super_admin and row.tenant_id not in scope.tenant_ids:
        raise HTTPException(status_code=404, detail="SSH key not found")
    require_tenant_role(
        scope, row.tenant_id, OperatorRole.admin, OperatorRole.operator
    )

    ref_server = session.exec(
        select(Server).where(Server.ssh_key_id == key_id)
    ).first()
    ref_client = session.exec(
        select(Client).where(Client.ssh_key_id == key_id)
    ).first()
    if ref_server is not None or ref_client is not None:
        raise HTTPException(
            status_code=409,
            detail="SSH key is still referenced by a server or client",
        )

    session.delete(row)
    session.commit()
    return None
