"""/tenants router — Phase 3b cycle 2 HTTP surface over the tenant registry.

Cycle 1 (Alembic 0014) shipped the :class:`Tenant` row + nullable
``tenant_id`` FKs. Cycle 2 layers the many-to-many join (one operator
↔ many tenants, with a per-tenant role on the join) and exposes both
sides over HTTP so the dashboard's ``web/app/tenants`` page can
manage the registry through the same mTLS-protected API every other
surface uses.

Endpoints:

* ``GET /tenants`` — list every tenant. Admin or auditor. Cycle 3
  tightens this to the operator's per-tenant set; cycle 2 returns
  all rows so a fresh-install operator can see the default tenant
  immediately.
* ``GET /tenants/{slug}`` — fetch one tenant by slug. Admin or
  auditor. Unknown slug → 404 with the slug echoed in the body.
* ``POST /tenants`` — create a new tenant. Admin only. ``slug`` is
  optional; the router derives a kebab-case form from ``name`` when
  omitted, matching the CLI default.
* ``POST /tenants/{slug}/operators`` — attach an operator (by CN)
  to the tenant with a per-tenant role. Admin only.
* ``DELETE /tenants/{slug}/operators/{cn}`` — detach. Admin only.
  204 on success; 404 if the pair doesn't exist.
* ``GET /tenants/{slug}/operators`` — list every operator attached
  to the tenant with the per-tenant role. Admin or auditor.

Role gating mirrors :mod:`wg_manager.routers.certs` exactly:
:func:`_get_operator` reads the snapshot
:class:`wg_manager.auth.MTLSAuthMiddleware` stashes on
``request.state.operator``; :func:`_RequireAdmin` /
:func:`_RequireAdminOrAuditor` compose on top of it. Tests override
each dep individually for stable role-mock plumbing.

The CLI side is :data:`wg_manager.cli.tenants_app` /
``wg-manager operators attach-tenant``. Both surfaces operate on the
same tables; the CLI stays the canonical first-install /
disaster-recovery path while the API is the steady-state operator
workflow.
"""

from __future__ import annotations

import re
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlmodel import Session, select

from wg_manager.auth import require_subject
from wg_manager.db import get_session
from wg_manager.models import (
    Operator,
    OperatorRole,
    OperatorTenant,
    Tenant,
)
from wg_manager.schemas import (
    OperatorTenantAttachRequest,
    OperatorTenantRead,
    TenantCreate,
    TenantRead,
)

router = APIRouter(prefix="/tenants", tags=["tenants"])


# ---------------------------------------------------------------------------
# Role-gating deps
# ---------------------------------------------------------------------------


def _get_operator(request: Request) -> Operator:
    """Return the :class:`Operator` stashed by ``MTLSAuthMiddleware``.

    Mirrors :func:`wg_manager.routers.certs._get_operator` byte-for-byte
    so the auth contract stays one shape across the API surface.
    """
    operator = getattr(request.state, "operator", None)
    if operator is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="operator unknown",
        )
    return operator


def _RequireAdmin(  # noqa: N802
    operator: Annotated[Operator, Depends(_get_operator)],
) -> Operator:
    """Admit only :attr:`OperatorRole.admin`.

    Gates create / attach / detach. Auditors and plain operators get
    403 — modifying the tenant registry is an admin action.
    """
    if operator.role != OperatorRole.admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="role not permitted",
        )
    return operator


def _RequireAdminOrAuditor(  # noqa: N802
    operator: Annotated[Operator, Depends(_get_operator)],
) -> Operator:
    """Admit :attr:`OperatorRole.admin` or :attr:`OperatorRole.auditor`.

    Gates the read endpoints. Plain operators (day-to-day "manage
    peers" role) cannot enumerate the tenant registry until cycle 3
    wires the per-tenant filter — at which point they will see the
    tenants they are attached to, but no more.
    """
    if operator.role not in (OperatorRole.admin, OperatorRole.auditor):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="role not permitted",
        )
    return operator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify(name: str) -> str:
    """Kebab-case form of ``name``. Matches :func:`wg_manager.cli._slugify`."""
    slug = _SLUG_RE.sub("-", name.lower()).strip("-")
    return slug or "tenant"


def _require_tenant(session: Session, slug: str) -> Tenant:
    """Look up a tenant by slug; 404 with the slug echoed if missing."""
    row = session.exec(select(Tenant).where(Tenant.slug == slug)).first()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"no tenant with slug {slug!r}",
        )
    return row


def _require_operator(session: Session, cn: str) -> Operator:
    """Look up an operator by CN; 422 with the CN echoed if missing."""
    row = session.exec(select(Operator).where(Operator.cn == cn)).first()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=(
                f"no operator registered with CN {cn!r} — register the "
                f"operator first via `wg-manager operators add --cn {cn}`"
            ),
        )
    return row


def _to_attach_read(
    join: OperatorTenant, tenant: Tenant, operator: Operator
) -> OperatorTenantRead:
    return OperatorTenantRead(
        id=int(join.id or 0),
        tenant_id=int(tenant.id or 0),
        tenant_slug=tenant.slug,
        tenant_name=tenant.name,
        operator_id=int(operator.id or 0),
        operator_cn=operator.cn,
        role=join.role,
        created_at=join.created_at,
    )


# ---------------------------------------------------------------------------
# Tenants — list / get / create
# ---------------------------------------------------------------------------


@router.get("", response_model=list[TenantRead])
def list_tenants(
    _: Annotated[Operator, Depends(_RequireAdminOrAuditor)],
    session: Annotated[Session, Depends(get_session)],
) -> list[Tenant]:
    """Return every tenant row, oldest-first."""
    return list(session.exec(select(Tenant).order_by(Tenant.id)).all())


@router.get("/{slug}", response_model=TenantRead)
def get_tenant(
    slug: str,
    _: Annotated[Operator, Depends(_RequireAdminOrAuditor)],
    session: Annotated[Session, Depends(get_session)],
) -> Tenant:
    """Return one tenant by slug; 404 if unknown."""
    return _require_tenant(session, slug)


@router.post(
    "",
    response_model=TenantRead,
    status_code=status.HTTP_201_CREATED,
)
def create_tenant(
    body: TenantCreate,
    _: Annotated[Operator, Depends(_RequireAdmin)],
    session: Annotated[Session, Depends(get_session)],
) -> Tenant:
    """Create a new tenant.

    Refuses with 409 when the resolved slug or the name collides with
    an existing row. The slug derivation matches the CLI: when the
    body omits ``slug`` the router kebab-cases ``name``.
    """
    target_slug = body.slug or _slugify(body.name)
    existing = session.exec(
        select(Tenant).where(Tenant.slug == target_slug)
    ).first()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"tenant with slug {target_slug!r} already exists "
                f"(id={existing.id})"
            ),
        )
    existing_name = session.exec(
        select(Tenant).where(Tenant.name == body.name)
    ).first()
    if existing_name is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"tenant with name {body.name!r} already exists "
                f"(id={existing_name.id})"
            ),
        )
    row = Tenant(name=body.name, slug=target_slug)
    session.add(row)
    session.commit()
    session.refresh(row)
    return row


# ---------------------------------------------------------------------------
# OperatorTenant — attach / detach / list per tenant
# ---------------------------------------------------------------------------


@router.post(
    "/{slug}/operators",
    response_model=OperatorTenantRead,
    status_code=status.HTTP_201_CREATED,
)
def attach_operator(
    slug: str,
    body: OperatorTenantAttachRequest,
    _: Annotated[Operator, Depends(_RequireAdmin)],
    session: Annotated[Session, Depends(get_session)],
) -> OperatorTenantRead:
    """Attach an operator to the tenant with a per-tenant role.

    Resolution: 404 if the tenant slug is unknown, 422 if the
    operator CN is unknown, 409 if the pair is already joined.
    """
    tenant = _require_tenant(session, slug)
    operator = _require_operator(session, body.cn)

    existing = session.exec(
        select(OperatorTenant).where(
            OperatorTenant.operator_id == operator.id,
            OperatorTenant.tenant_id == tenant.id,
        )
    ).first()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"operator {body.cn!r} already attached to tenant "
                f"{slug!r} (role={existing.role.value})"
            ),
        )
    join = OperatorTenant(
        operator_id=int(operator.id or 0),
        tenant_id=int(tenant.id or 0),
        role=body.role,
    )
    session.add(join)
    session.commit()
    session.refresh(join)
    return _to_attach_read(join, tenant, operator)


@router.delete(
    "/{slug}/operators/{cn}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
def detach_operator(
    slug: str,
    cn: str,
    _: Annotated[Operator, Depends(_RequireAdmin)],
    session: Annotated[Session, Depends(get_session)],
) -> Response:
    """Detach an operator from a tenant.

    Mirrors the attach failure modes: 404 on unknown tenant or
    operator, 404 if the pair isn't joined (the join existing is the
    precondition for removing it; there is no "soft" detach).
    """
    tenant = _require_tenant(session, slug)
    operator = session.exec(
        select(Operator).where(Operator.cn == cn)
    ).first()
    if operator is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"no operator with CN {cn!r}",
        )
    join = session.exec(
        select(OperatorTenant).where(
            OperatorTenant.operator_id == operator.id,
            OperatorTenant.tenant_id == tenant.id,
        )
    ).first()
    if join is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"operator {cn!r} is not attached to tenant {slug!r}"
            ),
        )
    session.delete(join)
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/{slug}/operators",
    response_model=list[OperatorTenantRead],
)
def list_tenant_operators(
    slug: str,
    _: Annotated[Operator, Depends(_RequireAdminOrAuditor)],
    session: Annotated[Session, Depends(get_session)],
) -> list[OperatorTenantRead]:
    """List every operator attached to the tenant."""
    tenant = _require_tenant(session, slug)
    rows = session.exec(
        select(OperatorTenant, Operator)
        .join(Operator, Operator.id == OperatorTenant.operator_id)
        .where(OperatorTenant.tenant_id == tenant.id)
        .order_by(OperatorTenant.id)
    ).all()
    return [_to_attach_read(join, tenant, operator) for join, operator in rows]
