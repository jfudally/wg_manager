"""Phase 3b cycle 3 — per-request tenant scope helper.

This module is the seam between the middleware's per-request tenant
resolution and the router-side list filtering / mutation gating.
It exposes:

* :class:`TenantScope` — frozen value object that captures whether
  the calling operator is a global super-admin (and therefore
  bypasses per-tenant filtering) and the set of tenant ids + per-
  tenant roles they have via the :class:`OperatorTenant` join.
* :func:`get_tenant_scope` — FastAPI dependency that hands the scope
  to a handler. Reads the middleware-populated
  ``request.state.tenant_ids`` / ``tenant_roles`` /
  ``is_super_admin`` slots when available; falls back to a fresh DB
  lookup when the middleware was in passthrough mode (the
  ``TLS_REQUIRED=false`` test / dev posture).
* :func:`scope_filter` — returns a SQLAlchemy column expression that
  narrows a query to the operator's tenant set, or ``None`` when no
  filter should be applied (super-admin or no-auth dev mode).
* :func:`require_tenant_role` — raises HTTP 403 unless the operator
  has one of the supplied per-tenant roles on ``tenant_id``. Super-
  admin bypasses.

The split keeps the auth / tenant logic in one tight surface while
letting each router compose the helpers it needs. List endpoints
typically just need ``scope_filter``; mutating endpoints need
``require_tenant_role`` plus a tenant-id resolver for create
payloads (when the operator omits ``tenant_id``).

Design decisions captured here:

* **Super-admin = global ``Operator.role == admin``.** Locked in the
  ROADMAP. The global role retains "system scope" semantics; per-
  tenant role on the join is the per-tenant scope. A super-admin
  sees every tenant and can mutate any row regardless of their per-
  tenant role.
* **Empty tenant set is a legitimate state for a non-super-admin.**
  An operator who was registered (CP3) but never attached to a
  tenant sees zero list rows. They are not 403'd up front — every
  list endpoint just returns ``[]``. Cycle 4 is what tightens the
  "must belong to *something*" invariant; cycle 3 keeps the door
  open so a fresh operator install doesn't lock itself out before
  the attach action runs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import ColumnElement
from sqlmodel import Session, select

from wg_manager import db as db_module
from wg_manager.models import (
    Operator,
    OperatorRole,
    OperatorTenant,
    Tenant,
)


@dataclass(frozen=True, slots=True)
class TenantScope:
    """Per-request tenant scope for the calling operator.

    Frozen so a handler can stash the scope on a per-request object
    without worrying about silent mutation. The ``unscoped`` factory
    is what the dev posture (``TLS_REQUIRED=false``, no operator
    resolved) returns; it acts as a "skip all per-tenant filtering"
    sentinel and is functionally identical to a super-admin scope.

    :ivar is_super_admin: ``True`` iff the operator's global role is
        :attr:`OperatorRole.admin`. Bypasses every per-tenant gate
        in this module.
    :ivar tenant_ids: Sorted tuple of tenant ids the operator has an
        :class:`OperatorTenant` join row for. Empty tuple is a
        legitimate state — list endpoints then return no rows.
    :ivar tenant_roles: Per-tenant role map keyed by tenant id.
        Mutation gates consult this for O(1) per-tenant role lookup.
    """

    is_super_admin: bool
    tenant_ids: tuple[int, ...] = ()
    tenant_roles: dict[int, OperatorRole] = field(default_factory=dict)

    @classmethod
    def unscoped(cls) -> "TenantScope":
        """Return a scope that skips every filter / gate.

        Used by the ``TLS_REQUIRED=false`` dev posture where no
        operator is resolved and the test suite's hermetic assumptions
        kick in. Operationally equivalent to a super-admin scope.
        """
        return cls(is_super_admin=True)

    def role_in(self, tenant_id: int) -> OperatorRole | None:
        """Return the operator's per-tenant role, or ``None`` if absent."""
        return self.tenant_roles.get(tenant_id)


def get_tenant_scope(request: Request) -> TenantScope:
    """FastAPI dependency: yield the calling operator's tenant scope.

    Reads the middleware-populated slots when ``MTLSAuthMiddleware``
    has resolved them; otherwise falls back to a fresh DB lookup
    against the module-level engine. The fallback keeps the
    ``TLS_REQUIRED=false`` test / dev posture working without
    requiring every test to wire the middleware end-to-end.

    The "no operator at all" branch returns an ``unscoped`` (super-
    admin-equivalent) scope so existing tests that bypassed the
    auth gate via :class:`MTLSAuthMiddleware`'s passthrough continue
    to see every row. Production cannot reach this branch because
    the middleware admits or rejects atomically.
    """
    is_super_admin = getattr(request.state, "is_super_admin", None)
    if is_super_admin is not None:
        tenant_ids = getattr(request.state, "tenant_ids", None) or ()
        tenant_roles = getattr(request.state, "tenant_roles", None) or {}
        return TenantScope(
            is_super_admin=bool(is_super_admin),
            tenant_ids=tuple(tenant_ids),
            tenant_roles=dict(tenant_roles),
        )
    operator = getattr(request.state, "operator", None)
    if operator is None:
        return TenantScope.unscoped()
    return _scope_from_db(operator)


def _scope_from_db(operator: Operator) -> TenantScope:
    """Read every ``OperatorTenant`` join row for ``operator`` and
    build a :class:`TenantScope`."""
    is_super_admin = operator.role == OperatorRole.admin
    op_id = operator.id
    if op_id is None:
        return TenantScope(is_super_admin=is_super_admin)
    with Session(db_module.engine) as session:
        rows = session.exec(
            select(OperatorTenant).where(
                OperatorTenant.operator_id == op_id
            )
        ).all()
    return TenantScope(
        is_super_admin=is_super_admin,
        tenant_ids=tuple(sorted(int(r.tenant_id) for r in rows)),
        tenant_roles={int(r.tenant_id): r.role for r in rows},
    )


def scope_filter(
    scope: TenantScope, model: Any
) -> ColumnElement[bool] | None:
    """Return a SQLAlchemy where-expression scoping ``model`` rows.

    Returns ``None`` when no filter applies (super-admin or
    ``unscoped``); list endpoints then run the query as-is. Otherwise
    returns ``Model.tenant_id IN scope.tenant_ids`` — empty tuple
    yields ``model.tenant_id.in_(())`` which most dialects translate
    to ``WHERE 0`` so the result set is empty (correct for a non-
    super-admin operator with no joins).
    """
    if scope.is_super_admin:
        return None
    return model.tenant_id.in_(scope.tenant_ids)


def require_tenant_role(
    scope: TenantScope,
    tenant_id: int | None,
    *allowed: OperatorRole,
) -> None:
    """Raise HTTP 403 unless ``scope`` permits one of ``allowed`` on ``tenant_id``.

    Super-admin bypass: every check passes. A ``tenant_id`` of
    ``None`` is treated as "global scope" — only super-admin admits.
    For a non-super-admin operator, the operator's per-tenant role
    must be in ``allowed`` or the request 403s with a stable
    ``"role not permitted"`` body.

    The non-empty-``allowed`` contract is enforced at the call site
    — passing zero roles is operator error and would silently turn
    the gate into a passthrough.
    """
    if not allowed:
        raise ValueError(
            "require_tenant_role() must be called with at least one role"
        )
    if scope.is_super_admin:
        return
    if tenant_id is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="super-admin role required",
        )
    role = scope.role_in(tenant_id)
    if role is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"operator not attached to tenant {tenant_id}",
        )
    if role not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="role not permitted",
        )


# Convenient annotated alias so routers can declare a dep without the
# ``Annotated[...]`` boilerplate at every site.
ScopeDep = Annotated[TenantScope, Depends(get_tenant_scope)]


_DEFAULT_TENANT_ID = 1


def resolve_create_tenant(
    scope: TenantScope,
    session: Session,
    explicit_tenant_id: int | None,
    *,
    allowed_roles: tuple[OperatorRole, ...] = (
        OperatorRole.admin,
        OperatorRole.operator,
    ),
) -> Tenant:
    """Resolve the tenant a new resource should land in.

    Phase 3b cycle 5 — the canonical helper every resource-POST
    handler calls before writing a new row. Centralises the four
    decision branches the ROADMAP locks in:

    * **Super-admin** — explicit ``tenant_id`` honoured; absent
      falls back to the default tenant (id 1). Existence of the
      target tenant is still checked (404 on miss).
    * **Single-tenant operator** — absent ``tenant_id`` auto-derives
      from their single join. Explicit ``tenant_id`` must match the
      operator's tenant (403 otherwise).
    * **Multi-tenant operator** — absent ``tenant_id`` raises 422
      with a body that names every candidate so the dashboard can
      render the select widget straight from the error. Explicit
      ``tenant_id`` must be in their tenant set.
    * **No-tenant operator** — every create is 403'd (the operator
      must be attached to a tenant before they can create).

    The resolved tenant must permit one of ``allowed_roles`` for the
    operator. Default is ``admin`` / ``operator`` (the create tier);
    callers asking for ``admin``-only (e.g. ``/tenants`` creation,
    which already lives behind a global gate) override.
    """
    # No-tenant non-super-admin path. Caught up front so the rest of
    # the helper can assume at least one tenant is in scope.
    if not scope.is_super_admin and not scope.tenant_ids:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "operator is not attached to any tenant — ask an "
                "admin to run `wg-manager operators attach-tenant`"
            ),
        )

    # Resolve target id.
    if explicit_tenant_id is not None:
        target_id = explicit_tenant_id
    elif scope.is_super_admin:
        target_id = _DEFAULT_TENANT_ID
    elif len(scope.tenant_ids) == 1:
        target_id = scope.tenant_ids[0]
    else:
        candidates = ", ".join(str(t) for t in scope.tenant_ids)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=(
                f"tenant_id is required: operator is attached to "
                f"multiple tenants ({candidates}); pick one in the body"
            ),
        )

    tenant = session.get(Tenant, target_id)
    if tenant is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"tenant_id {target_id} not found",
        )

    # Scope + role check.
    if not scope.is_super_admin:
        if target_id not in scope.tenant_ids:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"operator is not attached to tenant {target_id}"
                ),
            )
        role = scope.role_in(target_id)
        if role is None or role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="role not permitted",
            )
    return tenant


__all__ = [
    "ScopeDep",
    "TenantScope",
    "get_tenant_scope",
    "require_tenant_role",
    "resolve_create_tenant",
    "scope_filter",
]
