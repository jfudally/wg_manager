"""Phase 3b cycle 2 — add the ``operatortenant`` join table.

Revision ID: 0015_add_operator_tenant
Revises: 0014_add_tenant_table
Create Date: 2026-06-03

Cycle 1 (Alembic 0014) shipped the :class:`Tenant` row + a nullable
``tenant_id`` FK on every owned resource. Cycle 2 layers per-tenant
roles on top via a many-to-many join: one :class:`Operator` can be
attached to many tenants, one tenant can host many operators, and the
**per-tenant role** lives on the join.

The migration:

1. Creates the ``operatortenant`` table with ``id`` / ``operator_id``
   FK / ``tenant_id`` FK / ``role`` / ``created_at``.
2. Declares a unique constraint on ``(operator_id, tenant_id)`` so a
   duplicate attach is rejected at the DB layer.
3. Back-fills one join row per existing :class:`Operator` pointing at
   the default tenant (id=1), mirroring the operator's existing
   global ``role`` as the per-tenant role. **Zero behaviour change**
   for v0.1.0 callers: every operator stays in their existing tenant
   slot with their existing privileges.

The acceptance bar for cycle 2: an operator running ``alembic
upgrade head`` against a freshly-Cycle-1'd database must come up
cleanly, with every existing operator carrying a join row in the
default tenant, and no auth / routing behaviour change visible to
API clients.
"""

from __future__ import annotations

from datetime import datetime, timezone

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0015_add_operator_tenant"
down_revision = "0014_add_tenant_table"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create the join table and back-fill from every existing operator."""

    # ----- Step 1: operatortenant table --------------------------
    op.create_table(
        "operatortenant",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "operator_id",
            sa.Integer(),
            sa.ForeignKey(
                "operator.id", name="fk_operatortenant_operator_id"
            ),
            nullable=False,
        ),
        sa.Column(
            "tenant_id",
            sa.Integer(),
            sa.ForeignKey(
                "tenant.id", name="fk_operatortenant_tenant_id"
            ),
            nullable=False,
        ),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint(
            "operator_id",
            "tenant_id",
            name="uq_operatortenant_operator_tenant",
        ),
    )
    op.create_index(
        "ix_operatortenant_operator_id",
        "operatortenant",
        ["operator_id"],
    )
    op.create_index(
        "ix_operatortenant_tenant_id",
        "operatortenant",
        ["tenant_id"],
    )

    # ----- Step 2: back-fill from existing operators -------------
    # Mirror each operator's global role into a join row pointing at
    # the default tenant (id=1). Cycle 3 will start consulting this
    # join on every cert-bearing request; cycle 2 keeps the global
    # role column as the source-of-truth so a rollback is safe.
    #
    # Performed in Python rather than as a pure ``INSERT … SELECT``
    # because the ``created_at`` literal needs to be a current UTC
    # timestamp the calling Python process generates (matches the
    # idiom Alembic 0014's tenant seed uses).
    bind = op.get_bind()
    operators = bind.execute(
        sa.text("SELECT id, role FROM operator")
    ).fetchall()
    if operators:
        now = datetime.now(timezone.utc)
        bind.execute(
            sa.text(
                "INSERT INTO operatortenant "
                "(operator_id, tenant_id, role, created_at) "
                "VALUES (:operator_id, 1, :role, :created_at)"
            ),
            [
                {
                    "operator_id": row[0],
                    "role": row[1],
                    "created_at": now,
                }
                for row in operators
            ],
        )


def downgrade() -> None:
    """Drop the join table."""
    op.drop_index(
        "ix_operatortenant_tenant_id", table_name="operatortenant"
    )
    op.drop_index(
        "ix_operatortenant_operator_id", table_name="operatortenant"
    )
    op.drop_table("operatortenant")
