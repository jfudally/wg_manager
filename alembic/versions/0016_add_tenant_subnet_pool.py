"""Phase 3b cycle 4 — add the ``subnet_pool`` column to ``tenant``.

Revision ID: 0016_add_tenant_subnet_pool
Revises: 0015_add_operator_tenant
Create Date: 2026-06-04

Cycle 3 layered list filtering + per-tenant role gates on top of the
cycles 1-2 schema groundwork. Cycle 4 partitions IP space per tenant
so a WireGuard server's subnet must come out of its tenant's pool
rather than a single global address range. Two tenants with non-
overlapping pools can issue overlapping client IPs without colliding
because each lives in its own slice.

This migration:

1. Adds a ``subnet_pool`` ``VARCHAR(64)`` column to ``tenant``.
   Nullable at first so the back-fill in step 2 doesn't violate the
   constraint before it runs.
2. Back-fills every existing tenant row:
   - The reserved ``id=1`` (the ``default`` tenant from Alembic
     0014) gets ``Settings.default_subnet`` so a v0.1.0 deployment
     keeps every existing server inside its tenant's pool without
     any operator action.
   - Any other tenant rows added between cycles 2 and 4 get the
     RFC1918 fallback ``10.0.0.0/8`` so the operator never sees a
     "no IPs" failure on an unconfigured tenant. The dashboard
     surfaces the value so the operator can tighten via PATCH.
3. Tightens the column to ``NOT NULL`` via SQLite's batch alter
   path so the column ends up matching the model contract.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0016_add_tenant_subnet_pool"
down_revision = "0015_add_operator_tenant"
branch_labels = None
depends_on = None


_DEFAULT_TENANT_ID = 1
_FALLBACK_POOL = "10.0.0.0/8"


def upgrade() -> None:
    """Add the column, back-fill, tighten to NOT NULL."""
    # Step 1 — add nullable column so the back-fill is a single
    # SQL update rather than two DDL passes.
    with op.batch_alter_table("tenant") as batch:
        batch.add_column(
            sa.Column("subnet_pool", sa.String(length=64), nullable=True)
        )

    # Step 2 — back-fill.
    # Default tenant: the operator's configured DEFAULT_SUBNET. Read
    # via the live Settings object so a deployment that pins a
    # non-default value in their .env carries it forward.
    from wg_manager.config import settings as live_settings

    bind = op.get_bind()
    bind.execute(
        sa.text(
            "UPDATE tenant SET subnet_pool = :pool WHERE id = :id"
        ),
        {"pool": live_settings.default_subnet, "id": _DEFAULT_TENANT_ID},
    )
    # Non-default tenants — every other row gets the RFC1918 fallback.
    bind.execute(
        sa.text(
            "UPDATE tenant SET subnet_pool = :pool "
            "WHERE subnet_pool IS NULL"
        ),
        {"pool": _FALLBACK_POOL},
    )

    # Step 3 — tighten to NOT NULL.
    with op.batch_alter_table("tenant") as batch:
        batch.alter_column(
            "subnet_pool",
            existing_type=sa.String(length=64),
            nullable=False,
        )


def downgrade() -> None:
    """Drop the column."""
    with op.batch_alter_table("tenant") as batch:
        batch.drop_column("subnet_pool")
