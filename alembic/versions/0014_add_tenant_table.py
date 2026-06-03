"""Phase 3b cycle 1 — add the ``tenant`` table.

Revision ID: 0014_add_tenant_table
Revises: 0013_add_audit_event_table
Create Date: 2026-06-03

Phase 3b opens the multi-tenant operator model. **Cycle 1 ships
schema groundwork only** — zero behaviour change. The migration:

1. Creates a ``tenant`` table (``id`` / ``name`` unique / ``slug``
   unique / ``created_at``).
2. Inserts a ``default`` tenant row at id=1 so the back-fill in
   step 4 has a target.
3. Adds a **nullable** ``tenant_id`` FK column to every tenanted
   resource: ``operator`` / ``server`` / ``client`` / ``sshkey`` /
   ``certificate`` / ``auditevent``. Nullable for cycle 1 so the
   migration is non-breaking; cycle 3 will tighten to NOT NULL
   once the auth-side filter is enforced.
4. Back-fills every existing row's ``tenant_id`` to 1 (the default
   tenant).

The acceptance bar for cycle 1: an operator running ``alembic
upgrade head`` against a v0.1.0 deployment must come up cleanly,
with every existing row owned by the default tenant, and no auth /
routing behaviour change visible to API clients.
"""

from __future__ import annotations

from datetime import datetime, timezone

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0014_add_tenant_table"
down_revision = "0013_add_audit_event_table"
branch_labels = None
depends_on = None


# The six tenanted resource tables. Centralised here so the
# ``upgrade()`` add-column loop, the back-fill loop, and the
# ``downgrade()`` drop-column loop never drift apart.
_TENANTED_TABLES: tuple[str, ...] = (
    "operator",
    "server",
    "client",
    "sshkey",
    "certificate",
    "auditevent",
)


def upgrade() -> None:
    """Create the ``tenant`` table, the default row, and the FK
    columns on each tenanted resource."""

    # ----- Step 1: tenant table ----------------------------------
    op.create_table(
        "tenant",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("slug", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("name", name="uq_tenant_name"),
        sa.UniqueConstraint("slug", name="uq_tenant_slug"),
    )
    # Index on name + slug for fast existence checks at the API
    # layer (CLI ``wg-manager tenants get <slug>`` in cycle 2 hits
    # this).
    op.create_index("ix_tenant_name", "tenant", ["name"], unique=True)
    op.create_index("ix_tenant_slug", "tenant", ["slug"], unique=True)

    # ----- Step 2: default tenant --------------------------------
    # Insert at id=1 with a fixed timestamp. ``op.bulk_insert`` is
    # the canonical idiom for data steps in Alembic — SQLAlchemy
    # handles driver-specific quirks (e.g. SQLite's identity).
    tenant_tbl = sa.table(
        "tenant",
        sa.column("id", sa.Integer()),
        sa.column("name", sa.String()),
        sa.column("slug", sa.String()),
        sa.column("created_at", sa.DateTime()),
    )
    op.bulk_insert(
        tenant_tbl,
        [
            {
                "id": 1,
                "name": "default",
                "slug": "default",
                "created_at": datetime.now(timezone.utc),
            }
        ],
    )

    # ----- Step 3: tenant_id FK column on each resource ----------
    # Nullable in cycle 1 — cycle 3 tightens once the auth filter
    # is in place.
    for table in _TENANTED_TABLES:
        with op.batch_alter_table(table) as batch:
            batch.add_column(
                sa.Column(
                    "tenant_id",
                    sa.Integer(),
                    sa.ForeignKey("tenant.id", name=f"fk_{table}_tenant_id"),
                    nullable=True,
                )
            )
            batch.create_index(
                f"ix_{table}_tenant_id", ["tenant_id"]
            )

    # ----- Step 4: back-fill -------------------------------------
    # Every existing row is owned by tenant id=1 (the ``default``
    # tenant). Cycles 2-5 add real tenant rows through the API/CLI.
    for table in _TENANTED_TABLES:
        op.execute(f"UPDATE {table} SET tenant_id = 1 WHERE tenant_id IS NULL")


def downgrade() -> None:
    """Drop the FK columns, the tenant table, and the default row."""
    for table in _TENANTED_TABLES:
        with op.batch_alter_table(table) as batch:
            batch.drop_index(f"ix_{table}_tenant_id")
            batch.drop_column("tenant_id")

    op.drop_index("ix_tenant_slug", table_name="tenant")
    op.drop_index("ix_tenant_name", table_name="tenant")
    op.drop_table("tenant")
