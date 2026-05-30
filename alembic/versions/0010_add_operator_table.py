"""Phase 2d CP3 — add the ``operator`` registry table.

Revision ID: 0010_add_operator_table
Revises: 0009_drop_client_private_key_ct
Create Date: 2026-05-29

Opens the Phase 2d CP3 arc. Phase 2d CP2 made mTLS mandatory on the
API listener but accepted any cert that validated against the
configured CA bundle — :file:`SECURITY.md` calls this out as the
unresolved half of threat T-7 ("a Vault-signed cert with an unknown
CN is currently waved through"). CP3 closes that gap by introducing
an authorisation registry keyed on the cert's CN.

This revision lands the table only. The middleware tightening that
consults the registry, and the ``Certificate`` table that pairs each
issued cert with an operator, follow in subsequent sub-slices so each
step is reviewable in isolation.

Schema
------

``operator``:

* ``id`` — surrogate primary key.
* ``cn`` — Common Name from the client cert. Unique, indexed; stored
  verbatim (case-sensitive at the DB layer).
* ``display_name`` — optional human-readable label for the dashboard.
* ``role`` — string enum (``admin`` / ``operator`` / ``auditor``).
  Defaults to ``operator`` so admin must be set explicitly.
* ``status`` — string enum (``active`` / ``disabled``). Defaults to
  ``active``; disabling a row is the supported revocation path
  (preserves audit-log linkage).
* ``created_at`` — UTC timestamp.

Upgrade
-------

Creates the ``operator`` table and the ``ix_operator_cn`` unique
index. No data backfill — the table starts empty and the bootstrap
operator (the first CN authorised to manage the registry) is
populated by the CP3 CLI that lands in a follow-up sub-slice.

Downgrade
---------

Drops the index and the table. Any operator rows present at
downgrade time are abandoned; downgrading is only safe before the
middleware tightening has been deployed, otherwise every authorised
caller is locked out at the next restart.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0010_add_operator_table"
down_revision: Union[str, None] = "0009_drop_client_private_key_ct"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create ``operator`` + the unique CN index."""
    op.create_table(
        "operator",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("cn", sa.String(length=255), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=True),
        sa.Column(
            "role",
            sa.String(length=16),
            nullable=False,
            server_default="operator",
        ),
        sa.Column(
            "status",
            sa.String(length=16),
            nullable=False,
            server_default="active",
        ),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_operator_cn", "operator", ["cn"], unique=True
    )


def downgrade() -> None:
    """Drop the ``operator`` table and its index."""
    op.drop_index("ix_operator_cn", table_name="operator")
    op.drop_table("operator")
