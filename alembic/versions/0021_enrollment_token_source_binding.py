"""enroll: source-network binding on ``enrollmenttoken`` (Phase 3f hardening)

Revision ID: 0021_enrollment_token_source_binding
Revises: 0020_enrollment_token_revocation
Create Date: 2026-09-26

Backs the optional ``allowed_cidrs`` field on ``POST /v1/enrollment-tokens``.
A bound token is only redeemable from those networks (e.g. an
autoscaling group's NAT addresses), so a token leaked from userdata
is useless from anywhere else.

* ``allowed_cidrs``: canonical, comma-separated CIDRs. NULL means
  "anywhere", which is how every existing token keeps working after
  the upgrade.

**Downgrade.** Drops the column. Bound tokens become redeemable from
anywhere until they expire, so revoke them first if that matters.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0021_enrollment_token_source_binding"
down_revision: Union[str, None] = "0020_enrollment_token_revocation"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add the nullable ``allowed_cidrs`` column."""
    with op.batch_alter_table("enrollmenttoken") as batch:
        batch.add_column(sa.Column("allowed_cidrs", sa.String(length=1024), nullable=True))


def downgrade() -> None:
    """Drop ``allowed_cidrs``."""
    with op.batch_alter_table("enrollmenttoken") as batch:
        batch.drop_column("allowed_cidrs")
