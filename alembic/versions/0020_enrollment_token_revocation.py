"""enroll: revocation columns on ``enrollmenttoken`` (Phase 3f hardening)

Revision ID: 0020_enrollment_token_revocation
Revises: 0019_server_reconfig_generations
Create Date: 2026-09-26

Backs ``POST /v1/enrollment-tokens/{id}/revoke``. Revocation is soft:
the row stays, so ``GET /v1/enrollment-tokens`` can still show who
revoked what and when.

* ``revoked_at``: when the token was revoked (UTC). NULL means not
  revoked, so every existing token stays live across the upgrade.
* ``revoked_by_cn``: CN of the operator who revoked it.

**Downgrade.** Drops both columns. Revoked tokens that haven't expired
or been used up become redeemable again, so revoke by deleting the rows
first if that matters.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0020_enrollment_token_revocation"
down_revision: Union[str, None] = "0019_server_reconfig_generations"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add the nullable revocation columns."""
    with op.batch_alter_table("enrollmenttoken") as batch:
        batch.add_column(sa.Column("revoked_at", sa.DateTime(), nullable=True))
        batch.add_column(
            sa.Column("revoked_by_cn", sa.String(length=255), nullable=True)
        )


def downgrade() -> None:
    """Drop the revocation columns."""
    with op.batch_alter_table("enrollmenttoken") as batch:
        batch.drop_column("revoked_by_cn")
        batch.drop_column("revoked_at")
