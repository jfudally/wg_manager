"""enroll: source-network binding on ``enrollmenttoken`` (Phase 3f hardening)

Revision ID: 0022_enroll_token_source_binding
Revises: 0021_enrollment_token_revocation
Create Date: 2026-09-26

Backs the optional ``allowed_cidrs`` field on ``POST /v1/enrollment-tokens``.
A bound token is only redeemable from those networks (e.g. an
autoscaling group's NAT addresses), so a token leaked from userdata
is useless from anywhere else.

* ``allowed_cidrs``: canonical, comma-separated CIDRs. NULL means
  "anywhere", which is how every existing token keeps working after
  the upgrade.

**Revision id.** First published (v0.9.0, v0.10.0) as
``0022_enrollment_token_source_binding``. At 36 characters that overflows
MySQL's ``alembic_version.version_num`` (``VARCHAR(32)``): the
``ADD COLUMN`` auto-committed, recording the version failed, and every
retry failed on "Duplicate column name". No database ever recorded the
old id, so renaming it is safe. The upgrade also skips the column when a
failed attempt already added it, so those databases continue from 0021.

**Downgrade.** Drops the column. Bound tokens become redeemable from
anywhere until they expire, so revoke them first if that matters.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0022_enroll_token_source_binding"
down_revision: Union[str, None] = "0021_enrollment_token_revocation"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add the nullable ``allowed_cidrs`` column, unless it's already there.

    It already exists where a v0.9.0/v0.10.0 upgrade failed on MySQL
    after the DDL committed (see the module docstring).
    """
    existing = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("enrollmenttoken")}
    if "allowed_cidrs" in existing:
        return
    with op.batch_alter_table("enrollmenttoken") as batch:
        batch.add_column(sa.Column("allowed_cidrs", sa.String(length=1024), nullable=True))


def downgrade() -> None:
    """Drop ``allowed_cidrs``."""
    with op.batch_alter_table("enrollmenttoken") as batch:
        batch.drop_column("allowed_cidrs")
