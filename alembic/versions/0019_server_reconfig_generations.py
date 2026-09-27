"""wireguard: hub reconfigure generation counters on ``server``

Revision ID: 0019_server_reconfig_generations
Revises: 0018_add_enrollment_token
Create Date: 2026-09-26

Fixes a lost-update race in ``reconfigure_server_task``. The task used
to *skip* when another reconfigure held the hub's lock. But the holder
may have read the client list before the change that triggered the
skipped task was committed, so that peer silently never reached the hub.
Enrollment bursts from autoscaling groups made this likely.

* ``reconfig_requested_gen``: bumped every time something asks for the
  hub config to catch up (client added, removed, enrolled).
* ``reconfig_applied_gen``: the highest requested generation whose
  client list has actually been written to the hub.

A reconfigure reads ``requested`` before the client list, applies it,
then raises ``applied`` to that value. A queued task whose generation is
already applied has nothing to do, so bursts coalesce instead of
restarting the hub's interface once per change.

Both are NOT NULL with a server default of 0, so existing rows start in
sync and the upgrade is non-blocking.

**Downgrade.** Drops both columns; the task falls back to always applying.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0019_server_reconfig_generations"
down_revision: Union[str, None] = "0018_add_enrollment_token"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add the two generation counters to ``server``."""
    with op.batch_alter_table("server") as batch:
        batch.add_column(
            sa.Column(
                "reconfig_requested_gen",
                sa.Integer(),
                nullable=False,
                server_default="0",
            )
        )
        batch.add_column(
            sa.Column(
                "reconfig_applied_gen",
                sa.Integer(),
                nullable=False,
                server_default="0",
            )
        )


def downgrade() -> None:
    """Drop the generation counters."""
    with op.batch_alter_table("server") as batch:
        batch.drop_column("reconfig_applied_gen")
        batch.drop_column("reconfig_requested_gen")
