"""manual clients: nullable SSH fields + private_key + is_manual

Revision ID: 0003_manual_client
Revises: 0002_discovered_peer
Create Date: 2026-05-27
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0003_manual_client"
down_revision: Union[str, None] = "0002_discovered_peer"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add manual-client columns and relax SSH-field nullability.

    The manual-registration flow creates ``Client`` rows for devices
    wg-manager never SSHes into (phones, IoT, ...). Those rows must be
    able to leave ``hostname`` / ``ssh_username`` / ``ssh_key_id`` empty,
    and they need a place to stash the server-generated private key so
    the operator can re-export the rendered ``wg0.conf`` later.
    """
    with op.batch_alter_table("client") as batch:
        batch.alter_column("hostname", existing_type=sa.String(length=255), nullable=True)
        batch.alter_column("ssh_username", existing_type=sa.String(length=255), nullable=True)
        batch.alter_column("ssh_key_id", existing_type=sa.Integer(), nullable=True)
        batch.add_column(sa.Column("private_key", sa.Text(), nullable=True))
        batch.add_column(
            sa.Column(
                "is_manual",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )


def downgrade() -> None:
    """Reverse the manual-client schema additions.

    Any pre-existing manual rows must be deleted before downgrading —
    they have NULL SSH fields that the pre-0003 schema cannot store.
    """
    op.execute("DELETE FROM client WHERE is_manual = 1")
    with op.batch_alter_table("client") as batch:
        batch.drop_column("is_manual")
        batch.drop_column("private_key")
        batch.alter_column("ssh_key_id", existing_type=sa.Integer(), nullable=False)
        batch.alter_column("ssh_username", existing_type=sa.String(length=255), nullable=False)
        batch.alter_column("hostname", existing_type=sa.String(length=255), nullable=False)
