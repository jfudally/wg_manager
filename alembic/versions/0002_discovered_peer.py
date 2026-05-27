"""add discoveredpeer table

Revision ID: 0002_discovered_peer
Revises: 0001_initial
Create Date: 2026-05-21
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0002_discovered_peer"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "discoveredpeer",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("server_id", sa.Integer(), nullable=False),
        sa.Column("public_key", sa.String(length=255), nullable=False),
        sa.Column("allowed_ips", sa.String(length=255), nullable=False),
        sa.Column("endpoint", sa.String(length=255), nullable=True),
        sa.Column("last_handshake_at", sa.DateTime(), nullable=True),
        sa.Column("rx_bytes", sa.BigInteger(), nullable=False),
        sa.Column("tx_bytes", sa.BigInteger(), nullable=False),
        sa.Column("persistent_keepalive", sa.Integer(), nullable=True),
        sa.Column("is_managed", sa.Boolean(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["server_id"], ["server.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "server_id", "public_key", name="uq_discoveredpeer_server_pubkey"
        ),
    )
    op.create_index(
        "ix_discoveredpeer_server_id", "discoveredpeer", ["server_id"], unique=False
    )
    op.create_index(
        "ix_discoveredpeer_public_key", "discoveredpeer", ["public_key"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_discoveredpeer_public_key", table_name="discoveredpeer")
    op.drop_index("ix_discoveredpeer_server_id", table_name="discoveredpeer")
    op.drop_table("discoveredpeer")
