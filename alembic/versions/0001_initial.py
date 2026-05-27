"""initial schema: sshkey, server, client

Revision ID: 0001_initial
Revises:
Create Date: 2026-04-08
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_STATUS_VALUES = ("pending", "ready", "error")


def upgrade() -> None:
    op.create_table(
        "sshkey",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("private_key", sa.Text(), nullable=False),
        sa.Column("passphrase", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_sshkey_name", "sshkey", ["name"], unique=True)

    op.create_table(
        "server",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("ssh_port", sa.Integer(), nullable=False),
        sa.Column("ssh_username", sa.String(length=255), nullable=False),
        sa.Column("ssh_key_id", sa.Integer(), nullable=False),
        sa.Column("endpoint_host", sa.String(length=255), nullable=False),
        sa.Column("endpoint_port", sa.Integer(), nullable=False),
        sa.Column("interface", sa.String(length=64), nullable=False),
        sa.Column("subnet", sa.String(length=64), nullable=False),
        sa.Column("address", sa.String(length=64), nullable=False),
        sa.Column("public_key", sa.String(length=255), nullable=False),
        sa.Column(
            "status",
            sa.Enum(*_STATUS_VALUES, name="nodestatus"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["ssh_key_id"], ["sshkey.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "client",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("ssh_port", sa.Integer(), nullable=False),
        sa.Column("ssh_username", sa.String(length=255), nullable=False),
        sa.Column("ssh_key_id", sa.Integer(), nullable=False),
        sa.Column("server_id", sa.Integer(), nullable=False),
        sa.Column("address", sa.String(length=64), nullable=False),
        sa.Column("public_key", sa.String(length=255), nullable=False),
        sa.Column(
            "status",
            sa.Enum(*_STATUS_VALUES, name="nodestatus"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["server_id"], ["server.id"]),
        sa.ForeignKeyConstraint(["ssh_key_id"], ["sshkey.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_client_name", "client", ["name"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_client_name", table_name="client")
    op.drop_table("client")
    op.drop_table("server")
    op.drop_index("ix_sshkey_name", table_name="sshkey")
    op.drop_table("sshkey")
