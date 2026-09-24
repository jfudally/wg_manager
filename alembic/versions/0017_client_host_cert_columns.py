"""ssh-ca: host-cert columns on ``client``

Revision ID: 0017_client_host_cert_columns
Revises: 0016_add_tenant_subnet_pool
Create Date: 2026-09-24

Mirrors 0006 (the same six columns on ``server``) for SSH-provisioned
clients. ``provision_client_task`` now installs a CA-signed host cert
on every successful provision, and the new
``POST /clients/{id}/rotate-host-cert`` endpoint re-mints it before
TTL expiry; these columns record what the SSH CA last issued so the
dashboard can show the expiry and the audit trail survives a Vault CA
rotation. See 0006 for the rationale behind each column type.

All six columns are nullable: manual clients (no SSH) never get a host
cert, and existing rows stay NULL until their next provision or
rotation — the upgrade is non-blocking on a populated DB.

**Downgrade.** Drops the six columns. The cert itself lives on the
client host; re-applying the migration and rotating repopulates them.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0017_client_host_cert_columns"
down_revision: Union[str, None] = "0016_add_tenant_subnet_pool"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add the six nullable host-cert columns to ``client`` (no backfill)."""
    with op.batch_alter_table("client") as batch:
        batch.add_column(sa.Column("host_cert_pem", sa.Text(), nullable=True))
        # 63-bit serials overflow a 32-bit INTEGER on MySQL.
        batch.add_column(
            sa.Column("host_cert_serial", sa.BigInteger(), nullable=True)
        )
        batch.add_column(
            sa.Column("host_cert_principals", sa.String(length=512), nullable=True)
        )
        batch.add_column(
            sa.Column("host_cert_valid_after", sa.DateTime(), nullable=True)
        )
        batch.add_column(
            sa.Column("host_cert_valid_before", sa.DateTime(), nullable=True)
        )
        batch.add_column(
            sa.Column("host_cert_ca_public_key", sa.Text(), nullable=True)
        )


def downgrade() -> None:
    """Drop the six host-cert columns from ``client``."""
    with op.batch_alter_table("client") as batch:
        batch.drop_column("host_cert_ca_public_key")
        batch.drop_column("host_cert_valid_before")
        batch.drop_column("host_cert_valid_after")
        batch.drop_column("host_cert_principals")
        batch.drop_column("host_cert_serial")
        batch.drop_column("host_cert_pem")
