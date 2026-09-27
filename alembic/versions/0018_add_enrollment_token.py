"""enroll: add ``enrollmenttoken`` table (Phase 3f MVP)

Revision ID: 0018_add_enrollment_token
Revises: 0017_client_host_cert_columns
Create Date: 2026-09-26

Backs zero-touch host enrollment. An admin mints a token over the mTLS
API (``POST /v1/enrollment-tokens``); the token goes into a new host's
userdata. The host then redeems it on the enrollment listener
(``POST /v1/enroll``) to join the WireGuard fleet as a managed client.

Columns
-------

* ``token_hash``: SHA-256 hex of the plaintext token. It is the
  redemption lookup key, so it's unique and indexed. The plaintext is
  returned once at mint time and never stored, so a DB dump can't be
  replayed.
* ``server_id`` / ``tenant_id``: the hub the host joins and the tenant
  the new client row lands in (copied from the hub at mint time).
* ``ssh_key_id`` / ``ssh_username``: how the worker will SSH into the
  enrolled host afterwards. They're fixed by the admin at mint time so
  the host can't choose its own management identity.
* ``name_prefix``: client rows are named ``<prefix>-<hostname>``.
* ``max_uses`` / ``use_count``: one token can enroll up to
  ``max_uses`` hosts (1 by default; more for autoscaling groups).
* ``expires_at``: hard expiry (UTC).
* ``created_by_cn`` / ``created_at``: provenance for audit.

Downgrade
---------

Drops the table. Outstanding tokens stop working; hosts that already
enrolled are unaffected, because they're ordinary ``client`` rows.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0018_add_enrollment_token"
down_revision: Union[str, None] = "0017_client_host_cert_columns"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create ``enrollmenttoken`` + its indices."""
    op.create_table(
        "enrollmenttoken",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=True),
        sa.Column("server_id", sa.Integer(), nullable=False),
        sa.Column("ssh_key_id", sa.Integer(), nullable=False),
        sa.Column("ssh_username", sa.String(length=64), nullable=False),
        sa.Column("name_prefix", sa.String(length=32), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("max_uses", sa.Integer(), nullable=False),
        sa.Column(
            "use_count", sa.Integer(), nullable=False, server_default="0"
        ),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("created_by_cn", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenant.id"], name="fk_enrollmenttoken_tenant"
        ),
        sa.ForeignKeyConstraint(
            ["server_id"], ["server.id"], name="fk_enrollmenttoken_server"
        ),
        sa.ForeignKeyConstraint(
            ["ssh_key_id"], ["sshkey.id"], name="fk_enrollmenttoken_sshkey"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_enrollmenttoken_token_hash",
        "enrollmenttoken",
        ["token_hash"],
        unique=True,
    )
    op.create_index(
        "ix_enrollmenttoken_tenant_id", "enrollmenttoken", ["tenant_id"]
    )
    op.create_index(
        "ix_enrollmenttoken_server_id", "enrollmenttoken", ["server_id"]
    )


def downgrade() -> None:
    """Drop ``enrollmenttoken`` and its indices."""
    op.drop_index("ix_enrollmenttoken_server_id", table_name="enrollmenttoken")
    op.drop_index("ix_enrollmenttoken_tenant_id", table_name="enrollmenttoken")
    op.drop_index("ix_enrollmenttoken_token_hash", table_name="enrollmenttoken")
    op.drop_table("enrollmenttoken")
