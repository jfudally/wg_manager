"""ssh-ca CP4.1: per-row auth mode on ``sshkey``

Revision ID: 0007_sshkey_mode
Revises: 0006_host_cert_columns
Create Date: 2026-05-27

Phase 2c CP4 turns ``sshkey`` from a credential store into a *role
label* — a row with ``mode='ca'`` carries no plaintext private key
material; the task layer mints a fresh user cert from the SSH CA on
every connection. CP4.1's job is just to introduce the column so the
follow-up migration CLI (CP4.2) and the column-drop migration (CP4.4)
have something to drive off.

Schema delta (on ``sshkey``):

* ``mode`` — VARCHAR(16), NOT NULL, server-default ``'legacy'``. The
  column is backfilled to ``'legacy'`` on existing rows so a populated
  Phase 2b/2c DB stays consistent without operator action — every
  row that predates 0007 is by definition "still uses stored keys".

NOT NULL with a server default is important: it lets the CP4.2 CLI
``WHERE mode = 'legacy'`` lookups treat the column as set-or-set-to-
``ca`` (no NULL tristate to defend against), and it lets the CP4.4
column drop know exactly which rows still need migrating.

The string column shape (rather than SQLAlchemy's :class:`Enum`) is
deliberate: SQLite + MySQL handle :class:`Enum` differently —
SQLite stores the value as TEXT but does not enforce the check, while
MySQL emits a real ``ENUM(...)`` type whose values are baked into the
column definition. Adding a value (e.g. a future ``vault-issued``
mode) would then need a second ``ALTER TABLE`` round-trip on MySQL.
A plain VARCHAR with a server-default keeps both backends identical
and the migration body trivial; validation lives in the model layer
:class:`wg_manager.models.SSHKeyMode`, which is where Pydantic /
SQLModel can enforce it.

**Downgrade.** Pure schema reversal — drops the ``mode`` column. The
operator should never have to call this in production (the CP4.2
migration is one-way), but it stays around so a developer can rewind
a local DB to the Phase 2c-CP3 schema for testing.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0007_sshkey_mode"
down_revision: Union[str, None] = "0006_host_cert_columns"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# 16 chars comfortably fits ``"legacy"`` / ``"ca"`` plus a future
# value (e.g. ``"vault-issued"``) without a follow-up migration.
_MODE_TYPE = sa.String(length=16)
_LEGACY_DEFAULT = "legacy"


def upgrade() -> None:
    """Add the ``mode`` column and backfill every existing row to ``legacy``.

    The server-default takes care of any row inserted *after* the
    migration runs; the explicit ``UPDATE`` after the ``ADD COLUMN``
    handles rows that already existed (some DB engines treat the
    server-default as "default for inserts only", leaving pre-existing
    rows with NULL despite the NOT NULL declaration).
    """
    with op.batch_alter_table("sshkey") as batch:
        batch.add_column(
            sa.Column(
                "mode",
                _MODE_TYPE,
                nullable=False,
                server_default=_LEGACY_DEFAULT,
            )
        )
    # Belt-and-braces backfill. ``batch_alter_table`` already honours
    # the server-default on engines that respect it for existing rows
    # (Postgres, MySQL), but SQLite's ALTER TABLE semantics make this
    # explicit set safer than relying on default propagation.
    op.execute(
        sa.text("UPDATE sshkey SET mode = :v WHERE mode IS NULL").bindparams(
            v=_LEGACY_DEFAULT
        )
    )


def downgrade() -> None:
    """Drop the ``mode`` column.

    Idempotent counterpart to :func:`upgrade` — operators rewinding a
    local DB back through CP4.1 will lose the per-row mode information,
    but in the steady-state CP4 deployment every row is ``ca`` and the
    column drop in CP4.4 supersedes this downgrade path anyway.
    """
    with op.batch_alter_table("sshkey") as batch:
        batch.drop_column("mode")
