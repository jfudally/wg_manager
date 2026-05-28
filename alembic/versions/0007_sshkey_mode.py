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
  column is **backfilled per-row from the row's own data shape**:
  rows with a populated ``private_key_ct`` become ``'legacy'`` (they
  carry the stored-key material that *is* the legacy identity); rows
  with a NULL ``private_key_ct`` become ``'ca'`` (post-Alembic-0005
  a non-NULL ciphertext is the only way a row can be a valid legacy
  row, so a NULL-pk row must be a CA-mode row whose pre-CP4.1
  codepath never required the column).

Why the smart backfill: a "every row → legacy" backfill (the first
draft of 0007) creates a migration footgun for any operator who was
running pre-CP4.1 entirely on ``SSH_AUTH_MODE=ca`` — those rows have
NULL ``private_key_ct`` because the CA-mode codepath never wrote it,
and labelling them ``legacy`` makes the post-CP4.1 task layer route
through ``resolve_sshkey_private`` and crash with
``sshkey id=N has no private_key_ct``. The data-shape backfill lines
the column up with the deployment's actual behaviour at the moment
the migration runs.

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
_CA_VALUE = "ca"


def upgrade() -> None:
    """Add the ``mode`` column and backfill each existing row from its data shape.

    The server-default takes care of any row inserted *after* the
    migration runs; the explicit ``UPDATE`` pair after the ``ADD
    COLUMN`` handles rows that already existed (some DB engines treat
    the server-default as "default for inserts only", leaving
    pre-existing rows with NULL despite the NOT NULL declaration).

    The backfill is split into two statements that together cover
    every row deterministically:

    1. ``private_key_ct IS NOT NULL`` → ``'legacy'``. The row carries
       stored-key material; legacy is the only mode that uses it.
    2. ``private_key_ct IS NULL`` → ``'ca'``. Post-Alembic-0005 a
       legacy row *must* have a populated ciphertext column, so a
       NULL pk_ct row is conclusively a row that was used in CA mode
       under the pre-CP4.1 global ``SSH_AUTH_MODE=ca`` codepath.

    Both UPDATEs gate on ``mode = :default OR mode IS NULL`` so re-
    running the migration body (e.g. via ``alembic stamp`` + re-up)
    or running it after a manual repair never overwrites an
    operator-set value.
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
    # Stored-key rows → legacy. Predicate guards against clobbering a
    # value an operator may have set out-of-band before running the
    # migration (rare in practice but cheap to defend against).
    op.execute(
        sa.text(
            "UPDATE sshkey SET mode = :v "
            "WHERE private_key_ct IS NOT NULL "
            "AND (mode IS NULL OR mode = :v)"
        ).bindparams(v=_LEGACY_DEFAULT)
    )
    # NULL-pk rows → ca. The server-default landed them as 'legacy';
    # this UPDATE flips just that population to 'ca'. Restricting
    # ``WHERE mode = :default`` keeps the statement idempotent: rerun
    # after an operator manually fixed the rows and the predicate
    # matches nothing.
    op.execute(
        sa.text(
            "UPDATE sshkey SET mode = :ca "
            "WHERE private_key_ct IS NULL "
            "AND (mode IS NULL OR mode = :legacy)"
        ).bindparams(ca=_CA_VALUE, legacy=_LEGACY_DEFAULT)
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
