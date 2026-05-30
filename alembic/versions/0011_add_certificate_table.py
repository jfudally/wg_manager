"""Phase 2d CP3.3 — add the ``certificate`` registry table.

Revision ID: 0011_add_certificate_table
Revises: 0010_add_operator_table
Create Date: 2026-05-29

Continues the Phase 2d CP3 arc. CP3.1 landed the ``operator`` table
and CP3.2 wired it into the mTLS middleware. CP3.3 introduces an
audit registry that records *every* X.509 leaf wg-manager issues —
including the service certs that have no operator owner — so the
operator can answer "which certs are live, who owns them, when do
they expire, has any been revoked?" without grepping Vault.

The cert *body* is **not** persisted on the row. The PEM lives on the
disk path the CLI wrote it to at issue time; the private key is
surfaced once and never persisted server-side. The row carries metadata
only: serial, type, common name, SANs, validity window, revocation
flag, and the optional :class:`Operator` FK that ties operator-bound
certs (``cli`` / ``dashboard``) back to their human owner. The
``api`` / ``mysql`` service certs carry ``operator_id = NULL``.

Schema
------

``certificate``:

* ``id`` — surrogate primary key.
* ``serial`` — issuer-assigned serial as the decimal-string rendering
  of the X.509 integer. Unique + indexed; pinned to ``String(64)``
  (rather than ``BigInteger``) because cryptography's 160-bit serial
  overflows SQLite's signed-INT64 and Vault's serials regularly do
  too. The int round-trips losslessly via :func:`int` at the CLI
  boundary.
* ``cert_type`` — string enum (``api`` / ``cli`` / ``dashboard`` /
  ``mysql``). Indexed so ``wg-manager certs list --type cli`` is a
  single index scan.
* ``operator_id`` — nullable FK to ``operator.id``. Populated for
  ``cli`` / ``dashboard`` rows; ``NULL`` for ``api`` / ``mysql``.
* ``common_name`` — CN baked into the cert subject. Indexed because
  the renewal job (Phase 2d CP4) will walk by-CN to pair an expiring
  row with its replacement.
* ``sans`` — comma-separated SAN list, mirroring the storage style
  ``server.address`` already uses to keep the SQLite/MySQL schemas
  identical.
* ``not_before`` / ``not_after`` — UTC datetimes from the cert's
  validity window.
* ``revoked`` — bool, default ``False``. Indexed so a "show me the
  live certs" query is fast.
* ``revoked_at`` — nullable UTC datetime; populated in the same
  transaction as the ``revoked=True`` flip.
* ``created_at`` — UTC issue timestamp.

Upgrade
-------

Creates the ``certificate`` table, the unique-serial index, plus
per-column indices on ``cert_type``, ``operator_id``, ``common_name``,
and ``revoked``. No data backfill — the table starts empty.

Downgrade
---------

Drops the table and every index that ``upgrade()`` created. Any rows
present at downgrade time are abandoned along with the table. This is
safe to do while the system is online *only* if no operator has come
to rely on ``wg-manager certs list`` for their audit trail.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0011_add_certificate_table"
down_revision: Union[str, None] = "0010_add_operator_table"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create ``certificate`` + the supporting indices."""
    op.create_table(
        "certificate",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("serial", sa.String(length=64), nullable=False),
        sa.Column("cert_type", sa.String(length=16), nullable=False),
        sa.Column("operator_id", sa.Integer(), nullable=True),
        sa.Column("common_name", sa.String(length=255), nullable=False),
        sa.Column(
            "sans",
            sa.String(length=1024),
            nullable=False,
            server_default="",
        ),
        sa.Column("not_before", sa.DateTime(), nullable=False),
        sa.Column("not_after", sa.DateTime(), nullable=False),
        sa.Column(
            "revoked",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["operator_id"],
            ["operator.id"],
            name="fk_certificate_operator",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_certificate_serial", "certificate", ["serial"], unique=True
    )
    op.create_index(
        "ix_certificate_cert_type", "certificate", ["cert_type"]
    )
    op.create_index(
        "ix_certificate_operator_id", "certificate", ["operator_id"]
    )
    op.create_index(
        "ix_certificate_common_name", "certificate", ["common_name"]
    )
    op.create_index(
        "ix_certificate_revoked", "certificate", ["revoked"]
    )


def downgrade() -> None:
    """Drop the ``certificate`` table and every index."""
    op.drop_index("ix_certificate_revoked", table_name="certificate")
    op.drop_index("ix_certificate_common_name", table_name="certificate")
    op.drop_index("ix_certificate_operator_id", table_name="certificate")
    op.drop_index("ix_certificate_cert_type", table_name="certificate")
    op.drop_index("ix_certificate_serial", table_name="certificate")
    op.drop_table("certificate")
