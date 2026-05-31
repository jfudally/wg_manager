"""Phase 2d CP4.3 — record where each issued cert was written.

Revision ID: 0012_add_certificate_out_paths
Revises: 0011_add_certificate_table
Create Date: 2026-05-31

Continues the Phase 2d CP4 arc. CP4.1 wired the engine TLS connect
args; CP4.2 turned MySQL into a TLS-only listener and added the
``mysql-client`` cert type. CP4.3 introduces the renewal flow — and
for the walker to be able to re-mint a cert *in place* on the systemd
timer, each row has to remember where its PEM files live on disk.

Schema
------

Three new nullable string columns on ``certificate``:

* ``out_cert_path`` — absolute path of the leaf PEM (``--out-cert``
  from ``wg-manager certs issue``). ``NULL`` for ``POST /certs`` rows
  (the API returns the PEM in the response body and never writes to
  disk).
* ``out_key_path`` — matching private-key PEM path. ``NULL`` when
  ``out_cert_path`` is ``NULL``.
* ``out_chain_path`` — CA-bundle PEM path. ``NULL`` when
  ``out_cert_path`` is ``NULL``.

All three are intentionally nullable: pre-CP4.3 rows + API-issued
rows opt out of CLI-driven walker renewal; ``wg-manager certs renew``
falls back to printing PEMs to stdout for them so the operator can
pipe to whichever path they prefer.

Upgrade
-------

Adds the three columns. No backfill — pre-existing rows stay
``NULL`` until the operator re-issues them via the CLI.

Downgrade
---------

Drops the three columns. Path metadata is lost; subsequent CP4.3
``renew`` invocations against the row are effectively API-style
(PEMs come back to stdout). Safe to roll back online.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0012_add_certificate_out_paths"
down_revision: Union[str, None] = "0011_add_certificate_table"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add the three nullable out-path columns to ``certificate``."""
    op.add_column(
        "certificate",
        sa.Column("out_cert_path", sa.String(length=512), nullable=True),
    )
    op.add_column(
        "certificate",
        sa.Column("out_key_path", sa.String(length=512), nullable=True),
    )
    op.add_column(
        "certificate",
        sa.Column("out_chain_path", sa.String(length=512), nullable=True),
    )


def downgrade() -> None:
    """Drop the three columns added in :func:`upgrade`."""
    op.drop_column("certificate", "out_chain_path")
    op.drop_column("certificate", "out_key_path")
    op.drop_column("certificate", "out_cert_path")
