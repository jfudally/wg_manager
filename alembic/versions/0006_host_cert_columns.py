"""ssh-ca CP3: host-cert columns on ``server``

Revision ID: 0006_host_cert_columns
Revises: 0005_drop_plaintext
Create Date: 2026-05-27

Phase 2c checkpoint 3 wires up host-certificate provisioning. The host
side of the new flow lives in :func:`wg_manager.wireguard.provision_server`
(installs ``TrustedUserCAKeys`` + the signed host cert) and a new
``POST /servers/{id}/rotate-host-cert`` endpoint; this migration is the
control-plane-side mirror — six nullable columns on ``server`` that
record what the SSH CA last issued for each managed host.

Schema deltas (all nullable, all on ``server``):

* ``host_cert_pem`` — TEXT. The full OpenSSH-formatted host cert as
  last installed. Stored verbatim so the audit log / dashboard can
  render the exact bytes that were issued.
* ``host_cert_serial`` — BIGINT. ``secrets.randbits(63)`` (the size
  both :class:`~wg_manager.ssh_ca.LocalDevSSHCA` and OpenSSH use)
  routinely overruns a 32-bit ``Integer``. BigInteger is safe on
  MySQL and matches what cryptography reports back on parse.
* ``host_cert_principals`` — VARCHAR(512). Comma-separated principals
  embedded in the cert. Comma list rather than a JSON blob to keep
  the SQLite/MySQL schemas identical and to match the same shape
  ``Server.address`` already uses.
* ``host_cert_valid_after`` — DATETIME, nullable. When the cert
  became valid (per the cert body, not when we installed it).
* ``host_cert_valid_before`` — DATETIME, nullable. Cert expiry. The
  dashboard turns this into a "rotate now" badge once it crosses 50%
  of the TTL window.
* ``host_cert_ca_public_key`` — TEXT. The CA public key that signed
  the cert, captured at signing time. Deliberately redundant with
  the live CA pubkey so a CA rotation in Vault leaves an audit trail
  on every row that's still pinned to the old authority.

All six columns default to NULL so the upgrade is non-blocking on a
populated DB — existing rows continue to behave like Phase 2b rows
(no host cert; legacy host-key trust handled at the runner layer).
Provisioning populates them; the rotation endpoint updates them in
place.

**Downgrade.** Pure schema reversal — drops the six columns. No data
preservation needed because the host cert itself lives on the host;
the operator can re-mint at any time via the rotation endpoint after
re-applying the migration.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0006_host_cert_columns"
down_revision: Union[str, None] = "0005_drop_plaintext"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Cert bodies vary in length (Ed25519 signatures + a long principals list
# can push past 1 KiB). TEXT is the safe default and matches what Phase 2b
# picked for the ciphertext columns.
_PEM_TYPE = sa.Text()
# A 63-bit cert serial fits in BIGINT; INTEGER would overflow.
_SERIAL_TYPE = sa.BigInteger()
# Principals list — 512 chars covers ~30 typical hostnames without
# forcing TEXT semantics on MySQL.
_PRINCIPALS_TYPE = sa.String(length=512)


def upgrade() -> None:
    """Add the six host-cert columns to ``server``.

    All columns are nullable; no backfill is performed. Rows minted
    before CP3 keep their NULL values until provisioning re-runs.
    """
    with op.batch_alter_table("server") as batch:
        batch.add_column(sa.Column("host_cert_pem", _PEM_TYPE, nullable=True))
        batch.add_column(sa.Column("host_cert_serial", _SERIAL_TYPE, nullable=True))
        batch.add_column(
            sa.Column("host_cert_principals", _PRINCIPALS_TYPE, nullable=True)
        )
        batch.add_column(
            sa.Column("host_cert_valid_after", sa.DateTime(), nullable=True)
        )
        batch.add_column(
            sa.Column("host_cert_valid_before", sa.DateTime(), nullable=True)
        )
        batch.add_column(
            sa.Column("host_cert_ca_public_key", _PEM_TYPE, nullable=True)
        )


def downgrade() -> None:
    """Drop the six host-cert columns.

    The cert itself lives on the host, so dropping these columns only
    erases the control plane's *view* of what it issued. Re-applying
    the migration and calling ``POST /servers/{id}/rotate-host-cert``
    repopulates them.
    """
    with op.batch_alter_table("server") as batch:
        batch.drop_column("host_cert_ca_public_key")
        batch.drop_column("host_cert_valid_before")
        batch.drop_column("host_cert_valid_after")
        batch.drop_column("host_cert_principals")
        batch.drop_column("host_cert_serial")
        batch.drop_column("host_cert_pem")
