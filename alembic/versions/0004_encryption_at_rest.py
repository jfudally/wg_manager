"""encryption-at-rest: add ciphertext columns alongside plaintext

Revision ID: 0004_encryption_at_rest
Revises: 0003_manual_client
Create Date: 2026-05-27

Phase 2b dual-write migration. New columns are nullable so the upgrade
is non-blocking: existing rows continue to read through the plaintext
columns until ``wg-manager crypto migrate`` walks them. A follow-up
migration drops the plaintext columns once operators confirm every row
has been promoted.

Schema deltas:

* ``sshkey.private_key_ct`` — TEXT, nullable. Encrypted via
  :class:`wg_manager.crypto.CryptoBackend` with per-row context
  ``"sshkey:<id>:private_key"``.
* ``sshkey.passphrase_ct`` — VARCHAR(512), nullable. Same scheme with
  context ``"sshkey:<id>:passphrase"``. Stays NULL for rows whose
  passphrase is unset.
* ``client.private_key_ct`` — TEXT, nullable. Ciphertext of a manual
  client's WireGuard private key, context
  ``"client:<id>:private_key"``. SSH-provisioned clients have
  ``private_key=NULL`` already, so the ciphertext is NULL too.

No backfill happens here. The schema change is reversible (the
downgrade just drops the columns) so operators can apply this in
production with zero downtime, then run ``wg-manager crypto migrate``
out-of-band when convenient.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0004_encryption_at_rest"
down_revision: Union[str, None] = "0003_manual_client"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Ciphertext blobs vary in length by backend. Vault Transit returns
# roughly ``vault:vN:<base64-of-(nonce+ct+mac)>`` which sits well under
# 1 KiB for a typical PEM, but PEM bodies themselves are unbounded —
# RSA keys regularly exceed 1.6 KiB. TEXT is the safe default.
_CT_TYPE = sa.Text()
# Passphrases are short (operator-typed), so VARCHAR(512) gives us
# index-friendliness if we ever need it without blocking long values.
_PASS_CT_TYPE = sa.String(length=512)


def upgrade() -> None:
    """Add ciphertext columns to ``sshkey`` and ``client``.

    All three columns are nullable so the upgrade is safe to apply to
    a populated production DB without first running the backfill.
    """
    with op.batch_alter_table("sshkey") as batch:
        batch.add_column(sa.Column("private_key_ct", _CT_TYPE, nullable=True))
        batch.add_column(
            sa.Column("passphrase_ct", _PASS_CT_TYPE, nullable=True)
        )

    with op.batch_alter_table("client") as batch:
        batch.add_column(sa.Column("private_key_ct", _CT_TYPE, nullable=True))


def downgrade() -> None:
    """Drop the ciphertext columns.

    Safe to downgrade because we never made the plaintext columns
    nullable in this revision — they keep storing the secrets.
    """
    with op.batch_alter_table("client") as batch:
        batch.drop_column("private_key_ct")
    with op.batch_alter_table("sshkey") as batch:
        batch.drop_column("passphrase_ct")
        batch.drop_column("private_key_ct")
