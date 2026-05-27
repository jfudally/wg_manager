"""encryption-at-rest: drop legacy plaintext columns

Revision ID: 0005_drop_plaintext
Revises: 0004_encryption_at_rest
Create Date: 2026-05-27

Closes Phase 2b of [`ROADMAP.md`](../../ROADMAP.md). The `_ct` ciphertext
columns from revision 0004 now carry every persisted secret — SSH
private keys, SSH passphrases, manual-client WireGuard private keys.
This revision drops the legacy plaintext columns so a DB-read attacker
or a leaked backup walks away with ciphertext only.

Schema deltas:

* ``sshkey.private_key`` — dropped (was TEXT NOT NULL).
* ``sshkey.passphrase`` — dropped (was VARCHAR NULL).
* ``client.private_key`` — dropped (was VARCHAR NULL).

**Pre-flight check (operator).** Before applying this revision, run
``wg-manager crypto migrate`` against a copy of the database and
confirm ``GET /crypto/status`` reports ``sshkey_legacy=0`` and
``client_legacy=0``. The migration itself is a pure schema operation
and does **not** sanity-check row contents — applying it while legacy
rows still hold plaintext only means those secrets are lost.

**Downgrade.** Reverses the schema but **does not restore the data**
that lived in the dropped columns. The rows come back with NULL /
empty plaintext, with the ciphertext columns still populated. To
actually recover plaintext after a downgrade, operators must run
``wg-manager crypto rewrap`` to re-encrypt and then walk the rows
through whatever decryption tooling they prefer. We document this in
``docs/vault-cookbook.md`` §3.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0005_drop_plaintext"
down_revision: Union[str, None] = "0004_encryption_at_rest"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Drop the legacy plaintext columns from ``sshkey`` and ``client``."""
    with op.batch_alter_table("sshkey") as batch:
        batch.drop_column("passphrase")
        batch.drop_column("private_key")

    with op.batch_alter_table("client") as batch:
        batch.drop_column("private_key")


def downgrade() -> None:
    """Re-add the legacy plaintext columns.

    The columns come back empty — the data that lived in them at the
    time of the upgrade is gone. Operators who need to roll back must
    use ``wg-manager crypto rewrap`` (and out-of-band decryption) to
    repopulate them; the cookbook documents the recovery flow.
    """
    with op.batch_alter_table("sshkey") as batch:
        # ``nullable=True`` because the data we'd need to populate is no
        # longer available. The original column was ``NOT NULL``;
        # operators that downgrade must run the recovery procedure
        # before any new ORM-level inserts.
        batch.add_column(sa.Column("private_key", sa.Text(), nullable=True))
        batch.add_column(sa.Column("passphrase", sa.String(length=512), nullable=True))

    with op.batch_alter_table("client") as batch:
        batch.add_column(sa.Column("private_key", sa.String(length=512), nullable=True))
