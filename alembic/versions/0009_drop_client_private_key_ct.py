"""manual-client redesign: drop client.private_key_ct

Revision ID: 0009_drop_client_private_key_ct
Revises: 0008_drop_sshkey_ciphertext
Create Date: 2026-05-29

Closes the manual-client encrypt-at-rest arc. Manual clients are
devices wg-manager cannot log into (phones, IoT, locked-down embedded
boxes); the control plane has no operational use for the device's
private key once the operator has captured the rendered ``wg0.conf``.
Phase 2b wrapped the key in ciphertext to mitigate the DB-read risk —
the better answer (and what this revision lands) is to not persist it
at all.

After this revision:

* ``POST /clients/manual`` returns the rendered ``wg0.conf`` body
  (with the freshly-generated private key inline) as ``wg_config`` on
  the response. The control plane writes only the public key.
* ``GET /clients/{id}/config`` is gone — there is nothing left to
  re-render from. Operators who lose the original body delete the row
  and re-register, which generates a fresh keypair and reconfigures
  the hub.
* The ``crypto rewrap`` CLI and ``/crypto/status`` endpoint stay, but
  shrink: no wg-manager row carries ciphertext any more (0008 dropped
  the sshkey side; this revision drops the client side), so the
  CryptoBackend is purely a forward-compat substrate for any future
  encrypted column.

Upgrade
-------

Pure schema drop: removes ``client.private_key_ct`` (NULLABLE TEXT
since 0004). **Any ciphertext still on the column is destroyed** —
nothing in the current code path reads it, and the redesign's whole
point is that the control plane should not hold this material.
Operators with manual clients in service can keep using their
existing ``wg0.conf`` files; the row continues to carry the public
key the hub needs to admit the peer.

Downgrade
---------

Re-adds the column as ``NULLABLE TEXT``. The data is gone; rows come
back with NULL ciphertext. Operators downgrading must delete and
re-register every manual client through the prior release's POST
endpoint to repopulate the column.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0009_drop_client_private_key_ct"
down_revision: Union[str, None] = "0008_drop_sshkey_ciphertext"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Drop ``client.private_key_ct``.

    No guard — manual-client ciphertext was always optional (the
    column was NULLABLE) and the redesign's contract is that this
    material is liability rather than asset. Any value still on the
    column at upgrade time is deliberately abandoned.
    """
    with op.batch_alter_table("client") as batch:
        batch.drop_column("private_key_ct")


def downgrade() -> None:
    """Re-add ``client.private_key_ct`` as NULLABLE TEXT.

    The column comes back empty — there is no recovery path for the
    ciphertext that lived here at upgrade time. Operators must
    delete + re-register manual clients via the prior release to
    repopulate it.
    """
    with op.batch_alter_table("client") as batch:
        batch.add_column(sa.Column("private_key_ct", sa.Text(), nullable=True))
