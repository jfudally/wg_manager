"""ssh-ca CP4.4: drop sshkey ciphertext columns once every row is CA-mode

Revision ID: 0008_drop_sshkey_ciphertext
Revises: 0007_sshkey_mode
Create Date: 2026-05-28

Closes Phase 2c's SSH CA migration arc. By the time operators reach
this revision, every ``sshkey`` row should already have been flipped
from ``mode='legacy'`` to ``mode='ca'`` — either via the CP4.2 CLI
(``wg-manager ssh migrate-to-ca <id>``, available on the *prior*
release; the command is deleted in this release) or via the CP4.3
dashboard form. The revision then drops the two ciphertext columns:

* ``sshkey.private_key_ct``
* ``sshkey.passphrase_ct``

…leaving ``sshkey`` as a name-and-mode label only. Every connection
mints a fresh user cert from the SSH CA at task time
(:mod:`wg_manager.ssh_ca`); no plaintext SSH material persists on
the row.

Guard
-----

The revision **refuses to run** when any ``sshkey`` row is still in
``mode='legacy'``. Dropping the ciphertext columns in that state
would destroy the only material the operator can use to bootstrap
the CA trust anchor on the corresponding hosts — so the migration
raises a :class:`RuntimeError` whose message:

1. Names the count of legacy rows so the operator can gut-check
   their position in the upgrade.
2. Points at ``docs/migrations/2c-ssh-ca.md`` — the cookbook walks
   through the two supported recovery paths (roll back to the prior
   release and run the migration CLI, or use the documented SQL
   fixup for fleets without a working bastion).

The guard runs **before** any DDL so a refused upgrade leaves the
ciphertext columns intact — re-running after fixing the legacy rows
just works.

Why guard on ``mode`` instead of the ciphertext columns
------------------------------------------------------

A row may legitimately be ``mode='ca'`` with stale ciphertext (e.g.
an operator who flipped ``mode`` by hand without nulling the
ciphertext after CP4.2 finished its job). Those rows are safe to
drop the columns on — the ciphertext was already abandoned. The
``mode`` column is the source of truth for "does the task layer
still need this material to connect to a host?"

Downgrade
---------

Pure schema reversal: the two columns come back as ``NULLABLE TEXT``
(the original 0004 shape, post-0005 simplification). **The data is
gone** — there is no recovery for the ciphertext that lived in them
at the time of the upgrade. Operators who need to roll back must
provision fresh credentials and re-register the SSH keys via the
prior release's POST body. The cookbook documents this.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0008_drop_sshkey_ciphertext"
down_revision: Union[str, None] = "0007_sshkey_mode"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_LEGACY_MODE = "legacy"
_COOKBOOK = "docs/migrations/2c-ssh-ca.md"


def upgrade() -> None:
    """Refuse if any row is still legacy, then drop the ciphertext columns.

    The guard reads ``COUNT(*) WHERE mode = 'legacy'`` straight off
    the bind so it works identically on SQLite (tests) and MySQL
    (production). The check runs before any DDL — a refused upgrade
    leaves the schema unchanged so the operator's recovery path is
    "fix the rows and re-run", with no half-applied state to
    untangle.
    """
    bind = op.get_bind()
    legacy_count = bind.execute(
        sa.text(
            "SELECT COUNT(*) FROM sshkey WHERE mode = :legacy"
        ).bindparams(legacy=_LEGACY_MODE)
    ).scalar_one()

    if legacy_count:
        raise RuntimeError(
            f"Alembic 0008 refuses to run — {legacy_count} sshkey row(s) "
            f"still in mode='legacy'. Dropping the ciphertext columns now "
            f"would destroy the bootstrap material those rows still need. "
            f"Migrate them to CA mode first; see {_COOKBOOK} for the two "
            f"supported recovery paths (prior-release CLI or manual SQL "
            f"fixup). Inspect the offending rows with: "
            f"SELECT id, name FROM sshkey WHERE mode = '{_LEGACY_MODE}';"
        )

    with op.batch_alter_table("sshkey") as batch:
        batch.drop_column("private_key_ct")
        batch.drop_column("passphrase_ct")


def downgrade() -> None:
    """Re-add the two ciphertext columns as NULLABLE TEXT.

    The columns come back empty — the ciphertext that lived in them
    at the time of the upgrade is gone. Operators downgrading must
    re-register every SSH key via the prior release's POST body to
    repopulate the columns; see the cookbook.
    """
    with op.batch_alter_table("sshkey") as batch:
        batch.add_column(sa.Column("passphrase_ct", sa.Text(), nullable=True))
        batch.add_column(sa.Column("private_key_ct", sa.Text(), nullable=True))
