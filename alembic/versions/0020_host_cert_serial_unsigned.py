"""wireguard: widen ``host_cert_serial`` to unsigned 64-bit

Revision ID: 0020_host_cert_serial_unsigned
Revises: 0019_server_reconfig_generations
Create Date: 2026-10-05

SSH certificate serials are ``uint64``. 0006 / 0017 sized
``server.host_cert_serial`` and ``client.host_cert_serial`` as signed
``BIGINT`` for ``LocalDevSSHCA``'s ``randbits(63)`` serials, but Vault's
SSH CA draws from the full 64-bit range. About half of Vault serials
(``>= 2**63``) failed the post-rotation persist with ``(1264, "Out of
range value for column 'host_cert_serial'")`` — after the new cert was
already installed on the host — so the row kept showing the old,
expired cert.

* **MySQL / MariaDB**: ``MODIFY`` both columns to ``BIGINT UNSIGNED``.
  Every stored value is already ``< 2**63``, so the change is lossless.
* **SQLite**: no unsigned integer type. No-op;
  :class:`wg_manager.models.UnsignedBigInteger` maps the upper half of
  the range onto negative ``INTEGER`` values instead.

**Downgrade.** Signed ``BIGINT`` can't hold serials ``>= 2**63``, so
those are set to ``NULL`` before narrowing. The serial is metadata only
(nothing keys off it), and the next rotation repopulates it.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import mysql

revision: str = "0020_host_cert_serial_unsigned"
down_revision: Union[str, None] = "0019_server_reconfig_generations"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLES = ("server", "client")


def _is_mysql() -> bool:
    """Whether this migration is running against MySQL / MariaDB.

    Uses the migration context's dialect rather than ``op.get_bind()``
    so ``alembic upgrade --sql`` (offline mode) works too.
    """
    return op.get_context().dialect.name in ("mysql", "mariadb")


def upgrade() -> None:
    """Make both serial columns ``BIGINT UNSIGNED`` on MySQL."""
    if not _is_mysql():
        return
    for table in _TABLES:
        op.alter_column(
            table,
            "host_cert_serial",
            existing_type=sa.BigInteger(),
            type_=mysql.BIGINT(unsigned=True),
            existing_nullable=True,
        )


def downgrade() -> None:
    """Drop out-of-range serials, then narrow back to signed ``BIGINT``."""
    if not _is_mysql():
        return
    for table in _TABLES:
        op.execute(
            f"UPDATE {table} SET host_cert_serial = NULL "
            f"WHERE host_cert_serial >= {2**63}"
        )
        op.alter_column(
            table,
            "host_cert_serial",
            existing_type=mysql.BIGINT(unsigned=True),
            type_=sa.BigInteger(),
            existing_nullable=True,
        )
