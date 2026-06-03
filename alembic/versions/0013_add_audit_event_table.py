"""Phase 2e cycle 1 — add the ``auditevent`` table.

Revision ID: 0013_add_audit_event_table
Revises: 0012_add_certificate_out_paths
Create Date: 2026-06-01

Phase 2e introduces the application audit log. Phase 2d CP5 shipped
the per-request audit *stream* via the ``wg_manager.audit`` named
logger — admit / reject / bootstrap decisions land in stderr as
one-line JSON, easy to scrape into a SIEM but not queryable by the
dashboard. This migration adds the persisted-mutations counterpart:
every endpoint that *changes* a managed resource (``server`` /
``client`` / ``sshkey`` / ``certificate`` / global crypto secret)
will write one row here in the same transaction as the mutation.

Schema
------

``auditevent``:

* ``id`` — surrogate primary key.
* ``ts`` — UTC timestamp the event was emitted. Indexed because the
  ``/audit`` endpoint pages newest-first.
* ``event`` — slug of the form ``<resource>.<action>``
  (``server.create``, ``client.delete``, ``crypto.rotate``). Indexed
  so a single-event filter is one index scan.
* ``actor_cn`` — CN lifted off the mTLS cert that authorised the
  mutation. Nullable + indexed: nullable because system-origin events
  (``crypto.rotate``, ``bootstrap.host``) have no human actor;
  indexed for ``GET /audit?operator=<cn>``.
* ``actor_serial`` — cert serial as the decimal-string rendering of
  the X.509 integer (same convention :class:`Certificate.serial`
  uses). Nullable for the same reason ``actor_cn`` is.
* ``actor_role`` — snapshot of :class:`OperatorRole` at action time.
  Snapshot, not FK, so role changes don't retroactively rewrite
  history.
* ``resource_type`` — coarse bucket: ``server`` / ``client`` /
  ``ssh_key`` / ``certificate`` / ``crypto``. String rather than enum
  so future bucket additions don't need an Alembic migration.
* ``resource_id`` — row id of the affected resource. Nullable so
  global-scope events (``crypto.rotate``) can omit it cleanly rather
  than smuggling a sentinel ``0``.
* ``action`` — verb: ``create`` / ``update`` / ``delete`` / ``revoke``
  / ``rotate``. String for the same reason ``resource_type`` is.
* ``before_hash`` — SHA-256 hex (64 chars) of canonical JSON of the
  resource row *before* the mutation. ``NULL`` for create events.
* ``after_hash`` — SHA-256 hex of canonical JSON of the resource row
  *after* the mutation. ``NULL`` for delete events.
* ``payload`` — compact JSON summary dict. Stored as ``Text`` so the
  column doesn't impose a row-size ceiling, but kept small by
  convention. The audit-helper strips secret material before passing.
* ``request_id`` — correlation ID lifted from the request context
  (or a ``uuid4`` for system-origin events). Lets one operator action
  that fans out to multiple audit rows be re-joined for the dashboard.

Indexes
-------

Four indexes back the read patterns ``/audit`` will serve:

* ``ix_auditevent_ts`` — newest-first listing.
* ``ix_auditevent_event`` — filter by event slug.
* ``ix_auditevent_actor_cn`` — filter by operator.
* ``ix_auditevent_resource`` — composite ``(resource_type,
  resource_id)`` so ``GET /audit?resource_type=server&resource_id=7``
  hits a single index scan.

Upgrade
-------

Creates the ``auditevent`` table + the four indexes. No backfill —
the table starts empty; the CP5 stderr stream is the historical
audit trail for events that pre-date this migration.

Downgrade
---------

Drops the table and every index. Any persisted rows are abandoned —
operators who've come to rely on the dashboard ``/audit`` page
should snapshot the table before downgrading.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0013_add_audit_event_table"
down_revision: Union[str, None] = "0012_add_certificate_out_paths"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create ``auditevent`` + the four read-path indexes."""
    op.create_table(
        "auditevent",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("ts", sa.DateTime(), nullable=False),
        sa.Column("event", sa.String(length=64), nullable=False),
        sa.Column("actor_cn", sa.String(length=255), nullable=True),
        sa.Column("actor_serial", sa.String(length=64), nullable=True),
        sa.Column("actor_role", sa.String(length=16), nullable=True),
        sa.Column("resource_type", sa.String(length=32), nullable=False),
        sa.Column("resource_id", sa.Integer(), nullable=True),
        sa.Column("action", sa.String(length=16), nullable=False),
        sa.Column("before_hash", sa.String(length=64), nullable=True),
        sa.Column("after_hash", sa.String(length=64), nullable=True),
        sa.Column("payload", sa.Text(), nullable=True),
        sa.Column("request_id", sa.String(length=64), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_auditevent_ts", "auditevent", ["ts"])
    op.create_index("ix_auditevent_event", "auditevent", ["event"])
    op.create_index("ix_auditevent_actor_cn", "auditevent", ["actor_cn"])
    op.create_index(
        "ix_auditevent_resource",
        "auditevent",
        ["resource_type", "resource_id"],
    )


def downgrade() -> None:
    """Drop the ``auditevent`` table and every index ``upgrade`` created."""
    op.drop_index("ix_auditevent_resource", table_name="auditevent")
    op.drop_index("ix_auditevent_actor_cn", table_name="auditevent")
    op.drop_index("ix_auditevent_event", table_name="auditevent")
    op.drop_index("ix_auditevent_ts", table_name="auditevent")
    op.drop_table("auditevent")
