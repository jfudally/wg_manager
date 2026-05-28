"""Tests for Phase 2c CP4.4: ``Alembic 0008`` — drop the legacy SSH-key
ciphertext columns once every row has migrated to CA mode.

CP4.4 is the close-out for the Phase 2c CA migration arc. By the time
operators reach this revision they should have moved every ``sshkey``
row from ``mode='legacy'`` to ``mode='ca'`` via either the CP4.2 CLI
(``wg-manager ssh migrate-to-ca <id>``, available on the prior
release) or the equivalent dashboard form. The revision then drops
``sshkey.private_key_ct`` and ``sshkey.passphrase_ct`` — the row
becomes name-and-mode only, with every connection minting a fresh
user cert from the SSH CA at task time.

What this module pins down:

1. **Happy path.** Against a DB whose every ``sshkey`` row is
   ``mode='ca'``, ``alembic upgrade head`` drops both ciphertext
   columns cleanly and leaves the rest of the table intact.
2. **Guard.** Against a DB that still has any ``mode='legacy'`` row,
   the migration refuses to run at ``upgrade()`` time and raises a
   readable error naming the row count and pointing the operator at
   the cookbook (``docs/migrations/2c-ssh-ca.md``). The columns must
   *not* be dropped — the operator needs them to drive the prior
   release's migration CLI on the next attempt.
3. **Downgrade.** Reversing 0008 re-adds the two ciphertext columns
   as NULLABLE TEXT (the original 0004 shape). The data is gone — the
   downgrade is purely schema reversal; the docstring explains the
   recovery path, but the test only pins the schema contract.

The migration is driven through Alembic's real ``command.upgrade`` /
``command.downgrade`` so an env.py regression (logger reconfig,
metadata import order, …) would surface here too. The pattern mirrors
``tests/test_ssh_key_mode.py`` for CP4.1.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text


def _alembic_config(database_url: str):
    """Build an Alembic ``Config`` pointed at ``database_url``."""
    from alembic.config import Config

    cfg = Config(str(Path(__file__).resolve().parent.parent / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", database_url)
    return cfg


@pytest.fixture()
def file_db_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> str:
    """An on-disk SQLite URL ``alembic/env.py`` picks up via settings."""
    from wg_manager.config import settings as live_settings

    path = tmp_path / "wg_manager_cp4_4.sqlite"
    url = f"sqlite:///{path}"
    monkeypatch.setattr(live_settings, "database_url", url)
    return url


def _columns(database_url: str, table: str) -> set[str]:
    engine = create_engine(database_url)
    try:
        return {col["name"] for col in inspect(engine).get_columns(table)}
    finally:
        engine.dispose()


class TestAlembic0008HappyPath:
    """0008 drops both ciphertext columns when every row is ``mode='ca'``."""

    def test_upgrade_head_drops_private_key_ct(
        self, file_db_url: str
    ) -> None:
        """All-CA fixture → ``sshkey.private_key_ct`` no longer exists."""
        from alembic import command

        cfg = _alembic_config(file_db_url)
        # Upgrade to the revision just before 0008 so we can insert a
        # row with the pre-0008 column set.
        command.upgrade(cfg, "0007_sshkey_mode")
        engine = create_engine(file_db_url)
        try:
            with engine.begin() as conn:
                # NULL ciphertext + mode='ca' is the realistic shape
                # post-CP4.2 migration (``migrate_key_to_ca`` nulls the
                # ct columns after a successful flip).
                conn.execute(
                    text(
                        "INSERT INTO sshkey (name, private_key_ct, "
                        "passphrase_ct, mode, created_at) "
                        "VALUES ('lab', NULL, NULL, 'ca', "
                        "'2026-05-28 00:00:00')"
                    )
                )
        finally:
            engine.dispose()

        command.upgrade(cfg, "head")

        cols = _columns(file_db_url, "sshkey")
        assert "private_key_ct" not in cols, (
            "Alembic 0008 must drop sshkey.private_key_ct; columns "
            f"remaining: {cols!r}"
        )

    def test_upgrade_head_drops_passphrase_ct(
        self, file_db_url: str
    ) -> None:
        """All-CA fixture → ``sshkey.passphrase_ct`` no longer exists."""
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "0007_sshkey_mode")
        engine = create_engine(file_db_url)
        try:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO sshkey (name, private_key_ct, "
                        "passphrase_ct, mode, created_at) "
                        "VALUES ('lab', NULL, NULL, 'ca', "
                        "'2026-05-28 00:00:00')"
                    )
                )
        finally:
            engine.dispose()

        command.upgrade(cfg, "head")

        cols = _columns(file_db_url, "sshkey")
        assert "passphrase_ct" not in cols, (
            "Alembic 0008 must drop sshkey.passphrase_ct; columns "
            f"remaining: {cols!r}"
        )

    def test_upgrade_head_leaves_other_sshkey_columns_intact(
        self, file_db_url: str
    ) -> None:
        """``name``, ``mode``, ``created_at`` survive the column drop."""
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "head")
        cols = _columns(file_db_url, "sshkey")
        # We don't pin the exact set (future migrations may add more) —
        # just the minimum the post-CP4 schema must keep.
        assert {"id", "name", "mode", "created_at"} <= cols, (
            f"Post-0008 sshkey schema missing expected columns; got {cols!r}"
        )

    def test_upgrade_head_against_empty_sshkey_table(
        self, file_db_url: str
    ) -> None:
        """Fresh-install operators have zero rows — 0008 must still run."""
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "head")
        cols = _columns(file_db_url, "sshkey")
        assert "private_key_ct" not in cols
        assert "passphrase_ct" not in cols


class TestAlembic0008Guard:
    """0008 refuses to drop the columns while any row is still ``mode='legacy'``."""

    def test_upgrade_raises_when_legacy_row_present(
        self, file_db_url: str
    ) -> None:
        """The guard fires before any DDL — columns must survive the failed attempt."""
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "0007_sshkey_mode")
        engine = create_engine(file_db_url)
        try:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO sshkey (name, private_key_ct, "
                        "passphrase_ct, mode, created_at) "
                        "VALUES ('still-legacy', 'vault:v1:fake', "
                        "NULL, 'legacy', '2026-05-28 00:00:00')"
                    )
                )
        finally:
            engine.dispose()

        with pytest.raises(Exception) as exc_info:
            command.upgrade(cfg, "head")

        # The columns must still exist so the operator can re-run the
        # migration CLI against the prior release.
        cols = _columns(file_db_url, "sshkey")
        assert "private_key_ct" in cols, (
            "0008 must not drop ciphertext columns when the guard refuses; "
            f"sshkey columns after failed upgrade: {cols!r}"
        )
        assert "passphrase_ct" in cols

        # The message must name the count and point at the cookbook so
        # an operator running ``alembic upgrade head`` from a runbook
        # has the next step in hand.
        msg = str(exc_info.value)
        assert "legacy" in msg.lower(), (
            f"Guard error must mention 'legacy'; got: {msg!r}"
        )
        assert "1" in msg, (
            f"Guard error must surface the row count (=1 here); got: {msg!r}"
        )
        assert "docs/migrations/2c-ssh-ca.md" in msg, (
            "Guard error must point operators at the cookbook for the "
            f"recovery path; got: {msg!r}"
        )

    def test_upgrade_raises_with_multiple_legacy_rows(
        self, file_db_url: str
    ) -> None:
        """Row count in the message scales — gives operators a quick gut check."""
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "0007_sshkey_mode")
        engine = create_engine(file_db_url)
        try:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO sshkey (name, private_key_ct, "
                        "passphrase_ct, mode, created_at) VALUES "
                        "('a', 'vault:v1:fake', NULL, 'legacy', "
                        "'2026-05-28 00:00:00'), "
                        "('b', 'vault:v1:fake', NULL, 'legacy', "
                        "'2026-05-28 00:00:01'), "
                        "('c', NULL, NULL, 'ca', "
                        "'2026-05-28 00:00:02')"
                    )
                )
        finally:
            engine.dispose()

        with pytest.raises(Exception) as exc_info:
            command.upgrade(cfg, "head")

        msg = str(exc_info.value)
        # Two legacy rows (the 'ca' row should not be counted).
        assert "2" in msg, (
            "Guard message must report exactly the legacy row count "
            f"(2 here); got: {msg!r}"
        )

    def test_guard_does_not_fire_on_ca_only_table(
        self, file_db_url: str
    ) -> None:
        """A ``mode='ca'`` row with leftover ciphertext still passes the guard.

        Post-CP4.2 the migrate helper nulls the ciphertext columns,
        but an operator who flipped a row by hand might leave the
        ciphertext populated. The guard checks ``mode``, not the
        ciphertext columns — the columns are about to be dropped
        anyway, so their value is irrelevant.
        """
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "0007_sshkey_mode")
        engine = create_engine(file_db_url)
        try:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO sshkey (name, private_key_ct, "
                        "passphrase_ct, mode, created_at) "
                        "VALUES ('hand-flipped', 'vault:v1:stale', "
                        "'vault:v1:stale-pass', 'ca', "
                        "'2026-05-28 00:00:00')"
                    )
                )
        finally:
            engine.dispose()

        # Must not raise.
        command.upgrade(cfg, "head")

        cols = _columns(file_db_url, "sshkey")
        assert "private_key_ct" not in cols
        assert "passphrase_ct" not in cols


class TestAlembic0008Downgrade:
    """Reversing 0008 re-adds the two columns as nullable TEXT."""

    def test_downgrade_one_re_adds_both_ciphertext_columns(
        self, file_db_url: str
    ) -> None:
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "head")
        before = _columns(file_db_url, "sshkey")
        assert "private_key_ct" not in before  # sanity: at head
        assert "passphrase_ct" not in before

        command.downgrade(cfg, "-1")

        after = _columns(file_db_url, "sshkey")
        assert "private_key_ct" in after, (
            "0008 downgrade must restore private_key_ct as a NULLABLE "
            f"column; got: {after!r}"
        )
        assert "passphrase_ct" in after

    def test_round_trip_upgrade_downgrade_upgrade_is_idempotent(
        self, file_db_url: str
    ) -> None:
        """Migration body has no one-shot side effects."""
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "head")
        command.downgrade(cfg, "-1")
        command.upgrade(cfg, "head")
        cols = _columns(file_db_url, "sshkey")
        assert "private_key_ct" not in cols
        assert "passphrase_ct" not in cols
