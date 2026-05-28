"""Tests for Phase 2c CP4.1: ``SSHKey.mode`` column + Alembic 0007.

CP4 turns the ``sshkey`` table from a credential store into a *role
label*. Step 4.1 introduces the column that drives that semantic:

* ``SSHKey.mode`` is a :class:`SSHKeyMode` enum (``"legacy"`` or
  ``"ca"``). ``legacy`` rows still carry encrypted private-key
  material in ``private_key_ct``; ``ca`` rows are name-only —
  connections via them mint a fresh user cert from the SSH CA each
  time and never touch a persisted secret. CP4.2 ships the migration
  CLI that flips rows from legacy → ca; CP4.4 drops the ciphertext
  columns once every row is ``ca``.

What this module pins down today (the red-bar slice for 4.1):

1. ``SSHKey.mode`` exists on the model, defaults to ``"legacy"``, and
   round-trips through a SQLModel session.
2. The :class:`SSHKeyMode` enum is a ``str`` enum (so JSON-serialises
   to its value, not its name — important for the schema layer that
   CP4.1c surfaces next).
3. Alembic 0007 adds the ``mode`` column with a server-default of
   ``"legacy"`` and **backfills existing rows from their existing
   data shape**: a row with populated ``private_key_ct`` becomes
   ``"legacy"`` (it has a stored key, that is by definition the
   legacy identity); a row with NULL ``private_key_ct`` becomes
   ``"ca"`` (post-Alembic-0005 a non-NULL ciphertext is the *only*
   way a legacy row can exist, so a NULL pk_ct row must have been
   a CA-mode row whose pre-CP4.1 codepath never required the
   column). This avoids the migration footgun where a pre-CP4.1
   deployment running entirely on ``SSH_AUTH_MODE=ca`` got every
   row backfilled as ``"legacy"`` and then crashed at task time
   trying to read the (NULL) private key.
4. The downgrade drops the column cleanly; round-trip
   upgrade/downgrade/upgrade is idempotent.

The migration is exercised through Alembic's real upgrade/downgrade
commands against a temp SQLite DB (same pattern as the CP3 host-cert
tests). Driving it through alembic — not just by re-importing the
revision module — also catches an env.py regression: any logger
re-config breakage would surface here first.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel

from wg_manager.models import SSHKey, SSHKeyMode


# ---------------------------------------------------------------------------
# Model-level: enum shape + field defaults
# ---------------------------------------------------------------------------


class TestSSHKeyModeEnum:
    """The enum must be JSON-friendly so the API surface stays clean."""

    def test_is_string_enum(self) -> None:
        """``SSHKeyMode`` is a ``str`` subclass so JSON-serialises to its value.

        Pydantic / FastAPI will happily emit ``"legacy"`` and ``"ca"`` —
        not ``"SSHKeyMode.legacy"`` — only when the enum subclasses
        ``str``. Locks the contract so a future refactor that flips it
        to a plain ``Enum`` doesn't quietly break clients.
        """
        assert issubclass(SSHKeyMode, str)
        assert SSHKeyMode.legacy.value == "legacy"
        assert SSHKeyMode.ca.value == "ca"

    def test_has_exactly_two_members(self) -> None:
        """``legacy`` + ``ca`` — anything else is scope creep we don't want yet."""
        assert {m.value for m in SSHKeyMode} == {"legacy", "ca"}


class TestSSHKeyModelFields:
    """A freshly-constructed :class:`SSHKey` defaults to ``mode='legacy'``."""

    def test_mode_defaults_to_ca_on_new_row(self) -> None:
        """Phase 2c CP4.4 flipped the default from ``legacy`` to ``ca``.

        Pre-CP4.4 a fresh row defaulted to legacy and stayed there
        until ``wg-manager ssh migrate-to-ca`` flipped it. CP4.4
        retired the legacy path entirely; the default now matches the
        only mode the task layer can serve.
        """
        row = SSHKey(name="lab")
        assert row.mode == SSHKeyMode.ca

    def test_mode_accepts_ca(self) -> None:
        """Setting the field to ``ca`` is the post-CP4.4 steady state."""
        row = SSHKey(name="lab", mode=SSHKeyMode.ca)
        assert row.mode == SSHKeyMode.ca

    def test_mode_round_trips_through_session(self) -> None:
        """In-memory SQLite round-trip pins the column type to a string.

        Catches a SQLModel mistake where the enum is persisted as an
        ``Integer`` (ordinal) or a Python ``Enum`` repr — both of which
        would break Alembic's data migration in CP4.2 and the JSON
        surface in CP4.1c.
        """
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        SQLModel.metadata.create_all(engine)
        try:
            with Session(engine) as session:
                row = SSHKey(name="lab", mode=SSHKeyMode.ca)
                session.add(row)
                session.commit()
                session.refresh(row)
                assert row.mode == SSHKeyMode.ca
                # Raw read confirms it landed as the string value, not
                # an ordinal or a repr.
                stored = session.exec(
                    text("SELECT mode FROM sshkey WHERE id = :id").bindparams(  # type: ignore[arg-type]
                        id=row.id
                    )
                ).first()
                assert stored is not None
                assert stored[0] == "ca"
        finally:
            SQLModel.metadata.drop_all(engine)


# ---------------------------------------------------------------------------
# Alembic 0007: the migration adds + drops the column and backfills rows
# ---------------------------------------------------------------------------


def _alembic_config(database_url: str):
    """Build an Alembic ``Config`` pointed at ``database_url``."""
    from alembic.config import Config

    cfg = Config(str(Path(__file__).resolve().parent.parent / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", database_url)
    return cfg


class TestSSHKeyModeMigration:
    """The 0007 revision is reversible, idempotent, and backfills legacy rows."""

    @pytest.fixture()
    def file_db_url(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> str:
        """An on-disk SQLite URL that ``alembic/env.py`` will actually pick up."""
        from wg_manager.config import settings as live_settings

        path = tmp_path / "wg_manager_cp4.sqlite"
        url = f"sqlite:///{path}"
        monkeypatch.setattr(live_settings, "database_url", url)
        return url

    def _columns(self, database_url: str) -> set[str]:
        engine = create_engine(database_url)
        try:
            return {col["name"] for col in inspect(engine).get_columns("sshkey")}
        finally:
            engine.dispose()

    def test_upgrade_head_adds_mode_column(self, file_db_url: str) -> None:
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "head")
        assert "mode" in self._columns(file_db_url), (
            "Alembic 'head' is missing the sshkey.mode column — "
            "CP4.1 migration was not applied"
        )

    def test_upgrade_backfills_row_with_stored_key_to_legacy(
        self, file_db_url: str
    ) -> None:
        """A pre-CP4.1 row with a populated ``private_key_ct`` is ``legacy``.

        These are the rows that used the historical Phase 2b stored-key
        auth path. Post-Alembic-0005 a populated ciphertext is the
        canonical legacy shape; CP4.1 must label them accordingly so
        the CP4.2 migration CLI (which scans for ``mode='legacy'``)
        can find them.

        Pinned at ``0007_sshkey_mode`` rather than ``head`` because
        CP4.4 (Alembic 0008) drops ``sshkey.private_key_ct`` once the
        legacy rows have all been migrated to CA mode — running
        ``head`` here would either trip 0008's legacy-row guard or
        drop the column out from under the assertions below.
        """
        from alembic import command

        cfg = _alembic_config(file_db_url)
        # Upgrade to just before 0007 so the table exists but the
        # column doesn't yet. Insert a row, then upgrade the rest of
        # the way and verify the row was backfilled.
        command.upgrade(cfg, "0006_host_cert_columns")
        engine = create_engine(file_db_url)
        try:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO sshkey (name, private_key_ct, created_at) "
                        "VALUES ('pre-cp4', 'vault:v1:fake', "
                        "'2026-05-27 00:00:00')"
                    )
                )
            command.upgrade(cfg, "0007_sshkey_mode")
            with engine.begin() as conn:
                rows = list(
                    conn.execute(
                        text("SELECT name, mode FROM sshkey")
                    ).fetchall()
                )
            assert rows == [("pre-cp4", "legacy")], (
                "Rows with a populated private_key_ct must be backfilled "
                f"to 'legacy' by the CP4.1 migration; got {rows!r}"
            )
        finally:
            engine.dispose()

    def test_upgrade_backfills_row_with_null_pk_ct_to_ca(
        self, file_db_url: str
    ) -> None:
        """A pre-CP4.1 row with NULL ``private_key_ct`` is backfilled to ``ca``.

        Reproduces the migration footgun first hit on a real DB on
        2026-05-27: a deployment running entirely on
        ``SSH_AUTH_MODE=ca`` ended up with rows whose ``private_key_ct``
        was never populated (the CA-mode codepath didn't need it).
        Naive "every row → legacy" backfill then caused
        ``discover_all_peers`` to crash with ``sshkey id=N has no
        private_key_ct`` because the task layer routed those rows down
        the legacy branch.

        The smart backfill uses the row's own data shape as ground
        truth: a NULL pk_ct row *cannot* be a valid legacy row
        post-Alembic-0005 (which dropped the plaintext fallback), so
        it must have been CA-mode. Labelling it ``ca`` lines the
        column up with the deployment's actual behaviour.
        """
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "0006_host_cert_columns")
        engine = create_engine(file_db_url)
        try:
            with engine.begin() as conn:
                # NULL private_key_ct — the shape a CA-mode-only
                # deployment leaves behind.
                conn.execute(
                    text(
                        "INSERT INTO sshkey (name, private_key_ct, created_at) "
                        "VALUES ('pre-cp4-ca', NULL, "
                        "'2026-05-27 00:00:00')"
                    )
                )
            command.upgrade(cfg, "head")
            with engine.begin() as conn:
                rows = list(
                    conn.execute(
                        text("SELECT name, mode FROM sshkey")
                    ).fetchall()
                )
            assert rows == [("pre-cp4-ca", "ca")], (
                "Rows with NULL private_key_ct must be backfilled to "
                f"'ca' by the CP4.1 migration (they cannot be legacy "
                f"post-0005); got {rows!r}"
            )
        finally:
            engine.dispose()

    def test_upgrade_backfills_mixed_rows_per_data_shape(
        self, file_db_url: str
    ) -> None:
        """Mixed-shape table backfills each row independently.

        The realistic post-2c-pre-CP4.1 DB has both shapes side-by-side
        because an operator can flip ``SSH_AUTH_MODE`` between key
        creations. The migration must consult each row's own
        ``private_key_ct`` rather than picking a single mode for the
        whole table.

        Pinned at ``0007_sshkey_mode`` — see the legacy/CA backfill
        test above for why ``head`` is now off-limits.
        """
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "0006_host_cert_columns")
        engine = create_engine(file_db_url)
        try:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO sshkey (name, private_key_ct, created_at) "
                        "VALUES "
                        "('stored', 'vault:v1:fake', '2026-05-27 00:00:00'), "
                        "('ca-only', NULL, '2026-05-27 00:00:01')"
                    )
                )
            command.upgrade(cfg, "0007_sshkey_mode")
            with engine.begin() as conn:
                rows = {
                    name: mode
                    for name, mode in conn.execute(
                        text("SELECT name, mode FROM sshkey")
                    ).fetchall()
                }
            assert rows == {"stored": "legacy", "ca-only": "ca"}, (
                "Mixed-shape backfill must label each row by its own "
                f"private_key_ct; got {rows!r}"
            )
        finally:
            engine.dispose()

    def test_new_rows_default_to_legacy_after_upgrade(
        self, file_db_url: str
    ) -> None:
        """The column carries a server-side default so plain INSERTs work.

        Pinned at ``0007_sshkey_mode`` — the INSERT below references
        ``private_key_ct``, which 0008 drops, so ``head`` is no longer
        a valid target here.
        """
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "0007_sshkey_mode")
        engine = create_engine(file_db_url)
        try:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO sshkey (name, private_key_ct, created_at) "
                        "VALUES ('fresh', 'vault:v1:fake', "
                        "'2026-05-27 00:00:00')"
                    )
                )
                row = conn.execute(
                    text(
                        "SELECT mode FROM sshkey WHERE name = 'fresh'"
                    )
                ).fetchone()
            assert row is not None
            assert row[0] == "legacy", (
                "Insert without an explicit mode must default to "
                f"'legacy'; got {row[0]!r}"
            )
        finally:
            engine.dispose()

    def test_downgrade_one_drops_mode_column(self, file_db_url: str) -> None:
        """Rolling back 0007 drops the column and leaves everything else alone.

        Pinned at ``0007_sshkey_mode`` rather than ``head`` because the
        downgrade target is "one revision back from 0007", which is
        ``0006_host_cert_columns``. From ``head`` (0008) the ``-1``
        target is 0007 instead — which still has the mode column —
        and the assertion below would fail. Explicitly stating the
        upgrade target makes the test robust to future migrations.
        """
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "0007_sshkey_mode")
        before = self._columns(file_db_url)
        command.downgrade(cfg, "0006_host_cert_columns")
        after = self._columns(file_db_url)

        assert before - after == {"mode"}, (
            "CP4.1 downgrade should drop exactly the 'mode' column; "
            f"removed instead: {before - after!r}"
        )
        assert "mode" not in after
        assert "name" in after and "private_key_ct" in after

    def test_upgrade_then_downgrade_then_upgrade_is_idempotent(
        self, file_db_url: str
    ) -> None:
        """Round-trip survives; the migration body has no one-shot side effects.

        Pinned at ``0007_sshkey_mode`` — same reason as
        :meth:`test_downgrade_one_drops_mode_column`.
        """
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "0007_sshkey_mode")
        command.downgrade(cfg, "0006_host_cert_columns")
        command.upgrade(cfg, "0007_sshkey_mode")
        assert "mode" in self._columns(file_db_url)


# ---------------------------------------------------------------------------
# CP4.1c — schema surface: ``/ssh-keys`` endpoints report ``mode``
# ---------------------------------------------------------------------------


class TestSSHKeysAPIExposesMode:
    """The HTTP surface must surface ``mode`` so the dashboard can render it.

    Phase 2c CP4.4 made ``ca`` the only mode any row can carry — the
    POST/GET/list paths still surface the field (the dashboard hangs
    onto it for the badge) and the value is always ``ca`` for a
    freshly created row.
    """

    def test_post_response_includes_mode_ca(self, client) -> None:  # type: ignore[no-untyped-def]
        resp = client.post("/ssh-keys", json={"name": "cp4-1-post"})
        assert resp.status_code == 201, resp.text
        assert resp.json().get("mode") == "ca", (
            "POST /ssh-keys must surface the row's mode so the "
            "dashboard can render the badge without a second round trip"
        )

    def test_get_by_id_includes_mode(self, client) -> None:  # type: ignore[no-untyped-def]
        created = client.post(
            "/ssh-keys", json={"name": "cp4-1-get"}
        ).json()
        resp = client.get(f"/ssh-keys/{created['id']}")
        assert resp.status_code == 200, resp.text
        assert resp.json().get("mode") == "ca"

    def test_list_includes_mode(self, client) -> None:  # type: ignore[no-untyped-def]
        client.post("/ssh-keys", json={"name": "cp4-1-list"})
        resp = client.get("/ssh-keys")
        assert resp.status_code == 200
        rows = resp.json()
        assert rows, "list must include the row we just posted"
        assert all("mode" in r for r in rows), (
            "every row in GET /ssh-keys must surface its mode"
        )
        assert all(r["mode"] == "ca" for r in rows)
