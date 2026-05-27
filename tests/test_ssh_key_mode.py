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
   ``"legacy"`` and **backfills every existing row to ``"legacy"``**
   — the migration is non-blocking on a populated Phase 2b/2c DB.
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

    def test_mode_defaults_to_legacy_on_new_row(self) -> None:
        """Phase 2b rows / new uploads behave exactly as before until migrated."""
        row = SSHKey(name="lab")
        assert row.mode == SSHKeyMode.legacy

    def test_mode_accepts_ca(self) -> None:
        """Setting the field to ``ca`` is the post-CP4.2 steady state."""
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

    def test_upgrade_backfills_existing_rows_to_legacy(
        self, file_db_url: str
    ) -> None:
        """A Phase 2b/2c row that predates 0007 must come out as ``legacy``.

        The CP4.2 migration CLI relies on this: it scans for rows with
        ``mode='legacy'`` and walks each to ``ca``. If the migration
        leaves the column NULL instead of backfilling, every existing
        row would be silently invisible to the migration CLI.
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
            command.upgrade(cfg, "head")
            with engine.begin() as conn:
                rows = list(
                    conn.execute(
                        text("SELECT name, mode FROM sshkey")
                    ).fetchall()
                )
            assert rows == [("pre-cp4", "legacy")], (
                "Existing rows must be backfilled to 'legacy' by "
                f"the CP4.1 migration; got {rows!r}"
            )
        finally:
            engine.dispose()

    def test_new_rows_default_to_legacy_after_upgrade(
        self, file_db_url: str
    ) -> None:
        """The column carries a server-side default so plain INSERTs work."""
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "head")
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
        """Rolling back 0007 drops the column and leaves everything else alone."""
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "head")
        before = self._columns(file_db_url)
        command.downgrade(cfg, "-1")
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
        """Round-trip survives; the migration body has no one-shot side effects."""
        from alembic import command

        cfg = _alembic_config(file_db_url)
        command.upgrade(cfg, "head")
        command.downgrade(cfg, "-1")
        command.upgrade(cfg, "head")
        assert "mode" in self._columns(file_db_url)


# ---------------------------------------------------------------------------
# CP4.1c — schema surface: ``/ssh-keys`` endpoints report ``mode``
# ---------------------------------------------------------------------------


class TestSSHKeysAPIExposesMode:
    """The HTTP surface must surface ``mode`` so the dashboard can render it.

    These tests use the existing ``client`` fixture from ``conftest.py``
    (in-memory SQLite + the FastAPI app under test). They don't try to
    flip a row to ``ca`` via the API yet — that's CP4.2's migration
    CLI — but they do pin that ``mode`` is present on every read path
    (``POST``, ``GET /{id}``, ``GET /``) and defaults to ``legacy`` for
    freshly-created rows.
    """

    def test_post_response_includes_mode_legacy(self, client) -> None:  # type: ignore[no-untyped-def]
        import base64

        pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n"
        resp = client.post(
            "/ssh-keys",
            json={
                "name": "cp4-1-post",
                "private_key_b64": base64.b64encode(pem.encode()).decode(),
            },
        )
        assert resp.status_code == 201, resp.text
        assert resp.json().get("mode") == "legacy", (
            "POST /ssh-keys must surface the row's mode so the "
            "dashboard can render the badge without a second round trip"
        )

    def test_get_by_id_includes_mode(self, client) -> None:  # type: ignore[no-untyped-def]
        import base64

        pem = "-----BEGIN OPENSSH PRIVATE KEY-----\ny\n-----END OPENSSH PRIVATE KEY-----\n"
        created = client.post(
            "/ssh-keys",
            json={
                "name": "cp4-1-get",
                "private_key_b64": base64.b64encode(pem.encode()).decode(),
            },
        ).json()
        resp = client.get(f"/ssh-keys/{created['id']}")
        assert resp.status_code == 200, resp.text
        assert resp.json().get("mode") == "legacy"

    def test_list_includes_mode(self, client) -> None:  # type: ignore[no-untyped-def]
        import base64

        pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nz\n-----END OPENSSH PRIVATE KEY-----\n"
        client.post(
            "/ssh-keys",
            json={
                "name": "cp4-1-list",
                "private_key_b64": base64.b64encode(pem.encode()).decode(),
            },
        )
        resp = client.get("/ssh-keys")
        assert resp.status_code == 200
        rows = resp.json()
        assert rows, "list must include the row we just posted"
        assert all("mode" in r for r in rows), (
            "every row in GET /ssh-keys must surface its mode"
        )
        assert all(r["mode"] == "legacy" for r in rows)


# ---------------------------------------------------------------------------
# CP4.1d — task-layer routing reads per-key mode
# ---------------------------------------------------------------------------


class TestTaskLayerRoutesPerKeyMode:
    """The task layer's auth path is selected by ``SSHKey.mode``, not by env.

    Phase 2c CP2 shipped a global ``SSH_AUTH_MODE`` setting that
    routed every connection through the legacy path or the CA path
    in lockstep. CP4 supersedes that: each ``SSHKey`` row carries its
    own mode, so a fleet can migrate host-by-host. These tests pin
    that contract by:

    1. Forcing the global env var to one value, then asserting the
       runner construction uses the *opposite* path because the row's
       mode says so.
    2. Mirror across both directions so neither side wins by accident.

    The assertions are on ``FakeSSHRunner.CERTS_USED`` /
    ``KEYS_USED``: the CP2 tests already proved cert vs. legacy
    construction selects the right paramiko code paths — we just
    check which one fires.
    """

    @staticmethod
    def _flip_key_to_ca(session, key_id: int) -> None:  # type: ignore[no-untyped-def]
        """Direct-DB write that flips an :class:`SSHKey` row to ``mode=ca``.

        Stand-in for the CP4.2 ``wg-manager ssh migrate-to-ca`` CLI,
        which hasn't shipped yet. Using a session write here keeps
        these tests scoped to the routing seam rather than depending
        on the next sub-checkpoint's HTTP/CLI surface.
        """
        from wg_manager.models import SSHKey as _SSHKey, SSHKeyMode

        row = session.get(_SSHKey, key_id)
        assert row is not None, f"SSHKey {key_id} not found"
        row.mode = SSHKeyMode.ca
        session.add(row)
        session.commit()

    def test_ca_mode_key_uses_cert_path_even_with_legacy_env(
        self, client, session, monkeypatch  # type: ignore[no-untyped-def]
    ) -> None:
        """A ``mode='ca'`` row mints a per-session cert despite ``SSH_AUTH_MODE=legacy``."""
        import base64

        from tests.conftest import FakeSSHRunner

        # Force the (now-deprecated) global to ``legacy`` so the test
        # asserts the per-key mode wins, not "it accidentally agrees".
        monkeypatch.setenv("SSH_AUTH_MODE", "legacy")
        monkeypatch.setenv("SSH_CA_BACKEND", "local")
        monkeypatch.delenv("SSH_CA_LOCAL_DEV_PEM", raising=False)
        # CP3's host-cert install runs at the tail of CA-mode
        # provisioning and probes for the host's pubkey. Register one
        # so the task succeeds end-to-end.
        FakeSSHRunner.OUTPUTS[
            ("hub-ca.example.com", "ssh_host_ed25519_key.pub")
        ] = (
            "ssh-ed25519 "
            "AAAAC3NzaC1lZDI1NTE5AAAAINcv8wY+y8d0KcKZ6t6S/n7JoYx7M3jzqu7K2YgQGvD7"
            " root@hub-ca.example.com\n"
        )

        pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n"
        key_id = int(
            client.post(
                "/ssh-keys",
                json={
                    "name": "ca-mode-key",
                    "private_key_b64": base64.b64encode(pem.encode()).decode(),
                },
            ).json()["id"]
        )
        # Flip the row into CA mode before provisioning so the task
        # layer sees the new mode value.
        self._flip_key_to_ca(session, key_id)

        FakeSSHRunner.CERTS_USED.clear()
        FakeSSHRunner.KEYS_USED.clear()

        resp = client.post(
            "/servers",
            json={
                "hostname": "hub-ca.example.com",
                "ssh_username": "ubuntu",
                "ssh_key_id": key_id,
                "endpoint_host": "hub-ca.example.com",
            },
        )
        assert resp.status_code == 202, resp.text

        # Filter for non-empty cert_pem — FakeSSHRunner records *every*
        # construction (legacy too), so cert_pem being populated is the
        # actual signal that the CA branch fired.
        cert_records = [
            r
            for r in FakeSSHRunner.CERTS_USED
            if r[0] == "hub-ca.example.com" and r[1]
        ]
        assert cert_records, (
            "task layer did not route through the CA path even though the "
            "SSHKey row's mode is 'ca'; check _open_runner's mode resolution"
        )

    def test_legacy_mode_key_uses_stored_key_even_with_ca_env(
        self, client, monkeypatch  # type: ignore[no-untyped-def]
    ) -> None:
        """A ``mode='legacy'`` row uses ``private_key_ct`` even when ``SSH_AUTH_MODE=ca``."""
        import base64

        from tests.conftest import FakeSSHRunner

        monkeypatch.setenv("SSH_AUTH_MODE", "ca")
        monkeypatch.setenv("SSH_CA_BACKEND", "local")
        monkeypatch.delenv("SSH_CA_LOCAL_DEV_PEM", raising=False)

        pem = "-----BEGIN OPENSSH PRIVATE KEY-----\ny\n-----END OPENSSH PRIVATE KEY-----\n"
        key_id = int(
            client.post(
                "/ssh-keys",
                json={
                    "name": "legacy-mode-key",
                    "private_key_b64": base64.b64encode(pem.encode()).decode(),
                },
            ).json()["id"]
        )
        # No flip: the row stays mode='legacy' (default after CP4.1).

        FakeSSHRunner.CERTS_USED.clear()
        FakeSSHRunner.KEYS_USED.clear()

        resp = client.post(
            "/servers",
            json={
                "hostname": "hub-legacy.example.com",
                "ssh_username": "ubuntu",
                "ssh_key_id": key_id,
                "endpoint_host": "hub-legacy.example.com",
            },
        )
        assert resp.status_code == 202, resp.text

        cert_records = [
            r
            for r in FakeSSHRunner.CERTS_USED
            if r[0] == "hub-legacy.example.com" and r[1]  # non-empty cert_pem
        ]
        assert not cert_records, (
            "task layer routed a 'legacy' SSHKey through the CA path — "
            "the per-key mode column must override the env var; got "
            f"cert records {cert_records!r}"
        )
        key_records = [
            r for r in FakeSSHRunner.KEYS_USED if r[0] == "hub-legacy.example.com"
        ]
        assert key_records, (
            "task layer did not construct any runner for the legacy host"
        )
