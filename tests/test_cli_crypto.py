"""Tests for the ``wg-manager crypto …`` CLI subgroup.

Post-Phase-2b the only command in the subgroup is ``crypto rewrap``:
the earlier ``crypto migrate`` was removed alongside Alembic 0005's
drop of the plaintext columns, since there is nothing legacy left to
migrate. ``rewrap`` re-encrypts existing ciphertext under the active
key version — useful after ``vault write -f transit/keys/wg-manager/
rotate`` so every blob ends up on the same version.

These tests run against the in-memory SQLite engine provided by the
existing ``engine`` fixture. We seed encrypted rows directly through
``encrypt_*`` helpers so the test bypasses the FastAPI app — the goal
is to exercise the CLI's walk-and-rewrap logic in isolation.
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlmodel import Session, select
from typer.testing import CliRunner

from wg_manager import cli
from wg_manager.crypto import (
    encrypt_client_private_key,
    encrypt_sshkey_secrets,
    make_backend,
    resolve_client_private_key,
    resolve_sshkey_passphrase,
    resolve_sshkey_private,
)
from wg_manager.models import Client, NodeStatus, SSHKey, Server


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def patched_engine(
    engine: Any, monkeypatch: pytest.MonkeyPatch
) -> Any:
    """Wire ``cli._get_engine`` at the in-memory test engine.

    Mirrors the pattern used by the ``db backup`` / ``restore`` tests —
    the CLI bypasses the HTTP layer and opens its own SQLAlchemy
    session against the configured engine, so we have to monkeypatch
    the lookup.
    """
    monkeypatch.setattr(cli, "_get_engine", lambda url=None: engine)
    return engine


def _seed_encrypted_sshkey(
    engine: Any,
    *,
    name: str = "lab",
    private_key: str = "ENCRYPTED-PEM-BODY",
    passphrase: str | None = None,
) -> int:
    """Insert an :class:`SSHKey` row already encrypted under the test backend."""
    backend = make_backend()
    with Session(engine) as s:
        row = SSHKey(name=name)
        s.add(row)
        s.commit()
        s.refresh(row)
        encrypt_sshkey_secrets(
            backend, row, private_key=private_key, passphrase=passphrase
        )
        s.add(row)
        s.commit()
        s.refresh(row)
        assert row.private_key_ct is not None
        assert row.id is not None
        return int(row.id)


def _seed_encrypted_manual_client(
    engine: Any, *, name: str = "phone", private_key: str = "ENCRYPTED-WG-SECRET"
) -> int:
    """Insert a manual :class:`Client` already encrypted under the test backend.

    Requires a parent server, which we insert here too (status doesn't
    matter for the rewrap path)."""
    backend = make_backend()
    with Session(engine) as s:
        srv = Server(
            hostname="hub.example.com",
            ssh_username="ubuntu",
            ssh_key_id=1,  # FK lookup is not validated at this layer
            endpoint_host="hub.example.com",
            status=NodeStatus.ready,
            public_key="HUBPUBKEY",
        )
        s.add(srv)
        s.commit()
        s.refresh(srv)

        row = Client(
            name=name,
            server_id=srv.id,
            address="10.9.0.42/32",
            public_key="CLIENTPUBKEY",
            is_manual=True,
            status=NodeStatus.ready,
        )
        s.add(row)
        s.commit()
        s.refresh(row)
        encrypt_client_private_key(backend, row, private_key=private_key)
        s.add(row)
        s.commit()
        s.refresh(row)
        assert row.private_key_ct is not None
        return int(row.id)


def _invoke(runner: CliRunner, *args: str) -> Any:
    """Run the CLI and assert a clean exit. Returns the result object."""
    result = runner.invoke(cli.app, list(args))
    assert result.exit_code == 0, result.output
    return result


class TestCryptoRewrap:
    """``wg-manager crypto rewrap`` re-encrypts existing ciphertext.

    The motivating workflow is a Vault Transit key rotation: after
    ``vault write -f transit/keys/wg-manager/rotate`` every existing
    blob still decrypts (Transit retains old key versions), but new
    writes use the new version. ``rewrap`` walks every row, decrypts
    under the row's per-row context, and re-encrypts under the now-
    current key. The visible effect is that the version embedded in
    each blob (``vault:vN:…``) advances to match the active version.

    For ``LocalDevBackend`` rewrap is mostly a no-op — Fernet is
    randomised but unversioned, so the only observable change is that
    each row's ciphertext body is rewritten (a fresh IV/nonce). The
    command still walks the rows and reports counts so operators can
    smoke-test the workflow against the local backend before pointing
    it at production.
    """

    def test_rewraps_existing_sshkey_ciphertext(
        self,
        runner: CliRunner,
        patched_engine: Any,
    ) -> None:
        """Encrypted rows are re-encrypted; plaintext still decrypts to
        the same value after the rewrap so no data is lost."""
        key_id = _seed_encrypted_sshkey(
            patched_engine,
            name="lab",
            private_key="ORIGINAL-PEM-BODY",
            passphrase="hunter2",
        )
        backend = make_backend()
        with Session(patched_engine) as s:
            row = s.get(SSHKey, key_id)
            assert row is not None
            original_pk_ct = row.private_key_ct
            original_pp_ct = row.passphrase_ct

        _invoke(runner, "crypto", "rewrap")

        with Session(patched_engine) as s:
            row = s.get(SSHKey, key_id)
            assert row is not None
            # Body changed — re-encryption produces fresh ciphertext.
            assert row.private_key_ct != original_pk_ct
            assert row.passphrase_ct != original_pp_ct
            # …but it still decrypts to the original plaintext.
            assert resolve_sshkey_private(backend, row) == "ORIGINAL-PEM-BODY"
            assert resolve_sshkey_passphrase(backend, row) == "hunter2"

    def test_rewraps_manual_client_ciphertext(
        self,
        runner: CliRunner,
        patched_engine: Any,
    ) -> None:
        """The manual-client private key path is rewrapped too."""
        client_id = _seed_encrypted_manual_client(
            patched_engine, private_key="ORIGINAL-WG-SECRET"
        )
        backend = make_backend()
        with Session(patched_engine) as s:
            row = s.get(Client, client_id)
            assert row is not None
            original_ct = row.private_key_ct

        _invoke(runner, "crypto", "rewrap")

        with Session(patched_engine) as s:
            row = s.get(Client, client_id)
            assert row is not None
            assert row.private_key_ct != original_ct
            assert resolve_client_private_key(backend, row) == "ORIGINAL-WG-SECRET"

    def test_skips_rows_without_ciphertext(
        self,
        runner: CliRunner,
        patched_engine: Any,
    ) -> None:
        """An ``SSHKey`` with no ciphertext at all is skipped, not crashed on.

        Such a row shouldn't exist in normal operation post-0005 (the
        create path always populates ciphertext), but the CLI must
        tolerate the shape so operator-issued direct INSERTs don't
        break the workflow."""
        with Session(patched_engine) as s:
            row = SSHKey(name="orphan")
            s.add(row)
            s.commit()

        result = _invoke(runner, "crypto", "rewrap")
        with Session(patched_engine) as s:
            row = s.exec(select(SSHKey)).first()
            assert row is not None
            assert row.private_key_ct is None
        assert "skipped" in result.output.lower()

    def test_dry_run_does_not_persist(
        self,
        runner: CliRunner,
        patched_engine: Any,
    ) -> None:
        """``--dry-run`` reports what would change without writing."""
        _seed_encrypted_sshkey(patched_engine, name="lab")
        with Session(patched_engine) as s:
            before = s.exec(select(SSHKey)).first().private_key_ct

        _invoke(runner, "crypto", "rewrap", "--dry-run")

        with Session(patched_engine) as s:
            after = s.exec(select(SSHKey)).first().private_key_ct
        assert before == after, "--dry-run must not persist new ciphertext"

    def test_summary_reports_counts(
        self,
        runner: CliRunner,
        patched_engine: Any,
    ) -> None:
        """End-of-run summary surfaces rewrap counts per table."""
        _seed_encrypted_sshkey(patched_engine, name="lab")
        _seed_encrypted_manual_client(patched_engine)

        result = _invoke(runner, "crypto", "rewrap")
        out = result.output.lower()
        assert "sshkey" in out
        assert "client" in out
        assert "rewrap" in out


class TestCryptoMigrateRemoved:
    """The migrate command was removed with Alembic 0005."""

    def test_migrate_command_is_gone(self, runner: CliRunner) -> None:
        result = runner.invoke(cli.app, ["crypto", "migrate"])
        assert result.exit_code != 0
        assert (
            "no such command" in result.output.lower()
            or "no such" in result.output.lower()
        )
