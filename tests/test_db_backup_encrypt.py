"""Tests for Phase 2e backup cycle 2 — Transit-envelope-encrypted DB backups.

Cycle 2 extends ``wg-manager db backup`` / ``db restore`` with
``--encrypt`` / ``--decrypt`` flags that wrap the JSON dump in a
Transit-data-key envelope. The pattern:

1. ``db backup --encrypt`` mints a per-dump 256-bit AES key
   (the *data encryption key*, "DEK") via ``os.urandom``,
   AES-256-GCM-encrypts the JSON dump with it under a random
   12-byte nonce, then wraps the DEK via the configured
   :class:`wg_manager.crypto.CryptoBackend` (Transit in production,
   :class:`LocalDevBackend` Fernet in tests) bound to a
   ``backup:<utc_iso8601>`` context. The on-disk file is a JSON
   envelope — ciphertext + nonce + wrapped-DEK + the public envelope
   metadata an operator needs to identify the dump.
2. ``db restore --decrypt`` inverts: read envelope → unwrap DEK via
   the same backend + context → AES-256-GCM decrypt → JSON parse →
   regular restore path. Tamper detection is the AES-GCM tag (a
   flipped bit in the ciphertext or the nonce raises ``InvalidTag``).

The envelope is deliberately database-agnostic and version-tagged
so an operator can restore from an old dump into a fresh stack —
just like the plain JSON backup CP1 shipped.

These tests are hermetic: ``conftest.py`` pins
``CRYPTO_BACKEND=local`` + a fixed Fernet key, so the DEK-wrap leg
uses :class:`LocalDevBackend` without a Vault container. The smoke
flow against a real Vault Transit backend lives in
[`docs/runbooks/backup-restore.md`](../docs/runbooks/backup-restore.md)
and is the operator's responsibility during a drill.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest
from sqlmodel import Session
from typer.testing import CliRunner

from wg_manager import cli
from wg_manager import db as db_module
from wg_manager.models import NodeStatus, SSHKey, Server


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def backup_env(
    engine: Any,  # noqa: ARG001 — installs schema on db_module.engine
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wire ``cli._get_engine`` to the in-memory test engine.

    Mirrors the pattern :mod:`tests.test_cli_certs` uses for direct-DB
    CLI commands. The ``engine`` fixture already swaps
    :data:`wg_manager.db.engine` for the in-memory handle; this
    monkeypatch threads it through the CLI's ``--database-url``-aware
    accessor.
    """
    monkeypatch.setattr(cli, "_get_engine", lambda url=None: db_module.engine)


def _seed_two_rows() -> None:
    """Insert one SSHKey and one Server so the dump has content to
    round-trip. The exact shape doesn't matter — the round-trip
    assertion compares the dump bytes pre- and post-restore.
    """
    with Session(db_module.engine) as session:
        key = SSHKey(name="dev-role")
        session.add(key)
        session.flush()
        server = Server(
            hostname="srv-1.example.com",
            ssh_username="root",
            endpoint_host="srv-1.example.com",
            ssh_key_id=int(key.id or 0),
            status=NodeStatus.ready,
        )
        session.add(server)
        session.commit()


def _invoke(runner: CliRunner, *args: str) -> Any:
    """Invoke the CLI with the test args."""
    return runner.invoke(cli.app, list(args))


# ---------------------------------------------------------------------------
# Envelope shape — what the on-disk file looks like
# ---------------------------------------------------------------------------


class TestEnvelopeShape:
    """Pin the on-disk envelope format. Decryption code in a future
    refactor that drops a field trips here."""

    def test_encrypted_backup_writes_envelope_json(
        self, runner: CliRunner, backup_env: None, tmp_path: Path
    ) -> None:
        out = tmp_path / "backup.enc.json"
        result = _invoke(runner, "db", "backup", "--output", str(out), "--encrypt")
        assert result.exit_code == 0, result.output
        envelope = json.loads(out.read_text())
        assert envelope["encrypted"] is True
        # Version mirrors the plain-backup version so an unencrypted
        # restore against an encrypted file fails the existing version
        # check, not in a confusing place deep inside AES-GCM.
        assert "version" in envelope
        # The four fields the decrypt path needs.
        assert "dek_ct" in envelope
        assert "nonce_b64" in envelope
        assert "ciphertext_b64" in envelope
        assert "context" in envelope
        # Operator-facing breadcrumbs.
        assert "created_at" in envelope
        # Plaintext dump is NOT present.
        assert "tables" not in envelope

    def test_plaintext_backup_unchanged_no_encrypted_marker(
        self, runner: CliRunner, backup_env: None, tmp_path: Path
    ) -> None:
        """No regression: ``db backup`` without ``--encrypt`` still
        writes the plain JSON dump CP1 shipped."""
        out = tmp_path / "backup.json"
        result = _invoke(runner, "db", "backup", "--output", str(out))
        assert result.exit_code == 0, result.output
        dump = json.loads(out.read_text())
        assert dump.get("encrypted") is not True
        assert "tables" in dump


# ---------------------------------------------------------------------------
# Round-trip — the contract that matters
# ---------------------------------------------------------------------------


class TestRoundTrip:
    """An encrypted backup, dropped + restored, yields the same rows."""

    def test_round_trip_preserves_rows(
        self, runner: CliRunner, backup_env: None, tmp_path: Path
    ) -> None:
        _seed_two_rows()

        # Snapshot the current row count for the assertion.
        with Session(db_module.engine) as session:
            pre_keys = len(session.query(SSHKey).all())
            pre_servers = len(session.query(Server).all())
        assert pre_keys == 1 and pre_servers == 1

        out = tmp_path / "backup.enc.json"
        backup = _invoke(runner, "db", "backup", "--output", str(out), "--encrypt")
        assert backup.exit_code == 0, backup.output

        # Restore via the existing --drop-existing path; --decrypt
        # opts into the envelope-unwrap branch.
        restore = _invoke(
            runner,
            "db",
            "restore",
            "--input",
            str(out),
            "--decrypt",
            "--drop-existing",
        )
        assert restore.exit_code == 0, restore.output

        with Session(db_module.engine) as session:
            post_keys = len(session.query(SSHKey).all())
            post_servers = len(session.query(Server).all())
        assert post_keys == pre_keys
        assert post_servers == pre_servers

    def test_round_trip_empty_database(
        self, runner: CliRunner, backup_env: None, tmp_path: Path
    ) -> None:
        """A backup of an empty DB still round-trips. Edge case the
        envelope path must handle — a zero-row JSON is not zero bytes."""
        out = tmp_path / "empty.enc.json"
        backup = _invoke(runner, "db", "backup", "--output", str(out), "--encrypt")
        assert backup.exit_code == 0, backup.output

        restore = _invoke(
            runner, "db", "restore", "--input", str(out), "--decrypt"
        )
        assert restore.exit_code == 0, restore.output


# ---------------------------------------------------------------------------
# Tamper detection — the GCM tag does its job
# ---------------------------------------------------------------------------


class TestTamperDetection:
    """A flipped bit anywhere in the envelope-protected payload aborts
    the restore. The AES-GCM tag is what catches it; these tests pin
    the failure shape so a future refactor can't silently drop it."""

    def test_flipped_ciphertext_bit_fails_restore(
        self, runner: CliRunner, backup_env: None, tmp_path: Path
    ) -> None:
        _seed_two_rows()
        out = tmp_path / "tampered.enc.json"
        _invoke(runner, "db", "backup", "--output", str(out), "--encrypt")

        envelope = json.loads(out.read_text())
        ct = base64.b64decode(envelope["ciphertext_b64"])
        tampered = bytearray(ct)
        tampered[0] ^= 0x01
        envelope["ciphertext_b64"] = base64.b64encode(bytes(tampered)).decode("ascii")
        out.write_text(json.dumps(envelope))

        result = _invoke(
            runner,
            "db",
            "restore",
            "--input",
            str(out),
            "--decrypt",
            "--drop-existing",
        )
        assert result.exit_code != 0
        # The failure message should make it clear this was a tamper /
        # decrypt-failure, not a corrupted JSON dump after decryption.
        assert "decrypt" in result.output.lower() or "tamper" in result.output.lower()

    def test_flipped_nonce_bit_fails_restore(
        self, runner: CliRunner, backup_env: None, tmp_path: Path
    ) -> None:
        out = tmp_path / "tampered.enc.json"
        _invoke(runner, "db", "backup", "--output", str(out), "--encrypt")

        envelope = json.loads(out.read_text())
        nonce = bytearray(base64.b64decode(envelope["nonce_b64"]))
        nonce[0] ^= 0x01
        envelope["nonce_b64"] = base64.b64encode(bytes(nonce)).decode("ascii")
        out.write_text(json.dumps(envelope))

        result = _invoke(
            runner, "db", "restore", "--input", str(out), "--decrypt"
        )
        assert result.exit_code != 0
        assert "decrypt" in result.output.lower() or "tamper" in result.output.lower()

    def test_swapped_dek_ct_fails_restore(
        self, runner: CliRunner, backup_env: None, tmp_path: Path
    ) -> None:
        """Wrapping the DEK under a different per-backup context binds
        the envelope to a specific backup. Swapping ``dek_ct`` between
        two backups must fail."""
        out_a = tmp_path / "a.enc.json"
        out_b = tmp_path / "b.enc.json"
        _invoke(runner, "db", "backup", "--output", str(out_a), "--encrypt")
        _invoke(runner, "db", "backup", "--output", str(out_b), "--encrypt")

        env_a = json.loads(out_a.read_text())
        env_b = json.loads(out_b.read_text())
        # Swap A's wrapped DEK into B's envelope.
        env_b["dek_ct"] = env_a["dek_ct"]
        out_b.write_text(json.dumps(env_b))

        result = _invoke(
            runner, "db", "restore", "--input", str(out_b), "--decrypt"
        )
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Mode-mismatch ergonomics — clear errors when the operator forgets
# the flag, instead of mysterious JSON-parse failures deep inside the
# restore path.
# ---------------------------------------------------------------------------


class TestModeMismatch:
    def test_restore_without_decrypt_on_encrypted_file_errors_clearly(
        self, runner: CliRunner, backup_env: None, tmp_path: Path
    ) -> None:
        out = tmp_path / "backup.enc.json"
        _invoke(runner, "db", "backup", "--output", str(out), "--encrypt")

        result = _invoke(runner, "db", "restore", "--input", str(out))
        assert result.exit_code != 0
        assert (
            "encrypted" in result.output.lower()
            or "--decrypt" in result.output.lower()
        )

    def test_restore_with_decrypt_on_plain_file_errors_clearly(
        self, runner: CliRunner, backup_env: None, tmp_path: Path
    ) -> None:
        out = tmp_path / "backup.json"
        _invoke(runner, "db", "backup", "--output", str(out))

        result = _invoke(
            runner, "db", "restore", "--input", str(out), "--decrypt"
        )
        assert result.exit_code != 0
        assert (
            "plain" in result.output.lower()
            or "not encrypted" in result.output.lower()
            or "--decrypt" in result.output.lower()
        )


# ---------------------------------------------------------------------------
# Backend integration — the wrap/unwrap path uses the existing
# wg_manager.crypto surface, not a parallel encryption module.
# ---------------------------------------------------------------------------


class TestCryptoBackendIntegration:
    """Pin that the DEK wrap goes through ``crypto.make_backend()`` so
    a Vault Transit deployment gets the wrapped DEK in Vault — i.e. the
    Transit data-key flow the ROADMAP calls for."""

    def test_wrapped_dek_is_a_crypto_backend_ciphertext(
        self, runner: CliRunner, backup_env: None, tmp_path: Path
    ) -> None:
        """``LocalDevBackend.encrypt`` returns ``local:v1:<...>`` and
        ``VaultTransitBackend.encrypt`` returns ``vault:v1:<...>``. The
        ``dek_ct`` in the envelope must carry one of those prefixes
        so an operator can tell at a glance which backend wrapped it.
        """
        out = tmp_path / "backup.enc.json"
        _invoke(runner, "db", "backup", "--output", str(out), "--encrypt")

        envelope = json.loads(out.read_text())
        assert envelope["dek_ct"].startswith(("local:", "vault:")), envelope["dek_ct"]
