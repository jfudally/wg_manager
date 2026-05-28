"""Tests for the ``wg-manager crypto …`` CLI subgroup.

Phase 2c CP4.4 dropped the sshkey ciphertext columns — the row is now
a name-and-mode label only — so the only remaining secret at rest is
the manual-client WireGuard private key. ``crypto rewrap`` walks
just the :class:`Client` table now (the prior ``SSHKey`` half was
removed alongside the columns). The motivating Vault Transit key
rotation workflow still applies for the manual-client side: after
``vault write -f transit/keys/wg-manager/rotate`` ``rewrap`` walks
every encrypted client row and re-encrypts under the active key
version.

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
    make_backend,
    resolve_client_private_key,
)
from wg_manager.models import Client, NodeStatus, Server


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
    """``wg-manager crypto rewrap`` re-encrypts existing manual-client ciphertext."""

    def test_rewraps_manual_client_ciphertext(
        self,
        runner: CliRunner,
        patched_engine: Any,
    ) -> None:
        """Re-encryption produces fresh ciphertext that decrypts to the original."""
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

    def test_skips_ssh_provisioned_clients(
        self,
        runner: CliRunner,
        patched_engine: Any,
    ) -> None:
        """SSH-provisioned clients have ``private_key_ct=None`` and are skipped."""
        with Session(patched_engine) as s:
            srv = Server(
                hostname="hub.example.com",
                ssh_username="ubuntu",
                ssh_key_id=1,
                endpoint_host="hub.example.com",
                status=NodeStatus.ready,
                public_key="HUBPUBKEY",
            )
            s.add(srv)
            s.commit()
            s.refresh(srv)
            row = Client(
                name="laptop",
                server_id=srv.id,
                address="10.9.0.7/32",
                public_key="LAPTOP-PUB",
                is_manual=False,
                status=NodeStatus.ready,
            )
            s.add(row)
            s.commit()

        _invoke(runner, "crypto", "rewrap")
        # SSH-provisioned clients are silently skipped (no private_key_ct
        # to rewrap). The command exits cleanly without touching the row.
        with Session(patched_engine) as s:
            row = s.exec(select(Client)).first()
            assert row is not None
            assert row.private_key_ct is None

    def test_dry_run_does_not_persist(
        self,
        runner: CliRunner,
        patched_engine: Any,
    ) -> None:
        """``--dry-run`` reports what would change without writing."""
        client_id = _seed_encrypted_manual_client(patched_engine)
        with Session(patched_engine) as s:
            before = s.get(Client, client_id).private_key_ct

        _invoke(runner, "crypto", "rewrap", "--dry-run")

        with Session(patched_engine) as s:
            after = s.get(Client, client_id).private_key_ct
        assert before == after, "--dry-run must not persist new ciphertext"

    def test_summary_reports_client_counts(
        self,
        runner: CliRunner,
        patched_engine: Any,
    ) -> None:
        """End-of-run summary surfaces rewrap counts for the manual-client table."""
        _seed_encrypted_manual_client(patched_engine)

        result = _invoke(runner, "crypto", "rewrap")
        out = result.output.lower()
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
