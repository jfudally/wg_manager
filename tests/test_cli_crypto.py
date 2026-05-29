"""Tests for the ``wg-manager crypto …`` CLI subgroup.

Alembic 0008 dropped the sshkey ciphertext columns and 0009 dropped
the manual-client private-key ciphertext column — the row is now a
metadata label and manual clients never persist a private key. There
are no encrypted-at-rest columns left in the schema, so
``crypto rewrap`` has nothing to walk. We keep the command around as a
no-op so the operator's post-Transit-rotation muscle memory works and
it doubles as a "Vault is reachable; key is at version N" smoke test
— this test pins that behaviour.
"""

from __future__ import annotations

from typing import Any

import pytest
from typer.testing import CliRunner

from wg_manager import cli


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


def _invoke(runner: CliRunner, *args: str) -> Any:
    """Run the CLI and assert a clean exit. Returns the result object."""
    result = runner.invoke(cli.app, list(args))
    assert result.exit_code == 0, result.output
    return result


class TestCryptoRewrap:
    """``wg-manager crypto rewrap`` is a no-op against the current schema."""

    def test_exits_cleanly_with_no_rows_to_rewrap(
        self,
        runner: CliRunner,
        patched_engine: Any,
    ) -> None:
        """Without any encrypted-at-rest columns the command runs to
        completion without touching the DB."""
        result = _invoke(runner, "crypto", "rewrap")
        out = result.output.lower()
        # The summary reports completion + the active backend identity,
        # and explains why no rows were touched.
        assert "complete" in out
        assert "backend" in out
        assert "nothing to rewrap" in out

    def test_dry_run_is_a_no_op_too(
        self,
        runner: CliRunner,
        patched_engine: Any,
    ) -> None:
        """``--dry-run`` is accepted for forward-compat. Without rows
        to walk it produces the same summary the regular run does, just
        annotated as a dry run so the operator sees what they typed."""
        result = _invoke(runner, "crypto", "rewrap", "--dry-run")
        assert "dry-run" in result.output.lower()
        assert "nothing to rewrap" in result.output.lower()


class TestCryptoMigrateRemoved:
    """The migrate command was removed with Alembic 0005."""

    def test_migrate_command_is_gone(self, runner: CliRunner) -> None:
        result = runner.invoke(cli.app, ["crypto", "migrate"])
        assert result.exit_code != 0
        assert (
            "no such command" in result.output.lower()
            or "no such" in result.output.lower()
        )
