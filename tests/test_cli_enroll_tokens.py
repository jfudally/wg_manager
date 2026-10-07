"""Tests for ``wg-manager enroll-tokens`` (Phase 3f polish).

Thin HTTP wrappers over ``/v1/enrollment-tokens``, like most of the CLI,
so authorisation and auditing stay in the API. ``cli_env`` (from
``tests/test_cli.py``) routes the CLI's HTTP calls into the in-process
app.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from typer.testing import CliRunner

from tests.test_cli import cli_env, runner  # noqa: F401 (fixtures)
from tests.test_enrollment_tokens_api import _seed
from wg_manager import cli
from wg_manager.enrollment import find_token


def _invoke(runner: CliRunner, *args: str) -> Any:  # noqa: F811
    return runner.invoke(cli.app, ["enroll-tokens", *args])


@pytest.fixture()
def hub(cli_env: None) -> tuple[int, int]:  # noqa: F811
    """A ready hub + SSH key in tenant 1; returns ``(key_id, server_id)``."""
    return _seed()


def _create(runner: CliRunner, hub: tuple[int, int], *extra: str) -> Any:  # noqa: F811
    key_id, server_id = hub
    return _invoke(
        runner, "create", "--server-id", str(server_id), "--key-id", str(key_id),
        "--ssh-user", "wgmgr", *extra,
    )


class TestCreate:
    def test_prints_the_token_and_summary(self, runner, hub) -> None:  # noqa: F811
        result = _create(runner, hub)
        assert result.exit_code == 0, result.output
        body = json.loads(result.output)
        assert body["token"].startswith("wgmenr_")
        assert body["server_id"] == hub[1]
        assert body["max_uses"] == 1

    def test_token_only_is_scriptable(self, runner, hub) -> None:  # noqa: F811
        """``TOKEN=$(wg-manager enroll-tokens create ... --token-only)``."""
        from sqlmodel import Session

        from wg_manager import db as db_module

        result = _create(runner, hub, "--token-only")
        assert result.exit_code == 0, result.output
        token = result.output.strip()
        assert token.startswith("wgmenr_") and "\n" not in token
        with Session(db_module.engine) as s:
            assert find_token(s, token) is not None

    def test_options_are_forwarded(self, runner, hub) -> None:  # noqa: F811
        result = _create(
            runner, hub, "--name-prefix", "web", "--ttl", "2h", "--max-uses", "5",
            "--allow-cidr", "203.0.113.0/24", "--allow-cidr", "198.51.100.7",
        )
        assert result.exit_code == 0, result.output
        [row] = json.loads(_invoke(runner, "list").output)
        assert row["name_prefix"] == "web"
        assert row["max_uses"] == 5
        assert row["allowed_cidrs"] == ["203.0.113.0/24", "198.51.100.7/32"]

    @pytest.mark.parametrize(
        "ttl,seconds", [("600", 600), ("90s", 90), ("15m", 900), ("2h", 7200), ("1d", 86400)]
    )
    def test_ttl_units(self, ttl: str, seconds: int) -> None:
        assert cli._parse_duration(ttl) == seconds

    @pytest.mark.parametrize("ttl", ["", "abc", "1w", "-5m", "1.5h", "0"])
    def test_bad_ttl_is_a_usage_error(self, runner, hub, ttl: str) -> None:  # noqa: F811
        result = _create(runner, hub, "--ttl", ttl)
        assert result.exit_code == 2, result.output

    def test_api_errors_exit_1(self, runner, hub) -> None:  # noqa: F811
        result = _invoke(
            runner, "create", "--server-id", "999", "--key-id", str(hub[0]),
            "--ssh-user", "wgmgr",
        )
        assert result.exit_code == 1
        assert "404" in result.output


class TestList:
    def test_lists_newest_first_without_secrets(self, runner, hub) -> None:  # noqa: F811
        first = json.loads(_create(runner, hub).output)["id"]
        second = json.loads(_create(runner, hub).output)["id"]
        result = _invoke(runner, "list")
        assert result.exit_code == 0, result.output
        rows = json.loads(result.output)
        assert [r["id"] for r in rows] == [second, first]
        assert all("token" not in r and "token_hash" not in r for r in rows)

    def test_active_and_server_filters(self, runner, hub) -> None:  # noqa: F811
        live = json.loads(_create(runner, hub).output)["id"]
        dead = json.loads(_create(runner, hub).output)["id"]
        _invoke(runner, "revoke", str(dead))
        active = json.loads(_invoke(runner, "list", "--active").output)
        assert [r["id"] for r in active] == [live]
        other = json.loads(_invoke(runner, "list", "--server-id", "999").output)
        assert other == []


class TestRevoke:
    def test_revokes(self, runner, hub) -> None:  # noqa: F811
        token_id = json.loads(_create(runner, hub).output)["id"]
        result = _invoke(runner, "revoke", str(token_id))
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["status"] == "revoked"

    def test_unknown_exits_1(self, runner, hub) -> None:  # noqa: F811
        result = _invoke(runner, "revoke", "999")
        assert result.exit_code == 1
        assert "404" in result.output


def test_listed_in_help(runner) -> None:  # noqa: F811
    result = runner.invoke(cli.app, ["--help"])
    assert "enroll-tokens" in result.output
