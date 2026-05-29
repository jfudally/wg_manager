"""Tests for the ``wg-manager`` CLI.

The CLI is a thin HTTP client over the FastAPI app. We replace
``wg_manager.cli._make_http_client`` with a factory that routes requests
through httpx's ASGI transport, so CLI invocations exercise the real app
(with the same SQLite + FakeSSH fixtures as the API tests) without touching
a network socket.
"""

from __future__ import annotations

import base64
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from wg_manager import cli


_SAMPLE_PEM = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEBODY\n-----END OPENSSH PRIVATE KEY-----\n"
)


class _PassthroughClient:
    """Wrap an already-entered :class:`TestClient` so the CLI can use it.

    The CLI opens its HTTP client with ``with _client(ctx) as http:``.
    :class:`TestClient` is already entered by the ``client`` fixture and
    must not be closed or re-entered, so this wrapper turns the context
    manager into a no-op while forwarding request methods unchanged.
    """

    def __init__(self, inner: TestClient) -> None:
        self._inner = inner

    def __enter__(self) -> _PassthroughClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        return None

    def get(self, *args: Any, **kwargs: Any) -> Any:
        return self._inner.get(*args, **kwargs)

    def post(self, *args: Any, **kwargs: Any) -> Any:
        return self._inner.post(*args, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> Any:
        return self._inner.delete(*args, **kwargs)


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def cli_env(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[None, None, None]:
    """Route CLI HTTP calls at the in-process FastAPI app via TestClient."""

    def _factory(api_url: str) -> _PassthroughClient:  # noqa: ARG001
        return _PassthroughClient(client)

    monkeypatch.setattr(cli, "_make_http_client", _factory)
    yield


@pytest.fixture()
def key_file(tmp_path: Path) -> Path:
    p = tmp_path / "id_ed25519"
    p.write_text(_SAMPLE_PEM)
    return p


def _invoke(runner: CliRunner, *args: str) -> Any:
    result = runner.invoke(cli.app, list(args))
    assert result.exit_code == 0, result.output
    return result


class TestKeysCLI:
    def test_add_list_get_delete(
        self,
        runner: CliRunner,
        cli_env: None,  # noqa: ARG002
        key_file: Path,
    ) -> None:
        add = _invoke(
            runner, "keys", "add", "--name", "lab"
        )
        assert '"name": "lab"' in add.output

        listing = _invoke(runner, "keys", "list")
        assert '"name": "lab"' in listing.output

        get = _invoke(runner, "keys", "get", "1")
        assert '"id": 1' in get.output

        delete = _invoke(runner, "keys", "delete", "1")
        assert "deleted ssh key 1" in delete.output

    def test_get_unknown_key_exits_nonzero(
        self,
        runner: CliRunner,
        cli_env: None,  # noqa: ARG002
    ) -> None:
        result = runner.invoke(cli.app, ["keys", "get", "999"])
        assert result.exit_code == 1
        assert "error 404" in result.output or "error 404" in result.stderr


class TestServersCLI:
    def test_register_list_get_and_reprovision(
        self,
        runner: CliRunner,
        cli_env: None,  # noqa: ARG002
        key_file: Path,
    ) -> None:
        _invoke(runner, "keys", "add", "--name", "lab")

        register = _invoke(
            runner,
            "servers",
            "register",
            "--hostname",
            "hub.example.com",
            "--ssh-user",
            "ubuntu",
            "--key-id",
            "1",
            "--endpoint-host",
            "hub.example.com",
        )
        assert '"task_id"' in register.output
        assert '"address": "10.9.0.1/24"' in register.output

        listing = _invoke(runner, "servers", "list")
        assert '"hostname": "hub.example.com"' in listing.output

        get = _invoke(runner, "servers", "get", "1")
        assert '"status": "ready"' in get.output

        repro = _invoke(runner, "servers", "reprovision", "1")
        assert '"task_id"' in repro.output

    def test_register_with_wait_reports_success(
        self,
        runner: CliRunner,
        cli_env: None,  # noqa: ARG002
        key_file: Path,
    ) -> None:
        _invoke(runner, "keys", "add", "--name", "lab")
        result = _invoke(
            runner,
            "servers",
            "register",
            "--hostname",
            "hub.example.com",
            "--ssh-user",
            "ubuntu",
            "--key-id",
            "1",
            "--endpoint-host",
            "hub.example.com",
            "--wait",
        )
        assert "SUCCESS" in result.output

    def test_discover_and_list_discovered_peers(
        self,
        runner: CliRunner,
        cli_env: None,  # noqa: ARG002
        key_file: Path,
    ) -> None:
        from tests.conftest import FakeSSHRunner

        _invoke(runner, "keys", "add", "--name", "lab")
        _invoke(
            runner,
            "servers",
            "register",
            "--hostname",
            "hub.example.com",
            "--ssh-user",
            "ubuntu",
            "--key-id",
            "1",
            "--endpoint-host",
            "hub.example.com",
        )

        # Wire up the canned ``wg show wg0 dump`` output before kicking off
        # discovery. The eager Celery task will pick this up synchronously.
        FakeSSHRunner.OUTPUTS[("hub.example.com", "wg show wg0 dump")] = (
            "SRV_PRIV\tSRV_PUB\t51820\toff\n"
            "PEER_X\t(none)\t203.0.113.5:51820\t10.9.0.7/32\t0\t0\t0\toff\n"
        )

        discover = _invoke(runner, "servers", "discover", "1")
        assert '"task_id"' in discover.output

        listing = _invoke(runner, "servers", "discovered-peers", "1")
        assert '"public_key": "PEER_X"' in listing.output
        assert '"allowed_ips": "10.9.0.7/32"' in listing.output

    def test_discover_all_walks_every_server(
        self,
        runner: CliRunner,
        cli_env: None,  # noqa: ARG002
        key_file: Path,
    ) -> None:
        from tests.conftest import FakeSSHRunner

        _invoke(runner, "keys", "add", "--name", "lab")
        _invoke(
            runner,
            "servers",
            "register",
            "--hostname",
            "hub.example.com",
            "--ssh-user",
            "ubuntu",
            "--key-id",
            "1",
            "--endpoint-host",
            "hub.example.com",
        )
        FakeSSHRunner.OUTPUTS[("hub.example.com", "wg show wg0 dump")] = (
            "SRV_PRIV\tSRV_PUB\t51820\toff\n"
            "PEER_BATCH\t(none)\t(none)\t10.9.0.9/32\t0\t0\t0\toff\n"
        )

        out = _invoke(runner, "servers", "discover-all")
        assert '"task_id"' in out.output
        assert '"server_count": 1' in out.output


class TestClientsCLI:
    def _bootstrap(self, runner: CliRunner, key_file: Path) -> None:
        _invoke(runner, "keys", "add", "--name", "lab")
        _invoke(
            runner,
            "servers",
            "register",
            "--hostname",
            "hub.example.com",
            "--ssh-user",
            "ubuntu",
            "--key-id",
            "1",
            "--endpoint-host",
            "hub.example.com",
        )

    def test_register_list_get_and_reprovision(
        self,
        runner: CliRunner,
        cli_env: None,  # noqa: ARG002
        key_file: Path,
    ) -> None:
        self._bootstrap(runner, key_file)

        register = _invoke(
            runner,
            "clients",
            "register",
            "--name",
            "alpha",
            "--hostname",
            "alpha.example.com",
            "--ssh-user",
            "ubuntu",
            "--key-id",
            "1",
            "--server-id",
            "1",
        )
        assert '"address": "10.9.0.2/32"' in register.output

        listing = _invoke(runner, "clients", "list")
        assert '"name": "alpha"' in listing.output

        get = _invoke(runner, "clients", "get", "1")
        assert '"status": "ready"' in get.output

        repro = _invoke(runner, "clients", "reprovision", "1")
        assert '"task_id"' in repro.output

    def test_ssh_config_prints_to_stdout(
        self,
        runner: CliRunner,
        cli_env: None,  # noqa: ARG002
        key_file: Path,
    ) -> None:
        """``wg-manager clients ssh-config`` echoes the export to stdout."""
        self._bootstrap(runner, key_file)
        _invoke(
            runner,
            "clients", "register",
            "--name", "alpha",
            "--hostname", "alpha.example.com",
            "--ssh-user", "ubuntu",
            "--key-id", "1",
            "--server-id", "1",
        )

        result = _invoke(runner, "clients", "ssh-config")
        assert "Host alpha.vpn" in result.output
        assert "HostName 10.9.0.2" in result.output
        assert "User ubuntu" in result.output
        assert "IdentityFile ~/.ssh/lab" in result.output

    def test_add_manual_prints_config_to_stdout(
        self,
        runner: CliRunner,
        cli_env: None,  # noqa: ARG002
        key_file: Path,
    ) -> None:
        """``clients add-manual`` registers without provisioning and dumps
        the rendered wg config so the operator can copy it onto the device."""
        self._bootstrap(runner, key_file)

        result = _invoke(
            runner,
            "clients",
            "add-manual",
            "--name",
            "phone",
            "--server-id",
            "1",
        )
        # Registration response was printed (includes is_manual + the
        # follow-up reconfigure task_id) followed by the wg config body.
        assert '"is_manual": true' in result.output
        assert "--- begin wg0.conf ---" in result.output
        assert "[Interface]" in result.output
        assert "[Peer]" in result.output
        assert "PublicKey = PUBKEY::hub.example.com" in result.output

    def test_add_manual_writes_config_to_output_file(
        self,
        runner: CliRunner,
        cli_env: None,  # noqa: ARG002
        key_file: Path,
        tmp_path: Path,
    ) -> None:
        self._bootstrap(runner, key_file)
        outfile = tmp_path / "phone.conf"

        result = _invoke(
            runner,
            "clients",
            "add-manual",
            "--name",
            "phone",
            "--server-id",
            "1",
            "--config-output",
            str(outfile),
        )
        assert f"wrote wg config to {outfile}" in result.output
        body = outfile.read_text()
        assert "[Interface]" in body
        assert "Address = 10.9.0.2/32" in body

    def test_config_command_is_retired(
        self,
        runner: CliRunner,
        cli_env: None,  # noqa: ARG002
        key_file: Path,
    ) -> None:
        """``clients config <id>`` was removed alongside the
        ``GET /clients/{id}/config`` API endpoint. The wg0.conf body is
        now delivered exactly once on ``clients add-manual`` and the
        control plane no longer persists the private key required to
        re-render it. Typer should refuse the unknown subcommand."""
        self._bootstrap(runner, key_file)
        result = runner.invoke(cli.app, ["clients", "config", "1"])
        assert result.exit_code != 0, result.output
        out = (result.output + (result.stderr or "")).lower()
        assert "no such command" in out or "no such" in out

    def test_ssh_config_writes_to_output_file(
        self,
        runner: CliRunner,
        cli_env: None,  # noqa: ARG002
        key_file: Path,
        tmp_path: Path,
    ) -> None:
        """``--output FILE`` writes the block to disk instead of stdout."""
        self._bootstrap(runner, key_file)
        _invoke(
            runner,
            "clients", "register",
            "--name", "alpha",
            "--hostname", "alpha.example.com",
            "--ssh-user", "ubuntu",
            "--key-id", "1",
            "--server-id", "1",
        )

        outfile = tmp_path / "wg.conf"
        result = _invoke(
            runner, "clients", "ssh-config", "--output", str(outfile)
        )
        assert "Host alpha.vpn" not in result.output
        body = outfile.read_text()
        assert "Host alpha.vpn" in body
        assert "IdentityFile ~/.ssh/lab" in body


class TestTasksCLI:
    def test_status_for_unknown_task_reports_pending(
        self,
        runner: CliRunner,
        cli_env: None,  # noqa: ARG002
    ) -> None:
        result = _invoke(runner, "tasks", "status", "deadbeef")
        assert '"state": "PENDING"' in result.output


# ---------------------------------------------------------------------------
# db backup / restore
# ---------------------------------------------------------------------------


class TestDBBackupRestore:
    """Exercise ``wg-manager db backup`` and ``wg-manager db restore``.

    These commands operate directly on the database, not via the HTTP API.
    We monkeypatch ``cli._get_engine`` to return the in-memory SQLite engine
    used by the test suite.
    """

    @staticmethod
    def _populate(runner: CliRunner) -> None:
        """Create an SSH key, a server, and a client via the HTTP-backed CLI."""
        _invoke(runner, "keys", "add", "--name", "lab")

    def test_backup_creates_valid_json(
        self,
        runner: CliRunner,
        cli_env: None,  # noqa: ARG002
        engine: Any,  # noqa: ARG002 — ensures tables exist
        key_file: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from wg_manager import db as db_module_ref

        monkeypatch.setattr(cli, "_get_engine", lambda url=None: db_module_ref.engine)

        # Populate data via the API
        _invoke(runner, "keys", "add", "--name", "lab")
        _invoke(
            runner,
            "servers", "register",
            "--hostname", "hub.example.com",
            "--ssh-user", "ubuntu",
            "--key-id", "1",
            "--endpoint-host", "hub.example.com",
        )
        _invoke(
            runner,
            "clients", "register",
            "--name", "alpha",
            "--hostname", "alpha.example.com",
            "--ssh-user", "ubuntu",
            "--key-id", "1",
            "--server-id", "1",
        )

        outfile = tmp_path / "backup.json"
        result = _invoke(runner, "db", "backup", "--output", str(outfile))
        assert "backup written to" in result.output

        import json as json_mod

        data = json_mod.loads(outfile.read_text())
        assert data["version"] == 1
        assert len(data["tables"]["sshkey"]) == 1
        assert len(data["tables"]["server"]) == 1
        assert len(data["tables"]["client"]) == 1
        assert data["tables"]["sshkey"][0]["name"] == "lab"
        assert data["tables"]["server"][0]["hostname"] == "hub.example.com"
        assert data["tables"]["client"][0]["name"] == "alpha"

    def test_restore_round_trip(
        self,
        runner: CliRunner,
        cli_env: None,  # noqa: ARG002
        engine: Any,
        key_file: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from sqlmodel import Session, select

        from wg_manager import db as db_module_ref
        from wg_manager.models import Client, SSHKey, Server

        monkeypatch.setattr(cli, "_get_engine", lambda url=None: db_module_ref.engine)

        # Populate and backup.
        _invoke(runner, "keys", "add", "--name", "lab")
        _invoke(
            runner,
            "servers", "register",
            "--hostname", "hub.example.com",
            "--ssh-user", "ubuntu",
            "--key-id", "1",
            "--endpoint-host", "hub.example.com",
        )
        _invoke(
            runner,
            "clients", "register",
            "--name", "alpha",
            "--hostname", "alpha.example.com",
            "--ssh-user", "ubuntu",
            "--key-id", "1",
            "--server-id", "1",
        )

        outfile = tmp_path / "backup.json"
        _invoke(runner, "db", "backup", "--output", str(outfile))

        # Restore with --drop-existing (same DB, so tables are non-empty).
        result = _invoke(
            runner, "db", "restore", "--input", str(outfile), "--drop-existing"
        )
        assert "restore complete" in result.output

        # Verify data survived the round trip.
        with Session(engine) as session:
            keys = session.exec(select(SSHKey)).all()
            assert len(keys) == 1
            assert keys[0].name == "lab"
            servers = session.exec(select(Server)).all()
            assert len(servers) == 1
            assert servers[0].hostname == "hub.example.com"
            clients = session.exec(select(Client)).all()
            assert len(clients) == 1
            assert clients[0].name == "alpha"
            assert clients[0].address == "10.9.0.2/32"

    def test_restore_refuses_without_drop_existing(
        self,
        runner: CliRunner,
        cli_env: None,  # noqa: ARG002
        engine: Any,  # noqa: ARG002
        key_file: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from wg_manager import db as db_module_ref

        monkeypatch.setattr(cli, "_get_engine", lambda url=None: db_module_ref.engine)

        _invoke(runner, "keys", "add", "--name", "lab")

        outfile = tmp_path / "backup.json"
        _invoke(runner, "db", "backup", "--output", str(outfile))

        # Without --drop-existing, restore should refuse.
        result = runner.invoke(cli.app, ["db", "restore", "--input", str(outfile)])
        assert result.exit_code == 1

    def test_restore_into_empty_database(
        self,
        runner: CliRunner,
        cli_env: None,  # noqa: ARG002
        engine: Any,
        key_file: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Restore into a fresh DB without --drop-existing."""
        from sqlmodel import Session, select

        from wg_manager import db as db_module_ref
        from wg_manager.models import SSHKey

        monkeypatch.setattr(cli, "_get_engine", lambda url=None: db_module_ref.engine)

        # Populate, backup, then clear the DB.
        _invoke(runner, "keys", "add", "--name", "lab")
        outfile = tmp_path / "backup.json"
        _invoke(runner, "db", "backup", "--output", str(outfile))

        # Manually clear.
        with Session(engine) as session:
            for row in session.exec(select(SSHKey)).all():
                session.delete(row)
            session.commit()

        # Restore without --drop-existing should succeed.
        result = _invoke(runner, "db", "restore", "--input", str(outfile))
        assert "restore complete" in result.output
        with Session(engine) as session:
            assert len(session.exec(select(SSHKey)).all()) == 1
