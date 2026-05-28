"""Tests for the ``wg-manager ssh migrate-to-ca`` CLI subcommand (CP4.2).

The CLI is a thin HTTP wrapper around the CP4.2 endpoint shipped in
:mod:`wg_manager.routers.ssh_keys`. The endpoint's contract is pinned
in ``tests/test_ssh_migrate.py``; these tests focus on the CLI seams
that don't have an HTTP equivalent:

1. Reading the private key body from a file on disk (``--key-file``)
   and base64-encoding it before posting.
2. Passing through an optional passphrase (``--passphrase``).
3. Pretty-printing the per-server result envelope so the operator
   sees the per-host outcomes at a glance.
4. Exiting non-zero when *any* server's bootstrap failed so a CI
   pipeline driving the CLI fails fast.

The CLI uses the same in-process ASGI plumbing as
``tests/test_cli.py`` (the ``cli_env`` fixture wires httpx's
``_make_http_client`` at the FastAPI app via :class:`TestClient`).
"""

from __future__ import annotations

import base64
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from tests.conftest import FakeSSHRunner
from wg_manager import cli


_SAMPLE_PEM = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "cp4-2-cli-canary\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)
_SAMPLE_PEM_B64 = base64.b64encode(_SAMPLE_PEM.encode("utf-8")).decode("ascii")
_HOST_PUBKEY = (
    "ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAINcv8wY+y8d0KcKZ6t6S/n7JoYx7M3jzqu7K2YgQGvD7"
    " root@cp4-2-cli.example.com"
)


class _PassthroughClient:
    """Wrap an already-entered :class:`TestClient` for CLI consumption."""

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
    """Route CLI HTTP calls at the in-process FastAPI app via TestClient.

    Also enables the local CA backend so the CP4.2 helper can mint
    host certs during the bootstrap step.
    """
    monkeypatch.setenv("SSH_CA_BACKEND", "local")
    monkeypatch.delenv("SSH_CA_LOCAL_DEV_PEM", raising=False)

    def _factory(api_url: str) -> _PassthroughClient:  # noqa: ARG001
        return _PassthroughClient(client)

    monkeypatch.setattr(cli, "_make_http_client", _factory)
    yield


@pytest.fixture()
def key_file(tmp_path: Path) -> Path:
    p = tmp_path / "bootstrap_key"
    p.write_text(_SAMPLE_PEM)
    return p


def _register_host_pubkey(host: str) -> None:
    FakeSSHRunner.OUTPUTS[(host, "ssh_host_ed25519_key.pub")] = _HOST_PUBKEY + "\n"


def _seed_key_and_server(
    client: TestClient, hostname: str = "hub-cli.example.com"
) -> tuple[int, int]:
    """Register an SSH key + one legacy server using the FakeSSHRunner."""
    key_id = int(
        client.post(
            "/ssh-keys",
            json={"name": "cli-key", "private_key_b64": _SAMPLE_PEM_B64},
        ).json()["id"]
    )
    _register_host_pubkey(hostname)
    resp = client.post(
        "/servers",
        json={
            "hostname": hostname,
            "ssh_username": "ubuntu",
            "ssh_key_id": key_id,
            "endpoint_host": hostname,
        },
    )
    assert resp.status_code == 202, resp.text
    server_id = int(resp.json()["server"]["id"])
    return key_id, server_id


class TestSSHMigrateToCACLI:
    """``wg-manager ssh migrate-to-ca <key_id> --key-file PATH``."""

    def test_happy_path_exits_zero_and_prints_envelope(
        self,
        runner: CliRunner,
        cli_env: None,  # noqa: ARG002
        client: TestClient,
        key_file: Path,
    ) -> None:
        key_id, _server_id = _seed_key_and_server(client)

        result = runner.invoke(
            cli.app,
            [
                "ssh",
                "migrate-to-ca",
                str(key_id),
                "--key-file",
                str(key_file),
            ],
        )
        assert result.exit_code == 0, result.output
        # The envelope is pretty-printed JSON; key fields appear verbatim.
        assert '"mode": "ca"' in result.output
        assert '"servers_ok": 1' in result.output
        assert '"servers_failed": 0' in result.output
        assert '"status": "ok"' in result.output

    def test_unknown_key_exits_nonzero(
        self,
        runner: CliRunner,
        cli_env: None,  # noqa: ARG002
        key_file: Path,
    ) -> None:
        result = runner.invoke(
            cli.app,
            [
                "ssh",
                "migrate-to-ca",
                "9999",
                "--key-file",
                str(key_file),
            ],
        )
        assert result.exit_code != 0
        # The router returns 404; the CLI's ``_handle`` surfaces it.
        assert "404" in result.output or "not found" in result.output.lower()

    def test_partial_failure_exits_nonzero(
        self,
        runner: CliRunner,
        cli_env: None,  # noqa: ARG002
        client: TestClient,
        key_file: Path,
    ) -> None:
        """Operators driving the CLI from CI need a non-zero on any host fail.

        The HTTP endpoint always returns 200 with a per-server result
        envelope (so the dashboard renders uniformly), but a CLI caller
        usually wants a non-zero exit when *any* host failed so the
        pipeline aborts. The CLI translates ``servers_failed > 0`` into
        a non-zero exit; the JSON envelope still prints so the operator
        can see which hosts to fix.
        """
        from wg_manager.ssh import SSHConnectionError

        key_id, _ = _seed_key_and_server(client, hostname="hub-good.example.com")
        # Second server using the same key — but unreachable.
        _register_host_pubkey("hub-bad.example.com")
        resp = client.post(
            "/servers",
            json={
                "hostname": "hub-bad.example.com",
                "ssh_username": "ubuntu",
                "ssh_key_id": key_id,
                "endpoint_host": "hub-bad.example.com",
            },
        )
        assert resp.status_code == 202, resp.text
        # The provision task ran in legacy mode and succeeded against
        # the FakeSSHRunner. Now break the bootstrap call specifically.
        FakeSSHRunner.RAISE_ON_ENTER["hub-bad.example.com"] = SSHConnectionError(
            "connection refused"
        )

        result = runner.invoke(
            cli.app,
            [
                "ssh",
                "migrate-to-ca",
                str(key_id),
                "--key-file",
                str(key_file),
            ],
        )
        assert result.exit_code != 0, result.output
        assert '"servers_failed": 1' in result.output
        assert '"mode": "legacy"' in result.output, (
            "row mode stays legacy on partial failure so the operator "
            "can retry once the host is fixed"
        )

    def test_passphrase_is_forwarded_in_body(
        self,
        runner: CliRunner,
        cli_env: None,  # noqa: ARG002
        client: TestClient,
        key_file: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``--passphrase`` round-trips through the endpoint body.

        Spy on the SSHRunner construction: passphrase is the third
        positional of the FakeSSHRunner record.
        """
        key_id, _ = _seed_key_and_server(client, hostname="hub-pw.example.com")
        FakeSSHRunner.KEYS_USED.clear()

        result = runner.invoke(
            cli.app,
            [
                "ssh",
                "migrate-to-ca",
                str(key_id),
                "--key-file",
                str(key_file),
                "--passphrase",
                "s3cret",
            ],
        )
        assert result.exit_code == 0, result.output

        # At least one runner construction for the bootstrap host
        # received our passphrase. Earlier provisioning sessions used
        # a different (None) passphrase, so we filter on the host name.
        bootstrap_records = [
            r for r in FakeSSHRunner.KEYS_USED if r[0] == "hub-pw.example.com"
        ]
        assert any(
            passphrase == "s3cret" for _h, _k, passphrase in bootstrap_records
        ), (
            f"CLI did not forward --passphrase to the bootstrap session; "
            f"records={bootstrap_records!r}"
        )
