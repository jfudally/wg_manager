"""Tests for the Phase 2c CP4.5 ``wg-manager bootstrap-host`` CLI.

The CLI is the operator-facing seam between a fresh-box-with-only-
plain-ssh-key and a wg-manager-managed box. It does **one thing**:

1. Build a :class:`BootstrapSSHRunner` with the operator's
   ``--ssh-key`` (and optionally ``--ssh-key-passphrase``).
2. Resolve the SSH CA backend through the regular Settings →
   ``make_ssh_ca_backend`` factory.
3. Open the runner and call :func:`bootstrap_host` against the box.
4. Print a one-line ``[OK]`` summary on success or a clear error on
   failure (Vault unreachable, SSH refused, sudo missing).

No HTTP. No database writes. The operator follows up with
``wg-manager servers register`` or ``clients register`` to actually
catalogue the box in the state store.

These tests cover the CLI shape (required args, defaults, exit
codes, summary line) by mocking :func:`bootstrap_host` and
:func:`make_ssh_ca_backend` so the assertions are about the CLI
wiring, not the install path (which is already pinned by
:mod:`tests.test_bootstrap_ssh`).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from typer.testing import CliRunner

from wg_manager import cli
from wg_manager.ssh_ca import HostCert, SSHCAError


@pytest.fixture()
def runner() -> CliRunner:
    """Typer's in-process click runner."""
    return CliRunner()


@pytest.fixture()
def ed25519_key_file(tmp_path: Path) -> Path:
    """A real unencrypted OpenSSH ed25519 private key on disk.

    Reused from :mod:`tests.test_bootstrap_ssh` shape — the CLI's
    ``--ssh-key`` flag points at a real file; we mock the actual SSH
    session but the path-existence check (and the file-read inside
    :class:`BootstrapSSHRunner.__enter__`) still runs in the
    cycle 6 e2e test, so producing a real key here keeps the unit
    test forward-compatible.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path = tmp_path / "id_ed25519"
    path.write_bytes(pem)
    return path


def _fake_host_cert(serial: int = 12345) -> HostCert:
    """Return a HostCert value object the CLI can format into its summary."""
    return HostCert(
        cert_pem="ssh-ed25519-cert-v01@openssh.com AAAA…",
        valid_after=datetime(2026, 6, 1, tzinfo=timezone.utc),
        valid_before=datetime(2026, 6, 2, tzinfo=timezone.utc),
        serial=serial,
        principals=("fresh-host.example.com",),
    )


def _invoke(runner: CliRunner, *args: str) -> Any:
    """Invoke the CLI with the given args list."""
    return runner.invoke(cli.app, list(args))


class TestRequiredArgs:
    """``--hostname`` and ``--ssh-key`` are both required."""

    def test_cli_requires_hostname_and_key(
        self, runner: CliRunner, ed25519_key_file: Path
    ) -> None:
        """Missing either flag → Typer's "missing option" exit 2 path.

        Click/Typer raise ``SystemExit(2)`` (the conventional "usage
        error" code) when a required option is absent, so we assert
        on that rather than on the textual error body — the message
        format varies across click versions.
        """
        # Missing --hostname.
        result = _invoke(
            runner, "bootstrap-host", "--ssh-key", str(ed25519_key_file)
        )
        assert result.exit_code == 2, result.output

        # Missing --ssh-key.
        result = _invoke(
            runner, "bootstrap-host", "--hostname", "fresh-host.example.com"
        )
        assert result.exit_code == 2, result.output


class TestPrincipalDefault:
    """``--principal`` defaults to ``--hostname`` when not supplied."""

    def test_cli_defaults_principal_to_hostname(
        self,
        runner: CliRunner,
        ed25519_key_file: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """No ``--principal`` ⇒ the bootstrap call uses ``hostname``.

        Mocks both the CA factory and the orchestrator so we only
        assert what the CLI hands down — keeps the test about
        wiring rather than the install path.
        """
        captured_kwargs: dict[str, Any] = {}

        def _fake_bootstrap(**kwargs: Any) -> HostCert:
            captured_kwargs.update(kwargs)
            return _fake_host_cert()

        # The CLI imports bootstrap_host into the cli module's
        # namespace; patch the attribute as resolved there so the
        # mock takes effect.
        monkeypatch.setattr(cli, "bootstrap_host", _fake_bootstrap)
        monkeypatch.setattr(
            cli,
            "make_ssh_ca_backend",
            lambda *_args, **_kw: mock.MagicMock(name="SSHCABackend"),
        )
        # The runner context-manager is mocked so no TCP happens.
        monkeypatch.setattr(
            cli,
            "BootstrapSSHRunner",
            lambda **_kw: _NoopRunner(),
        )

        result = _invoke(
            runner,
            "bootstrap-host",
            "--hostname",
            "fresh-host.example.com",
            "--ssh-key",
            str(ed25519_key_file),
        )
        assert result.exit_code == 0, result.output
        assert captured_kwargs["principal"] == "fresh-host.example.com"
        assert captured_kwargs["hostname"] == "fresh-host.example.com"

    def test_cli_explicit_principal_overrides_hostname(
        self,
        runner: CliRunner,
        ed25519_key_file: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``--principal foo`` is honoured even when ``--hostname`` differs.

        The hostname / principal split exists for fleets where the
        SSH dial-name and the cert principal don't match (e.g.
        public IP vs internal DNS); the CLI must pass both through
        untouched.
        """
        captured_kwargs: dict[str, Any] = {}

        def _fake_bootstrap(**kwargs: Any) -> HostCert:
            captured_kwargs.update(kwargs)
            return _fake_host_cert()

        monkeypatch.setattr(cli, "bootstrap_host", _fake_bootstrap)
        monkeypatch.setattr(
            cli,
            "make_ssh_ca_backend",
            lambda *_args, **_kw: mock.MagicMock(name="SSHCABackend"),
        )
        monkeypatch.setattr(
            cli,
            "BootstrapSSHRunner",
            lambda **_kw: _NoopRunner(),
        )

        result = _invoke(
            runner,
            "bootstrap-host",
            "--hostname",
            "203.0.113.5",
            "--principal",
            "vpn-hub-1.internal",
            "--ssh-key",
            str(ed25519_key_file),
        )
        assert result.exit_code == 0, result.output
        assert captured_kwargs["hostname"] == "203.0.113.5"
        assert captured_kwargs["principal"] == "vpn-hub-1.internal"


class TestSuccessSummary:
    """A successful bootstrap exits 0 with a one-line OK summary."""

    def test_cli_exit_zero_on_success_with_summary_line(
        self,
        runner: CliRunner,
        ed25519_key_file: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The summary names the host + cert serial + validity window.

        The summary line is the visible contract — operator scripts
        grep it to know the install landed, and the cert serial is
        the join key against the future ``servers register`` row.
        Format: ``[OK] bootstrapped <host>: cert serial=<n> valid_until=<ts>``.
        """
        cert = _fake_host_cert(serial=99999)
        monkeypatch.setattr(
            cli,
            "bootstrap_host",
            lambda **_kw: cert,
        )
        monkeypatch.setattr(
            cli,
            "make_ssh_ca_backend",
            lambda *_args, **_kw: mock.MagicMock(name="SSHCABackend"),
        )
        monkeypatch.setattr(
            cli,
            "BootstrapSSHRunner",
            lambda **_kw: _NoopRunner(),
        )

        result = _invoke(
            runner,
            "bootstrap-host",
            "--hostname",
            "fresh-host.example.com",
            "--ssh-key",
            str(ed25519_key_file),
        )
        assert result.exit_code == 0, result.output
        # Pin the prefix + each piece of the summary so a future
        # cosmetic edit doesn't accidentally drop one.
        assert "[OK] bootstrapped fresh-host.example.com" in result.output
        assert "serial=99999" in result.output
        assert "valid_until=" in result.output


class TestVaultUnreachable:
    """A Vault-side failure exits 1 with a clear error on stderr."""

    def test_cli_exit_one_on_vault_unreachable(
        self,
        runner: CliRunner,
        ed25519_key_file: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The CA factory raising ``SSHCAError`` → exit 1 + stderr message.

        Operators see this when they've forgotten ``make
        ssh-ca-bootstrap``; the error must surface the Vault-side
        reason rather than a 30-frame paramiko traceback (the
        Vault round-trip happens *before* the runner opens).
        """

        def _boom(*_args: Any, **_kw: Any) -> Any:
            raise SSHCAError("vault: connection refused")

        monkeypatch.setattr(cli, "make_ssh_ca_backend", _boom)
        # bootstrap_host / the runner must never be reached if the
        # CA factory fails. We replace them with raise-on-call so a
        # regression that swallows the SSHCAError surfaces here.
        monkeypatch.setattr(
            cli,
            "bootstrap_host",
            lambda **_kw: pytest.fail(
                "bootstrap_host must not be called when CA factory fails"
            ),
        )
        monkeypatch.setattr(
            cli,
            "BootstrapSSHRunner",
            lambda **_kw: pytest.fail(
                "BootstrapSSHRunner must not be constructed when "
                "CA factory fails"
            ),
        )

        # CliRunner captures stderr into result.output unless
        # mix_stderr=False; we want to assert on either stream so we
        # check the combined output (default behaviour).
        result = _invoke(
            runner,
            "bootstrap-host",
            "--hostname",
            "fresh-host.example.com",
            "--ssh-key",
            str(ed25519_key_file),
        )
        assert result.exit_code == 1, result.output
        assert "vault" in result.output.lower()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _NoopRunner:
    """In-process stand-in for BootstrapSSHRunner — context-manager only.

    The CLI enters the runner inside a ``with`` block before handing
    it to :func:`bootstrap_host`; the fake here implements the
    context-manager protocol and returns ``self`` so a downstream
    ``with runner as session: …`` pattern (the CLI's call shape)
    works without TCP / SSH.
    """

    def __enter__(self) -> Any:
        return self

    def __exit__(
        self,
        exc_type: Any,
        exc: Any,
        tb: Any,
    ) -> None:
        return None
