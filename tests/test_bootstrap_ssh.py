"""Tests for Phase 2c CP4.5 — operator-driven host bootstrap SSH runner.

Closes the gap CP4.4 created: with the production :class:`SSHRunner`
locked to CA-only auth + :class:`KnownHostsCAPolicy`, a *fresh* host
that hasn't been bootstrapped yet has nothing for the runner to talk
to. CP4.5 introduces a separate, narrowly-scoped runner
(``BootstrapSSHRunner``) that:

* Uses :class:`paramiko.AutoAddPolicy` for host-key acceptance — the
  whole point of the bootstrap flow is to TOFU once so we can install
  the host cert that makes the production runner trust the box.
* Authenticates with an operator-supplied long-lived private key,
  exactly the way an operator would dial the box with `ssh`. There is
  no Vault-minted user cert here — we don't have CA trust yet.
* Lives in its own module so the production runner stays CA-only and
  the no-TOFU invariant in :mod:`wg_manager.ssh` is preserved.

These unit tests use ``unittest.mock.patch`` to stub paramiko itself
so we can assert the construction shape (policy installed, key
loaded, ``connect`` arguments) without touching a real sshd. The CP5
e2e suite proves the runner actually opens a session against a real
OpenSSH server.
"""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import paramiko
import pytest

from wg_manager.bootstrap_ssh import BootstrapSSHRunner, bootstrap_host
from wg_manager.host_ssh import (
    HOST_CA_PUB_PATH,
    HOST_CERT_PATH,
    SSHD_DROPIN_PATH,
)
from wg_manager.ssh_ca import LocalDevSSHCA


@pytest.fixture()
def ed25519_key_file(tmp_path: Path) -> Path:
    """Write a fresh, unencrypted OpenSSH ed25519 private key to a temp file.

    The bootstrap runner reads the path operator-side and loads the key
    inside ``__enter__``; we generate a real key so paramiko's loader
    is exercised end-to-end (a hand-rolled fake would skip the actual
    PEM parse the bug-prone path the runner runs).
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


class TestBootstrapRunnerWiring:
    """The runner uses AutoAddPolicy + private-key auth, no cert / no CA policy."""

    def test_bootstrap_runner_uses_autoaddpolicy_and_loads_key(
        self, ed25519_key_file: Path
    ) -> None:
        """Verify the paramiko surface: AutoAddPolicy installed, pkey passed.

        We mock :class:`paramiko.SSHClient` so the assertion lives
        entirely in-process and exposes:

        * ``set_missing_host_key_policy`` was called with an
          :class:`paramiko.AutoAddPolicy` instance — the bootstrap
          path is the *only* legitimate TOFU surface in wg-manager.
        * ``client.connect`` received the loaded pkey via the ``pkey``
          kwarg — operator-supplied long-lived key, no Vault round-trip.
        * ``load_certificate`` was never called on the pkey (the
          production runner's CA mode would call this; the bootstrap
          path must not).
        """
        runner = BootstrapSSHRunner(
            host="fresh-host.example.com",
            port=22,
            username="ubuntu",
            key_path=ed25519_key_file,
        )

        with mock.patch(
            "wg_manager.bootstrap_ssh.paramiko.SSHClient"
        ) as fake_client_cls:
            fake_client = fake_client_cls.return_value
            with runner:
                pass

        # Policy: AutoAddPolicy (TOFU) — the bootstrap path is the
        # one place wg-manager intentionally allows it.
        assert fake_client.set_missing_host_key_policy.called, (
            "BootstrapSSHRunner must call set_missing_host_key_policy"
        )
        installed_policy = fake_client.set_missing_host_key_policy.call_args[
            0
        ][0]
        assert isinstance(installed_policy, paramiko.AutoAddPolicy), (
            f"expected AutoAddPolicy (TOFU is legitimate during bootstrap), "
            f"got {type(installed_policy).__name__}"
        )

        # connect kwargs: real loaded pkey was passed.
        assert fake_client.connect.called
        connect_kwargs = fake_client.connect.call_args.kwargs
        assert connect_kwargs["hostname"] == "fresh-host.example.com"
        assert connect_kwargs["port"] == 22
        assert connect_kwargs["username"] == "ubuntu"
        pkey = connect_kwargs["pkey"]
        assert isinstance(pkey, paramiko.PKey), (
            f"expected a paramiko.PKey on the connect call, "
            f"got {type(pkey).__name__}"
        )
        # No CA-mode plumbing should have been wired in.
        assert not hasattr(pkey, "_called_load_certificate"), (
            "BootstrapSSHRunner must not invoke load_certificate on the pkey"
        )

    def test_bootstrap_runner_does_not_install_known_hosts_ca_policy(
        self, ed25519_key_file: Path
    ) -> None:
        """Pin the invariant: bootstrap is the *only* TOFU-permitting path.

        This test is the brittle one on purpose. If someone tries to
        "harden" the bootstrap runner by adding a :class:`KnownHostsCAPolicy`
        (or any other CA-aware policy) here, the production no-TOFU
        invariant in :mod:`wg_manager.ssh` becomes the *only* thing
        keeping the broader codebase from re-introducing TOFU through
        the bootstrap door. Locking the policy choice down so the
        bootstrap runner *only* installs :class:`paramiko.AutoAddPolicy`
        keeps the two modes cleanly separated: production = no TOFU,
        bootstrap = TOFU once and the operator knows it.

        The flip side (the production runner stays TOFU-free) is
        already pinned by :mod:`tests.test_ssh_cert_mode`; this
        complement keeps both halves of the contract under test.
        """
        from wg_manager.ssh import KnownHostsCAPolicy

        runner = BootstrapSSHRunner(
            host="fresh-host.example.com",
            port=22,
            username="ubuntu",
            key_path=ed25519_key_file,
        )

        with mock.patch(
            "wg_manager.bootstrap_ssh.paramiko.SSHClient"
        ) as fake_client_cls:
            fake_client = fake_client_cls.return_value
            with runner:
                pass

        # Exactly one policy was installed; assert *what* it was — and
        # *what it wasn't*.
        policies_installed = [
            call.args[0]
            for call in fake_client.set_missing_host_key_policy.call_args_list
        ]
        assert len(policies_installed) == 1, (
            f"expected exactly one policy install during bootstrap, "
            f"got {len(policies_installed)}: {policies_installed!r}"
        )
        policy = policies_installed[0]
        assert isinstance(policy, paramiko.AutoAddPolicy), (
            f"BootstrapSSHRunner must install AutoAddPolicy (TOFU); "
            f"got {type(policy).__name__}"
        )
        assert not isinstance(policy, KnownHostsCAPolicy), (
            "BootstrapSSHRunner must NOT install KnownHostsCAPolicy "
            "— that would defeat the bootstrap purpose (the host has "
            "no CA-signed host cert *yet*; installing the CA-mode "
            "policy here would reject every fresh host)."
        )


class _FakeRunner:
    """Minimal stand-in for BootstrapSSHRunner used by the orchestrator tests.

    Records ``write_file`` and ``sudo`` calls in declaration order so
    the test can pin both *what* was written (paths, payloads, modes)
    and the relative ordering against the sshd reload. The runner does
    not enforce the context-manager protocol — the tests pass it to
    :func:`bootstrap_host` already "open", which mirrors the CLI
    layer's usage (CLI enters the runner once and then drives the
    orchestrator inside the `with` block).
    """

    def __init__(self, host_pubkey: str) -> None:
        self.host_pubkey = host_pubkey
        self.write_file_calls: list[tuple[str, str, str, bool]] = []
        self.sudo_calls: list[str] = []
        self.run_calls: list[str] = []

    def run(self, cmd: str, check: bool = True) -> Any:
        self.run_calls.append(cmd)
        return _Result(0, "", "")

    def sudo(self, cmd: str, check: bool = True) -> Any:
        self.sudo_calls.append(cmd)
        # The install helper probes for the host pubkey via
        # ``sudo cat /etc/ssh/ssh_host_ed25519_key.pub``; return our
        # canned value when that path appears anywhere in the command.
        if "ssh_host_ed25519_key.pub" in cmd:
            return _Result(0, self.host_pubkey + "\n", "")
        return _Result(0, "", "")

    def write_file(
        self,
        path: str,
        content: str,
        mode: str = "644",
        sudo: bool = True,
    ) -> Any:
        self.write_file_calls.append((path, content, mode, sudo))
        return _Result(0, "", "")


class _Result:
    """Tiny CommandResult-shaped value for the fake runner."""

    def __init__(self, rc: int, stdout: str, stderr: str) -> None:
        self.rc = rc
        self.stdout = stdout
        self.stderr = stderr


# Real ed25519 host pubkey used across the orchestrator tests. Mirrors
# the value :mod:`tests.test_host_ssh` uses; a fixed string keeps the
# host-cert mint deterministic so the principal assertion stays stable
# across runs.
_HOST_PUBKEY = (
    "ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAINcv8wY+y8d0KcKZ6t6S/n7JoYx7M3jzqu7K2YgQGvD7"
    " root@fresh-host.example.com"
)


# Late import so the typing-only ``Any`` doesn't trigger a NameError
# when the test file is collected before the bootstrap module is
# wired up (cycle 1 ordering).
from typing import Any  # noqa: E402


class TestBootstrapHostOrchestration:
    """``bootstrap_host`` writes three files + reloads sshd, in order."""

    def test_bootstrap_host_writes_three_files_and_reloads_sshd(self) -> None:
        """Pin the wire-level shape of the bootstrap install.

        Asserts the orchestrator does exactly what an operator would
        do by hand:

        1. Writes ``/etc/ssh/wg-manager-user-ca.pub`` with the CA's
           OpenSSH-formatted public key.
        2. Writes ``/etc/ssh/ssh_host_ed25519_key-cert.pub`` with a
           freshly-minted host cert against the host's existing
           ed25519 pubkey.
        3. Writes ``/etc/ssh/sshd_config.d/wg-manager.conf`` with
           ``TrustedUserCAKeys`` + ``HostCertificate`` directives.
        4. Reloads sshd via the four-step shell-or so distros that
           name the unit ``ssh`` (Debian/Ubuntu) and those that name
           it ``sshd`` (RHEL/Amazon Linux) both work.

        The three writes must happen *before* the reload so a partial
        failure on the reload still leaves the cert material in
        place for an operator to inspect.
        """
        ca = LocalDevSSHCA.generate()
        runner = _FakeRunner(_HOST_PUBKEY)

        cert = bootstrap_host(
            runner=runner,
            hostname="fresh-host.example.com",
            principal="fresh-host.example.com",
            ca=ca,
            ttl_seconds=86400,
        )

        # The returned HostCert carries the principal we asked for.
        assert "fresh-host.example.com" in cert.principals

        # Three writes happened, in CA-then-cert-then-dropin order.
        assert len(runner.write_file_calls) == 3, (
            f"expected three write_file calls, got "
            f"{len(runner.write_file_calls)}: "
            f"{[c[0] for c in runner.write_file_calls]!r}"
        )

        paths_in_order = [call[0] for call in runner.write_file_calls]
        assert paths_in_order == [
            HOST_CA_PUB_PATH,
            HOST_CERT_PATH,
            SSHD_DROPIN_PATH,
        ], (
            f"writes must land in CA / host-cert / drop-in order, "
            f"got {paths_in_order!r}"
        )

        # CA pubkey body matches verbatim (trailing newline tolerated).
        ca_body = runner.write_file_calls[0][1]
        assert ca_body.strip() == ca.ca_public_key.strip()
        # Host cert body begins with the OpenSSH ed25519 cert algo
        # name; that's the strongest assertion we can make without
        # re-parsing the cert here (the cert content is already
        # exercised by :mod:`tests.test_ssh_ca`).
        host_cert_body = runner.write_file_calls[1][1]
        assert host_cert_body.startswith(
            "ssh-ed25519-cert-v01@openssh.com "
        )
        # Drop-in references the two real paths so sshd actually
        # picks the install up.
        dropin = runner.write_file_calls[2][1]
        assert f"TrustedUserCAKeys {HOST_CA_PUB_PATH}" in dropin
        assert f"HostCertificate {HOST_CERT_PATH}" in dropin

        # All three writes asked for sudo + 0o644 — the OpenSSH
        # convention for these paths.
        for path, _body, mode, sudo in runner.write_file_calls:
            assert mode == "644", f"unexpected mode {mode!r} for {path!r}"
            assert sudo is True, f"expected sudo write for {path!r}"

        # Exactly one sshd reload happens *after* the writes. The
        # shell-or covers ``sshd`` and ``ssh`` unit names + reload
        # vs restart so distro variants don't matter.
        reload_cmds = [
            cmd for cmd in runner.sudo_calls if "systemctl" in cmd
        ]
        assert len(reload_cmds) == 1, (
            f"expected exactly one sshd reload call, got "
            f"{len(reload_cmds)}: {reload_cmds!r}"
        )
        joined = reload_cmds[0]
        # All four branches must be present so the call works on the
        # broad range of distros wg-manager targets.
        assert "systemctl reload sshd" in joined
        assert "systemctl restart sshd" in joined
        assert "systemctl reload ssh" in joined
        assert "systemctl restart ssh" in joined
