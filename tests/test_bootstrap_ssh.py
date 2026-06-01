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

from wg_manager.bootstrap_ssh import BootstrapSSHRunner


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
