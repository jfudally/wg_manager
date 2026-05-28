"""Tests for Phase 2c CP3: host-side SSH CA install.

CP3's host-side deliverable is a single helper that, given an open
:class:`~wg_manager.ssh.SSHRunner`, a :class:`~wg_manager.models.Server`
row, and an :class:`~wg_manager.ssh_ca.SSHCABackend`, leaves the target
host in this state:

1. ``/etc/ssh/wg-manager-user-ca.pub`` holds the CA public key wg-manager
   advertises (used by sshd's ``TrustedUserCAKeys`` directive to accept
   user certs minted by that CA).
2. ``/etc/ssh/ssh_host_ed25519_key-cert.pub`` holds the freshly-minted
   host cert for this server's existing host pubkey.
3. ``/etc/ssh/sshd_config.d/wg-manager.conf`` references both files via
   ``TrustedUserCAKeys`` and ``HostCertificate``.
4. ``sshd`` has been reloaded so the new config is in effect.

The helper returns the :class:`~wg_manager.ssh_ca.HostCert` it minted
so the task layer can persist serial / principals / TTL on the
``server`` row (the CP3.1 columns). The function is idempotent — it
always overwrites the same paths, so re-running it (rotation flow,
re-provision after a CA rotation) replaces the previous cert in place
without any cleanup step.

These tests use :class:`tests.conftest.FakeSSHRunner` so we observe
exactly what would have been pushed over the wire, without needing a
real sshd. CP5 will add an end-to-end test against a dockerised sshd.
"""

from __future__ import annotations

import pytest

from tests.conftest import FakeSSHRunner
from wg_manager.host_ssh import (
    HOST_CA_PUB_PATH,
    HOST_CERT_PATH,
    SSHD_DROPIN_PATH,
    install_host_cert,
)
from wg_manager.models import Server
from wg_manager.ssh_ca import HostCert, LocalDevSSHCA


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def fake_runner_clean() -> FakeSSHRunner:
    """Return a fresh FakeSSHRunner with its class-level state reset.

    The unit tests in this module don't go through the HTTP / Celery
    fixtures, so we have to clear the class-level state ourselves —
    otherwise prior-test commands leak into our assertions.
    """
    FakeSSHRunner.COMMANDS = []
    FakeSSHRunner.PUBKEYS = {}
    FakeSSHRunner.OUTPUTS = {}
    FakeSSHRunner.RAISE_ON_ENTER = {}
    FakeSSHRunner.KEYS_USED = []
    FakeSSHRunner.CERTS_USED = []
    FakeSSHRunner.SUPPRESS_HOST_PUBKEY = set()
    runner = FakeSSHRunner(
        host="hub.example.com",
        port=22,
        username="ubuntu",
        pkey_pem="(unused-by-fake)",
    )
    return runner


@pytest.fixture()
def host_pubkey() -> str:
    """An ed25519 host public key in OpenSSH single-line form.

    A real value (generated once) rather than a fixture-time mint, so
    the test fails loudly if our cert-minting helper subtly munges the
    input shape.
    """
    return (
        "ssh-ed25519 "
        "AAAAC3NzaC1lZDI1NTE5AAAAINcv8wY+y8d0KcKZ6t6S/n7JoYx7M3jzqu7K2YgQGvD7"
        " root@hub.example.com"
    )


def _register_host_pubkey(runner: FakeSSHRunner, pubkey: str) -> None:
    """Wire FakeSSHRunner so ``cat /etc/ssh/ssh_host_ed25519_key.pub`` returns ``pubkey``.

    The probe command the production helper runs is matched via the
    ``OUTPUTS`` substring map (which is how the existing ``wg show wg0
    dump`` discovery test stubs its remote command output).
    """
    FakeSSHRunner.OUTPUTS[
        (runner.host, "ssh_host_ed25519_key.pub")
    ] = pubkey + "\n"


def _server_row(hostname: str = "hub.example.com") -> Server:
    """Build a Server with no host-cert columns set yet."""
    return Server(
        hostname=hostname,
        ssh_username="ubuntu",
        ssh_key_id=1,
        endpoint_host=hostname,
    )


# ---------------------------------------------------------------------------
# install_host_cert — happy path
# ---------------------------------------------------------------------------


class TestInstallHostCertHappyPath:
    """A fresh install lays down the three files + reloads sshd."""

    def test_returns_a_HostCert_for_the_host_pubkey(
        self, fake_runner_clean: FakeSSHRunner, host_pubkey: str
    ) -> None:
        _register_host_pubkey(fake_runner_clean, host_pubkey)
        ca = LocalDevSSHCA.generate()
        server = _server_row()

        cert = install_host_cert(
            runner=fake_runner_clean,
            server=server,
            ca=ca,
            ttl_seconds=86400,
        )

        assert isinstance(cert, HostCert)
        # The cert's principals must include the server's hostname so
        # an SSH client doing strict host-cert verification accepts it.
        assert server.hostname in cert.principals
        # The CP3.1 columns are populated by the *caller* (the task
        # layer) — install_host_cert just returns the cert. We verify
        # the row is left untouched so the helper stays single-purpose.
        assert server.host_cert_pem is None
        assert server.host_cert_serial is None

    def test_writes_ca_pubkey_cert_and_dropin_then_reloads_sshd(
        self, fake_runner_clean: FakeSSHRunner, host_pubkey: str
    ) -> None:
        _register_host_pubkey(fake_runner_clean, host_pubkey)
        ca = LocalDevSSHCA.generate()
        server = _server_row()

        install_host_cert(
            runner=fake_runner_clean,
            server=server,
            ca=ca,
            ttl_seconds=86400,
        )

        commands = [cmd for _host, cmd in FakeSSHRunner.COMMANDS]
        joined = "\n".join(commands)

        # CA pubkey lands at the documented path.
        assert any(HOST_CA_PUB_PATH in c for c in commands), (
            f"expected a write to {HOST_CA_PUB_PATH}, got: {commands!r}"
        )
        # Host cert lands at the OpenSSH-conventional path so sshd's
        # default ``HostCertificate`` resolution rules work even if a
        # third party edits the drop-in.
        assert any(HOST_CERT_PATH in c for c in commands), (
            f"expected a write to {HOST_CERT_PATH}, got: {commands!r}"
        )
        # The sshd drop-in is what actually opts the host into cert
        # auth — both directives must end up in it.
        assert any(SSHD_DROPIN_PATH in c for c in commands), (
            f"expected a write to {SSHD_DROPIN_PATH}, got: {commands!r}"
        )
        # sshd must be reloaded for the new directives to take effect.
        assert "systemctl reload" in joined or "systemctl restart" in joined

    def test_dropin_contents_reference_the_two_other_files(
        self,
        fake_runner_clean: FakeSSHRunner,
        host_pubkey: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Spy on ``runner.write_file`` to inspect the drop-in body verbatim.

        The default FakeSSHRunner.write_file discards its content
        argument; we replace it for this test with a recording shim so
        we can assert on the exact bytes the drop-in receives.
        """
        captured: dict[str, str] = {}

        def fake_write(
            path: str, content: str, mode: str = "644", sudo: bool = True
        ) -> object:
            captured[path] = content
            return None

        monkeypatch.setattr(fake_runner_clean, "write_file", fake_write)
        _register_host_pubkey(fake_runner_clean, host_pubkey)
        ca = LocalDevSSHCA.generate()
        server = _server_row()

        install_host_cert(
            runner=fake_runner_clean,
            server=server,
            ca=ca,
            ttl_seconds=86400,
        )

        dropin = captured.get(SSHD_DROPIN_PATH)
        assert dropin is not None, (
            f"helper never wrote the drop-in at {SSHD_DROPIN_PATH}; "
            f"only saw writes to: {list(captured)!r}"
        )
        assert f"TrustedUserCAKeys {HOST_CA_PUB_PATH}" in dropin
        assert f"HostCertificate {HOST_CERT_PATH}" in dropin

        # And the CA pubkey file must contain exactly the CA's pubkey.
        ca_pub_body = captured.get(HOST_CA_PUB_PATH)
        assert ca_pub_body is not None
        assert ca_pub_body.strip() == ca.ca_public_key.strip()

        # The host-cert file must contain the cert body from the CA mint.
        host_cert_body = captured.get(HOST_CERT_PATH)
        assert host_cert_body is not None
        assert host_cert_body.startswith(
            "ssh-ed25519-cert-v01@openssh.com "
        )


# ---------------------------------------------------------------------------
# Edge cases — broken host pubkey, narrow TTL
# ---------------------------------------------------------------------------


class TestInstallHostCertEdgeCases:
    """The helper fails loudly when prerequisites are missing."""

    def test_raises_when_host_has_no_ed25519_host_key(
        self, fake_runner_clean: FakeSSHRunner
    ) -> None:
        """No registered output for the ``cat`` probe ⇒ FakeSSHRunner returns ``""``.

        Production callers see this when the host hasn't generated an
        ed25519 host key yet (very rare on modern distros, but possible
        in lab images). The helper should refuse rather than try to
        sign an empty string and pass garbage to Vault.
        """
        ca = LocalDevSSHCA.generate()
        server = _server_row()

        # CP4.4 added a default "always-return-a-canned-pubkey"
        # fallback to FakeSSHRunner.run; opt this host out so the
        # probe returns "" and exercises the empty-file failure path.
        FakeSSHRunner.SUPPRESS_HOST_PUBKEY.add(fake_runner_clean.host)
        with pytest.raises(RuntimeError) as exc_info:
            install_host_cert(
                runner=fake_runner_clean,
                server=server,
                ca=ca,
                ttl_seconds=86400,
            )
        assert "host public key" in str(exc_info.value).lower()
