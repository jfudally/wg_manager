"""End-to-end happy-path proof for the Phase 2c cert-based SSH stack.

Closes the Phase 2c "Acceptance" criterion:

    Provisioning a fresh server end-to-end on a throwaway VM
    completes using only Vault-signed certs.

…in the dockerised-sshd shape CP5 commits to. WireGuard itself is
out of scope (Docker Desktop on macOS doesn't expose the kernel
modules ``wg-quick up`` needs; Phase 1 already validated that
path). What this proves:

1. The CA mints an ephemeral keypair + short-lived user cert.
2. :class:`paramiko`'s SSH handshake against a real sshd succeeds
   when both the user cert and the host cert chain back to the
   same Vault CA.
3. ``runner.run`` and ``runner.sudo`` round-trip as expected so
   the production task layer's call sites (which use the same
   surface) work against a real OpenSSH server.
"""

from __future__ import annotations

from wg_manager.ssh import SSHRunner
from wg_manager.ssh_ca import VaultSSHCA

from tests.e2e.conftest import E2EEnv


def test_runner_connects_with_vault_signed_certs(
    sshd_container: E2EEnv,
    vault_ssh_ca: VaultSSHCA,
    installed_host_cert: None,
) -> None:
    """Mint a user cert, open a real SSH session, run a command.

    This is the smallest assertion that the entire cert-based stack
    works end-to-end:

    * sshd's ``TrustedUserCAKeys`` is the Vault CA's pubkey
      (installed by the ``sshd_container`` fixture).
    * sshd's ``HostCertificate`` is signed by that same CA (the
      ``installed_host_cert`` fixture).
    * The runner mints a fresh user cert against the same CA, with
      ``wguser`` as the principal sshd will accept.
    * :class:`KnownHostsCAPolicy` validates the host cert before
      paramiko hands the session over to the client.
    * ``runner.run("echo …")`` round-trips.
    """
    user_cert = vault_ssh_ca.mint_user_cert(
        principals=[sshd_container.username],
        ttl_seconds=300,
    )

    runner = SSHRunner(
        host=sshd_container.host,
        port=sshd_container.port,
        username=sshd_container.username,
        pkey_pem=user_cert.private_pem,
        cert_pem=user_cert.cert_pem,
        ca_public_key=vault_ssh_ca.ca_public_key,
    )

    with runner as session:
        result = session.run("echo wg-manager-e2e-ok")
        assert result.rc == 0
        assert result.stdout.strip() == "wg-manager-e2e-ok"


def test_sudo_passthrough(
    sshd_container: E2EEnv,
    vault_ssh_ca: VaultSSHCA,
    installed_host_cert: None,
) -> None:
    """``runner.sudo`` runs the command as root inside the container.

    The production provisioning path calls ``runner.sudo("apt-get
    install -y wireguard-tools")`` and similar — proving the sudo
    surface works against a real sshd (with ``wguser`` set up for
    passwordless sudo by the ``tests/e2e/Dockerfile``) is the
    cheapest way to pin that the e2e setup is faithful to the
    production execution model.
    """
    user_cert = vault_ssh_ca.mint_user_cert(
        principals=[sshd_container.username],
        ttl_seconds=300,
    )

    runner = SSHRunner(
        host=sshd_container.host,
        port=sshd_container.port,
        username=sshd_container.username,
        pkey_pem=user_cert.private_pem,
        cert_pem=user_cert.cert_pem,
        ca_public_key=vault_ssh_ca.ca_public_key,
    )

    with runner as session:
        result = session.sudo("id -u")
        assert result.rc == 0
        # uid 0 = root: sudo elevated us as expected.
        assert result.stdout.strip() == "0"
