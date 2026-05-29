"""Phase 2c CP5 — client refuses a host cert signed by an untrusted CA.

Pins the third of the Phase 2c "Tests" criteria:

    Host-cert mismatch (re-signed by an attacker CA) is rejected
    by the client.

The threat model: an attacker swaps the sshd host cert for one
signed by a CA they control (or by the legitimate but stale
operator CA). Without :class:`wg_manager.ssh.KnownHostsCAPolicy`
enforcing that the host cert chains back to the Vault CA the
runner is configured for, paramiko would happily accept whatever
host key the connection presents (the legacy TOFU mode CP4.4
retired). This test pins the enforcement: install an attacker-
signed host cert, point the runner at the real Vault CA, watch
the handshake refuse before auth even starts.
"""

from __future__ import annotations

import pytest

from wg_manager.ssh import SSHConnectionError, SSHRunner
from wg_manager.ssh_ca import LocalDevSSHCA, VaultSSHCA

from tests.e2e.conftest import E2EEnv


def test_client_rejects_host_cert_from_attacker_ca(
    sshd_container: E2EEnv,
    vault_ssh_ca: VaultSSHCA,
) -> None:
    """sshd serves a cert signed by an unrelated CA; the client refuses.

    Generates an ephemeral :class:`LocalDevSSHCA` to stand in for
    the "attacker" (any CA the runner doesn't trust would do; an
    in-memory ed25519 one is cheapest). The runner stays configured
    to trust only the real Vault CA, so
    :class:`KnownHostsCAPolicy` raises
    :class:`UntrustedHostKeyError`, which the runner wraps in
    :class:`SSHConnectionError`.

    The user cert is still Vault-signed — without that the failure
    mode would be ambiguous (which side rejected first?).
    """
    attacker_ca = LocalDevSSHCA.generate()
    attacker_host_cert = attacker_ca.mint_host_cert(
        public_key_openssh=sshd_container.host_pubkey_openssh,
        principals=[sshd_container.hostname_principal],
        ttl_seconds=300,
    )
    sshd_container.write_host_cert(attacker_host_cert.cert_pem)

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
        # Trust only the real Vault CA — the attacker cert chains
        # to something else, so :class:`KnownHostsCAPolicy` rejects.
        ca_public_key=vault_ssh_ca.ca_public_key,
    )

    with pytest.raises(SSHConnectionError) as excinfo:
        with runner:
            pass

    # The wrapper from src/wg_manager/ssh.py wraps host-key
    # rejection in SSHConnectionError; the underlying cause is
    # ``UntrustedHostKeyError``. Either word being present is
    # enough — what we want to pin is "refused before auth," not
    # the exact message wording.
    msg = str(excinfo.value).lower()
    assert any(
        token in msg
        for token in ("host", "untrusted", "ca", "policy", "unknown server")
    ), f"expected host-key refusal, got: {excinfo.value!r}"
