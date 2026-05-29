"""Phase 2c CP5 — sshd refuses a Vault-signed user cert past its TTL.

Pins the first of the three Phase 2c "Tests" criteria:

    Cert TTL is honoured (sleep-past-expiry test against
    ``vault server -dev`` with a 5-second TTL).

The 5-second TTL comes from the auxiliary ``wg-manager-e2e-user-
short`` role that the session-scoped Vault bootstrap configures
(see :func:`tests.e2e.conftest.vault_ssh_ca_short_ttl`). A connect
*right after* minting still succeeds — that's the cheap check that
the cert is well-formed; the value here is the second attempt,
~6 seconds later, where sshd rejects on the cert's expiry rather
than on any other problem.
"""

from __future__ import annotations

import time

import pytest

from wg_manager.ssh import SSHConnectionError, SSHRunner
from wg_manager.ssh_ca import VaultSSHCA

from tests.e2e.conftest import E2EEnv


def test_cert_rejected_after_ttl_expiry(
    sshd_container: E2EEnv,
    vault_ssh_ca: VaultSSHCA,
    vault_ssh_ca_short_ttl: VaultSSHCA,
    installed_host_cert: None,
) -> None:
    """A 5-second cert works before expiry and is refused after.

    Two assertions in one test because they're inseparable: the
    "before" handshake proves the cert is otherwise valid (so the
    "after" failure can be attributed to expiry alone, not some
    other config bug). Splitting into two tests would force re-
    minting and lose that linkage.
    """
    user_cert = vault_ssh_ca_short_ttl.mint_user_cert(
        principals=[sshd_container.username],
        ttl_seconds=5,
    )

    runner = SSHRunner(
        host=sshd_container.host,
        port=sshd_container.port,
        username=sshd_container.username,
        pkey_pem=user_cert.private_pem,
        cert_pem=user_cert.cert_pem,
        ca_public_key=vault_ssh_ca.ca_public_key,
        # Slightly larger than the cert TTL so the post-sleep
        # connect attempt doesn't get masked by a TCP-side timeout.
        connect_timeout=10.0,
    )

    # Pre-expiry — the cert should authenticate cleanly.
    with runner as session:
        assert session.run("echo pre-expiry").stdout.strip() == "pre-expiry"

    # Sleep past expiry. ssh_user_cert_ttl_seconds is 5 above; we
    # wait 7s to give Vault and sshd's clock skew tolerance some
    # room. (Vault is in the same container universe as the
    # test, so skew is effectively zero, but the buffer makes the
    # test resilient to a busy CI box.)
    time.sleep(7)

    # Post-expiry — sshd rejects the cert at auth time.
    with pytest.raises(SSHConnectionError) as excinfo:
        with runner:
            pass

    # Defensive on the failure shape: an auth-time refusal is what
    # we want, not a TCP error.
    msg = str(excinfo.value).lower()
    assert "authentication" in msg or "auth" in msg, (
        f"expected auth-time refusal, got: {excinfo.value!r}"
    )
