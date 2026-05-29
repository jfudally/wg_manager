"""Phase 2c CP5 — sshd refuses a cert whose principals don't include the user.

Pins the second of the Phase 2c "Tests" criteria:

    Mismatched principals are rejected by ``sshd``.

A cert minted with ``valid_principals=[otheruser]`` but presented
on a ``wguser`` connection is exactly the failure mode an attacker
who steals a cert minted for one host would face when reusing it
elsewhere. The auxiliary multi-user role (see
:func:`tests.e2e.conftest.vault_ssh_ca_multi_user`) is what lets
Vault sign the cert at all — the production role only lists the
real connect username.
"""

from __future__ import annotations

import pytest

from wg_manager.ssh import SSHConnectionError, SSHRunner
from wg_manager.ssh_ca import VaultSSHCA

from tests.e2e.conftest import E2E_OTHER_PRINCIPAL, E2EEnv


def test_sshd_rejects_cert_with_wrong_principal(
    sshd_container: E2EEnv,
    vault_ssh_ca: VaultSSHCA,
    vault_ssh_ca_multi_user: VaultSSHCA,
    installed_host_cert: None,
) -> None:
    """Cert valid for ``otheruser`` is refused when connecting as ``wguser``."""
    user_cert = vault_ssh_ca_multi_user.mint_user_cert(
        principals=[E2E_OTHER_PRINCIPAL],
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

    with pytest.raises(SSHConnectionError) as excinfo:
        with runner:
            pass

    msg = str(excinfo.value).lower()
    assert "authentication" in msg or "auth" in msg, (
        f"expected auth-time refusal, got: {excinfo.value!r}"
    )
