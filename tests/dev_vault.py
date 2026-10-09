"""Shared "is the dev Vault up?" probe for the Vault-backed tests.

The crypto, PKI, SSH CA and e2e tests run against ``make vault-up``'s
dev-mode Vault and skip when it isn't there. They default to
``http://127.0.0.1:8200``, which on a host that also runs the prod stack
(rv) is the **production** Vault. Answering at that address is therefore
not enough: the probe only accepts a dev-mode server, so the tests never
send the dev root token to, or mount engines on, a real Vault.
"""

from __future__ import annotations

import os

import requests

#: Where the Vault-backed tests look for the dev Vault.
VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
#: The dev server's root token (``VAULT_DEV_ROOT_TOKEN_ID`` in docker-compose.yml).
VAULT_TOKEN = os.environ.get("VAULT_TOKEN", "dev-only-root")


def dev_vault_available(addr: str = VAULT_ADDR, timeout: float = 0.5) -> bool:
    """Return ``True`` only if ``addr`` is an unsealed dev-mode Vault.

    Reads the unauthenticated ``/v1/sys/seal-status``, so no token is
    sent before the server is known to be a dev one. ``vault server
    -dev`` reports ``storage_type: inmem``. Any persistent backend
    (prod uses raft), a sealed server, an unreachable address or an
    unexpected reply returns ``False``, and the caller skips.

    :param addr: Vault base URL, e.g. ``http://127.0.0.1:8200``.
    :param timeout: Seconds to wait for the reply. Kept short because
        the plain ``make test`` run usually has no Vault at all.
    :returns: Whether the Vault-backed tests may use this server.
    """
    try:
        resp = requests.get(f"{addr}/v1/sys/seal-status", timeout=timeout)
        status = resp.json() if resp.status_code == 200 else None
    except (requests.RequestException, ValueError):
        return False
    if not isinstance(status, dict):
        return False
    return status.get("storage_type") == "inmem" and status.get("sealed") is False
