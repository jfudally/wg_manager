#!/usr/bin/env python
"""Idempotently configure the Vault SSH CA used by wg-manager.

Reads :class:`wg_manager.config.Settings` for ``VAULT_ADDR`` /
``VAULT_TOKEN`` / ``SSH_CA_VAULT_*``, then calls
:meth:`wg_manager.ssh_ca.VaultSSHCA.bootstrap` to:

* enable the SSH secrets engine at ``ssh_ca_vault_mount`` (default
  ``ssh``)
* submit (i.e. generate) a CA signing key — Vault keeps the private
  half; we only ever read the public half via ``/<mount>/public_key``
* create the user-cert role (default name ``wg-manager-provision``)
  with TTL 5m and ``permit-pty``
* create the host-cert role (default name ``wg-manager-hosts``) with
  TTL 24h

Re-run any time. The bootstrap swallows Vault's "already exists" errors
so a second invocation against the same mount is a no-op.

Usage::

    make ssh-ca-bootstrap                       # uses .env
    VAULT_ADDR=https://vault.prod ./scripts/ssh_ca_bootstrap.py
"""

from __future__ import annotations

import sys

import hvac

from wg_manager.config import Settings
from wg_manager.ssh_ca import SSHCAError, VaultSSHCA


def main() -> int:
    """Bootstrap the SSH CA. Return shell-conventional exit code."""
    settings = Settings()
    if not settings.crypto_vault_token:
        print(
            "ERROR: VAULT_TOKEN (or CRYPTO_VAULT_TOKEN) is unset — cannot bootstrap",
            file=sys.stderr,
        )
        return 2

    client = hvac.Client(
        url=settings.crypto_vault_addr, token=settings.crypto_vault_token
    )

    try:
        backend = VaultSSHCA.bootstrap(
            client=client,
            mount_point=settings.ssh_ca_vault_mount,
            user_role=settings.ssh_ca_vault_user_role,
            host_role=settings.ssh_ca_vault_host_role,
        )
    except SSHCAError as exc:
        print(f"ERROR: bootstrap failed: {exc}", file=sys.stderr)
        return 1

    print(f"[OK] SSH CA configured at {settings.ssh_ca_vault_mount!r}")
    print(f"     user role: {settings.ssh_ca_vault_user_role}")
    print(f"     host role: {settings.ssh_ca_vault_host_role}")
    print("     CA public key (drop into /etc/ssh/wg-manager-user-ca.pub):")
    print(f"       {backend.ca_public_key}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
