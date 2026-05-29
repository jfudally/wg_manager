#!/usr/bin/env python
"""Idempotently configure the Vault PKI used by wg-manager (Phase 2d).

Reads :class:`wg_manager.config.Settings` for ``VAULT_ADDR`` /
``VAULT_TOKEN`` / ``PKI_VAULT_*``, then calls
:meth:`wg_manager.pki.VaultPKI.bootstrap` to:

* enable the root PKI engine at ``pki_vault_root_mount`` (default
  ``pki``)
* generate a self-signed root cert (10-year TTL) — Vault keeps the
  private half; the operator never sees it
* enable the intermediate PKI engine at ``pki_vault_int_mount``
  (default ``pki_int``)
* generate the intermediate's CSR, sign it with the root, install the
  signed cert (with the root concatenated so ``/ca_chain`` returns
  the full path)
* create the server-cert role (default name ``wg-manager-server``)
  with ``serverAuth`` + the configured ``allowed_domains``
* create the client-cert role (default name ``wg-manager-client``)
  with ``clientAuth`` + permissive ``allow_any_name`` so operator
  CNs work out of the box

Re-run any time. The bootstrap swallows Vault's "already exists"
shapes so a second invocation against the same mounts is a no-op.

Usage::

    make pki-bootstrap                          # uses .env
    VAULT_ADDR=https://vault.prod ./scripts/pki_bootstrap.py
"""

from __future__ import annotations

import sys

import hvac
from cryptography import x509

from wg_manager.config import Settings
from wg_manager.pki import PKIError, VaultPKI


def _summarise_chain(pem: str) -> list[str]:
    """Return ``"CN=… (NotAfter=…)`` summaries for each cert in ``pem``."""
    out: list[str] = []
    for cert in x509.load_pem_x509_certificates(pem.encode()):
        cn = "<no-cn>"
        for attr in cert.subject:
            if attr.oid.dotted_string == "2.5.4.3":  # commonName
                cn = str(attr.value)
                break
        out.append(f"CN={cn}, NotAfter={cert.not_valid_after_utc.isoformat()}")
    return out


def main() -> int:
    """Bootstrap the PKI. Return shell-conventional exit code."""
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
        backend = VaultPKI.bootstrap(
            client=client,
            root_mount=settings.pki_vault_root_mount,
            intermediate_mount=settings.pki_vault_int_mount,
            server_role=settings.pki_vault_server_role,
            client_role=settings.pki_vault_client_role,
            allowed_domains=settings.pki_vault_allowed_domains,
        )
    except PKIError as exc:
        print(f"ERROR: bootstrap failed: {exc}", file=sys.stderr)
        return 1

    print(f"[OK] PKI configured")
    print(f"     root mount:         {settings.pki_vault_root_mount}")
    print(f"     intermediate mount: {settings.pki_vault_int_mount}")
    print(f"     server role:        {settings.pki_vault_server_role}")
    print(f"     client role:        {settings.pki_vault_client_role}")
    print(
        f"     allowed domains:    "
        f"{settings.pki_vault_allowed_domains or '(any — dev default)'}"
    )
    print("     ca_bundle:")
    for line in _summarise_chain(backend.ca_bundle_pem):
        print(f"       - {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
