#!/usr/bin/env python
"""Bootstrap the Vault Transit secrets engine + ``wg-manager`` master key.

:class:`wg_manager.crypto.VaultTransitBackend` is deliberately dumb —
it does not call ``create_key`` itself, so a running prod stack with
``CRYPTO_BACKEND=vault`` will 500 the first time anything touches the
crypto router unless something else provisioned the Transit mount +
key first. Before this script existed the bootstrap step was
documented as a manual ``client.secrets.transit.create_key(...)``
snippet in ``docs/vault-cookbook.md`` §1 — the self-bootstrapping
prod stack invokes this script from ``prod_bootstrap_substrate.sh``
so an operator running ``make prod-up`` gets a usable Transit key
on the first invocation.

Idempotent. Re-running against an already-bootstrapped Transit
mount + key is a no-op. The two operations:

  1. **Enable the Transit secrets engine** at the configured mount
     path (default ``transit``). ``client.sys.enable_secrets_engine``
     returns ``400 path is already in use`` on a re-run; we catch +
     ignore.
  2. **Create the master key** (default name ``wg-manager``) with
     ``derived=True``. The ``derived=True`` flag is **load-bearing**:
     :mod:`wg_manager.crypto` passes a per-row context to
     ``encrypt_data`` so a swapped ciphertext from another row fails
     to decrypt. Without ``derived=True``, Transit silently ignores
     the context and the row-swap defence disappears (see
     ``crypto.py:206`` and the docstring on
     :class:`VaultTransitBackend`). We `read_key` first; only
     `create_key` if the read fails with ``InvalidPath``.

Usage
-----

::

    python scripts/transit_bootstrap.py
    python scripts/transit_bootstrap.py --vault-addr http://127.0.0.1:8200 \\
        --token dev-only-root
    python scripts/transit_bootstrap.py --key-name wg-manager \\
        --mount-point transit

Exits ``0`` on success (either newly bootstrapped or already
present), ``1`` on Vault auth failure or unexpected error.
"""

from __future__ import annotations

import argparse
import os
import sys

import hvac
from hvac.exceptions import InvalidPath, InvalidRequest


def _enable_transit_idempotent(
    client: hvac.Client, mount_point: str
) -> bool:
    """Enable the Transit engine; return ``True`` if newly enabled.

    :param client: Authenticated hvac client.
    :param mount_point: Mount path (default ``transit``).
    :return: ``True`` if the engine was newly enabled this call;
        ``False`` if it was already mounted (idempotent re-run).
    :raises InvalidRequest: For any non-"already in use" failure.
    """
    try:
        client.sys.enable_secrets_engine(
            backend_type="transit", path=mount_point
        )
        return True
    except InvalidRequest as exc:
        if "path is already in use" in str(exc):
            return False
        raise


def _create_key_idempotent(
    client: hvac.Client, key_name: str, mount_point: str
) -> bool:
    """Create the master key with ``derived=True``; return ``True``
    if newly created.

    Reads first so we don't issue a spurious POST against an existing
    key — and so the script logs ``already present`` cleanly on
    re-runs.

    :param client: Authenticated hvac client.
    :param key_name: Transit key name. Must match
        ``CRYPTO_VAULT_TRANSIT_KEY`` in the app's env.
    :param mount_point: Mount path.
    :return: ``True`` if the key was newly created this call;
        ``False`` if it already existed.
    """
    try:
        client.secrets.transit.read_key(
            name=key_name, mount_point=mount_point
        )
        return False
    except InvalidPath:
        client.secrets.transit.create_key(
            name=key_name,
            mount_point=mount_point,
            derived=True,
        )
        return True


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns the desired exit code."""
    parser = argparse.ArgumentParser(
        description=(
            "Bootstrap the Vault Transit engine + wg-manager master "
            "key. Idempotent — safe to re-run."
        ),
    )
    parser.add_argument(
        "--vault-addr",
        default=os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200"),
        help="Vault address (default: $VAULT_ADDR or http://127.0.0.1:8200)",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("VAULT_TOKEN", "dev-only-root"),
        help="Vault token (default: $VAULT_TOKEN or dev-only-root)",
    )
    parser.add_argument(
        "--key-name",
        default=os.environ.get("CRYPTO_VAULT_TRANSIT_KEY", "wg-manager"),
        help=(
            "Transit key name. Must match the app's "
            "CRYPTO_VAULT_TRANSIT_KEY env (default: wg-manager)."
        ),
    )
    parser.add_argument(
        "--mount-point",
        default=os.environ.get("CRYPTO_VAULT_TRANSIT_MOUNT", "transit"),
        help=(
            "Transit mount path. Must match the app's "
            "CRYPTO_VAULT_TRANSIT_MOUNT env (default: transit)."
        ),
    )
    args = parser.parse_args(argv)

    client = hvac.Client(url=args.vault_addr, token=args.token)
    if not client.is_authenticated():
        print(
            f"ERROR: vault authentication failed at {args.vault_addr}",
            file=sys.stderr,
        )
        return 1

    engine_state = (
        "enabled" if _enable_transit_idempotent(client, args.mount_point)
        else "already present"
    )
    key_state = (
        "created" if _create_key_idempotent(
            client, args.key_name, args.mount_point
        )
        else "already present"
    )
    print(
        f"transit engine mount={args.mount_point}: {engine_state}; "
        f"key name={args.key_name} derived=True: {key_state}"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
