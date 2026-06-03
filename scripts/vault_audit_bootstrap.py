"""Bootstrap a file audit device on a running Vault.

Phase 2e audit-log cycle 1 — closes the device-enable half of the
ROADMAP "Vault audit log is shipped off-host" bullet. Wraps
:func:`wg_manager.vault_audit.bootstrap_file_audit_device` so an
operator can run a single command to enable Vault's file audit device
against the dev compose stack (cycle 2 adds the vector sidecar that
ships the file off-host; cycle 3 documents the production paths).

Usage
-----

::

    python scripts/vault_audit_bootstrap.py
    python scripts/vault_audit_bootstrap.py --vault-addr http://127.0.0.1:8200 \\
        --token dev-only-root
    python scripts/vault_audit_bootstrap.py --device-path audit \\
        --log-file /var/log/vault/audit.log

Exits ``0`` on success (either newly enabled or already present), ``1``
on Vault auth failure or unexpected error. Output is a single line so
it can be read off a CI log without ceremony.
"""

from __future__ import annotations

import argparse
import os
import sys

import hvac

from wg_manager.vault_audit import (
    DEFAULT_AUDIT_DEVICE_PATH,
    DEFAULT_LOG_FILE_PATH,
    bootstrap_file_audit_device,
)


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns the desired exit code."""
    parser = argparse.ArgumentParser(
        description=(
            "Enable a file audit device on a running Vault. "
            "Idempotent — safe to re-run."
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
        "--device-path",
        default=DEFAULT_AUDIT_DEVICE_PATH,
        help=f"Audit device mount path (default: {DEFAULT_AUDIT_DEVICE_PATH})",
    )
    parser.add_argument(
        "--log-file",
        default=DEFAULT_LOG_FILE_PATH,
        help=(
            "In-container log file path; must be on a writable volume "
            f"(default: {DEFAULT_LOG_FILE_PATH})"
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

    newly_enabled = bootstrap_file_audit_device(
        client,
        device_path=args.device_path,
        log_file_path=args.log_file,
    )
    status = "enabled" if newly_enabled else "already present"
    print(
        f"audit device path={args.device_path} log_file={args.log_file}: {status}"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
