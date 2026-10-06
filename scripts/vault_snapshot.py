"""Stream a Vault raft snapshot to stdout (Phase 3d cycle 5c).

Runs inside a throwaway ``bootstrap-app`` container on the primary:

    compose run --rm --no-deps -T \\
        --entrypoint /usr/local/bin/entrypoint-wg-manager.sh \\
        bootstrap-app python /app/scripts/vault_snapshot.py > vault.snap

The image's entrypoint shim exports ``VAULT_TOKEN`` (the root token from
``vault-init.json``) and the service env carries ``VAULT_ADDR``, so the
token never reaches the host. ``scripts/standby_bundle.sh`` is the only
caller; the snapshot is how the warm standby gets the primary's Vault.

Uses ``GET /v1/sys/storage/raft/snapshot`` directly (stdlib urllib, no
``vault`` CLI in the image). Fails loudly — non-zero exit, nothing on
stdout's consumer side worth keeping — on a missing token, an HTTP
error, or an empty body, so a broken snapshot can never be shipped as
if it were good.
"""

from __future__ import annotations

import os
import sys
import urllib.error
import urllib.request

_CHUNK = 64 * 1024


def main() -> int:
    """Fetch the snapshot and copy it to stdout.

    :return: Process exit code — 0 on success, 1 on any failure.
    """
    addr = os.environ.get("VAULT_ADDR", "").rstrip("/")
    token = os.environ.get("VAULT_TOKEN", "")
    if not addr:
        print("ERROR: VAULT_ADDR is not set", file=sys.stderr)
        return 1
    if not token:
        print(
            "ERROR: VAULT_TOKEN is not set — run via the wg-manager entrypoint "
            "shim, which reads it from /app/vault-init.json",
            file=sys.stderr,
        )
        return 1
    if sys.stdout.isatty():
        print("ERROR: refusing to write a binary snapshot to a terminal", file=sys.stderr)
        return 1

    req = urllib.request.Request(
        f"{addr}/v1/sys/storage/raft/snapshot",
        headers={"X-Vault-Token": token},
    )
    written = 0
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            out = sys.stdout.buffer
            while chunk := resp.read(_CHUNK):
                out.write(chunk)
                written += len(chunk)
            out.flush()
    except urllib.error.HTTPError as exc:
        print(f"ERROR: Vault answered HTTP {exc.code} for the raft snapshot", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"ERROR: could not fetch the raft snapshot: {exc}", file=sys.stderr)
        return 1
    if written == 0:
        print("ERROR: Vault returned an empty raft snapshot", file=sys.stderr)
        return 1
    print(f"snapshot: {written} bytes", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
