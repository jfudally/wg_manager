"""Restore the primary's Vault from a raft snapshot (Phase 3d cycle 5d).

Runs on the standby during ``make failover``, inside a throwaway
``bootstrap-app`` container. It is called twice, with a Vault restart in
between:

    # 1. restore (snapshot on stdin)
    compose run ... bootstrap-app python /app/scripts/vault_restore.py < standby/vault.snap
    # 2. restart, so Vault loads the snapshot's seal config
    compose restart vault
    # 3. unseal with the shipped keys + verify
    compose run ... bootstrap-app python /app/scripts/vault_restore.py --verify

The entrypoint shim exports ``VAULT_TOKEN`` from ``/app/vault-init.json``.
On a standby that file is the one shipped from the primary (cycle 5c),
so the token and the unseal keys in it belong to the snapshot's Vault.

**Restore.** A raft restore needs a running, unsealed, *active* Vault to
post the snapshot to:

* **Uninitialized** (the standby's first failover): initialize a
  *throwaway* Vault with one key share, unseal it, and restore with its
  root token. The throwaway keys stay in memory. They are never written
  anywhere and are useless once the snapshot's keyring is in. This
  deliberately bypasses ``vault_init_unseal.sh``, whose guard rightly
  refuses to initialize next to a non-empty ``vault-init.json``.
* **Initialized, sealed:** unseal with the shipped keys.
* **Initialized, unsealed:** use the shipped token.

In each case, wait until raft has elected the node active (a restore
posted before that fails with "local node not active"), then ``POST
/v1/sys/storage/raft/snapshot-force``.

**Why the restart.** After the restore, the *running* server still
holds the old seal configuration in memory, e.g. the throwaway's
1-of-1. It rejects the snapshot's Shamir shares ("invalid key size 33")
and re-seals itself a moment later. Only a restart loads the snapshot's
seal config. The live drill found this; it's invisible when both sides
happen to use the same share count.

**Verify** (``--verify``). Wait for Vault (unsealing with the shipped
keys whenever it reports sealed), then check that the shipped root
token can list mounts and that the engines wg-manager depends on
(``ssh/``, ``pki/``, ``transit/``) are present.

The snapshot is read fully and checked to be non-empty *before* Vault
is touched, so a missing snapshot can't leave a throwaway Vault behind.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

# Engines whose absence after the restore means something is wrong.
REQUIRED_MOUNTS = ("ssh/", "pki/", "transit/")


class RestoreError(RuntimeError):
    """A step failed. The message is printed for the operator."""


def _log(msg: str) -> None:
    print(f"==> {msg}", file=sys.stderr)


def _call(
    addr: str,
    method: str,
    path: str,
    *,
    token: str = "",
    body: bytes | None = None,
    ctype: str = "application/json",
) -> tuple[int, bytes]:
    """Make one Vault API request.

    :return: ``(status, body)``. HTTP errors are returned, not raised.
    :raises RestoreError: The Vault couldn't be reached at all.
    """
    headers = {"Content-Type": ctype}
    if token:
        headers["X-Vault-Token"] = token
    req = urllib.request.Request(f"{addr}{path}", data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except OSError as exc:
        raise RestoreError(f"cannot reach Vault at {addr}: {exc}") from exc


def _json(addr: str, method: str, path: str, **kw) -> dict:
    """Make a request that must succeed and return JSON."""
    status, raw = _call(addr, method, path, **kw)
    if status >= 300:
        raise RestoreError(f"{method} {path} -> HTTP {status} {raw[:200]!r}")
    return json.loads(raw or b"{}")


def _unseal(addr: str, keys: list[str]) -> None:
    """Submit unseal keys until Vault reports unsealed."""
    for key in keys:
        resp = _json(addr, "PUT", "/v1/sys/unseal", body=json.dumps({"key": key}).encode())
        if not resp.get("sealed", True):
            return
    raise RestoreError("Vault is still sealed after submitting every unseal key")


def _wait_active(addr: str, timeout: float = 90.0, unseal_keys: list[str] | None = None) -> None:
    """Block until Vault is initialized, unsealed and the ACTIVE node.

    ``/v1/sys/health`` answers 200 only for the active node (429 standby,
    503 sealed, 501 uninitialized). Right after an unseal, raft takes a
    moment to elect the node leader.

    :param unseal_keys: If given, unseal with them whenever Vault reports
        sealed. Vault can re-seal a moment after looking unsealed.
    :raises RestoreError: Not active within ``timeout`` seconds.
    """
    deadline = time.monotonic() + timeout
    while True:
        try:
            status, _ = _call(addr, "GET", "/v1/sys/health")
        except RestoreError:
            status = 0  # still starting (e.g. right after a restart)
        if status == 200:
            return
        if status == 503 and unseal_keys:
            _log("Vault is sealed: unsealing with the shipped keys.")
            _unseal(addr, unseal_keys)
            continue
        if time.monotonic() >= deadline:
            raise RestoreError(
                f"Vault did not become active within {timeout:.0f}s "
                f"(last health: HTTP {status})"
            )
        time.sleep(0.5)


def _shipped_keys(init_file: str) -> list[str]:
    """Unseal keys from the shipped vault-init.json."""
    with open(init_file) as fh:
        init = json.load(fh)
    keys = init.get("unseal_keys_b64") or init.get("keys_base64") or []
    if not keys:
        raise RestoreError(f"no unseal keys in {init_file}")
    return keys


def restore(addr: str, token: str, init_file: str, snapshot: bytes) -> None:
    """Post ``snapshot`` into the Vault at ``addr`` (phase 1).

    :param addr: Vault address, e.g. ``http://vault:8200``.
    :param token: The shipped root token (from the entrypoint shim).
    :param init_file: Path to the shipped ``vault-init.json``.
    :param snapshot: The raft snapshot bytes.
    :raises RestoreError: Any step failed.
    """
    if not snapshot:
        raise RestoreError("the snapshot is empty — nothing to restore (run make standby-pull)")
    shipped_keys = _shipped_keys(init_file)

    initialized = _json(addr, "GET", "/v1/sys/init").get("initialized", False)
    restore_token = token
    if not initialized:
        _log("Vault is uninitialized: starting a throwaway Vault to restore into "
             "(its keys stay in memory).")
        init = _json(addr, "PUT", "/v1/sys/init",
                     body=json.dumps({"secret_shares": 1, "secret_threshold": 1}).encode())
        _unseal(addr, init.get("keys_base64") or init.get("keys") or [])
        restore_token = init["root_token"]
    elif _json(addr, "GET", "/v1/sys/seal-status").get("sealed", True):
        _log("Vault is sealed: unsealing with the shipped keys.")
        _unseal(addr, shipped_keys)
    _wait_active(addr)

    _log(f"Restoring the raft snapshot ({len(snapshot)} bytes)...")
    status, raw = _call(addr, "POST", "/v1/sys/storage/raft/snapshot-force",
                        token=restore_token, body=snapshot, ctype="application/octet-stream")
    if status >= 300:
        raise RestoreError(f"the snapshot restore failed: HTTP {status} {raw[:200]!r}")
    _log("Snapshot restored. Restart Vault now so it loads the snapshot's seal "
         "config, then run this with --verify.")


def verify(addr: str, token: str, init_file: str) -> list[str]:
    """Unseal the restarted Vault with the shipped keys and check it (phase 3).

    :return: The mount paths visible with the shipped root token.
    :raises RestoreError: Not unsealable, not active, or missing an engine.
    """
    shipped_keys = _shipped_keys(init_file)
    deadline = time.monotonic() + 90
    while True:
        _wait_active(addr, unseal_keys=shipped_keys)
        status, raw = _call(addr, "GET", "/v1/sys/mounts", token=token)
        if status == 200:
            mounts = json.loads(raw)
            break
        # Sealed or not active again in between: go round.
        if status not in (429, 500, 503) or time.monotonic() >= deadline:
            raise RestoreError(f"GET /v1/sys/mounts -> HTTP {status} after the restore")
        time.sleep(0.5)
    paths = sorted((mounts.get("data") or mounts).keys())
    missing = [m for m in REQUIRED_MOUNTS if m not in paths]
    if missing:
        raise RestoreError(
            f"the restored Vault lacks {', '.join(missing)} — wrong or damaged snapshot "
            "(try standby/vault.snap.prev)"
        )
    return paths


def main(argv: list[str]) -> int:
    """Run phase 1 (restore, snapshot on stdin) or phase 3 (``--verify``).

    :return: Process exit code.
    """
    addr = os.environ.get("VAULT_ADDR", "").rstrip("/")
    token = os.environ.get("VAULT_TOKEN", "")
    init_file = os.environ.get("VAULT_INIT_FILE", "/app/vault-init.json")
    try:
        if not addr or not token:
            raise RestoreError(
                "VAULT_ADDR and VAULT_TOKEN must be set (run via the entrypoint shim)"
            )
        if argv == ["--verify"]:
            paths = verify(addr, token, init_file)
            print(f"==> Vault verified. Mounts: {' '.join(paths)}")
        elif not argv:
            restore(addr, token, init_file, sys.stdin.buffer.read())
        else:
            raise RestoreError("usage: vault_restore.py [--verify]")
    except (RestoreError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
