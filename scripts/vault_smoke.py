"""Vault smoke test — Phase 2a spike, throwaway.

Exercises the four Vault secrets engines wg-manager will depend on in
later sub-phases, against a ``vault server -dev`` container:

* **Transit** (Phase 2b) — symmetric encrypt/decrypt round-trip.
* **KV v2** (referenced as the fallback for any per-row metadata we
  decide *not* to put through Transit).
* **SSH CA** (Phase 2c) — sign an Ed25519 user public key.
* **PKI** (Phase 2d) — issue an X.509 leaf cert from an in-Vault root.

This file lives under ``scripts/`` (not ``src/``) and is **explicitly
throwaway**. It is not imported by the application and is not on the
``wg_manager`` import path. Phase 2b is where the production
``wg_manager.crypto`` module first imports ``hvac``; until then this
script is the only place ``hvac`` is touched.

Idempotency
-----------

Each step assumes nothing about prior runs:

* Engine-enable calls swallow "path is already in use" errors.
* Transit / SSH / PKI role creation is upsert-style.
* The script can be re-run any number of times against the same dev
  Vault and should always exit 0.

Usage
-----

::

    python scripts/vault_smoke.py
    python scripts/vault_smoke.py --vault-addr http://127.0.0.1:8200 \\
        --token dev-only-root

Exits ``0`` if every step round-trips correctly, ``1`` otherwise. Output
is plain text — one line per step plus a final summary — so it can be
read off a CI log without ceremony.
"""

from __future__ import annotations

import argparse
import base64
import os
import sys
import time
import traceback
from dataclasses import dataclass
from typing import Callable

import hvac
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hvac.exceptions import InvalidRequest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class StepResult:
    """Outcome of one smoke-test step.

    :ivar name: Human-readable step name (printed in the summary).
    :ivar ok: ``True`` if the step's assertions held.
    :ivar detail: One-line message; the error string when ``ok`` is
        ``False``, the round-tripped value when ``ok`` is ``True``.
    :ivar elapsed_ms: Wall-clock duration in milliseconds, for a rough
        sense of which engines are slow.
    """

    name: str
    ok: bool
    detail: str
    elapsed_ms: int


def _enable_engine_idempotent(
    client: hvac.Client, *, backend_type: str, path: str
) -> None:
    """Enable a Vault secrets engine, treating "already mounted" as success.

    Vault returns HTTP 400 with ``path is already in use`` when the mount
    exists. ``hvac`` surfaces that as :class:`InvalidRequest`; we swallow
    it specifically so re-runs of the smoke script don't blow up.

    :param client: An authenticated ``hvac.Client``.
    :param backend_type: One of ``"transit"``, ``"kv"``, ``"ssh"``,
        ``"pki"``.
    :param path: Mount path under ``/v1/``.
    """
    try:
        kwargs: dict[str, object] = {"backend_type": backend_type, "path": path}
        if backend_type == "kv":
            kwargs["options"] = {"version": "2"}
        client.sys.enable_secrets_engine(**kwargs)
    except InvalidRequest as exc:
        if "path is already in use" in str(exc):
            return
        raise


def _wait_for_vault(client: hvac.Client, timeout_s: float = 15.0) -> None:
    """Block until the dev Vault answers ``sys/health`` as ready.

    ``docker compose up -d vault`` returns before the listener is bound,
    so a smoke script invoked back-to-back with ``vault-up`` can race
    the boot. We poll for up to ``timeout_s`` seconds; longer waits mean
    something's wrong and we want a loud failure, not a hang.

    :raises RuntimeError: If the Vault doesn't come up in time.
    """
    deadline = time.monotonic() + timeout_s
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            if client.sys.is_initialized() and not client.sys.is_sealed():
                return
        except Exception as exc:  # noqa: BLE001 — best-effort retry
            last_error = exc
        time.sleep(0.5)
    raise RuntimeError(
        f"Vault at {client.url} did not become ready within {timeout_s}s "
        f"(last error: {last_error!r})"
    )


def _time_step(name: str, fn: Callable[[], str]) -> StepResult:
    """Run a step, capture timing and any exception.

    :param name: Step label.
    :param fn: Zero-arg callable that returns the "detail" string on
        success and raises on failure.
    :return: A :class:`StepResult`.
    """
    started = time.monotonic()
    try:
        detail = fn()
        ok = True
    except Exception as exc:  # noqa: BLE001 — top-level catch is the point
        detail = f"{type(exc).__name__}: {exc}"
        ok = False
        traceback.print_exc(file=sys.stderr)
    elapsed_ms = int((time.monotonic() - started) * 1000)
    return StepResult(name=name, ok=ok, detail=detail, elapsed_ms=elapsed_ms)


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------


_TRANSIT_KEY = "wg-manager-smoke"
_KV_PATH = "wg-manager-smoke"
_SSH_ROLE = "wg-manager-smoke"
_PKI_ROLE = "wg-manager-smoke"


def step_transit(client: hvac.Client) -> str:
    """Encrypt then decrypt a marker via Transit; assert round-trip.

    Uses the same context-pinning pattern Phase 2b will use in
    ``wg_manager.crypto``: a per-row context binds the ciphertext to its
    intended row, so a swapped blob from another row fails to decrypt.
    """
    _enable_engine_idempotent(client, backend_type="transit", path="transit")
    client.secrets.transit.create_key(name=_TRANSIT_KEY)

    marker = b"hello-from-wg-manager"
    context = b"sshkey:smoke"

    encrypt_resp = client.secrets.transit.encrypt_data(
        name=_TRANSIT_KEY,
        plaintext=base64.b64encode(marker).decode(),
        context=base64.b64encode(context).decode(),
    )
    ciphertext: str = encrypt_resp["data"]["ciphertext"]
    if not ciphertext.startswith("vault:v"):
        raise AssertionError(
            f"expected ciphertext to start with 'vault:v…', got {ciphertext[:16]!r}"
        )

    decrypt_resp = client.secrets.transit.decrypt_data(
        name=_TRANSIT_KEY,
        ciphertext=ciphertext,
        context=base64.b64encode(context).decode(),
    )
    decoded = base64.b64decode(decrypt_resp["data"]["plaintext"])
    if decoded != marker:
        raise AssertionError(f"transit round-trip mismatch: {decoded!r} != {marker!r}")

    return f"ciphertext={ciphertext[:24]}… round-trip ok"


def step_kv2(client: hvac.Client) -> str:
    """Write a KV v2 secret and read it back."""
    _enable_engine_idempotent(client, backend_type="kv", path="secret")

    payload = {"hello": "wg-manager", "phase": "2a"}
    client.secrets.kv.v2.create_or_update_secret(
        path=_KV_PATH,
        secret=payload,
        mount_point="secret",
    )
    read = client.secrets.kv.v2.read_secret_version(
        path=_KV_PATH,
        mount_point="secret",
        raise_on_deleted_version=True,
    )
    got = read["data"]["data"]
    if got != payload:
        raise AssertionError(f"kv v2 round-trip mismatch: {got!r} != {payload!r}")

    return f"path=secret/{_KV_PATH} round-trip ok"


def step_ssh_ca(client: hvac.Client) -> str:
    """Sign an ephemeral Ed25519 public key as a short-lived user cert.

    Mirrors the Phase 2c flow: caller generates a keypair in memory,
    Vault signs the public half, the cert is used and discarded. No
    private-key material ever lives in Vault or on disk.
    """
    _enable_engine_idempotent(client, backend_type="ssh", path="ssh")

    # Configure the CA. ``submit_ca_information`` is idempotent only in
    # the sense that the second call returns 400 — we swallow the same
    # "already configured" shape.
    try:
        client.secrets.ssh.submit_ca_information(
            generate_signing_key=True, mount_point="ssh"
        )
    except InvalidRequest as exc:
        if "keys are already configured" not in str(exc):
            raise

    client.secrets.ssh.create_role(
        name=_SSH_ROLE,
        key_type="ca",
        allow_user_certificates=True,
        default_user="root",
        allowed_users="root",
        default_extensions={"permit-pty": ""},
        allowed_extensions="permit-pty",
        ttl="60s",
        max_ttl="60s",
        mount_point="ssh",
    )

    ephemeral = Ed25519PrivateKey.generate()
    public_openssh = (
        ephemeral.public_key()
        .public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )
        .decode()
    )

    sign_resp = client.secrets.ssh.sign_ssh_key(
        name=_SSH_ROLE,
        public_key=public_openssh,
        valid_principals="root",
        cert_type="user",
        ttl="60s",
        mount_point="ssh",
    )
    signed_key: str = sign_resp["data"]["signed_key"]
    if not signed_key.startswith("ssh-ed25519-cert-v01@openssh.com "):
        raise AssertionError(
            f"expected ssh-ed25519 cert, got prefix {signed_key.split()[0]!r}"
        )

    return f"signed {len(signed_key.split()[1])} bytes of cert (ttl=60s)"


def step_pki(client: hvac.Client) -> str:
    """Stand up an internal root and issue a short-lived leaf certificate."""
    _enable_engine_idempotent(client, backend_type="pki", path="pki")

    # Generating the root twice returns 204 with an empty body in modern
    # Vault; older versions returned 400. Treat both as fine.
    try:
        client.secrets.pki.generate_root(
            type="internal",
            common_name="wg-manager smoke root",
            extra_params={"ttl": "8760h"},
            mount_point="pki",
        )
    except InvalidRequest as exc:
        if "already exists" not in str(exc):
            raise

    client.secrets.pki.create_or_update_role(
        name=_PKI_ROLE,
        extra_params={
            "allowed_domains": ["wg.local"],
            "allow_subdomains": True,
            "max_ttl": "1h",
        },
        mount_point="pki",
    )

    issue_resp = client.secrets.pki.generate_certificate(
        name=_PKI_ROLE,
        common_name="smoke.wg.local",
        extra_params={"ttl": "5m"},
        mount_point="pki",
    )
    cert_pem: str = issue_resp["data"]["certificate"]
    if "BEGIN CERTIFICATE" not in cert_pem:
        raise AssertionError("PKI issue returned no PEM body")

    serial: str = issue_resp["data"]["serial_number"]
    return f"issued leaf cert serial={serial} (ttl=5m)"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI args, falling back to env vars matching the Vault CLI."""
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
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
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run all four engine round-trips and return a process exit code."""
    args = _parse_args(argv)
    client = hvac.Client(url=args.vault_addr, token=args.token)

    print(f"vault-smoke: connecting to {args.vault_addr}")
    _wait_for_vault(client)
    if not client.is_authenticated():
        print("vault-smoke: token rejected by Vault", file=sys.stderr)
        return 1

    steps: list[StepResult] = [
        _time_step("transit", lambda: step_transit(client)),
        _time_step("kv-v2", lambda: step_kv2(client)),
        _time_step("ssh-ca", lambda: step_ssh_ca(client)),
        _time_step("pki", lambda: step_pki(client)),
    ]

    print()
    print("vault-smoke results:")
    for step in steps:
        mark = "PASS" if step.ok else "FAIL"
        print(f"  [{mark}] {step.name:<8} ({step.elapsed_ms:>4} ms) — {step.detail}")

    failed = [s for s in steps if not s.ok]
    if failed:
        print(f"\nvault-smoke: {len(failed)} step(s) failed", file=sys.stderr)
        return 1

    print("\nvault-smoke: all 4 engines round-tripped ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
