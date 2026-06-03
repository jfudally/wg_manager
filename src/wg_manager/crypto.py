"""Encryption-at-rest abstraction for wg-manager (Phase 2b).

wg-manager persists secret material — SSH private keys, SSH passphrases,
manual-client WireGuard private keys — in MySQL. Without encryption a
DB-read attacker (leaked backup, SQLi, rogue insider) walks away with
root on every managed host. This module is the single seam through
which every such secret is wrapped before going to the DB and unwrapped
on the way out.

Two backends implement :class:`CryptoBackend`:

* :class:`VaultTransitBackend` — production. Encryption/decryption
  happens inside Vault via the Transit secrets engine; the master key
  never leaves Vault. Selected by ``CRYPTO_BACKEND=vault``.
* :class:`LocalDevBackend` — tests and local development. A
  :class:`~cryptography.fernet.Fernet` keyed from
  ``CRYPTO_LOCAL_DEV_KEY``. Selected by ``CRYPTO_BACKEND=local``. **Not
  safe for production** — the key sits in the app's environment, so a
  host compromise reads every secret.

Both share the same contract:

* Ciphertext blobs are opaque strings starting with a backend-specific
  prefix (``vault:`` or ``local:v1:``). Callers must not parse them.
* Every encrypt call takes a ``context`` string. The context is
  cryptographically bound to the resulting blob so a DB-read attacker
  who swaps blob A into row B cannot decrypt it. wg-manager's
  convention is ``f"<table>:{row_id}"`` — see
  ``docs/vault-cookbook.md`` §1.
* Any failure to decrypt — whether from a wrong context, tampering, a
  rotated-away key, or a missing key — raises :class:`DecryptError`.
  Callers cannot (and must not try to) distinguish the underlying
  cause: defenders see "decrypt failed" and route to the same incident
  response either way.

Phase 2b ships the abstraction and the unit tests. Phase 2b also
includes the dual-write Alembic migration and the ``wg-manager crypto
migrate`` CLI that walk every legacy row; those land in a follow-up
commit so this module can be reviewed in isolation.
"""

from __future__ import annotations

import base64
from typing import Protocol, runtime_checkable

import hvac
from cryptography.fernet import Fernet, InvalidToken
from hvac.exceptions import InvalidRequest as HvacInvalidRequest
from hvac.exceptions import VaultError as HvacVaultError

from wg_manager.config import Settings


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class CryptoError(Exception):
    """Base class for every crypto failure surfaced by this module."""


class DecryptError(CryptoError):
    """Decryption refused — wrong context, tampering, or missing key.

    The exception body is intentionally vague. Defenders should treat a
    DecryptError as an "investigate now" signal regardless of cause;
    leaking *why* it failed (context mismatch vs. tampered MAC) would
    help an attacker probing the system.
    """


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class CryptoBackend(Protocol):
    """Common interface for every encryption-at-rest backend.

    :cvar name: Short human label used in logs, the ``/healthz``
        payload, and the dashboard "Crypto status" panel.
    :cvar blob_prefix: String prefix every ciphertext starts with.
        Used by the dual-write migration to tell legacy plaintext rows
        from already-encrypted ones, and by the dashboard to render an
        "encrypted" badge.
    """

    name: str
    blob_prefix: str

    @property
    def key_version(self) -> int:
        """Current active key version.

        ``LocalDevBackend`` returns ``1`` (it does not rotate);
        ``VaultTransitBackend`` returns Transit's ``latest_version``.
        """
        ...

    def encrypt(self, plaintext: bytes, *, context: str) -> str:
        """Encrypt ``plaintext`` under the given ``context``.

        :param plaintext: Bytes to protect.
        :param context: Per-row binding string. Must be passed verbatim
            on decrypt or the operation raises :class:`DecryptError`.
        :return: An opaque ciphertext blob; safe to store as TEXT.
        """
        ...

    def decrypt(self, blob: str, *, context: str) -> bytes:
        """Reverse :meth:`encrypt`.

        :raises DecryptError: If the blob is tampered, the context is
            wrong, or the key has been removed.
        """
        ...


# ---------------------------------------------------------------------------
# LocalDevBackend
# ---------------------------------------------------------------------------


class LocalDevBackend:
    """Fernet-keyed backend for unit tests and laptop development.

    The plaintext is framed as ``[u16 context-length | context | data]``
    before Fernet encryption, so on decrypt we can verify the stored
    context matches the one the caller supplied. Fernet's HMAC covers
    the entire frame, so any tampering invalidates the token and a
    wrong key produces :class:`DecryptError` too.

    .. warning::
        **Never select this backend in production.** The Fernet key
        sits in the app's environment (or `.env`), so a host
        compromise reads every secret in MySQL with no further
        privilege escalation. The point is local-dev parity, not
        defence in depth.
    """

    name = "local-dev"
    blob_prefix = "local:v1:"

    def __init__(self, key: bytes | str) -> None:
        """Initialise the backend.

        :param key: A urlsafe-base64 32-byte Fernet key. Generate one
            with :py:meth:`cryptography.fernet.Fernet.generate_key`.
        :raises ValueError: If the key is malformed.
        """
        if isinstance(key, str):
            key = key.encode("ascii")
        self._fernet = Fernet(key)

    @property
    def key_version(self) -> int:
        """LocalDevBackend does not rotate; returns ``1`` always."""
        return 1

    def encrypt(self, plaintext: bytes, *, context: str) -> str:
        context_bytes = context.encode("utf-8")
        if len(context_bytes) > 0xFFFF:
            raise ValueError(
                f"context too long ({len(context_bytes)} bytes > 65535)"
            )
        framed = (
            len(context_bytes).to_bytes(2, "big") + context_bytes + plaintext
        )
        token = self._fernet.encrypt(framed).decode("ascii")
        return self.blob_prefix + token

    def decrypt(self, blob: str, *, context: str) -> bytes:
        if not blob.startswith(self.blob_prefix):
            raise DecryptError(
                f"blob missing {self.blob_prefix!r} prefix; not a "
                f"{self.name} ciphertext"
            )
        token = blob[len(self.blob_prefix) :].encode("ascii")
        try:
            framed = self._fernet.decrypt(token)
        except InvalidToken as exc:
            raise DecryptError("local-dev decrypt failed") from exc

        context_len = int.from_bytes(framed[:2], "big")
        stored_context = framed[2 : 2 + context_len].decode("utf-8")
        if stored_context != context:
            raise DecryptError("local-dev decrypt failed")
        return framed[2 + context_len :]


# ---------------------------------------------------------------------------
# VaultTransitBackend
# ---------------------------------------------------------------------------


class VaultTransitBackend:
    """Production backend backed by Vault's Transit secrets engine.

    The Transit master key never leaves Vault: encrypt sends plaintext
    over the mTLS-protected connection (Phase 2d adds the mTLS part) and
    Vault returns ciphertext. The plaintext is base64-encoded on the
    wire as Transit requires. The Transit key is expected to have been
    created with ``derived=True`` so the context argument actually
    affects the derived data-encryption key — without ``derived=True``,
    Transit silently ignores the context and our row-swap defence
    disappears. :func:`make_backend` is responsible for setting this up
    when it provisions the key on first use.

    Blob format is whatever Transit returns: ``vault:vN:base64…`` where
    ``N`` is the key version. The version embedded in the blob lets
    Transit decrypt old blobs after a rotation, which is the
    foundational requirement for the ``crypto rewrap`` migration story.
    """

    name = "vault-transit"
    blob_prefix = "vault:"

    def __init__(
        self,
        client: hvac.Client,
        *,
        key_name: str,
        mount_point: str = "transit",
    ) -> None:
        """Initialise the backend.

        :param client: An authenticated ``hvac.Client``. Token / AppRole
            login is the caller's responsibility — we do not log in here
            so test code can pass a pre-authenticated client.
        :param key_name: Name of the Transit key. Must exist; this
            constructor does not call ``create_key`` to keep the
            backend dumb.
        :param mount_point: Transit mount path; defaults to
            ``"transit"`` (matches the cookbook).
        """
        self._client = client
        self._key_name = key_name
        self._mount_point = mount_point

    @property
    def key_version(self) -> int:
        from wg_manager.metrics import vault_call

        with vault_call(engine="transit", operation="read"):
            resp = self._client.secrets.transit.read_key(
                name=self._key_name, mount_point=self._mount_point
            )
        return int(resp["data"]["latest_version"])

    def encrypt(self, plaintext: bytes, *, context: str) -> str:
        from wg_manager.metrics import vault_call

        with vault_call(engine="transit", operation="encrypt"):
            resp = self._client.secrets.transit.encrypt_data(
                name=self._key_name,
                plaintext=base64.b64encode(plaintext).decode("ascii"),
                context=base64.b64encode(context.encode("utf-8")).decode("ascii"),
                mount_point=self._mount_point,
            )
        return resp["data"]["ciphertext"]

    def decrypt(self, blob: str, *, context: str) -> bytes:
        from wg_manager.metrics import vault_call

        if not blob.startswith(self.blob_prefix):
            raise DecryptError(
                f"blob missing {self.blob_prefix!r} prefix; not a "
                f"{self.name} ciphertext"
            )
        try:
            with vault_call(engine="transit", operation="decrypt"):
                resp = self._client.secrets.transit.decrypt_data(
                    name=self._key_name,
                    ciphertext=blob,
                    context=base64.b64encode(context.encode("utf-8")).decode("ascii"),
                    mount_point=self._mount_point,
                )
        except HvacInvalidRequest as exc:
            raise DecryptError("vault transit decrypt failed") from exc
        except HvacVaultError as exc:
            # Catches Forbidden, InternalServerError, …. Network errors
            # (ConnectionError etc.) are *not* DecryptError and must
            # propagate so the caller can distinguish "your blob is
            # broken" from "Vault is down".
            raise DecryptError("vault transit decrypt failed") from exc
        return base64.b64decode(resp["data"]["plaintext"])

    def rotate(self) -> None:
        """Bump the Transit key to a new version.

        Existing blobs continue to decrypt (Transit retains the old
        version); new writes use the new version. The ``crypto rewrap``
        CLI (Phase 2b follow-up) walks every row to upgrade existing
        ciphertext.
        """
        from wg_manager.metrics import vault_call

        with vault_call(engine="transit", operation="rotate"):
            self._client.secrets.transit.rotate_key(
                name=self._key_name, mount_point=self._mount_point
            )


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def make_backend(settings: Settings | None = None) -> CryptoBackend:
    """Construct the backend selected by ``settings.crypto_backend``.

    :param settings: An explicit :class:`Settings` instance. When
        ``None`` (the production path), the module-global
        :data:`wg_manager.config.settings` is used. Tests pass a
        freshly-instantiated ``Settings()`` so monkeypatched env vars
        take effect.
    :raises ValueError: If ``CRYPTO_BACKEND`` is missing required
        configuration or names an unknown backend. Failing here at
        construction time is intentional: a misconfigured app should
        refuse to start rather than silently fall back to plaintext.
    """
    if settings is None:
        from wg_manager.config import settings as _module_settings

        settings = _module_settings

    kind = settings.crypto_backend.lower()
    if kind == "local":
        if not settings.crypto_local_dev_key:
            raise ValueError(
                "CRYPTO_BACKEND=local requires CRYPTO_LOCAL_DEV_KEY to be set. "
                "Generate one with: python -c 'from cryptography.fernet import "
                "Fernet; print(Fernet.generate_key().decode())'"
            )
        return LocalDevBackend(settings.crypto_local_dev_key)

    if kind == "vault":
        if not settings.crypto_vault_token:
            raise ValueError(
                "CRYPTO_BACKEND=vault requires CRYPTO_VAULT_TOKEN (or VAULT_TOKEN) "
                "to be set. Phase 2e replaces this with AppRole."
            )
        client = hvac.Client(
            url=settings.crypto_vault_addr,
            token=settings.crypto_vault_token,
        )
        return VaultTransitBackend(
            client,
            key_name=settings.crypto_vault_transit_key,
            mount_point=settings.crypto_vault_transit_mount,
        )

    raise ValueError(
        f"unknown CRYPTO_BACKEND={settings.crypto_backend!r}; "
        f"must be 'local' or 'vault'"
    )


# ---------------------------------------------------------------------------
# Row-level helpers — historical
# ---------------------------------------------------------------------------
#
# Earlier phases ran two row-level seams through this module:
#
# * the SSH-key ciphertext helpers — retired in Alembic 0008 when the
#   row became a name-and-mode label and SSH auth started minting from
#   the CA at task time;
# * the manual-client WireGuard private-key helpers — retired in
#   Alembic 0009 because wg-manager has no operational use for the
#   private key of a device it can't log into, so persisting it was
#   pure liability.
#
# No row in the current schema carries encrypted secret material, so
# there is no row-level helper to expose. The :class:`CryptoBackend`
# infrastructure stays in place because the Vault Transit binding is
# the canonical substrate for any future encrypted-at-rest column.


__all__ = [
    "CryptoBackend",
    "CryptoError",
    "DecryptError",
    "LocalDevBackend",
    "VaultTransitBackend",
    "make_backend",
]
