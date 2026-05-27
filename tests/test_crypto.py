"""Tests for :mod:`wg_manager.crypto` — Phase 2b encryption at rest.

Both :class:`LocalDevBackend` (Fernet) and :class:`VaultTransitBackend`
(hvac → Vault Transit) implement the same :class:`CryptoBackend`
protocol. The parameterised matrix in :class:`TestCryptoBackends` proves
they share observable behaviour — round-trip, context binding, tamper
detection — so production callers never need to know which backend is
active.

Vault-backed cases are auto-skipped when no Vault is reachable at
``$VAULT_ADDR`` (default ``http://127.0.0.1:8200``). The plain
``pytest -q`` run stays hermetic; ``make vault-up`` + ``pytest -q``
exercises the full matrix. Phase 2b's acceptance criteria require both
modes green.
"""

from __future__ import annotations

import os

import hvac
import pytest
import requests
from cryptography.fernet import Fernet
from hvac.exceptions import InvalidRequest as HvacInvalidRequest

from wg_manager.config import Settings
from wg_manager.crypto import (
    CryptoBackend,
    DecryptError,
    LocalDevBackend,
    VaultTransitBackend,
    make_backend,
)


# ---------------------------------------------------------------------------
# Vault availability probe
# ---------------------------------------------------------------------------

_VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
_VAULT_TOKEN = os.environ.get("VAULT_TOKEN", "dev-only-root")


def _vault_reachable() -> bool:
    """Return ``True`` if a Vault listener answers at ``$VAULT_ADDR``.

    Used by the ``vault_backend`` fixture to decide whether to skip the
    Vault half of the parameterised matrix. The probe uses a 0.5s
    timeout — if the operator wanted Vault tests they'd have already
    brought it up; we don't want to block the local-only run.
    """
    try:
        resp = requests.get(f"{_VAULT_ADDR}/v1/sys/health", timeout=0.5)
        return resp.status_code < 500
    except requests.RequestException:
        return False


_VAULT_AVAILABLE = _vault_reachable()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def local_backend() -> LocalDevBackend:
    """A LocalDevBackend keyed by a freshly-generated Fernet key."""
    return LocalDevBackend(Fernet.generate_key())


@pytest.fixture
def vault_backend(request: pytest.FixtureRequest) -> VaultTransitBackend:
    """A VaultTransitBackend talking to the dev container.

    Each test gets its own Transit key (named after the test node) so
    rotation tests can't contaminate round-trip tests. The Transit key
    is created with ``derived=True`` so the context argument is actually
    cryptographically bound to the ciphertext rather than ignored.
    """
    if not _VAULT_AVAILABLE:
        pytest.skip(f"Vault not reachable at {_VAULT_ADDR}")
    client = hvac.Client(url=_VAULT_ADDR, token=_VAULT_TOKEN)
    try:
        client.sys.enable_secrets_engine(backend_type="transit", path="transit")
    except HvacInvalidRequest as exc:
        if "path is already in use" not in str(exc):
            raise

    # Sanitised node id: pytest can include square brackets and slashes.
    suffix = (
        request.node.name.replace("[", "-")
        .replace("]", "")
        .replace("/", "-")
        .lower()
    )
    key_name = f"wg-manager-test-{suffix}"[:64]
    client.secrets.transit.create_key(name=key_name, derived=True)
    return VaultTransitBackend(client, key_name=key_name)


@pytest.fixture(params=["local", "vault"])
def backend(request: pytest.FixtureRequest) -> CryptoBackend:
    """Yield each backend in turn so contract tests run against both."""
    return request.getfixturevalue(f"{request.param}_backend")


# ---------------------------------------------------------------------------
# Shared contract tests
# ---------------------------------------------------------------------------


class TestCryptoBackends:
    """Behaviours every backend must satisfy."""

    _PEM = (
        b"-----BEGIN OPENSSH PRIVATE KEY-----\n"
        b"REDACTEDBODY\n"
        b"-----END OPENSSH PRIVATE KEY-----\n"
    )

    def test_round_trip_text(self, backend: CryptoBackend) -> None:
        blob = backend.encrypt(self._PEM, context="sshkey:1")
        assert backend.decrypt(blob, context="sshkey:1") == self._PEM

    def test_round_trip_binary(self, backend: CryptoBackend) -> None:
        plaintext = bytes(range(256))
        blob = backend.encrypt(plaintext, context="sshkey:1")
        assert backend.decrypt(blob, context="sshkey:1") == plaintext

    def test_round_trip_empty(self, backend: CryptoBackend) -> None:
        blob = backend.encrypt(b"", context="sshkey:1")
        assert backend.decrypt(blob, context="sshkey:1") == b""

    def test_round_trip_large(self, backend: CryptoBackend) -> None:
        plaintext = b"X" * 10_000
        blob = backend.encrypt(plaintext, context="sshkey:1")
        assert backend.decrypt(blob, context="sshkey:1") == plaintext

    def test_blob_carries_backend_prefix(self, backend: CryptoBackend) -> None:
        """Blob prefix lets the migration CLI and UI tell legacy from encrypted."""
        blob = backend.encrypt(b"x", context="c")
        assert blob.startswith(backend.blob_prefix), (
            f"{backend.name}: blob {blob[:16]!r} missing prefix {backend.blob_prefix!r}"
        )

    def test_ciphertext_is_non_deterministic(self, backend: CryptoBackend) -> None:
        """Same plaintext + context must produce different ciphertext each call.

        Both backends use random IV/nonce; deterministic encryption would
        let a DB-read attacker recognise repeated values.
        """
        a = backend.encrypt(b"secret", context="sshkey:1")
        b = backend.encrypt(b"secret", context="sshkey:1")
        assert a != b

    def test_wrong_context_rejects_decrypt(self, backend: CryptoBackend) -> None:
        """Defeats row-swap attacks (a DB-read attacker who moves blob A→B)."""
        blob = backend.encrypt(b"secret", context="sshkey:1")
        with pytest.raises(DecryptError):
            backend.decrypt(blob, context="sshkey:2")

    def test_tamper_detection(self, backend: CryptoBackend) -> None:
        """Flipping a byte in the body must invalidate the blob."""
        blob = backend.encrypt(b"secret", context="sshkey:1")
        # Mutate a character well past the prefix.
        idx = len(blob) // 2
        flipped = "A" if blob[idx] != "A" else "B"
        tampered = blob[:idx] + flipped + blob[idx + 1 :]
        assert tampered != blob, "test mutation was a no-op"
        with pytest.raises(DecryptError):
            backend.decrypt(tampered, context="sshkey:1")


# ---------------------------------------------------------------------------
# Factory selection
# ---------------------------------------------------------------------------


class TestMakeBackend:
    """``make_backend()`` reads settings and returns the right backend."""

    def test_local_backend_selected_by_settings(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        key = Fernet.generate_key().decode()
        monkeypatch.setenv("CRYPTO_BACKEND", "local")
        monkeypatch.setenv("CRYPTO_LOCAL_DEV_KEY", key)
        backend = make_backend(Settings())
        assert isinstance(backend, LocalDevBackend)
        # Sanity round-trip so we know the key actually loaded.
        assert backend.decrypt(backend.encrypt(b"hi", context="c"), context="c") == b"hi"

    def test_vault_backend_selected_by_settings(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        if not _VAULT_AVAILABLE:
            pytest.skip(f"Vault not reachable at {_VAULT_ADDR}")
        monkeypatch.setenv("CRYPTO_BACKEND", "vault")
        monkeypatch.setenv("VAULT_ADDR", _VAULT_ADDR)
        monkeypatch.setenv("VAULT_TOKEN", _VAULT_TOKEN)
        monkeypatch.setenv("CRYPTO_VAULT_TRANSIT_KEY", "wg-manager-make-backend")
        backend = make_backend(Settings())
        assert isinstance(backend, VaultTransitBackend)

    def test_unknown_backend_value_is_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CRYPTO_BACKEND", "magical-realism")
        with pytest.raises(ValueError, match="magical-realism"):
            make_backend(Settings())

    def test_local_backend_demands_dev_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Refuse to construct a LocalDevBackend with no key — a Fernet with
        an implicit/random key would silently lose every blob across restart."""
        monkeypatch.setenv("CRYPTO_BACKEND", "local")
        monkeypatch.delenv("CRYPTO_LOCAL_DEV_KEY", raising=False)
        with pytest.raises(ValueError, match="CRYPTO_LOCAL_DEV_KEY"):
            make_backend(Settings())


# ---------------------------------------------------------------------------
# Vault-specific: key rotation
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _VAULT_AVAILABLE, reason="Vault not reachable")
class TestVaultRotation:
    """Behaviours that depend on Transit's versioned key model.

    Phase 2b ships a ``wg-manager crypto rewrap`` CLI that upgrades
    existing ciphertext to the latest key version. Those tests live in
    the CLI test module once the command is wired; here we just prove
    the backend tolerates rotation.
    """

    def test_old_ciphertext_decrypts_after_rotation(
        self, vault_backend: VaultTransitBackend
    ) -> None:
        old_blob = vault_backend.encrypt(b"before-rotation", context="sshkey:1")
        vault_backend.rotate()
        new_blob = vault_backend.encrypt(b"after-rotation", context="sshkey:1")

        assert vault_backend.decrypt(old_blob, context="sshkey:1") == b"before-rotation"
        assert vault_backend.decrypt(new_blob, context="sshkey:1") == b"after-rotation"
        # Vault embeds the key version in the blob: vault:vN:…
        assert old_blob.startswith("vault:v")
        assert new_blob.startswith("vault:v")
        assert old_blob.split(":")[1] != new_blob.split(":")[1]

    def test_key_version_advances_after_rotation(
        self, vault_backend: VaultTransitBackend
    ) -> None:
        before = vault_backend.key_version
        vault_backend.rotate()
        after = vault_backend.key_version
        assert after == before + 1
