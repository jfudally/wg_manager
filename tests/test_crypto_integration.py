"""Integration helpers between :mod:`wg_manager.crypto` and the ORM rows.

The base backend (``CryptoBackend``) is row-agnostic: it just wraps bytes
under a context. These helpers know how to build that context from a
:class:`SSHKey` or :class:`Client` row and which columns to write the
ciphertext into. Post-Phase-2b every secret-touching site funnels
through this seam — every read through ``resolve_*``, every write
through ``encrypt_*`` or the single-field setters.

These tests cover the contract:

* Round-trip: ``encrypt_*`` populates the ``_ct`` column; ``resolve_*``
  decrypts it back to the original plaintext.
* SSH-provisioned clients carry no key material — both columns NULL,
  and ``resolve_*`` returns ``None`` rather than raising.
* Context isolation: a row keyed at ``id=1`` cannot decrypt a blob
  produced for ``id=2``. This is the row-swap defence and the whole
  reason the helpers exist instead of calling ``backend.encrypt``
  directly at the call sites.
"""

from __future__ import annotations

import pytest

from wg_manager.crypto import (
    DecryptError,
    LocalDevBackend,
    encrypt_client_private_key,
    encrypt_sshkey_secrets,
    resolve_client_private_key,
    resolve_sshkey_passphrase,
    resolve_sshkey_private,
    set_sshkey_passphrase,
    set_sshkey_private,
)
from wg_manager.models import Client, NodeStatus, SSHKey


# A small, valid Fernet key generated for this module so the helpers can
# be exercised without touching the test conftest. Published in the repo —
# never use this for anything outside tests.
_TEST_FERNET_KEY = b"6BR-12U4QDta_TTnZnieCyvMU5VzRSnUqbH6hA80Ihw="


@pytest.fixture()
def backend() -> LocalDevBackend:
    """A throwaway LocalDevBackend instance for the helper tests."""
    return LocalDevBackend(_TEST_FERNET_KEY)


def _ssh_row(
    row_id: int = 1,
    *,
    private_key_ct: str | None = None,
    passphrase_ct: str | None = None,
) -> SSHKey:
    """Build an :class:`SSHKey` row without going through a Session.

    Post-Phase-2b the row holds only ciphertext columns; tests that
    want to exercise the encrypted path construct the row blank and
    then call :func:`encrypt_sshkey_secrets` to populate them.
    """
    row = SSHKey(id=row_id, name=f"ssh-{row_id}")
    row.private_key_ct = private_key_ct
    row.passphrase_ct = passphrase_ct
    return row


def _client_row(
    row_id: int = 1,
    *,
    private_key_ct: str | None = None,
) -> Client:
    """Build a manual :class:`Client` row."""
    row = Client(
        id=row_id,
        name=f"client-{row_id}",
        server_id=1,
        address="10.9.0.42/32",
        public_key="PUBKEY",
        is_manual=True,
        status=NodeStatus.ready,
    )
    row.private_key_ct = private_key_ct
    return row


# ---------------------------------------------------------------------------
# encrypt_sshkey_secrets / set_sshkey_private / set_sshkey_passphrase
# ---------------------------------------------------------------------------


class TestEncryptSSHKeySecrets:
    def test_populates_private_key_ct(self, backend: LocalDevBackend) -> None:
        row = _ssh_row(row_id=42)
        encrypt_sshkey_secrets(backend, row, private_key="THE-PEM")
        assert row.private_key_ct is not None
        assert row.private_key_ct.startswith(backend.blob_prefix)

    def test_populates_passphrase_ct_when_set(
        self, backend: LocalDevBackend
    ) -> None:
        row = _ssh_row(row_id=42)
        encrypt_sshkey_secrets(
            backend, row, private_key="x", passphrase="hunter2"
        )
        assert row.passphrase_ct is not None
        assert row.passphrase_ct.startswith(backend.blob_prefix)

    def test_leaves_passphrase_ct_null_when_unset(
        self, backend: LocalDevBackend
    ) -> None:
        """No passphrase argument means no ciphertext — don't conjure one up."""
        row = _ssh_row(row_id=42)
        encrypt_sshkey_secrets(backend, row, private_key="x", passphrase=None)
        assert row.passphrase_ct is None

    def test_requires_row_id(self, backend: LocalDevBackend) -> None:
        """No ID means no stable context binding — refuse to encrypt."""
        row = _ssh_row(row_id=1)
        row.id = None
        with pytest.raises(ValueError, match="id"):
            encrypt_sshkey_secrets(backend, row, private_key="x")


class TestSetSSHKeySingleField:
    """Single-field setters used by the PATCH router so a partial rotate
    does not burn a Vault encrypt on the untouched field."""

    def test_set_private_overwrites_existing_ciphertext(
        self, backend: LocalDevBackend
    ) -> None:
        row = _ssh_row(row_id=5)
        encrypt_sshkey_secrets(backend, row, private_key="first")
        first_ct = row.private_key_ct
        set_sshkey_private(backend, row, "second")
        assert row.private_key_ct != first_ct
        assert resolve_sshkey_private(backend, row) == "second"

    def test_set_passphrase_to_none_clears_column(
        self, backend: LocalDevBackend
    ) -> None:
        row = _ssh_row(row_id=5)
        encrypt_sshkey_secrets(
            backend, row, private_key="x", passphrase="initial"
        )
        assert row.passphrase_ct is not None
        set_sshkey_passphrase(backend, row, None)
        assert row.passphrase_ct is None


# ---------------------------------------------------------------------------
# resolve_sshkey_private / resolve_sshkey_passphrase
# ---------------------------------------------------------------------------


class TestResolveSSHKeyPrivate:
    def test_round_trip_via_ciphertext(self, backend: LocalDevBackend) -> None:
        row = _ssh_row(row_id=7)
        encrypt_sshkey_secrets(backend, row, private_key="THE-PEM")
        assert resolve_sshkey_private(backend, row) == "THE-PEM"

    def test_refuses_row_with_no_ciphertext(
        self, backend: LocalDevBackend
    ) -> None:
        """Every row must satisfy ``private_key_ct is not None`` post-0005.

        A NULL there means the row was inserted bypassing the
        encryption seam, which is a programming error worth shouting
        about rather than silently returning empty plaintext.
        """
        row = _ssh_row(row_id=7, private_key_ct=None)
        with pytest.raises(ValueError, match="private_key_ct"):
            resolve_sshkey_private(backend, row)

    def test_row_swap_refused(self, backend: LocalDevBackend) -> None:
        """Stealing a ciphertext from another row and pasting it in must
        not decrypt. This is the whole point of context-bound blobs."""
        donor = _ssh_row(row_id=1)
        encrypt_sshkey_secrets(backend, donor, private_key="donor-secret")
        victim = _ssh_row(row_id=2)
        encrypt_sshkey_secrets(backend, victim, private_key="victim-secret")
        # Operator-grade row swap: attacker pastes donor's ciphertext into
        # victim's row, hoping resolve_* will hand back donor's secret.
        victim.private_key_ct = donor.private_key_ct
        with pytest.raises(DecryptError):
            resolve_sshkey_private(backend, victim)


class TestResolveSSHKeyPassphrase:
    def test_returns_none_when_no_passphrase_set(
        self, backend: LocalDevBackend
    ) -> None:
        row = _ssh_row(row_id=1)
        encrypt_sshkey_secrets(backend, row, private_key="x", passphrase=None)
        assert resolve_sshkey_passphrase(backend, row) is None

    def test_round_trip_via_ciphertext(self, backend: LocalDevBackend) -> None:
        row = _ssh_row(row_id=1)
        encrypt_sshkey_secrets(
            backend, row, private_key="x", passphrase="hunter2"
        )
        assert resolve_sshkey_passphrase(backend, row) == "hunter2"


# ---------------------------------------------------------------------------
# encrypt_client_private_key / resolve_client_private_key
# ---------------------------------------------------------------------------


class TestClientPrivateKey:
    def test_round_trip(self, backend: LocalDevBackend) -> None:
        row = _client_row(row_id=3)
        encrypt_client_private_key(backend, row, private_key="WG-SECRET")
        assert row.private_key_ct is not None
        assert resolve_client_private_key(backend, row) == "WG-SECRET"

    def test_resolve_returns_none_when_unset(
        self, backend: LocalDevBackend
    ) -> None:
        """SSH-provisioned clients have ``private_key_ct=None`` — they
        never had a key to encrypt and ``resolve_*`` must tolerate
        that rather than raising."""
        row = _client_row(row_id=3, private_key_ct=None)
        assert resolve_client_private_key(backend, row) is None

    def test_row_swap_refused(self, backend: LocalDevBackend) -> None:
        donor = _client_row(row_id=10)
        encrypt_client_private_key(backend, donor, private_key="donor")
        victim = _client_row(row_id=11)
        encrypt_client_private_key(backend, victim, private_key="victim")
        victim.private_key_ct = donor.private_key_ct
        with pytest.raises(DecryptError):
            resolve_client_private_key(backend, victim)
