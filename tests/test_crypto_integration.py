"""Integration helpers between :mod:`wg_manager.crypto` and the ORM rows.

The base backend (``CryptoBackend``) is row-agnostic: it just wraps bytes
under a context. These helpers know how to build that context from the
single remaining secret-bearing row — the manual :class:`Client` — and
which column to write the ciphertext into.

Phase 2c CP4.4 dropped the sshkey ciphertext columns entirely (the row
is name-and-mode only post-migration), so the prior ``encrypt_sshkey_*``
/ ``resolve_sshkey_*`` / ``set_sshkey_*`` helpers and their tests are
gone with them. The contract the remaining tests pin is:

* Round-trip: ``encrypt_client_private_key`` populates
  :attr:`Client.private_key_ct`; ``resolve_client_private_key`` decrypts
  it back to the original plaintext.
* SSH-provisioned clients carry no key material — the column is
  ``NULL`` and ``resolve_*`` returns ``None`` rather than raising.
* Context isolation: a row keyed at ``id=10`` cannot decrypt a blob
  produced for ``id=11``. This is the row-swap defence and the whole
  reason the helpers exist instead of calling ``backend.encrypt``
  directly at the call sites.
"""

from __future__ import annotations

import pytest

from wg_manager.crypto import (
    DecryptError,
    LocalDevBackend,
    encrypt_client_private_key,
    resolve_client_private_key,
)
from wg_manager.models import Client, NodeStatus


# A small, valid Fernet key generated for this module so the helpers can
# be exercised without touching the test conftest. Published in the repo —
# never use this for anything outside tests.
_TEST_FERNET_KEY = b"6BR-12U4QDta_TTnZnieCyvMU5VzRSnUqbH6hA80Ihw="


@pytest.fixture()
def backend() -> LocalDevBackend:
    """A throwaway LocalDevBackend instance for the helper tests."""
    return LocalDevBackend(_TEST_FERNET_KEY)


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
