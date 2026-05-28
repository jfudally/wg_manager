"""/crypto router — operator visibility into encryption-at-rest state.

The dashboard's "Crypto status" panel calls
:func:`get_crypto_status` to render:

* which backend is active (``local-dev`` vs ``vault-transit``);
* the current key version (Transit ``latest_version``; ``1`` for
  local-dev which does not rotate);
* per-table counts of how many rows are already encrypted vs. how many
  legacy plaintext-only rows remain.

These numbers drive two operator workflows:

* **Pre-drop-plaintext check.** Before applying the future migration
  that removes the plaintext columns, every legacy count must be zero.
* **Post-rotation visibility.** After a Transit key rotation, the
  active ``key_version`` bumps. The future ``crypto rewrap`` CLI uses
  the same numbers to decide which rows still ride an old version and
  need re-encrypting.

The endpoint is intentionally read-only and never returns plaintext or
ciphertext bodies — only counts and metadata — so it is safe to leave
unauthenticated through the Phase 2 window. Phase 2d's mTLS roll-out
will gate it like every other endpoint.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from wg_manager.crypto import CryptoBackend
from wg_manager.db import get_session
from wg_manager.deps import get_crypto_backend
from wg_manager.models import Client
from wg_manager.schemas import CryptoStatusResponse

router = APIRouter(prefix="/crypto", tags=["crypto"])

_SessionDep = Annotated[Session, Depends(get_session)]
_CryptoDep = Annotated[CryptoBackend, Depends(get_crypto_backend)]


@router.get("/status", response_model=CryptoStatusResponse)
def get_crypto_status(
    session: _SessionDep, crypto: _CryptoDep
) -> CryptoStatusResponse:
    """Return current encryption-at-rest state.

    Counting rules:

    * **client_encrypted** — manual ``Client`` rows with
      ``private_key_ct`` populated.
    * **client_legacy** — manual ``Client`` rows (``is_manual=True``)
      whose ``private_key_ct`` is ``NULL``. SSH-provisioned clients
      legitimately carry no key material and are excluded from both
      buckets — they have nothing to encrypt.

    Phase 2c CP4.4 dropped the sshkey ciphertext columns, so the
    ``SSHKey`` table no longer contributes to either bucket — every
    row is a name-and-mode label and SSH auth mints from the CA at
    task time.

    The key-version probe goes through the live backend so a Transit
    rotation that happened outside wg-manager is immediately visible
    here. For ``LocalDevBackend`` the version is always ``1``.
    """
    client_encrypted = 0
    client_legacy = 0
    for client_row in session.exec(select(Client)).all():
        if client_row.private_key_ct is not None:
            client_encrypted += 1
        elif client_row.is_manual:
            # SSH-provisioned clients legitimately have no key material;
            # only manual clients without ciphertext are "legacy".
            client_legacy += 1

    return CryptoStatusResponse(
        backend=crypto.name,
        key_version=crypto.key_version,
        client_encrypted=client_encrypted,
        client_legacy=client_legacy,
    )
