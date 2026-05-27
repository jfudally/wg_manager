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
from wg_manager.models import Client, SSHKey
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

    * **sshkey_encrypted** — ``SSHKey`` rows with ``private_key_ct``
      populated. The normal state for every row created via the
      FastAPI app post-Phase-2b.
    * **sshkey_legacy** — ``SSHKey`` rows where ``private_key_ct`` is
      ``NULL``. After Alembic 0005 dropped the plaintext columns the
      only way to land in this bucket is a direct INSERT that bypassed
      the encryption seam. Operators want this at zero; non-zero is a
      flag to inspect.
    * **client_encrypted** — manual ``Client`` rows with
      ``private_key_ct`` populated.
    * **client_legacy** — manual ``Client`` rows (``is_manual=True``)
      whose ``private_key_ct`` is ``NULL``. SSH-provisioned clients
      legitimately carry no key material and are excluded from both
      buckets — they have nothing to encrypt.

    The key-version probe goes through the live backend so a Transit
    rotation that happened outside wg-manager is immediately visible
    here. For ``LocalDevBackend`` the version is always ``1``.
    """
    sshkey_encrypted = 0
    sshkey_legacy = 0
    for sshkey_row in session.exec(select(SSHKey)).all():
        if sshkey_row.private_key_ct is not None:
            sshkey_encrypted += 1
        else:
            sshkey_legacy += 1

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
        sshkey_encrypted=sshkey_encrypted,
        sshkey_legacy=sshkey_legacy,
        client_encrypted=client_encrypted,
        client_legacy=client_legacy,
    )
