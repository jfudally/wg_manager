"""/crypto router — operator visibility into the encryption-at-rest backend.

The dashboard's "Crypto status" panel calls :func:`get_crypto_status`
to render:

* which backend is active (``local-dev`` vs ``vault-transit``);
* the current key version (Transit ``latest_version``; ``1`` for
  local-dev which does not rotate).

After Alembic 0008 (sshkey ciphertext columns gone) and 0009 (manual-
client private-key ciphertext column gone), there is no row-level
secret material left in the schema, so the endpoint reports only the
backend identity and version. The Vault Transit binding still matters
— it remains the canonical substrate for any future encrypted-at-rest
column — and "is Vault healthy?" is the question this endpoint now
answers.

The endpoint is intentionally read-only and never returns plaintext or
ciphertext bodies — only metadata — so it is safe to leave
unauthenticated through the Phase 2 window. Phase 2d's mTLS roll-out
gates it like every other endpoint.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from wg_manager.crypto import CryptoBackend
from wg_manager.deps import get_crypto_backend
from wg_manager.schemas import CryptoStatusResponse

router = APIRouter(prefix="/crypto", tags=["crypto"])

_CryptoDep = Annotated[CryptoBackend, Depends(get_crypto_backend)]


@router.get("/status", response_model=CryptoStatusResponse)
def get_crypto_status(crypto: _CryptoDep) -> CryptoStatusResponse:
    """Return current encryption-at-rest backend state.

    The key-version probe goes through the live backend so a Transit
    rotation that happened outside wg-manager is immediately visible
    here. For ``LocalDevBackend`` the version is always ``1``.
    """
    return CryptoStatusResponse(
        backend=crypto.name,
        key_version=crypto.key_version,
    )
