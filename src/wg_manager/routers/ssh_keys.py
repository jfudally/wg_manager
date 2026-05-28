"""/ssh-keys router — CRUD over stored SSH credentials."""

from __future__ import annotations

import base64
import binascii
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, select

from wg_manager.config import Settings
from wg_manager.crypto import (
    CryptoBackend,
    encrypt_sshkey_secrets,
    set_sshkey_passphrase,
    set_sshkey_private,
)
from wg_manager.db import get_session
from wg_manager.deps import get_crypto_backend
from wg_manager.models import Client, SSHKey, Server
from wg_manager.schemas import (
    SSHKeyCreate,
    SSHKeyMigrateToCARequest,
    SSHKeyMigrateToCAResponse,
    SSHKeyRead,
    SSHKeyUpdate,
)
from wg_manager.ssh_migrate import migrate_key_to_ca

router = APIRouter(prefix="/ssh-keys", tags=["ssh-keys"])

_SessionDep = Annotated[Session, Depends(get_session)]
_CryptoDep = Annotated[CryptoBackend, Depends(get_crypto_backend)]


@router.post("", response_model=SSHKeyRead, status_code=status.HTTP_201_CREATED)
def create_ssh_key(
    payload: SSHKeyCreate, session: _SessionDep, crypto: _CryptoDep
) -> SSHKey:
    """Register a new SSH key. The private key body is never returned.

    Post-Phase-2b the row stores ciphertext only — the legacy plaintext
    columns were dropped in Alembic revision 0005. The handler keeps
    the decoded PEM in a local variable, INSERTs the row (no secrets
    yet) so it gets an ``id``, then encrypts the plaintext into the
    ``_ct`` columns under the row's per-row context. The two-commit
    pattern is required because the per-row context binding embeds
    ``row.id``, which only exists after the first flush.
    """
    existing = session.exec(select(SSHKey).where(SSHKey.name == payload.name)).first()
    if existing is not None:
        raise HTTPException(status_code=409, detail=f"SSH key named {payload.name!r} already exists")
    try:
        pem_bytes = base64.b64decode(payload.private_key_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(
            status_code=422,
            detail=f"private_key_b64 is not valid base64: {exc}",
        ) from exc
    private_key_plaintext = pem_bytes.decode("utf-8")
    row = SSHKey(name=payload.name)
    session.add(row)
    session.commit()
    session.refresh(row)
    encrypt_sshkey_secrets(
        crypto,
        row,
        private_key=private_key_plaintext,
        passphrase=payload.passphrase,
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    return row


@router.get("", response_model=list[SSHKeyRead])
def list_ssh_keys(session: _SessionDep) -> list[SSHKey]:
    """List all registered SSH keys (metadata only)."""
    return list(session.exec(select(SSHKey)).all())


@router.get("/{key_id}", response_model=SSHKeyRead)
def get_ssh_key(key_id: int, session: _SessionDep) -> SSHKey:
    """Return metadata for a single SSH key."""
    row = session.get(SSHKey, key_id)
    if row is None:
        raise HTTPException(status_code=404, detail="SSH key not found")
    return row


@router.patch("/{key_id}", response_model=SSHKeyRead)
def update_ssh_key(
    key_id: int,
    payload: SSHKeyUpdate,
    session: _SessionDep,
    crypto: _CryptoDep,
) -> SSHKey:
    """Partially update an SSH key.

    Any subset of ``name``, ``passphrase`` and ``private_key_b64`` may be
    supplied; omitted (or explicitly ``null``) fields are left unchanged on
    the row. The response continues to use :class:`SSHKeyRead` and never
    echoes the private key body or passphrase back, even when those were
    just rotated by this same request.

    Behaviour mirrors :func:`update_server` / :func:`update_client`:

    * **404** if no key with ``key_id`` exists.
    * **409** if ``name`` collides with a *different* key's name (renaming
      a key onto its own existing name is a no-op and returns 200).
    * **422** if ``private_key_b64`` is supplied but does not decode as
      valid base64 — the row is not touched in that case.

    Rotating the private key body does **not** automatically reprovision
    nodes that still reference this key; servers and clients pick up the
    new credential the next time they SSH out (i.e. on their next
    provision / reprovision / discover call).

    :param key_id: Primary key of the :class:`SSHKey` row to update.
    :type key_id: int
    :param payload: Partial update payload.
    :type payload: SSHKeyUpdate
    :return: The updated row, serialised via :class:`SSHKeyRead`.
    :rtype: SSHKey
    :raises HTTPException: 404 / 409 / 422 as documented above.
    """
    row = session.get(SSHKey, key_id)
    if row is None:
        raise HTTPException(status_code=404, detail="SSH key not found")

    updates = payload.model_dump(exclude_unset=True, exclude_none=True)

    new_name = updates.get("name")
    if new_name is not None and new_name != row.name:
        collision = session.exec(
            select(SSHKey).where(SSHKey.name == new_name)
        ).first()
        if collision is not None:
            raise HTTPException(
                status_code=409,
                detail=f"SSH key named {new_name!r} already exists",
            )

    new_pem_b64 = updates.pop("private_key_b64", None)
    new_passphrase_supplied = "passphrase" in updates
    new_passphrase_value = updates.pop("passphrase", None)

    new_private_key_plaintext: str | None = None
    if new_pem_b64 is not None:
        try:
            pem_bytes = base64.b64decode(new_pem_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise HTTPException(
                status_code=422,
                detail=f"private_key_b64 is not valid base64: {exc}",
            ) from exc
        new_private_key_plaintext = pem_bytes.decode("utf-8")

    for field, value in updates.items():
        setattr(row, field, value)

    # Re-encrypt only the field(s) the operator actually rotated.
    # Reading the untouched secret (to encrypt back unchanged) means
    # one Vault decrypt + encrypt round-trip per untouched field per
    # PATCH; touching only the rotated columns keeps PATCH cheap.
    if new_private_key_plaintext is not None:
        set_sshkey_private(crypto, row, new_private_key_plaintext)
    if new_passphrase_supplied:
        set_sshkey_passphrase(crypto, row, new_passphrase_value)

    session.add(row)
    session.commit()
    session.refresh(row)
    return row


@router.post(
    "/{key_id}/migrate-to-ca",
    response_model=SSHKeyMigrateToCAResponse,
    status_code=status.HTTP_200_OK,
)
def migrate_ssh_key_to_ca(
    key_id: int,
    payload: SSHKeyMigrateToCARequest,
    session: _SessionDep,
) -> SSHKeyMigrateToCAResponse:
    """Bootstrap each server using ``key_id`` and flip the row to CA mode.

    Phase 2c CP4.2 — closes the chicken-and-egg gap CP4.1 left behind.
    The endpoint accepts a one-shot ``private_key_b64`` body, opens a
    legacy SSH session to each server that references the key, installs
    the CA trust anchor + signed host cert, and (iff every server
    succeeded) flips the row to ``mode=ca`` and nulls the ciphertext
    columns. See :func:`wg_manager.ssh_migrate.migrate_key_to_ca` for
    the full mutation contract and partial-failure semantics.

    Always returns 200 on a well-formed call — partial failure is
    encoded in the per-server result list, not in the HTTP status, so
    the dashboard and CLI render the per-host outcome table uniformly.

    :raises HTTPException: 404 if ``key_id`` is unknown; 422 if
        ``private_key_b64`` is not valid base64.
    """
    row = session.get(SSHKey, key_id)
    if row is None:
        raise HTTPException(status_code=404, detail="SSH key not found")

    try:
        pem_bytes = base64.b64decode(payload.private_key_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(
            status_code=422,
            detail=f"private_key_b64 is not valid base64: {exc}",
        ) from exc
    private_key_pem = pem_bytes.decode("utf-8")

    results = migrate_key_to_ca(
        session=session,
        key=row,
        private_key_pem=private_key_pem,
        passphrase=payload.passphrase,
        settings=Settings(),
    )

    ok = sum(1 for r in results if r.status == "ok")
    failed = sum(1 for r in results if r.status != "ok")

    # Re-read the row to surface the final mode (the helper may or may
    # not have flipped it depending on per-server outcomes).
    session.refresh(row)

    return SSHKeyMigrateToCAResponse(
        key_id=row.id or key_id,
        name=row.name,
        mode=row.mode,
        servers_total=len(results),
        servers_ok=ok,
        servers_failed=failed,
        results=results,
    )


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_ssh_key(key_id: int, session: _SessionDep) -> None:
    """Delete an SSH key. Returns 409 if still referenced by a server or client."""
    row = session.get(SSHKey, key_id)
    if row is None:
        raise HTTPException(status_code=404, detail="SSH key not found")

    ref_server = session.exec(select(Server).where(Server.ssh_key_id == key_id)).first()
    ref_client = session.exec(select(Client).where(Client.ssh_key_id == key_id)).first()
    if ref_server is not None or ref_client is not None:
        raise HTTPException(
            status_code=409,
            detail="SSH key is still referenced by a server or client",
        )

    session.delete(row)
    session.commit()
    return None
