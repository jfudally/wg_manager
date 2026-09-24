"""Shared helper: encrypt registration-time SSH-CA bootstrap material.

Both ``POST /servers`` and ``POST /clients`` accept an optional operator
OOB SSH key (see :class:`wg_manager.schemas.BootstrapKeyFields`). This
module turns that plaintext into crypto-backend ciphertext + context
pairs before the router queues the provisioning task, so the Celery
broker never carries plaintext key material. The task layer decrypts
in worker memory (:func:`wg_manager.tasks._run_bootstrap_if_supplied`).
"""

from __future__ import annotations

from typing import Literal

from wg_manager.config import settings
from wg_manager.crypto import make_backend as make_crypto_backend
from wg_manager.schemas import BootstrapKeyFields


def encrypt_bootstrap_kwargs(
    payload: BootstrapKeyFields, *, node_kind: Literal["server", "client"]
) -> dict[str, str | None]:
    """Encrypt the bootstrap PEM/passphrase into task kwargs.

    :param payload: The validated registration body. Only its
        ``bootstrap_ssh_key_pem`` / ``bootstrap_ssh_key_passphrase``
        fields are read.
    :param node_kind: ``"server"`` or ``"client"``. Scopes the
        encryption context (``provision-<kind>:bootstrap-pem``) so a
        ciphertext minted for one task can't be replayed into the other
        under a context-binding crypto backend (Vault Transit derived
        keys).
    :return: The four ``bootstrap_*`` kwargs accepted by
        ``provision_server_task`` / ``provision_client_task``. Every
        value is ``None`` when no PEM was supplied, which makes the task
        skip the bootstrap step entirely.
    """
    kwargs: dict[str, str | None] = {
        "bootstrap_pem_ciphertext": None,
        "bootstrap_pem_context": None,
        "bootstrap_passphrase_ciphertext": None,
        "bootstrap_passphrase_context": None,
    }
    if payload.bootstrap_ssh_key_pem is None:
        return kwargs

    crypto = make_crypto_backend(settings)
    pem_context = f"provision-{node_kind}:bootstrap-pem"
    kwargs["bootstrap_pem_context"] = pem_context
    kwargs["bootstrap_pem_ciphertext"] = crypto.encrypt(
        payload.bootstrap_ssh_key_pem.encode("utf-8"), context=pem_context
    )
    if payload.bootstrap_ssh_key_passphrase is not None:
        passphrase_context = f"provision-{node_kind}:bootstrap-passphrase"
        kwargs["bootstrap_passphrase_context"] = passphrase_context
        kwargs["bootstrap_passphrase_ciphertext"] = crypto.encrypt(
            payload.bootstrap_ssh_key_passphrase.encode("utf-8"),
            context=passphrase_context,
        )
    return kwargs
