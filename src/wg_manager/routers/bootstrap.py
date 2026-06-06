"""``POST /bootstrap-host`` — API surface for the dashboard's bootstrap flow.

Lifts the ``wg-manager bootstrap-host`` CLI onto the operator dashboard
so a fresh host can be onboarded without shelling into the prod stack.
The CLI still works; this router is the friendlier path for the same
work.

Security posture (load-bearing — read before touching this module):

* The operator's long-lived bootstrap key is uploaded **only** for the
  duration of one request. The router encrypts the PEM (and optional
  passphrase) via :mod:`wg_manager.crypto` before queueing so the
  broker (Valkey/Redis) only ever sees ciphertext. The plaintext
  exists for one frame inside the API request and one frame inside
  the Celery task — nowhere else.
* The key is **never** persisted to the DB and **never** echoed in
  responses. The 202 response carries the task ID and the hostname
  only; the dashboard polls ``GET /tasks/{task_id}`` for the cert
  metadata.
* Bootstrap does **not** create a ``server`` row. Two operator
  actions on purpose — see :mod:`wg_manager.bootstrap_ssh` and
  ``docs/operator-guide.md`` §3.

The encryption context is a fixed string so the task decrypts under
the same anchor; we use the route name so a future re-purposing of
the crypto backend (e.g. distinct domains per resource) can't
silently cross over.
"""

from __future__ import annotations

from typing import Final

from fastapi import APIRouter, status

from wg_manager.config import Settings
from wg_manager.crypto import make_backend as make_crypto_backend
from wg_manager.schemas import BootstrapHostRequest, BootstrapHostResponse
from wg_manager.tasks import bootstrap_host_task

router = APIRouter(tags=["bootstrap"])


_PEM_CONTEXT: Final[str] = "bootstrap-host:pem"
_PASSPHRASE_CONTEXT: Final[str] = "bootstrap-host:passphrase"


@router.post(
    "/bootstrap-host",
    response_model=BootstrapHostResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def bootstrap_host_endpoint(
    payload: BootstrapHostRequest,
) -> BootstrapHostResponse:
    """Encrypt the operator's bootstrap key and dispatch the install task.

    See module docstring for the security posture. The flow is:

    1. Resolve the SSH-CA settings so the task's TTL default mirrors
       the CLI's default.
    2. Encrypt ``payload.ssh_key_pem`` (and ``ssh_key_passphrase``
       when present) with the crypto backend. The contexts are fixed
       strings so the worker can decrypt against the same anchor.
    3. Dispatch :func:`wg_manager.tasks.bootstrap_host_task` with the
       ciphertext + bootstrap coordinates. The response carries the
       task ID; the dashboard polls ``GET /tasks/{task_id}`` for
       the cert serial + validity once the worker reports done.

    :param payload: Validated request body.
    :type payload: BootstrapHostRequest
    :return: ``{"task_id", "hostname"}``.
    :rtype: BootstrapHostResponse
    """
    settings = Settings()
    crypto = make_crypto_backend(settings)

    pem_ciphertext = crypto.encrypt(
        payload.ssh_key_pem.encode("utf-8"), context=_PEM_CONTEXT
    )
    passphrase_ciphertext: str | None = None
    passphrase_context: str | None = None
    if payload.ssh_key_passphrase is not None:
        passphrase_ciphertext = crypto.encrypt(
            payload.ssh_key_passphrase.encode("utf-8"),
            context=_PASSPHRASE_CONTEXT,
        )
        passphrase_context = _PASSPHRASE_CONTEXT

    effective_principal = payload.principal or payload.hostname
    effective_ttl = (
        payload.ttl_seconds
        if payload.ttl_seconds is not None
        else settings.ssh_host_cert_ttl_seconds
    )

    async_result = bootstrap_host_task.delay(
        hostname=payload.hostname,
        ssh_port=payload.ssh_port,
        ssh_user=payload.ssh_user,
        principal=effective_principal,
        ttl_seconds=effective_ttl,
        connect_timeout=payload.connect_timeout,
        pem_ciphertext=pem_ciphertext,
        pem_context=_PEM_CONTEXT,
        passphrase_ciphertext=passphrase_ciphertext,
        passphrase_context=passphrase_context,
    )

    return BootstrapHostResponse(
        task_id=async_result.id,
        hostname=payload.hostname,
    )
