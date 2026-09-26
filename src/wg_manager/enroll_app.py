"""Phase 3f — ASGI app served on the enrollment-only listener.

This is a **separate** FastAPI application from
:func:`wg_manager.main.create_app`, not a filtered view of it. The
enrollment listener accepts TLS clients without a certificate (see
:func:`wg_manager.tls_listeners.enroll_ssl_kwargs`), so the safety
property "an anonymous caller can reach only enrollment" is enforced
by construction: no operator router is ever imported into this app.
``tests/test_enroll_listener.py`` checks that every route on the main
app 404s here.

Mounted surface:

* ``POST /v1/enroll`` — token redemption. **Spike stub**: returns 501
  until the Phase 3f MVP lands the token model.
* ``/healthz`` + ``/readyz`` (and ``/v1/`` twins) — the same probes as
  the operator app, so a load balancer can health-check this port too.

OpenAPI docs are disabled: this is a public listener and the schema
would only serve as a map for scanners.
"""

from __future__ import annotations

from fastapi import APIRouter, FastAPI, status
from fastapi.responses import JSONResponse

from wg_manager.routers import health

ENROLL_PATH = "/v1/enroll"

_router = APIRouter(tags=["enroll"])


@_router.post(ENROLL_PATH, status_code=status.HTTP_501_NOT_IMPLEMENTED)
def enroll() -> JSONResponse:
    """Redeem an enrollment token (spike stub).

    Always answers 501. The MVP will accept
    ``{wg_public_key, ssh_host_ed25519_pubkey, hostname}`` plus a
    bearer token and return the hub peer block, the SSH user CA and a
    signed host cert. See ``ROADMAP.md`` Phase 3f.

    :return: 501 with a short machine-readable detail.
    """
    return JSONResponse(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        content={"detail": "enrollment not implemented yet (Phase 3f spike)"},
    )


def create_enroll_app() -> FastAPI:
    """Build the enrollment-listener application.

    :return: A FastAPI app exposing only the enrollment route and the
        health probes, with docs / OpenAPI disabled.
    :rtype: FastAPI
    """
    application = FastAPI(
        title="wg-manager-enroll",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    application.include_router(_router)
    # Same dual mount as the operator app (Phase 3c contract) so an LB
    # probe config can be shared between the two listeners.
    application.include_router(health.router)
    application.include_router(health.router, prefix="/v1")
    return application
