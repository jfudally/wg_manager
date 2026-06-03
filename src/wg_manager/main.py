"""FastAPI application factory for wg-manager.

Schema management is owned by Alembic — run ``alembic upgrade head`` (or
``make migrate``) before starting the API for the first time. The app does
not call ``create_all`` on its own.
"""

from __future__ import annotations

from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware

from wg_manager._tls_uvicorn import enable_tls_extension
from wg_manager.auth import MTLSAuthMiddleware
from wg_manager.config import Settings, settings
from wg_manager.metrics import MetricsMiddleware, metrics_response
from wg_manager.routers import (
    audit,
    certs,
    clients,
    crypto,
    servers,
    ssh_keys,
    tasks,
)

# uvicorn 0.44 doesn't implement the ASGI-TLS extension natively
# (encode/uvicorn#1530). Patch it at import time so the auth middleware
# can read scope["extensions"]["tls"]["client_cert_chain"] on every
# request. Idempotent — safe to call from any process that imports
# this module (including the ``--reload`` worker that re-imports
# ``wg_manager.main`` on every restart). See
# :mod:`wg_manager._tls_uvicorn` for the workaround details.
enable_tls_extension()


def _parse_cors_origins(raw: str) -> list[str]:
    """Split the comma-separated ``cors_origins`` setting into a list.

    Whitespace-only entries are skipped. A bare ``"*"`` is forwarded as-is
    so :class:`CORSMiddleware` can apply its wildcard behaviour.
    """
    return [o.strip() for o in raw.split(",") if o.strip()]


def create_app() -> FastAPI:
    """Build and return the FastAPI application.

    Reads :class:`wg_manager.config.Settings` afresh so an in-process
    test that flips an env var via ``monkeypatch.setenv`` then calls
    ``create_app()`` picks up the override — the module-level
    ``settings`` (imported at boot) doesn't.

    :return: Configured FastAPI app with all routers attached.
    :rtype: FastAPI
    """
    application = FastAPI(title="wg-manager", version="0.1.0")
    app_settings = Settings()

    # CORS is added *first* so it ends up *outermost* in the stack
    # (Starlette runs middleware in reverse-added order). That way the
    # CORS preflight headers are present even on a 401 from
    # :class:`MTLSAuthMiddleware`, so the dashboard sees a clean CORS
    # response with the auth failure inside the body — not a network
    # error from a missing ``Access-Control-Allow-Origin`` header.
    application.add_middleware(
        CORSMiddleware,
        allow_origins=_parse_cors_origins(app_settings.cors_origins),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Phase 2d CP2: per-request client-cert verification. Gated by
    # ``TLS_REQUIRED`` so the test suite (which never speaks TLS via
    # ``TestClient``) stays hermetic. Production posture is
    # ``TLS_REQUIRED=true`` — see ``.env.example``.
    application.add_middleware(MTLSAuthMiddleware, settings=app_settings)

    # Phase 3a cycle 1: Prometheus metrics. Added last so it runs
    # innermost (Starlette runs middleware in reverse-added order),
    # which means the recorded duration is the time spent in the
    # routers — auth + CORS overhead lives in the outer layers and
    # would distort the per-route latency histogram if included.
    # The middleware skips OPTIONS preflight and the /metrics path
    # itself; see :mod:`wg_manager.metrics`.
    application.add_middleware(MetricsMiddleware)

    application.include_router(ssh_keys.router)
    application.include_router(servers.router)
    application.include_router(clients.router)
    application.include_router(tasks.router)
    application.include_router(crypto.router)
    application.include_router(certs.router)
    application.include_router(audit.router)

    # Phase 3a cycle 1: /metrics endpoint exposes the Prometheus
    # registry in the standard text format. Sits behind the mTLS
    # listener like every other route — Prometheus scrapers
    # configure a client cert the same way operators do.
    @application.get("/metrics", include_in_schema=False)
    def metrics() -> Response:
        body, content_type = metrics_response()
        return Response(content=body, media_type=content_type)

    return application


app = create_app()
