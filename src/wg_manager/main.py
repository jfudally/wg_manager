"""FastAPI application factory for wg-manager.

Schema management is owned by Alembic — run ``alembic upgrade head`` (or
``make migrate``) before starting the API for the first time. The app does
not call ``create_all`` on its own.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from wg_manager.config import settings
from wg_manager.routers import clients, crypto, servers, ssh_keys, tasks


def _parse_cors_origins(raw: str) -> list[str]:
    """Split the comma-separated ``cors_origins`` setting into a list.

    Whitespace-only entries are skipped. A bare ``"*"`` is forwarded as-is
    so :class:`CORSMiddleware` can apply its wildcard behaviour.
    """
    return [o.strip() for o in raw.split(",") if o.strip()]


def create_app() -> FastAPI:
    """Build and return the FastAPI application.

    :return: Configured FastAPI app with all routers attached.
    :rtype: FastAPI
    """
    application = FastAPI(title="wg-manager", version="0.1.0")

    # The Next.js dashboard in ``web/`` calls the API from the browser, so
    # we need CORS headers. Origins are configurable via the
    # ``CORS_ORIGINS`` env var — see :class:`wg_manager.config.Settings`.
    application.add_middleware(
        CORSMiddleware,
        allow_origins=_parse_cors_origins(settings.cors_origins),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    application.include_router(ssh_keys.router)
    application.include_router(servers.router)
    application.include_router(clients.router)
    application.include_router(tasks.router)
    application.include_router(crypto.router)
    return application


app = create_app()
