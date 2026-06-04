"""Phase 3c — public API versioning seam.

Two pieces:

1. :class:`DeprecationMiddleware` — stamps RFC 9745
   ``Deprecation: true``, ``Sunset: <date>``, and ``Link: <...>;
   rel="deprecation"`` headers on every response from an *unprefixed*
   legacy path (anything that doesn't start with ``/v1`` and isn't
   on the exempt list). Also emits one structured
   ``api.deprecation`` audit line so operators can grep for legacy
   callers.
2. :func:`build_v1_openapi` — returns the filtered OpenAPI dict for
   ``/v1/openapi.json``. Strips every operation whose path is
   outside ``/v1`` and pins ``info.version`` to the v1 contract
   floor (``"1.0"``).

The split keeps the versioning concerns in one tight module rather
than scattering header-writing logic across every router.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Iterable

from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from wg_manager.audit import emit as _emit_audit
from wg_manager.config import Settings


# Paths that are operational/observability infrastructure rather
# than user-facing API surface — we don't want to stamp
# deprecation headers on them.
_EXEMPT_PREFIXES: tuple[str, ...] = (
    "/v1",
    "/openapi.json",
    "/v1/openapi.json",
    "/docs",
    "/redoc",
    "/metrics",
    # Phase 3d cycle 1 — load-balancer probes are infra, not API.
    "/healthz",
    "/readyz",
)


def _is_legacy_path(path: str) -> bool:
    """Return ``True`` iff ``path`` should carry the deprecation envelope."""
    if not path or path == "/":
        # Bare ``/`` is the FastAPI default redirect to /docs — not
        # part of the API contract.
        return False
    for prefix in _EXEMPT_PREFIXES:
        if path == prefix or path.startswith(prefix + "/"):
            return False
    return True


class DeprecationMiddleware(BaseHTTPMiddleware):
    """Stamp Deprecation/Sunset/Link on legacy paths + emit audit.

    Idempotent on the response — repeated invocations would overwrite
    the same headers with the same values, so re-mounting the
    middleware in a test app is safe.
    """

    def __init__(
        self,
        app: ASGIApp,
        settings: Settings | None = None,
    ) -> None:
        super().__init__(app)
        self._settings = settings or Settings()

    async def dispatch(  # type: ignore[override]
        self, request: Request, call_next
    ):
        response: Response = await call_next(request)
        path = request.url.path
        if not _is_legacy_path(path):
            return response

        response.headers["Deprecation"] = "true"
        response.headers["Sunset"] = self._settings.api_legacy_sunset_date
        response.headers["Link"] = (
            f'<{self._settings.api_deprecation_doc_url}>; '
            f'rel="deprecation"; type="text/html"'
        )

        # One audit line per legacy hit. Operators run a SIEM query
        # against ``event=api.deprecation`` to enumerate callers
        # still on the legacy surface.
        _emit_audit(
            "api.deprecation",
            path=path,
            method=request.method,
            sunset=self._settings.api_legacy_sunset_date,
        )
        return response


# ---------------------------------------------------------------------------
# OpenAPI surface
# ---------------------------------------------------------------------------


def build_v1_openapi(app: FastAPI) -> dict[str, Any]:
    """Return a filtered OpenAPI dict that contains only ``/v1`` paths.

    Used by the ``/v1/openapi.json`` handler. A standalone helper
    (rather than a closure inside ``create_app``) so tests can
    exercise the filter directly without spinning the app.

    The returned dict is a deep copy of FastAPI's ``app.openapi()``
    output — mutating it doesn't affect subsequent calls to
    ``app.openapi()``.
    """
    full = deepcopy(app.openapi())
    paths = full.get("paths", {})
    full["paths"] = {
        path: op for path, op in paths.items() if path.startswith("/v1")
    }
    # Pin the contract floor so a v1-typed client gets a stable
    # version string regardless of the wider wg-manager release.
    info = full.setdefault("info", {})
    info["version"] = "1.0"
    info["title"] = info.get("title", "wg-manager") + " (v1)"
    return full


__all__ = [
    "DeprecationMiddleware",
    "build_v1_openapi",
]
