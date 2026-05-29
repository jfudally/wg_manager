"""Tests for :func:`wg_manager.main.create_app` mTLS wiring (Phase 2d CP2).

Pins three contracts on the app factory:

* :class:`wg_manager.auth.MTLSAuthMiddleware` is installed in the app's
  middleware stack.
* Under ``tls_required=True`` a normal handler 401s when the
  ``TestClient`` doesn't inject a client cert chain — proves the
  middleware is *active*, not just present.
* OPTIONS preflight from a CORS-allowed origin succeeds under
  ``tls_required=True``. This pins the middleware ordering invariant:
  ``MTLSAuthMiddleware`` must short-circuit on OPTIONS *or* sit inside
  the CORS middleware so the CORS preflight response is what the
  browser sees. Either ordering choice the implementation makes is
  fine as long as the preflight returns 200 with the CORS headers.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from wg_manager.auth import MTLSAuthMiddleware
from wg_manager.config import Settings
from wg_manager.main import create_app


def _middleware_classes(app) -> list[type]:
    """Return the middleware class chain installed on ``app``.

    Starlette / FastAPI keep middleware in ``app.user_middleware`` as a
    list of :class:`starlette.middleware.Middleware` records; each
    record's ``cls`` is the middleware class. Walking that list is
    the lowest-friction way to assert "middleware X is installed"
    without spinning up a TestClient.
    """
    return [m.cls for m in app.user_middleware]


class TestCreateAppInstallsMTLSMiddleware:
    """``create_app()`` wires the mTLS middleware into the stack."""

    def test_mtls_middleware_present_exactly_once(self) -> None:
        app = create_app()
        classes = _middleware_classes(app)
        count = sum(1 for c in classes if c is MTLSAuthMiddleware)
        assert count == 1, (
            f"expected exactly one MTLSAuthMiddleware in stack; "
            f"got {count} (stack: {[c.__name__ for c in classes]})"
        )

    def test_tls_required_blocks_request_without_cert(
        self, monkeypatch
    ) -> None:
        """Flipping ``tls_required=True`` at app-build time produces a 401
        on a normal route (the TestClient never injects a cert chain),
        proving the middleware is enforcing — not just present in the
        stack."""
        monkeypatch.setenv("TLS_REQUIRED", "true")
        # ``create_app`` reads from a fresh ``Settings()`` at call time,
        # which picks up the monkey-patched env. The previously-imported
        # module-level ``app`` is unaffected.
        app = create_app()

        # Sanity: settings did pick up the override.
        assert Settings().tls_required is True

        client = TestClient(app)
        # Hit a route that doesn't depend on the DB — the middleware
        # short-circuits with 401 before routing, so this proves the
        # enforcement path is active without needing the in-memory
        # engine fixture.
        resp = client.get("/this-route-does-not-exist")
        assert resp.status_code == 401
        assert resp.json() == {"detail": "client cert required"}

    def test_options_preflight_succeeds_under_tls_required(
        self, monkeypatch
    ) -> None:
        """A CORS preflight from a configured origin must succeed even
        when ``tls_required=True`` — the browser can't send the cert
        until preflight clears."""
        monkeypatch.setenv("TLS_REQUIRED", "true")
        app = create_app()
        client = TestClient(app)

        resp = client.options(
            "/this-route-does-not-exist",
            headers={
                "Origin": "http://localhost:3100",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "content-type",
            },
        )
        assert resp.status_code != 401, (
            "OPTIONS preflight blocked by mTLS — dashboard CORS will "
            "fail in production"
        )
        # The CORS middleware should have echoed our origin back. The
        # dashboard binds 127.0.0.1:3100 (Rancher Desktop holds :3000),
        # so the configured origin matches the BFF host.
        assert (
            resp.headers.get("access-control-allow-origin")
            == "http://localhost:3100"
        )
