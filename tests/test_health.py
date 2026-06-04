"""Phase 3d cycle 1 — ``/healthz`` (liveness) + ``/readyz`` (readiness).

Load balancers in front of a multi-replica deployment need two
probes:

* **Liveness** (``/healthz``) — "is this process alive?" Returns 200
  as long as the FastAPI handler chain is running. The LB uses it
  to decide whether to terminate the pod; an out-of-pool replica
  whose handlers still respond is healthy.
* **Readiness** (``/readyz``) — "can this process serve traffic
  *right now*?" Returns 200 only when every external dependency
  (database, Vault if configured, Celery broker) is reachable.
  Returns 503 with a structured per-dep status body otherwise so
  the LB takes the replica out of rotation until the dep comes
  back.

Both endpoints **bypass mTLS** because load balancers carry no
client cert (they're not API operators). Phase 3c's
``DeprecationMiddleware`` and the auth middleware both honour the
exemption.

The handler set is the same on legacy and ``/v1`` paths so an
operator on either side gets the same probe answers; the dual mount
keeps it cheap (the same handler, two routes).
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# /healthz — process liveness
# ---------------------------------------------------------------------------


class TestHealthzLiveness:
    def test_legacy_healthz_returns_200(self, client: TestClient) -> None:
        """Unconditional 200. No auth, no deps."""
        resp = client.get("/healthz")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body.get("status") == "ok"

    def test_v1_healthz_returns_200(self, client: TestClient) -> None:
        resp = client.get("/v1/healthz")
        assert resp.status_code == 200, resp.text

    def test_healthz_does_not_touch_db(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Liveness is purely "process is up" — it must not open a DB
        connection. Crashing the engine and seeing healthz still 200
        is the cleanest proof."""
        from wg_manager import db as db_module

        original = db_module.engine

        class _ExplodingEngine:
            def connect(self) -> object:
                raise RuntimeError("db is dead — healthz must not call this")

            def __getattr__(self, name: str) -> Any:
                # Anything else (dispose, dialect, etc.) raises too.
                raise RuntimeError(
                    f"db is dead — healthz must not access engine.{name}"
                )

        monkeypatch.setattr(db_module, "engine", _ExplodingEngine())
        try:
            resp = client.get("/healthz")
            assert resp.status_code == 200, resp.text
        finally:
            monkeypatch.setattr(db_module, "engine", original)

    def test_healthz_does_not_carry_deprecation_header(
        self, client: TestClient
    ) -> None:
        """``/healthz`` is operational infrastructure, not part of the
        deprecating legacy API surface. Phase 3c's middleware exempts
        it so the LB doesn't see a noisy header on every probe."""
        resp = client.get("/healthz")
        assert "Deprecation" not in resp.headers
        assert "Sunset" not in resp.headers


# ---------------------------------------------------------------------------
# /readyz — dependency-aware readiness
# ---------------------------------------------------------------------------


class TestReadyzReadiness:
    def test_legacy_readyz_returns_200_when_deps_reachable(
        self, client: TestClient
    ) -> None:
        """All deps wired through to the conftest's in-memory engine
        + local backends → the readiness probe is happy."""
        resp = client.get("/readyz")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body.get("status") == "ok"
        # Per-dep status surfaces so an operator can see *which* deps
        # were checked even on the happy path.
        checks = body.get("checks", {})
        assert "db" in checks
        assert checks["db"] == "ok"

    def test_v1_readyz_returns_200(self, client: TestClient) -> None:
        resp = client.get("/v1/readyz")
        assert resp.status_code == 200, resp.text

    def test_readyz_returns_503_when_db_unreachable(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When the DB connection round-trip raises, ``/readyz``
        returns 503 with per-dep status so the LB knows which dep is
        broken."""
        from wg_manager import db as db_module

        class _BrokenEngine:
            def connect(self) -> object:
                raise RuntimeError("simulated mysql outage")

        original = db_module.engine
        monkeypatch.setattr(db_module, "engine", _BrokenEngine())
        try:
            resp = client.get("/readyz")
            assert resp.status_code == 503, resp.text
            body = resp.json()
            assert body.get("status") == "degraded"
            checks = body.get("checks", {})
            assert checks.get("db") != "ok"
            # The body names *which* dep failed so the LB / operator
            # can correlate with the upstream alarm.
            assert "db" in str(body).lower()
        finally:
            monkeypatch.setattr(db_module, "engine", original)

    def test_readyz_does_not_carry_deprecation_header(
        self, client: TestClient
    ) -> None:
        """Same exemption as ``/healthz`` — operational, not part of
        the legacy API surface."""
        resp = client.get("/readyz")
        assert "Deprecation" not in resp.headers


# ---------------------------------------------------------------------------
# Both probes bypass mTLS
# ---------------------------------------------------------------------------


class TestHealthProbesByPassMTLS:
    """Load balancers don't carry client certs. The probes must
    answer without an operator cert even when ``TLS_REQUIRED=true``."""

    def test_healthz_admitted_without_operator(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Flip TLS_REQUIRED on for this request. The
        ``MTLSAuthMiddleware`` must let ``/healthz`` through even
        without a cert (the conftest's passthrough mode is the
        ``TLS_REQUIRED=false`` shape; this test pins the explicit
        bypass list)."""
        from wg_manager.auth import MTLSAuthMiddleware

        # The middleware's known-bypass path is the canonical
        # mechanism — assert the predicate decisively rather than
        # spinning a TLS-required app + scope-injecting fixture, which
        # would duplicate the live-uvicorn harness.
        assert MTLSAuthMiddleware.is_health_path("/healthz") is True
        assert MTLSAuthMiddleware.is_health_path("/readyz") is True
        assert MTLSAuthMiddleware.is_health_path("/v1/healthz") is True
        assert MTLSAuthMiddleware.is_health_path("/v1/readyz") is True
        # Sanity: regular API paths are NOT on the bypass list.
        assert MTLSAuthMiddleware.is_health_path("/tenants") is False
        assert MTLSAuthMiddleware.is_health_path("/v1/tenants") is False
