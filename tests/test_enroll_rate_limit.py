"""Rate limiting on ``POST /v1/enroll`` (Phase 3f hardening).

Two per-source-IP buckets, applied before any DB or CA work:

* **Requests:** a loose cap on every enroll request. It's loose
  because an autoscaling group in a private subnet usually reaches the
  internet through one NAT address.
* **Failures:** a strict cap on failed attempts (401 bad token, 422 bad
  body). Once reached, that IP is locked out for the rest of the
  window, *even with a valid token*. Successful enrollments never
  count against it.

Blocked callers get 429 with ``Retry-After``. Backend errors fail
closed with 503. Health probes are never limited. A lockout is logged
once per window, not once per blocked request, so an attack can't flood
the audit stream.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Generator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from tests import test_enroll_redeem as _redeem
from tests.test_enroll_redeem import _auth, _body, _mint
from wg_manager import db as db_module
from wg_manager import enroll_app as enroll_app_module
from wg_manager.config import Settings
from wg_manager.db import get_session
from wg_manager.enroll_app import ENROLL_PATH, create_enroll_app
from wg_manager.models import EnrollmentToken
from wg_manager.ratelimit import MemoryLimiter, RateLimitBackendError

# Reuse the ready-hub fixture from the redemption tests.
hub = _redeem.hub


def _post(tc: TestClient, host: str, token: str) -> int:
    """POST a well-formed enroll body for ``host``; return the status."""
    return tc.post(ENROLL_PATH, json=_body(host), headers=_auth(token)).status_code


@pytest.fixture(autouse=True)
def _no_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    class _R:
        id = "t"

    monkeypatch.setattr(enroll_app_module, "request_reconfigure", lambda _sid: _R())


@pytest.fixture()
def make_client(engine: Any) -> Generator[Callable[..., TestClient], None, None]:
    """Build enroll-app TestClients with given limits and source IP."""
    opened: list[TestClient] = []

    def _make(ip: str = "203.0.113.7", limiter: Any = None, **limits: Any) -> TestClient:
        settings = Settings(enroll_rate_limit_backend="memory", **limits)
        app = create_enroll_app(settings, limiter=limiter)

        def _session():
            with Session(engine) as s:
                yield s

        app.dependency_overrides[get_session] = _session
        tc = TestClient(app, client=(ip, 40000))
        opened.append(tc)
        return tc

    yield _make
    for tc in opened:
        tc.close()


def _use_count() -> int:
    with Session(db_module.engine) as s:
        return sum(t.use_count for t in s.exec(select(EnrollmentToken)).all())


class TestRequestBucket:
    def test_blocks_after_limit_with_retry_after(self, make_client, hub: int) -> None:
        lim = MemoryLimiter()
        tc = make_client(limiter=lim, enroll_rate_limit_requests=2)
        token = _mint(hub, max_uses=5)
        codes = [
            tc.post(ENROLL_PATH, json=_body(f"h{i}"), headers=_auth(token)).status_code
            for i in range(3)
        ]
        assert codes == [201, 201, 429]
        resp = tc.post(ENROLL_PATH, json=_body("h9"), headers=_auth(token))
        assert resp.status_code == 429
        assert int(resp.headers["retry-after"]) > 0
        assert resp.json() == {"detail": "too many requests"}
        assert _use_count() == 2  # blocked requests never reach the token

    def test_ips_are_independent(self, make_client, hub: int) -> None:
        lim = MemoryLimiter()
        a = make_client("198.51.100.1", limiter=lim, enroll_rate_limit_requests=1)
        b = make_client("198.51.100.2", limiter=lim, enroll_rate_limit_requests=1)
        token = _mint(hub, max_uses=5)
        assert a.post(ENROLL_PATH, json=_body("a1"), headers=_auth(token)).status_code == 201
        assert a.post(ENROLL_PATH, json=_body("a2"), headers=_auth(token)).status_code == 429
        assert b.post(ENROLL_PATH, json=_body("b1"), headers=_auth(token)).status_code == 201

    def test_zero_disables(self, make_client, hub: int) -> None:
        tc = make_client(enroll_rate_limit_requests=0, enroll_failure_limit=0)
        for _ in range(20):
            assert tc.post(ENROLL_PATH, json=_body(), headers=_auth("wgmenr_x")).status_code == 401


class TestFailureBucket:
    def test_bad_tokens_lock_out_the_ip_even_for_a_valid_token(
        self, make_client, hub: int
    ) -> None:
        tc = make_client(enroll_failure_limit=3)
        for _ in range(3):
            assert _post(tc, "h", "wgmenr_bad") == 401
        good = _mint(hub)
        resp = tc.post(ENROLL_PATH, json=_body(), headers=_auth(good))
        assert resp.status_code == 429
        assert _use_count() == 0

    def test_validation_errors_count_as_failures(self, make_client, hub: int) -> None:
        tc = make_client(enroll_failure_limit=2)
        token = _mint(hub)
        for _ in range(2):
            resp = tc.post(ENROLL_PATH, json={"junk": 1}, headers=_auth(token))
            assert resp.status_code == 422
        assert tc.post(ENROLL_PATH, json=_body(), headers=_auth(_mint(hub))).status_code == 429

    def test_successes_do_not_count(self, make_client, hub: int) -> None:
        tc = make_client(enroll_failure_limit=1)
        token = _mint(hub, max_uses=5)
        for i in range(5):
            assert _post(tc, f"ok{i}", token) == 201

    def test_conflicts_do_not_count(self, make_client, hub: int) -> None:
        """A 409 (e.g. a re-run of userdata) isn't an attack signal."""
        tc = make_client(enroll_failure_limit=1)
        token = _mint(hub, max_uses=5)
        tc.post(ENROLL_PATH, json=_body("dup"), headers=_auth(token))
        assert tc.post(ENROLL_PATH, json=_body("dup"), headers=_auth(token)).status_code == 409
        assert tc.post(ENROLL_PATH, json=_body("other"), headers=_auth(token)).status_code == 201

    def test_lockout_logged_once(
        self, make_client, hub: int, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.INFO, logger="wg_manager.audit")
        tc = make_client(enroll_failure_limit=2)
        for _ in range(6):
            tc.post(ENROLL_PATH, json=_body(), headers=_auth("wgmenr_bad"))
        lines = [r.getMessage() for r in caplog.records
                 if r.name == "wg_manager.audit" and "enroll.rate_limited" in r.getMessage()]
        assert len(lines) == 1
        assert "203.0.113.7" in lines[0] and "failures" in lines[0]


class TestScopeAndFailureModes:
    def test_health_is_never_limited(self, make_client) -> None:
        tc = make_client(enroll_rate_limit_requests=1)
        for _ in range(5):
            assert tc.get("/v1/healthz").status_code == 200

    def test_backend_error_fails_closed(self, make_client, hub: int) -> None:
        class _Down:
            def hit(self, *a: Any, **k: Any):
                raise RateLimitBackendError("valkey down")

            def peek(self, *a: Any, **k: Any):
                raise RateLimitBackendError("valkey down")

        tc = make_client(limiter=_Down())
        resp = tc.post(ENROLL_PATH, json=_body(), headers=_auth(_mint(hub)))
        assert resp.status_code == 503
        assert "retry-after" in resp.headers
        assert _use_count() == 0

    def test_default_app_uses_settings_limits(self) -> None:
        """create_enroll_app() with no args builds its limiter from Settings."""
        s = Settings()
        assert s.enroll_rate_limit_requests == 120
        assert s.enroll_rate_limit_window_seconds == 60
        assert s.enroll_failure_limit == 10
        assert s.enroll_failure_window_seconds == 600
        create_enroll_app()  # memory backend in the test env
