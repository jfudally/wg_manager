"""Failed-redeem metrics for ``POST /v1/enroll`` (Phase 3f hardening).

The enroll listener is its own process on a public port, so it can't
serve ``/metrics`` itself without exposing it. Instead each enroll
replica counts outcomes into one Valkey hash
(:mod:`wg_manager.enroll_metrics`), and the operator API's mTLS
``/metrics`` reads that hash at scrape time, so one scrape covers every
replica:

* ``wg_manager_enroll_responses_total{status}``: every enroll response.
* ``wg_manager_enroll_rejects_total{reason}``: token rejections, by the
  same reason the audit log records (never exposed to the caller).
* ``wg_manager_enroll_rate_limited_total{bucket}``: 429s by bucket.
* ``wg_manager_enroll_metrics_up``: 0 when the store can't be read,
  so a dead pipeline doesn't look like "no failures".

Recording must never change a response: if Valkey is down the enroll
request is answered as before (the limiter already fails closed).
"""

from __future__ import annotations

from collections.abc import Callable, Generator
from typing import Any

import pytest
import redis
from fastapi.testclient import TestClient
from sqlmodel import Session

from tests import test_enroll_redeem as _redeem
from tests.test_enroll_redeem import _auth, _body, _mint
from wg_manager import enroll_app as enroll_app_module
from wg_manager.config import Settings
from wg_manager.db import get_session
from wg_manager.enroll_app import ENROLL_PATH, create_enroll_app
from wg_manager.enroll_metrics import (
    EnrollMetricsBackendError,
    MemoryEnrollMetrics,
    RedisEnrollMetrics,
    make_enroll_metrics,
)

hub = _redeem.hub


class _FakeRedis:
    """Just enough of redis.Redis for a hash of counters."""

    def __init__(self) -> None:
        self.hashes: dict[str, dict[str, int]] = {}
        self.fail = False

    def _check(self) -> None:
        if self.fail:
            raise redis.ConnectionError("valkey down")

    def hincrby(self, key: str, field: str, amount: int = 1) -> int:
        self._check()
        h = self.hashes.setdefault(key, {})
        h[field] = h.get(field, 0) + amount
        return h[field]

    def hgetall(self, key: str) -> dict[bytes, bytes]:
        self._check()
        return {k.encode(): str(v).encode() for k, v in self.hashes.get(key, {}).items()}


# ---------------------------------------------------------------------------
# Recorder backends
# ---------------------------------------------------------------------------


@pytest.fixture(params=["memory", "redis"])
def recorder(request: pytest.FixtureRequest) -> Any:
    if request.param == "memory":
        return MemoryEnrollMetrics()
    return RedisEnrollMetrics(_FakeRedis())


class TestRecorder:
    def test_counts_and_snapshots(self, recorder: Any) -> None:
        recorder.record_response(201)
        recorder.record_response(401)
        recorder.record_response(401)
        recorder.record_reject("unknown_token")
        recorder.record_rate_limited("failures")
        snap = recorder.snapshot()
        assert snap.responses == {"201": 1, "401": 2}
        assert snap.rejects == {"unknown_token": 1}
        assert snap.rate_limited == {"failures": 1}

    def test_empty_snapshot(self, recorder: Any) -> None:
        snap = recorder.snapshot()
        assert (snap.responses, snap.rejects, snap.rate_limited) == ({}, {}, {})

    def test_redis_uses_one_namespaced_hash(self) -> None:
        fake = _FakeRedis()
        RedisEnrollMetrics(fake).record_reject("expired")
        assert list(fake.hashes) == ["wgm:enroll:metrics"]

    def test_record_never_raises_when_backend_is_down(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        fake = _FakeRedis()
        fake.fail = True
        rec = RedisEnrollMetrics(fake)
        rec.record_response(401)  # must not raise
        rec.record_response(401)
        warnings = [r for r in caplog.records if "enroll metrics" in r.getMessage()]
        # Logged, but not once per request: an attack mustn't flood the log.
        assert len(warnings) == 1

    def test_snapshot_raises_when_backend_is_down(self) -> None:
        fake = _FakeRedis()
        fake.fail = True
        with pytest.raises(EnrollMetricsBackendError):
            RedisEnrollMetrics(fake).snapshot()

    def test_unknown_fields_in_the_hash_are_ignored(self) -> None:
        """Old / foreign fields mustn't break the scrape or add series."""
        fake = _FakeRedis()
        fake.hashes["wgm:enroll:metrics"] = {"bogus": 5, "response:201": 2}
        assert RedisEnrollMetrics(fake).snapshot().responses == {"201": 2}

    def test_factory_follows_the_rate_limit_backend(self) -> None:
        mem = make_enroll_metrics(Settings(enroll_rate_limit_backend="memory"))
        assert isinstance(mem, MemoryEnrollMetrics)
        red = make_enroll_metrics(
            Settings(
                enroll_rate_limit_backend="redis",
                enroll_rate_limit_redis_url="redis://valkey.example:6379/3",
            )
        )
        assert isinstance(red, RedisEnrollMetrics)
        kwargs = red.client.connection_pool.connection_kwargs
        assert (kwargs["host"], kwargs["db"]) == ("valkey.example", 3)


# ---------------------------------------------------------------------------
# Recording from the enroll app
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _no_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    class _R:
        id = "t"

    monkeypatch.setattr(enroll_app_module, "request_reconfigure", lambda _sid: _R())


@pytest.fixture()
def make_client(engine: Any) -> Generator[Callable[..., TestClient], None, None]:
    opened: list[TestClient] = []

    def _make(metrics: Any, **limits: Any) -> TestClient:
        settings = Settings(enroll_rate_limit_backend="memory", **limits)
        app = create_enroll_app(settings, metrics=metrics)

        def _session():
            with Session(engine) as s:
                yield s

        app.dependency_overrides[get_session] = _session
        tc = TestClient(app, client=("203.0.113.7", 40000))
        opened.append(tc)
        return tc

    yield _make
    for tc in opened:
        tc.close()


class TestRecordingFromEnrollApp:
    def test_success(self, make_client, hub: int) -> None:
        m = MemoryEnrollMetrics()
        tc = make_client(m)
        assert tc.post(ENROLL_PATH, json=_body(), headers=_auth(_mint(hub))).status_code == 201
        snap = m.snapshot()
        assert snap.responses == {"201": 1}
        assert snap.rejects == {}

    def test_rejects_by_reason(self, make_client, hub: int) -> None:
        m = MemoryEnrollMetrics()
        tc = make_client(m)
        tc.post(ENROLL_PATH, json=_body())                                  # no header
        tc.post(ENROLL_PATH, json=_body(), headers=_auth("wgmenr_nope"))    # unknown
        tc.post(ENROLL_PATH, json=_body(), headers=_auth("wgmenr_nope"))
        snap = m.snapshot()
        assert snap.responses == {"401": 3}
        assert snap.rejects == {"missing_token": 1, "unknown_token": 2}

    def test_validation_errors(self, make_client, hub: int) -> None:
        m = MemoryEnrollMetrics()
        tc = make_client(m)
        tc.post(ENROLL_PATH, json={"junk": 1}, headers=_auth(_mint(hub)))
        assert m.snapshot().responses == {"422": 1}

    def test_rate_limited_by_bucket(self, make_client, hub: int) -> None:
        m = MemoryEnrollMetrics()
        tc = make_client(m, enroll_failure_limit=1)
        tc.post(ENROLL_PATH, json=_body(), headers=_auth("wgmenr_nope"))   # 401, trips
        tc.post(ENROLL_PATH, json=_body(), headers=_auth("wgmenr_nope"))   # 429
        tc.post(ENROLL_PATH, json=_body(), headers=_auth("wgmenr_nope"))   # 429
        snap = m.snapshot()
        assert snap.responses == {"401": 1, "429": 2}
        # Every blocked request counts (unlike the once-per-trip audit line).
        assert snap.rate_limited == {"failures": 2}

    def test_request_bucket(self, make_client, hub: int) -> None:
        m = MemoryEnrollMetrics()
        tc = make_client(m, enroll_rate_limit_requests=1, enroll_failure_limit=0)
        tc.post(ENROLL_PATH, json=_body(), headers=_auth("wgmenr_nope"))
        tc.post(ENROLL_PATH, json=_body(), headers=_auth("wgmenr_nope"))
        assert m.snapshot().rate_limited == {"requests": 1}

    def test_health_probes_are_not_counted(self, make_client) -> None:
        m = MemoryEnrollMetrics()
        make_client(m).get("/healthz")
        assert m.snapshot().responses == {}

    def test_metrics_outage_does_not_change_the_response(
        self, make_client, hub: int
    ) -> None:
        fake = _FakeRedis()
        fake.fail = True
        tc = make_client(RedisEnrollMetrics(fake))
        assert tc.post(ENROLL_PATH, json=_body(), headers=_auth(_mint(hub))).status_code == 201
        assert tc.post(ENROLL_PATH, json=_body(), headers=_auth("wgmenr_x")).status_code == 401


# ---------------------------------------------------------------------------
# Exposed on the operator API's /metrics
# ---------------------------------------------------------------------------


class TestCollector:
    def _scrape(self, store: Any) -> str:
        from prometheus_client import CollectorRegistry, generate_latest

        from wg_manager.metrics import EnrollMetricsCollector

        reg = CollectorRegistry()
        reg.register(EnrollMetricsCollector(lambda: store))
        return generate_latest(reg).decode()

    def test_exposes_counters(self) -> None:
        m = MemoryEnrollMetrics()
        for _ in range(3):
            m.record_reject("unknown_token")
        m.record_response(401)
        m.record_rate_limited("failures")
        body = self._scrape(m)
        assert 'wg_manager_enroll_rejects_total{reason="unknown_token"} 3.0' in body
        assert 'wg_manager_enroll_responses_total{status="401"} 1.0' in body
        assert 'wg_manager_enroll_rate_limited_total{bucket="failures"} 1.0' in body
        assert "wg_manager_enroll_metrics_up 1.0" in body

    def test_store_down_reports_up_zero_and_no_counters(self) -> None:
        fake = _FakeRedis()
        fake.fail = True
        body = self._scrape(RedisEnrollMetrics(fake))
        assert "wg_manager_enroll_metrics_up 0.0" in body
        assert "wg_manager_enroll_rejects_total{" not in body

    def test_registered_on_the_operator_metrics_endpoint(self, client: TestClient) -> None:
        body = client.get("/metrics").text
        assert "wg_manager_enroll_metrics_up" in body

    def test_not_served_on_the_enroll_listener(self) -> None:
        tc = TestClient(create_enroll_app(Settings(enroll_rate_limit_backend="memory")))
        assert tc.get("/metrics").status_code == 404


class TestProdCompose:
    """api (which serves /metrics) must read the store enroll writes to."""

    def test_api_and_enroll_resolve_the_same_store(self) -> None:
        from pathlib import Path

        import yaml

        from tests.test_compose_prod_overlay import _ComposeLoader, _env

        root = Path(__file__).resolve().parents[1]
        services = yaml.load(
            (root / "docker-compose.prod.yml").read_text(), Loader=_ComposeLoader
        )["services"]
        api, enroll = _env(services["api"]), _env(services["enroll"])
        # Both fall back to the broker URL unless one overrides the store.
        assert api.get("ENROLL_RATE_LIMIT_REDIS_URL") == enroll.get(
            "ENROLL_RATE_LIMIT_REDIS_URL"
        )
        if "ENROLL_RATE_LIMIT_REDIS_URL" not in api:
            assert api["CELERY_BROKER_URL"] == enroll["CELERY_BROKER_URL"]
        assert api.get("ENROLL_RATE_LIMIT_BACKEND", "redis") == "redis"
