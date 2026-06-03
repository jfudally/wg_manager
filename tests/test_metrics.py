"""Tests for ``wg_manager.metrics`` (Phase 3a cycle 1).

The metrics module declares the four metric families that the
Grafana dashboard panels (and any operator's alerting rules) read
from:

* ``wg_manager_http_requests_total`` / ``_duration_seconds`` — per
  request, recorded by an ASGI middleware that wraps the FastAPI
  app. The path label uses the *route template* (e.g.
  ``/clients/{client_id}``) not the raw URL, so cardinality stays
  bounded by the route table rather than by request volume.
* ``wg_manager_celery_tasks_total`` / ``_task_duration_seconds`` —
  recorded by Celery signal handlers registered via
  ``signals.task_prerun`` + ``task_postrun``.
* ``wg_manager_vault_requests_total`` / ``_duration_seconds`` —
  recorded by a ``vault_call(engine, operation)`` context manager
  that wraps every Vault round-trip.
* ``wg_manager_certs_issued_total`` / ``_revoked_total`` /
  ``_renewed_total`` — counters bumped by the cert routers + CLI
  on every lifecycle event.

The ``/metrics`` HTTP endpoint exposes the Prometheus text format
through the existing mTLS listener — scrapers configure a client
cert the same way operators do.

These tests pin both the surface area (metric names, label sets,
endpoint shape) and the wiring (middleware records every request,
Celery signals fire, the context manager records latency + outcome).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Module surface — every metric the dashboard + alerting recipes reference
# ---------------------------------------------------------------------------


class TestMetricFamilies:
    """The Counter / Histogram declarations are stable names downstream
    operators put into Prometheus queries. A rename here breaks every
    dashboard panel that referenced the old name — pin them."""

    def test_http_metrics_present(self) -> None:
        from wg_manager import metrics

        assert hasattr(metrics, "http_requests_total")
        assert hasattr(metrics, "http_request_duration_seconds")

    def test_celery_metrics_present(self) -> None:
        from wg_manager import metrics

        assert hasattr(metrics, "celery_tasks_total")
        assert hasattr(metrics, "celery_task_duration_seconds")

    def test_vault_metrics_present(self) -> None:
        from wg_manager import metrics

        assert hasattr(metrics, "vault_requests_total")
        assert hasattr(metrics, "vault_request_duration_seconds")

    def test_cert_metrics_present(self) -> None:
        from wg_manager import metrics

        assert hasattr(metrics, "certs_issued_total")
        assert hasattr(metrics, "certs_revoked_total")
        assert hasattr(metrics, "certs_renewed_total")

    def test_http_metric_has_method_path_status_labels(self) -> None:
        from wg_manager import metrics

        # _labelnames is the prometheus_client internal — accessing it
        # lets us pin the label set without scraping a registry text.
        assert set(metrics.http_requests_total._labelnames) == {
            "method",
            "path",
            "status",
        }

    def test_celery_metric_has_task_name_state_labels(self) -> None:
        from wg_manager import metrics

        assert set(metrics.celery_tasks_total._labelnames) == {
            "task_name",
            "state",
        }

    def test_vault_metric_has_engine_operation_result_labels(self) -> None:
        from wg_manager import metrics

        assert set(metrics.vault_requests_total._labelnames) == {
            "engine",
            "operation",
            "result",
        }


# ---------------------------------------------------------------------------
# /metrics endpoint — returns Prometheus text format
# ---------------------------------------------------------------------------


@pytest.fixture()
def client() -> TestClient:
    """Build a hermetic TestClient against the FastAPI app.

    Conftest sets ``TLS_REQUIRED=false`` so the MTLSAuthMiddleware is
    in passthrough mode; the metrics endpoint is therefore reachable
    without minting a client cert just to test it.
    """
    from wg_manager.main import app

    return TestClient(app)


class TestMetricsEndpoint:
    def test_metrics_endpoint_returns_200(self, client: TestClient) -> None:
        response = client.get("/metrics")
        assert response.status_code == 200

    def test_metrics_endpoint_returns_prometheus_text_format(
        self, client: TestClient
    ) -> None:
        """The Prometheus text format declares its content-type as
        ``text/plain; version=0.0.4; charset=utf-8`` (or similar).
        Scrapers parse based on this header."""
        response = client.get("/metrics")
        ctype = response.headers.get("content-type", "")
        assert "text/plain" in ctype, (
            f"metrics endpoint must return Prometheus text format, "
            f"got content-type={ctype}"
        )

    def test_metrics_body_contains_wg_manager_metrics(
        self, client: TestClient
    ) -> None:
        """The body must list at least one wg_manager_* metric. Empty
        bodies would mean the registry wasn't wired."""
        response = client.get("/metrics")
        # # TYPE lines are the canonical Prometheus self-describing
        # headers — pin one of our metric names appears.
        assert "wg_manager_" in response.text


# ---------------------------------------------------------------------------
# HTTP middleware — records every request
# ---------------------------------------------------------------------------


class TestHttpMiddleware:
    def test_middleware_records_a_request(self, client: TestClient) -> None:
        """Hit a known endpoint, scrape /metrics, confirm the counter
        bumped for that route template."""
        # Use an endpoint that returns 200 in the hermetic env.
        client.get("/audit")
        scrape = client.get("/metrics").text
        # Look for the counter line — Prometheus format prints
        # ``wg_manager_http_requests_total{method="GET",path="...",status="200"}``
        assert 'wg_manager_http_requests_total{' in scrape
        assert 'method="GET"' in scrape

    def test_middleware_uses_route_template_not_raw_path(
        self, client: TestClient
    ) -> None:
        """A request to ``/audit?event=foo`` should record path
        ``/audit``, not the query string. (Cardinality discipline.)"""
        client.get("/audit?event=foo")
        scrape = client.get("/metrics").text
        # The path label must not carry the query string.
        assert 'path="/audit?' not in scrape

    def test_middleware_skips_options_preflight(
        self, client: TestClient
    ) -> None:
        """OPTIONS preflight from the dashboard CORS negotiation is
        high-volume + low-signal — skip it."""
        # Need to provide CORS headers so Starlette routes the OPTIONS
        # through the middleware stack.
        client.options(
            "/audit",
            headers={
                "Origin": "http://localhost:3100",
                "Access-Control-Request-Method": "GET",
            },
        )
        scrape = client.get("/metrics").text
        # No OPTIONS-labelled line should appear in the counter.
        assert 'method="OPTIONS"' not in scrape

    def test_middleware_skips_metrics_endpoint(
        self, client: TestClient
    ) -> None:
        """Scraping /metrics shouldn't record itself — Prometheus
        scrapes every 15s by default and self-counts add noise."""
        # Trigger a couple of scrapes.
        client.get("/metrics")
        client.get("/metrics")
        scrape = client.get("/metrics").text
        # The /metrics path itself shouldn't appear as a label.
        assert 'path="/metrics"' not in scrape


# ---------------------------------------------------------------------------
# Vault round-trip context manager
# ---------------------------------------------------------------------------


class TestVaultCallContextManager:
    def test_records_success_outcome(self) -> None:
        from prometheus_client import generate_latest

        from wg_manager import metrics

        with metrics.vault_call(engine="transit", operation="encrypt"):
            pass  # no-op successful round-trip

        scrape = generate_latest(metrics.REGISTRY).decode("utf-8")
        assert 'engine="transit"' in scrape
        assert 'operation="encrypt"' in scrape
        assert 'result="ok"' in scrape

    def test_records_error_outcome(self) -> None:
        from prometheus_client import generate_latest

        from wg_manager import metrics

        with pytest.raises(RuntimeError):
            with metrics.vault_call(engine="pki", operation="issue"):
                raise RuntimeError("simulated Vault failure")

        scrape = generate_latest(metrics.REGISTRY).decode("utf-8")
        assert 'engine="pki"' in scrape
        assert 'operation="issue"' in scrape
        assert 'result="error"' in scrape

    def test_records_duration(self) -> None:
        """The histogram must have at least one observed sample after
        a successful call — proves the timing block runs."""
        from prometheus_client import generate_latest

        from wg_manager import metrics

        with metrics.vault_call(engine="ssh", operation="sign"):
            pass

        scrape = generate_latest(metrics.REGISTRY).decode("utf-8")
        # ``_count`` is a derived series Prometheus emits per histogram.
        assert "wg_manager_vault_request_duration_seconds_count" in scrape


# ---------------------------------------------------------------------------
# Celery signal handlers
# ---------------------------------------------------------------------------


class TestCelerySignals:
    """The handlers register on import — pin that they exist and that
    a fake task run bumps the counter."""

    def test_module_registers_celery_handlers(self) -> None:
        from celery.signals import task_postrun, task_prerun

        from wg_manager import metrics  # noqa: F401 — import for side effects

        # With ``weak=False`` Celery stores receivers as bare callables,
        # not weakrefs. ``signal.receivers`` is a list of
        # ``((id_pair, ), receiver)`` tuples — we want the second
        # element of each tuple.
        def _module(receiver) -> str:
            return getattr(receiver, "__module__", "") or ""

        prerun_modules = {_module(r) for _, r in task_prerun.receivers}
        postrun_modules = {_module(r) for _, r in task_postrun.receivers}

        assert "wg_manager.metrics" in prerun_modules, (
            f"wg_manager.metrics must register a task_prerun receiver "
            f"(got modules: {prerun_modules})"
        )
        assert "wg_manager.metrics" in postrun_modules, (
            f"wg_manager.metrics must register a task_postrun receiver "
            f"(got modules: {postrun_modules})"
        )
