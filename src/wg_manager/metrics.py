"""Prometheus metrics for wg-manager (Phase 3a cycle 1).

Four metric families covering the dimensions an operator wants on
Grafana when answering "is wg-manager healthy right now?":

* **HTTP** — per-request method / route-template / status code.
  Recorded by :class:`MetricsMiddleware`, which wraps the FastAPI
  app at the outermost layer so 5xx from any middleware (auth,
  validation) still gets counted.
* **Celery** — per-task name + state. Recorded by signal handlers
  registered via :mod:`celery.signals`.
* **Vault round-trips** — engine / operation / result + latency.
  Recorded by the :func:`vault_call` context manager that wraps
  every Vault call site in :mod:`wg_manager.crypto`,
  :mod:`wg_manager.ssh_ca`, and :mod:`wg_manager.pki`.
* **Cert lifecycle** — issue / revoke / renew counters bumped by
  the cert routers and the CLI.

The ``GET /metrics`` endpoint is wired into the FastAPI app and
exposes the registry in the standard Prometheus text format. The
endpoint sits *behind* the mTLS listener — Prometheus scrapers
configure a client cert the same way operators do, keeping the
security posture uniform.

Cardinality discipline:

* The HTTP ``path`` label uses the FastAPI route *template*
  (e.g. ``/clients/{client_id}``), not the raw URL. The middleware
  reads ``scope["route"].path`` after the routing layer has run.
* The Celery ``task_name`` label is bounded by the task table.
* The Vault ``engine`` / ``operation`` labels are bounded by the
  small set of call sites in the three Vault-backed modules.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from celery.signals import task_postrun, task_prerun
from prometheus_client import (
    CollectorRegistry,
    Counter,
    Histogram,
    generate_latest,
)
from prometheus_client.core import GaugeMetricFamily
from prometheus_client.exposition import CONTENT_TYPE_LATEST

# Module-local registry — keeps test isolation cleaner than relying
# on prometheus_client's global default. The ``/metrics`` endpoint
# exposes this registry directly.
REGISTRY = CollectorRegistry()


# ---------------------------------------------------------------------------
# Metric families
# ---------------------------------------------------------------------------

http_requests_total = Counter(
    "wg_manager_http_requests_total",
    "Total HTTP requests handled by the API, by method, route template, "
    "and response status code.",
    labelnames=["method", "path", "status"],
    registry=REGISTRY,
)
http_request_duration_seconds = Histogram(
    "wg_manager_http_request_duration_seconds",
    "HTTP request duration in seconds, by method + route template.",
    labelnames=["method", "path"],
    registry=REGISTRY,
)

celery_tasks_total = Counter(
    "wg_manager_celery_tasks_total",
    "Total Celery tasks executed, by name and terminal state "
    "(SUCCESS / FAILURE / REVOKED / ...).",
    labelnames=["task_name", "state"],
    registry=REGISTRY,
)
celery_task_duration_seconds = Histogram(
    "wg_manager_celery_task_duration_seconds",
    "Celery task wall-clock duration in seconds, by task name.",
    labelnames=["task_name"],
    registry=REGISTRY,
)

vault_requests_total = Counter(
    "wg_manager_vault_requests_total",
    "Total Vault round-trips by engine (transit/ssh/pki), operation "
    "(encrypt/decrypt/sign-user/sign-host/issue/revoke/...), and "
    "result (ok/error).",
    labelnames=["engine", "operation", "result"],
    registry=REGISTRY,
)
vault_request_duration_seconds = Histogram(
    "wg_manager_vault_request_duration_seconds",
    "Vault round-trip duration in seconds, by engine + operation.",
    labelnames=["engine", "operation"],
    registry=REGISTRY,
)

certs_issued_total = Counter(
    "wg_manager_certs_issued_total",
    "Total certs issued, by type (api / cli / dashboard / mysql / mysql-client).",
    labelnames=["cert_type"],
    registry=REGISTRY,
)
certs_revoked_total = Counter(
    "wg_manager_certs_revoked_total",
    "Total certs revoked, by type.",
    labelnames=["cert_type"],
    registry=REGISTRY,
)
certs_renewed_total = Counter(
    "wg_manager_certs_renewed_total",
    "Total certs renewed, by type.",
    labelnames=["cert_type"],
    registry=REGISTRY,
)


# ---------------------------------------------------------------------------
# ASGI middleware — records every HTTP request
# ---------------------------------------------------------------------------


class MetricsMiddleware:
    """ASGI middleware that records HTTP request counts + durations.

    Three intentional skip conditions:

    * **OPTIONS** — CORS preflight is high-volume + low-signal and
      would dominate the request-rate panel for any browser client.
    * **/metrics itself** — Prometheus scrapes every 15s by default,
      so counting our own scrapes would mask real traffic patterns.
    * **Non-HTTP scopes** — ASGI also delivers lifespan + websocket
      scopes; the metric is HTTP-specific.

    The path label is the FastAPI route template (e.g.
    ``/clients/{client_id}``) when the routing layer matched, or
    the raw scope path as fallback. Route templates keep cardinality
    bounded by the route table size rather than by request volume.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)

        method = scope.get("method", "UNKNOWN")
        raw_path = scope.get("path", "")

        # Skip OPTIONS preflight and the metrics endpoint itself.
        if method == "OPTIONS" or raw_path == "/metrics":
            return await self.app(scope, receive, send)

        status_holder: list[int] = [500]

        async def send_wrapper(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                status_holder[0] = int(message.get("status", 500))
            await send(message)

        start = time.perf_counter()
        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration = time.perf_counter() - start

            # ``scope["route"]`` is set by Starlette's Router after a
            # successful match. Falling back to the raw path keeps the
            # 404 case from breaking the middleware — at the cost of
            # one extra label value per unmatched URL, which is rare
            # for a healthy deployment.
            route = scope.get("route")
            path = (
                route.path
                if route is not None and hasattr(route, "path")
                else raw_path
            )

            status = str(status_holder[0])
            http_requests_total.labels(
                method=method, path=path, status=status
            ).inc()
            http_request_duration_seconds.labels(
                method=method, path=path
            ).observe(duration)


# ---------------------------------------------------------------------------
# Celery signal handlers
# ---------------------------------------------------------------------------

# Map task_id → start timestamp so the postrun handler can compute
# duration without relying on Celery's own timing fields (which are
# not always populated when ``task_always_eager=True``, as in tests).
_TASK_START: dict[str, float] = {}


@task_prerun.connect(weak=False)
def _on_task_prerun(
    sender: Any = None,
    task_id: str | None = None,
    task: Any = None,
    *_: Any,
    **__: Any,
) -> None:
    """Record the start time so :func:`_on_task_postrun` can compute
    the wall-clock duration."""
    if task_id:
        _TASK_START[task_id] = time.perf_counter()


@task_postrun.connect(weak=False)
def _on_task_postrun(
    sender: Any = None,
    task_id: str | None = None,
    task: Any = None,
    state: str | None = None,
    *_: Any,
    **__: Any,
) -> None:
    """Bump the per-task / per-state counter + observe the duration."""
    name = getattr(task, "name", "unknown")
    start = _TASK_START.pop(task_id, None) if task_id else None
    if start is not None:
        celery_task_duration_seconds.labels(task_name=name).observe(
            time.perf_counter() - start
        )
    celery_tasks_total.labels(
        task_name=name, state=state or "UNKNOWN"
    ).inc()


# ---------------------------------------------------------------------------
# Vault round-trip context manager
# ---------------------------------------------------------------------------


@contextmanager
def vault_call(*, engine: str, operation: str) -> Iterator[None]:
    """Wrap a Vault round-trip with timing + outcome metrics + span.

    Usage::

        with vault_call(engine="transit", operation="encrypt"):
            client.secrets.transit.encrypt_data(...)

    The context manager records ``result="ok"`` on a clean exit and
    ``result="error"`` on any exception (then re-raises). The
    duration histogram observes regardless of outcome.

    Phase 3a cycle 2 extends the wrap to also start an OpenTelemetry
    span named ``vault.<engine>.<operation>`` with ``vault.engine``
    and ``vault.operation`` attributes. The two streams share one
    call site so a metric-only deployment and a metric+trace
    deployment don't drift apart.
    """
    # Local import: the tracing module imports the OTel SDK, which
    # itself takes a measurable startup cost. Production deployments
    # with OTEL_EXPORTER=none don't pay that cost on cold paths that
    # never hit vault_call (e.g. /metrics itself).
    from opentelemetry.trace import Status, StatusCode

    from wg_manager.tracing import get_tracer

    tracer = get_tracer()
    span_ctx = tracer.start_as_current_span(f"vault.{engine}.{operation}")
    span = span_ctx.__enter__()
    span.set_attribute("vault.engine", engine)
    span.set_attribute("vault.operation", operation)

    start = time.perf_counter()
    result = "ok"
    try:
        yield
    except BaseException as exc:
        result = "error"
        span.set_status(
            Status(StatusCode.ERROR, description=type(exc).__name__)
        )
        raise
    finally:
        duration = time.perf_counter() - start
        vault_requests_total.labels(
            engine=engine, operation=operation, result=result
        ).inc()
        vault_request_duration_seconds.labels(
            engine=engine, operation=operation
        ).observe(duration)
        # Pass no exception info to __exit__ since we've already
        # tagged the span status above; OTel only needs to know the
        # context is closing.
        span_ctx.__exit__(None, None, None)


# ---------------------------------------------------------------------------
# /metrics endpoint response
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Cert-lifecycle gauge collector (Phase 3a cycle 3)
# ---------------------------------------------------------------------------


class CertificateLifecycleCollector:
    """Emit one ``wg_manager_cert_not_after_seconds`` sample per
    non-revoked cert in the ``certificate`` table.

    The collector walks the table on every scrape rather than caching
    so a freshly-issued or freshly-revoked cert shows up on the next
    Prometheus scrape (15s by default). Cardinality is bounded by the
    active cert count — operators + service certs, typically tens —
    so per-cert labels are safe.

    Revoked certs are intentionally excluded: emitting a revoked
    cert's expiry as a gauge sample would either fire noisy "expiring
    soon" alerts on a cert nobody cares about, or mask the absence of
    a real replacement.
    """

    def collect(self):  # noqa: ANN201 — prometheus_client's protocol
        from sqlmodel import Session, select

        from wg_manager import db as db_module
        from wg_manager.models import Certificate

        gauge = GaugeMetricFamily(
            "wg_manager_cert_not_after_seconds",
            (
                "Unix timestamp of each non-revoked cert's `not_after`. "
                "Subtract `time()` to get seconds-until-expiry; the "
                "WgCertExpiringSoon alert fires on `< 7 days`."
            ),
            labels=["serial", "cn", "cert_type"],
        )
        try:
            with Session(db_module.engine) as session:
                rows = session.exec(
                    select(Certificate).where(Certificate.revoked == False)  # noqa: E712
                ).all()
        except Exception:  # noqa: BLE001 — never let a DB blip crash the scrape
            return
        for row in rows:
            if row.not_after is None:
                continue
            gauge.add_metric(
                [
                    str(row.serial),
                    row.common_name or "",
                    row.cert_type.value if row.cert_type else "",
                ],
                row.not_after.timestamp(),
            )
        yield gauge


# Register the collector at import time so ``/metrics`` picks it up
# without further wiring. Idempotent against test re-imports — the
# CollectorRegistry rejects double-registration, so we guard it.
try:
    REGISTRY.register(CertificateLifecycleCollector())
except ValueError:
    # Already registered by an earlier import (e.g. pytest re-import
    # under ``--forked``). Safe to ignore.
    pass


def metrics_response() -> tuple[bytes, str]:
    """Return ``(body, content_type)`` for the ``/metrics`` endpoint.

    The body is the standard Prometheus text format; the content-type
    is what scrapers expect (``text/plain; version=0.0.4; ...``).
    """
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST


__all__ = [
    "CertificateLifecycleCollector",
    "MetricsMiddleware",
    "REGISTRY",
    "certs_issued_total",
    "certs_renewed_total",
    "certs_revoked_total",
    "celery_task_duration_seconds",
    "celery_tasks_total",
    "http_request_duration_seconds",
    "http_requests_total",
    "metrics_response",
    "vault_call",
    "vault_request_duration_seconds",
    "vault_requests_total",
]
