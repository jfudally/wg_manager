"""OpenTelemetry tracing for wg-manager (Phase 3a cycle 2).

Three exporter modes (selected via ``OTEL_EXPORTER`` / Settings):

* ``none`` (default) — zero overhead; :func:`get_tracer` returns a
  NoOp tracer and the production paths through
  :func:`wg_manager.metrics.vault_call`, :func:`ssh_span`, and the
  Celery instrumentor become no-ops.
* ``console`` — every finished span prints to stderr. Local dev.
* ``otlp-http`` — POST to ``OTEL_EXPORTER_OTLP_ENDPOINT`` (default
  ``http://localhost:4318``). Production wires this at a collector
  that fans out to Jaeger / Tempo / Honeycomb / etc.

Three span families:

* **Celery tasks** — auto-instrumented via
  :class:`opentelemetry.instrumentation.celery.CeleryInstrumentor`.
  Every task gets a root span named ``celery.<task_name>``.
* **Vault round-trips** — :func:`wg_manager.metrics.vault_call`
  starts a span ``vault.<engine>.<operation>`` and tags it with
  ``vault.engine`` / ``vault.operation`` attributes. Same wrap as
  cycle 1's metrics — one call site, two streams.
* **SSH commands** — :func:`ssh_span` wraps
  :class:`wg_manager.ssh.SSHRunner.run` and ``.sudo`` so the trace
  shows every command-exec as a sub-span under the parent Celery
  task.

The combined trace topology for a single provisioning run:

    celery.wg_manager.tasks.provision_server  (root)
    ├── vault.ssh.sign-user
    ├── ssh.run  (apt install wireguard)
    ├── ssh.run  (wg-quick up wg0)
    ├── vault.ssh.sign-host
    └── ssh.run  (install host cert)

Tests use a fourth ``memory`` mode via
:func:`install_in_memory_exporter`. The global TracerProvider in
OpenTelemetry is set-once — the helper detects an already-installed
in-memory exporter and re-uses it.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
)
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)
from opentelemetry.trace import Status, StatusCode

_LOG = logging.getLogger(__name__)

# Module-local handle for the in-memory exporter (when tests install
# it). ``None`` in production — tests check this and re-use it.
_MEMORY_EXPORTER: InMemorySpanExporter | None = None

# Set after the first successful :func:`setup_tracing` call so
# subsequent calls become no-ops (OTel global provider is set-once).
_SETUP_DONE: bool = False

_VALID_EXPORTERS = frozenset({"none", "console", "otlp-http", "memory"})


def setup_tracing(
    *,
    exporter_kind: str | None = None,
    otlp_endpoint: str | None = None,
    service_name: str = "wg-manager",
) -> None:
    """Install the global TracerProvider according to ``exporter_kind``.

    Idempotent: the first call wins; subsequent calls log + return.
    Test setups should call :func:`install_in_memory_exporter`
    explicitly — it bypasses the set-once guard.

    :param exporter_kind: ``"none"`` / ``"console"`` / ``"otlp-http"``
        / ``"memory"``. Defaults to ``$OTEL_EXPORTER`` or ``"none"``.
    :param otlp_endpoint: OTLP/HTTP collector URL. Defaults to
        ``$OTEL_EXPORTER_OTLP_ENDPOINT`` or
        ``http://localhost:4318``.
    :param service_name: ``service.name`` attribute on every span.
    :raises ValueError: If ``exporter_kind`` is not in
        :data:`_VALID_EXPORTERS`.
    """
    global _SETUP_DONE

    if exporter_kind is None:
        exporter_kind = os.environ.get("OTEL_EXPORTER", "none")
    if otlp_endpoint is None:
        otlp_endpoint = os.environ.get(
            "OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318"
        )

    if exporter_kind not in _VALID_EXPORTERS:
        raise ValueError(
            f"unknown exporter_kind {exporter_kind!r}; expected one of "
            f"{sorted(_VALID_EXPORTERS)}"
        )

    if _SETUP_DONE:
        _LOG.debug(
            "tracing.setup_tracing: provider already installed, "
            "ignoring exporter_kind=%s",
            exporter_kind,
        )
        return

    if exporter_kind == "none":
        # The OTel default tracer provider is a NoOp — leave it alone
        # and just mark setup as done so future calls are silent.
        _SETUP_DONE = True
        _instrument_celery()
        return

    resource = Resource.create({"service.name": service_name})
    provider = TracerProvider(resource=resource)

    if exporter_kind == "console":
        provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
    elif exporter_kind == "otlp-http":
        # Defer the import so a deployment that doesn't install the
        # OTLP exporter package can still boot with exporter=none.
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )

        provider.add_span_processor(
            BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{otlp_endpoint}/v1/traces"))
        )
    elif exporter_kind == "memory":
        global _MEMORY_EXPORTER

        _MEMORY_EXPORTER = InMemorySpanExporter()
        provider.add_span_processor(SimpleSpanProcessor(_MEMORY_EXPORTER))

    trace.set_tracer_provider(provider)
    _SETUP_DONE = True
    _instrument_celery()


def _instrument_celery() -> None:
    """Install the Celery auto-instrumentation.

    Idempotent — :meth:`CeleryInstrumentor.instrument` no-ops on a
    second call. Lives in its own helper so production startup and
    test setup can both ensure it ran without double-importing the
    Celery module.
    """
    try:
        from opentelemetry.instrumentation.celery import CeleryInstrumentor

        CeleryInstrumentor().instrument()
    except Exception as exc:  # noqa: BLE001 — never let tracing crash startup
        _LOG.warning("failed to instrument Celery: %s", exc)


def install_in_memory_exporter() -> InMemorySpanExporter:
    """Bypass the set-once guard and install an in-memory exporter.

    Returns the (singleton) exporter instance. Tests call this from
    a fixture and read ``.get_finished_spans()`` after the code under
    test runs.

    Idempotent — re-uses the existing in-memory exporter if one is
    already installed.
    """
    global _SETUP_DONE, _MEMORY_EXPORTER

    if _MEMORY_EXPORTER is not None:
        return _MEMORY_EXPORTER

    _SETUP_DONE = False  # reset so setup_tracing actually installs
    setup_tracing(exporter_kind="memory")
    assert _MEMORY_EXPORTER is not None
    return _MEMORY_EXPORTER


def get_tracer() -> trace.Tracer:
    """Return the module's tracer.

    Production paths import via this helper rather than
    ``trace.get_tracer(__name__)`` so all wg-manager spans share one
    instrumentation library name.
    """
    return trace.get_tracer("wg_manager")


@contextmanager
def ssh_span(operation: str, **attributes: Any) -> Iterator[Any]:
    """Wrap an SSH-side operation in a span.

    Used by :class:`wg_manager.ssh.SSHRunner.run` / ``.sudo`` so a
    provisioning trace shows every command-exec as a sub-span under
    the parent Celery task.

    :param operation: ``run`` / ``sudo`` / ``connect`` / etc. Becomes
        the span name suffix: ``ssh.<operation>``.
    :param attributes: Span attributes, prefixed ``ssh.`` so they
        sort cleanly under the parent in the trace UI.
    """
    tracer = get_tracer()
    with tracer.start_as_current_span(f"ssh.{operation}") as span:
        for key, value in attributes.items():
            span.set_attribute(f"ssh.{key}", value)
        try:
            yield span
        except BaseException as exc:
            span.set_status(Status(StatusCode.ERROR, description=type(exc).__name__))
            raise


__all__ = [
    "get_tracer",
    "install_in_memory_exporter",
    "setup_tracing",
    "ssh_span",
]
