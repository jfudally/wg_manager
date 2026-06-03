"""Tests for ``wg_manager.tracing`` (Phase 3a cycle 2).

Three OTLP exporter modes:

* ``none`` (default) — zero overhead; ``trace.get_tracer()`` returns
  a NoOp tracer and no spans land anywhere.
* ``console`` — every finished span prints to stderr. Local dev.
* ``otlp-http`` — POST to ``OTEL_EXPORTER_OTLP_ENDPOINT`` (default
  ``http://localhost:4318``). Production wires this at a collector.

Tests use a fourth ``memory`` mode that ships only for testing.
:func:`wg_manager.tracing.install_in_memory_exporter` swaps the
global provider for one wired to an :class:`InMemorySpanExporter`,
so test code can ``exporter.get_finished_spans()`` to assert on
captured spans without needing a live collector.

The cycle 1 gap (claimed Vault round-trips were wrapped but never
verified the wraps were in place) is closed by
``tests/test_call_sites_traced.py`` — this file covers the
**behavioural** contract (spans get captured), the other covers the
**source-level** contract (the wraps are present in the source).
"""

from __future__ import annotations

import pytest


@pytest.fixture()
def memory_exporter():
    """Yield an in-memory span exporter, pre-cleared.

    Installs the in-memory exporter as the global provider on first
    call; subsequent fixture invocations clear and re-use the same
    instance (OTel's global provider is set-once).
    """
    from wg_manager.tracing import install_in_memory_exporter

    exporter = install_in_memory_exporter()
    exporter.clear()
    yield exporter
    exporter.clear()


# ---------------------------------------------------------------------------
# Module surface
# ---------------------------------------------------------------------------


class TestModuleSurface:
    def test_get_tracer_returns_a_tracer(self) -> None:
        from wg_manager import tracing

        tracer = tracing.get_tracer()
        # Both the no-op and SDK tracers have ``start_as_current_span``.
        assert hasattr(tracer, "start_as_current_span")

    def test_setup_tracing_accepts_none(self) -> None:
        from wg_manager import tracing

        # Idempotent — calling with the same exporter twice is a no-op.
        tracing.setup_tracing(exporter_kind="none")
        tracing.setup_tracing(exporter_kind="none")

    def test_setup_tracing_rejects_unknown_exporter(self) -> None:
        from wg_manager import tracing

        with pytest.raises(ValueError, match="exporter_kind"):
            tracing.setup_tracing(exporter_kind="not-a-real-exporter")


# ---------------------------------------------------------------------------
# vault_call extension — emits a span alongside the metric
# ---------------------------------------------------------------------------


class TestVaultCallSpan:
    """Cycle 1 wrapped Vault round-trips in ``vault_call`` for metrics.
    Cycle 2 extends ``vault_call`` to also start an OTel span so the
    same wrap point feeds both the histogram and the trace."""

    def test_vault_call_emits_span(self, memory_exporter) -> None:
        from wg_manager.metrics import vault_call

        with vault_call(engine="transit", operation="encrypt"):
            pass

        spans = memory_exporter.get_finished_spans()
        names = [s.name for s in spans]
        assert any("vault" in n for n in names), (
            f"vault_call must emit a span with 'vault' in the name; got: {names}"
        )

    def test_span_carries_engine_and_operation_attributes(
        self, memory_exporter
    ) -> None:
        from wg_manager.metrics import vault_call

        with vault_call(engine="pki", operation="issue"):
            pass

        spans = memory_exporter.get_finished_spans()
        vault_spans = [s for s in spans if "vault" in s.name]
        assert vault_spans, "no vault span captured"
        attrs = dict(vault_spans[0].attributes or {})
        assert attrs.get("vault.engine") == "pki"
        assert attrs.get("vault.operation") == "issue"

    def test_error_outcome_sets_span_status_error(
        self, memory_exporter
    ) -> None:
        """A raised exception inside ``vault_call`` must propagate AND
        the span's status must be ``ERROR`` so trace UIs flag it."""
        from opentelemetry.trace import StatusCode

        from wg_manager.metrics import vault_call

        with pytest.raises(RuntimeError):
            with vault_call(engine="ssh", operation="sign-user"):
                raise RuntimeError("simulated Vault failure")

        spans = memory_exporter.get_finished_spans()
        vault_spans = [s for s in spans if "vault" in s.name]
        assert vault_spans
        assert vault_spans[0].status.status_code == StatusCode.ERROR


# ---------------------------------------------------------------------------
# SSH wrapper — wraps run / sudo with sub-spans
# ---------------------------------------------------------------------------


class TestSshSpan:
    """``ssh_span(operation, **attrs)`` is the helper SSHRunner.run /
    sudo wrap themselves with. End-to-end tests run against
    FakeSSHRunner so the assertion is hermetic."""

    def test_ssh_span_helper_emits_span(self, memory_exporter) -> None:
        from wg_manager.tracing import ssh_span

        with ssh_span("connect", host="example.com"):
            pass

        spans = memory_exporter.get_finished_spans()
        names = [s.name for s in spans]
        assert any("ssh" in n for n in names), (
            f"ssh_span must emit a span with 'ssh' in the name; got: {names}"
        )

    def test_ssh_span_carries_attributes(self, memory_exporter) -> None:
        from wg_manager.tracing import ssh_span

        with ssh_span("run", host="vpn-hub-1", cmd="apt install wireguard"):
            pass

        spans = memory_exporter.get_finished_spans()
        ssh_spans = [s for s in spans if "ssh" in s.name]
        assert ssh_spans
        attrs = dict(ssh_spans[0].attributes or {})
        assert attrs.get("ssh.host") == "vpn-hub-1"
        assert attrs.get("ssh.cmd") == "apt install wireguard"


# ---------------------------------------------------------------------------
# Celery auto-instrumentation
# ---------------------------------------------------------------------------


class TestCeleryInstrumentation:
    """Cycle 2 calls ``CeleryInstrumentor().instrument()`` at setup so
    every task gets a span automatically. Verify it's wired."""

    def test_celery_instrumentor_is_installed(self) -> None:
        from opentelemetry.instrumentation.celery import CeleryInstrumentor

        from wg_manager import tracing  # noqa: F401 — import for side effects

        # ``is_instrumented_by_opentelemetry`` is the canonical marker
        # CeleryInstrumentor sets on the celery_app it instrumented.
        # If our tracing module ran instrumentation, this is True.
        assert CeleryInstrumentor().is_instrumented_by_opentelemetry
