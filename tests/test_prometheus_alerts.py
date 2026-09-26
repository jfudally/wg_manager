"""Tests for ``docs/observability/prometheus-alerts.yaml`` (Phase 3a cycle 3).

The alerting recipes ship as a Prometheus rules YAML an operator can
drop into their Prometheus config (or adapt to their own
alertmanager). Three rules:

* ``Wg5xxSurge`` — 5xx rate exceeds threshold (default 5% of total
  request rate over 5m).
* ``WgVaultLatencyHigh`` — Vault round-trip p95 > 2s for 5m.
* ``WgCertExpiringSoon`` — non-revoked cert with ``not_after``
  within the next 7 days.

These tests pin the file's shape so a hand-edit can't drop a rule.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
ALERTS_PATH = REPO_ROOT / "docs" / "observability" / "prometheus-alerts.yaml"


@pytest.fixture(scope="module")
def alerts() -> dict:
    return yaml.safe_load(ALERTS_PATH.read_text())


@pytest.fixture(scope="module")
def alert_names(alerts: dict) -> set[str]:
    names: set[str] = set()
    for group in alerts.get("groups", []) or []:
        for rule in group.get("rules", []) or []:
            name = rule.get("alert")
            if name:
                names.add(name)
    return names


@pytest.fixture(scope="module")
def all_exprs(alerts: dict) -> str:
    exprs: list[str] = []
    for group in alerts.get("groups", []) or []:
        for rule in group.get("rules", []) or []:
            exprs.append(rule.get("expr") or "")
    return "\n".join(exprs)


class TestAlertsFileExists:
    def test_file_exists(self) -> None:
        assert ALERTS_PATH.is_file()

    def test_is_valid_yaml(self) -> None:
        body = yaml.safe_load(ALERTS_PATH.read_text())
        assert isinstance(body, dict)
        assert "groups" in body


class TestThreeAlertsPresent:
    def test_5xx_surge_alert_present(self, alert_names: set[str]) -> None:
        assert any("5xx" in n.lower() or "5XX" in n for n in alert_names), (
            f"5xx-surge alert missing — got names: {alert_names}"
        )

    def test_vault_latency_alert_present(self, alert_names: set[str]) -> None:
        assert any("vault" in n.lower() for n in alert_names)

    def test_cert_expiring_alert_present(self, alert_names: set[str]) -> None:
        assert any("cert" in n.lower() and "expir" in n.lower() for n in alert_names)


class TestExprsReferenceCanonicalMetrics:
    def test_5xx_expr_uses_http_counter(self, all_exprs: str) -> None:
        assert "wg_manager_http_requests_total" in all_exprs

    def test_vault_expr_uses_duration_histogram(self, all_exprs: str) -> None:
        assert "wg_manager_vault_request_duration_seconds" in all_exprs

    def test_cert_expr_uses_cert_gauge(self, all_exprs: str) -> None:
        assert "wg_manager_cert_not_after_seconds" in all_exprs


class TestEveryAlertHasRequiredFields:
    """Each Prometheus alert rule must declare ``alert`` (name),
    ``expr`` (PromQL), and ``annotations`` (summary / description)
    for it to land cleanly in Alertmanager. Pin so a hand-edit can't
    ship a rule that's silent on fire."""

    def test_each_alert_has_expr(self, alerts: dict) -> None:
        for group in alerts.get("groups", []):
            for rule in group.get("rules", []):
                if rule.get("alert"):
                    assert rule.get("expr"), (
                        f"alert {rule['alert']!r} has no expr"
                    )

    def test_each_alert_has_annotations(self, alerts: dict) -> None:
        for group in alerts.get("groups", []):
            for rule in group.get("rules", []):
                if rule.get("alert"):
                    annots = rule.get("annotations") or {}
                    assert annots.get("summary"), (
                        f"alert {rule['alert']!r} has no annotations.summary"
                    )


class TestEnrollAlerts:
    """Phase 3f hardening: alerts on the enrollment listener's counters."""

    ENROLL_ALERTS = ("WgEnrollTokenGuessing", "WgEnrollDeadTokens", "WgEnrollMetricsDown")

    @pytest.fixture(scope="class")
    def rules(self, alerts: dict) -> dict[str, dict]:
        return {
            r["alert"]: r
            for g in alerts["groups"]
            for r in g["rules"]
            if r.get("alert") in self.ENROLL_ALERTS
        }

    def test_present(self, rules: dict[str, dict]) -> None:
        assert set(rules) == set(self.ENROLL_ALERTS)

    def test_guessing_watches_unknown_tokens(self, rules: dict[str, dict]) -> None:
        expr = rules["WgEnrollTokenGuessing"]["expr"]
        assert "wg_manager_enroll_rejects_total" in expr
        assert 'reason="unknown_token"' in expr

    def test_dead_tokens_watches_expired_and_exhausted(self, rules: dict[str, dict]) -> None:
        expr = rules["WgEnrollDeadTokens"]["expr"]
        assert "wg_manager_enroll_rejects_total" in expr
        assert "expired" in expr and "exhausted" in expr

    def test_metrics_down_watches_up_gauge(self, rules: dict[str, dict]) -> None:
        assert "wg_manager_enroll_metrics_up" in rules["WgEnrollMetricsDown"]["expr"]

    def test_metric_names_match_what_the_collector_emits(
        self, rules: dict[str, dict]
    ) -> None:
        """Catch a typo'd metric name, which would make an alert never fire."""
        import re

        from prometheus_client import CollectorRegistry, generate_latest

        from wg_manager.enroll_metrics import MemoryEnrollMetrics
        from wg_manager.metrics import EnrollMetricsCollector

        store = MemoryEnrollMetrics()
        store.record_reject("unknown_token")
        store.record_response(401)
        store.record_rate_limited("failures")
        reg = CollectorRegistry()
        reg.register(EnrollMetricsCollector(lambda: store))
        body = generate_latest(reg).decode()
        emitted = set(re.findall(r"^(wg_manager_\w+?)(?:\{| )", body, re.M))
        for name, rule in rules.items():
            for metric in re.findall(r"wg_manager_\w+", rule["expr"]):
                assert metric in emitted, (name, metric)
