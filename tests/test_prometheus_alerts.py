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


class TestHostCertRotationAlerts:
    """SSH host-cert alerts on ``wg_manager_host_cert_valid_before_seconds``.

    Beat renews host certs 12h before expiry, hourly. A cert that keeps
    getting closer to expiry means rotation is failing; one that has
    expired can only be recovered by hand with ``bootstrap-host``.
    """

    def _rule(self, alerts: dict, name: str) -> dict:
        for group in alerts.get("groups", []):
            for rule in group.get("rules", []):
                if rule.get("alert") == name:
                    return rule
        pytest.fail(f"alert {name!r} missing")

    def test_rotation_failing_alert_uses_host_cert_gauge(self, alerts: dict) -> None:
        rule = self._rule(alerts, "WgHostCertRotationFailing")
        assert "wg_manager_host_cert_valid_before_seconds" in rule["expr"]
        assert rule["labels"]["severity"] == "warning"

    def test_expired_alert_is_critical(self, alerts: dict) -> None:
        rule = self._rule(alerts, "WgHostCertExpired")
        assert "wg_manager_host_cert_valid_before_seconds" in rule["expr"]
        assert rule["labels"]["severity"] == "critical"

    def test_expired_runbook_points_at_in_stack_bootstrap(self, alerts: dict) -> None:
        """Recovery is the in-stack bootstrap-host (Path B), not the bare CLI."""
        rule = self._rule(alerts, "WgHostCertExpired")
        assert rule["annotations"]["runbook"].startswith(
            "docs/deploy/single-host-prod.md"
        )
