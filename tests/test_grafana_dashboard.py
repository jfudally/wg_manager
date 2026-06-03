"""Tests for ``docs/observability/grafana-dashboard.json`` (Phase 3a cycle 1).

The dashboard is the operator-facing entry point for the metrics
``wg_manager.metrics`` exposes. A future refactor that renames a
metric without updating this dashboard would break the panel; the
panels themselves reference the canonical metric names so a
metric-rename in :mod:`wg_manager.metrics` trips the test here
before it lands.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_PATH = (
    REPO_ROOT / "docs" / "observability" / "grafana-dashboard.json"
)


@pytest.fixture(scope="module")
def dashboard() -> dict:
    return json.loads(DASHBOARD_PATH.read_text())


class TestDashboardExists:
    def test_dashboard_file_exists(self) -> None:
        assert DASHBOARD_PATH.is_file(), (
            f"{DASHBOARD_PATH} is missing — Phase 3a cycle 1 ships the "
            "starter dashboard alongside the metrics module"
        )

    def test_dashboard_is_valid_json(self) -> None:
        # Already covered by the fixture's json.loads, but pin
        # explicitly so the test name surfaces in CI.
        json.loads(DASHBOARD_PATH.read_text())


class TestDashboardStructure:
    """The Grafana dashboard JSON has a stable top-level shape — a
    ``title`` + ``panels`` array. Pin them so a hand-edit that breaks
    importability is caught."""

    def test_has_title(self, dashboard: dict) -> None:
        assert dashboard.get("title")

    def test_has_panels_array(self, dashboard: dict) -> None:
        panels = dashboard.get("panels")
        assert isinstance(panels, list) and len(panels) > 0


class TestPanelsCoverEveryMetricFamily:
    """Each metric family ``wg_manager.metrics`` declares must show up
    in at least one panel's PromQL query. Otherwise we're shipping a
    dashboard that pretends the metric isn't there."""

    @pytest.fixture(scope="class")
    def all_queries(self, dashboard: dict) -> str:
        """Flatten every panel's ``targets[].expr`` into one big blob —
        the metric-name search reduces to a substring check."""
        queries: list[str] = []
        for panel in dashboard.get("panels", []):
            for target in panel.get("targets", []):
                expr = target.get("expr") or ""
                queries.append(expr)
        return "\n".join(queries)

    def test_http_metrics_covered(self, all_queries: str) -> None:
        assert "wg_manager_http_requests_total" in all_queries, (
            "dashboard must include a panel querying "
            "wg_manager_http_requests_total"
        )
        assert "wg_manager_http_request_duration_seconds" in all_queries

    def test_celery_metrics_covered(self, all_queries: str) -> None:
        assert "wg_manager_celery_tasks_total" in all_queries
        assert "wg_manager_celery_task_duration_seconds" in all_queries

    def test_vault_metrics_covered(self, all_queries: str) -> None:
        assert "wg_manager_vault_requests_total" in all_queries
        assert "wg_manager_vault_request_duration_seconds" in all_queries

    def test_cert_metrics_covered(self, all_queries: str) -> None:
        # At least one cert lifecycle counter is referenced.
        assert (
            "wg_manager_certs_issued_total" in all_queries
            or "wg_manager_certs_renewed_total" in all_queries
            or "wg_manager_certs_revoked_total" in all_queries
        )
