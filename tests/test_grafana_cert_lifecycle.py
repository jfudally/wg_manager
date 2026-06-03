"""Tests for the cert-lifecycle Grafana dashboard (Phase 3a cycle 3).

A second dashboard alongside cycle 1's service-health view. Mirrors
:mod:`tests.test_grafana_dashboard`'s pattern — pin file existence,
JSON validity, top-level shape, and panel coverage of the metric
families the dashboard depends on.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_PATH = (
    REPO_ROOT / "docs" / "observability" / "grafana-cert-lifecycle.json"
)


@pytest.fixture(scope="module")
def dashboard() -> dict:
    return json.loads(DASHBOARD_PATH.read_text())


@pytest.fixture(scope="module")
def all_queries(dashboard: dict) -> str:
    queries: list[str] = []
    for panel in dashboard.get("panels", []):
        for target in panel.get("targets", []):
            queries.append(target.get("expr") or "")
    return "\n".join(queries)


class TestDashboardExists:
    def test_dashboard_file_exists(self) -> None:
        assert DASHBOARD_PATH.is_file(), (
            f"{DASHBOARD_PATH} is missing — Phase 3a cycle 3 ships the "
            "cert-lifecycle dashboard alongside the service-health one"
        )

    def test_dashboard_is_valid_json(self) -> None:
        json.loads(DASHBOARD_PATH.read_text())


class TestDashboardStructure:
    def test_has_title(self, dashboard: dict) -> None:
        title = dashboard.get("title", "")
        assert title and (
            "cert" in title.lower() or "lifecycle" in title.lower()
        )

    def test_has_panels_array(self, dashboard: dict) -> None:
        panels = dashboard.get("panels")
        assert isinstance(panels, list) and len(panels) > 0


class TestPanelsCoverCertMetrics:
    def test_cert_expiry_gauge_referenced(self, all_queries: str) -> None:
        """The whole point of cycle 3 is the per-cert TTL gauge — at
        least one panel must query it."""
        assert "wg_manager_cert_not_after_seconds" in all_queries

    def test_cert_lifecycle_counters_referenced(self, all_queries: str) -> None:
        """The issue/revoke/renew rate panels surface the operator's
        rotation cadence at a glance."""
        assert "wg_manager_certs_issued_total" in all_queries
        assert "wg_manager_certs_revoked_total" in all_queries
        assert "wg_manager_certs_renewed_total" in all_queries
