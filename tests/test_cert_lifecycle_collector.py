"""Tests for the cert-lifecycle gauge collector (Phase 3a cycle 3).

Cycle 3 ships a per-cert ``wg_manager_cert_not_after_seconds`` gauge
so the operator dashboard can render "expiring soon" tables and the
Prometheus alerting rule can fire on `(metric - time()) < 7 days`.

Cycles 1 + 2 only ship aggregate counters
(``wg_manager_certs_issued_total`` etc.) — those tell you the rate
of activity but not which individual certs are due. This is the
table-backed pattern: prometheus_client's :class:`Collector`
protocol lets us walk the ``certificate`` table on each scrape
and emit one sample per non-revoked row.

Cardinality is bounded by the active cert count (operators +
service certs, typically tens, not thousands) so per-cert labels
are safe.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi.testclient import TestClient
from prometheus_client.parser import text_string_to_metric_families
from sqlmodel import Session


@pytest.fixture()
def client_with_certs(engine: Any) -> TestClient:  # noqa: ARG001
    """Seed two cert rows (one expiring soon, one not) and return
    a TestClient.

    The ``engine`` fixture from ``conftest.py`` installs an
    in-memory SQLite schema; the collector reads from
    :data:`wg_manager.db.engine` so seeding through the test
    engine works without further wiring.
    """
    from wg_manager import db as db_module
    from wg_manager.main import app
    from wg_manager.models import Certificate, CertificateType

    now = datetime.now(timezone.utc)
    with Session(db_module.engine) as session:
        session.add(
            Certificate(
                serial="111",
                cert_type=CertificateType.api,
                common_name="api.example.com",
                sans="api.example.com",
                not_before=now,
                not_after=now + timedelta(days=3),  # expiring soon
            )
        )
        session.add(
            Certificate(
                serial="222",
                cert_type=CertificateType.cli,
                common_name="ops@example.com",
                sans="ops@example.com",
                not_before=now,
                not_after=now + timedelta(days=60),
            )
        )
        # Revoked certs must NOT appear in the gauge — once revoked,
        # the cert's expiry is moot for alerting.
        session.add(
            Certificate(
                serial="333",
                cert_type=CertificateType.cli,
                common_name="revoked@example.com",
                sans="revoked@example.com",
                not_before=now,
                not_after=now + timedelta(days=2),
                revoked=True,
                revoked_at=now,
            )
        )
        session.commit()

    return TestClient(app)


class TestCertLifecycleGauge:
    def test_gauge_appears_on_metrics_endpoint(
        self, client_with_certs: TestClient
    ) -> None:
        body = client_with_certs.get("/metrics").text
        assert "wg_manager_cert_not_after_seconds" in body

    def test_gauge_includes_active_certs(
        self, client_with_certs: TestClient
    ) -> None:
        body = client_with_certs.get("/metrics").text
        # The two active certs' serials must both appear in label sets.
        assert 'serial="111"' in body
        assert 'serial="222"' in body

    def test_gauge_excludes_revoked_certs(
        self, client_with_certs: TestClient
    ) -> None:
        """A revoked cert is decommissioned — emitting its expiry as
        a gauge sample would either cause noisy "cert expiring" alerts
        on a cert nobody cares about, or worse, mask the absence of a
        real replacement."""
        body = client_with_certs.get("/metrics").text
        assert 'serial="333"' not in body

    def test_gauge_carries_cn_and_cert_type_labels(
        self, client_with_certs: TestClient
    ) -> None:
        body = client_with_certs.get("/metrics").text
        # Both labels must appear so the dashboard can render a
        # readable "who's expiring" table without joining back to the
        # database.
        assert 'cn="api.example.com"' in body
        assert 'cert_type="api"' in body

    def test_value_is_utc_epoch_on_a_non_utc_host(
        self, client_with_certs: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The sample is ``not_after``'s UTC epoch whatever the host's TZ.

        Regression: the collector called ``.timestamp()`` on the value
        read back from the database. Before sqlmodel 0.0.45 that value
        was naive, so ``.timestamp()`` read it as *local* time and the
        gauge was off by the host's UTC offset (alerts early or late).
        """
        expected = (datetime.now(timezone.utc) + timedelta(days=3)).timestamp()
        # New York's offset is never zero, so a local-time reading shows.
        monkeypatch.setenv("TZ", "America/New_York")
        time.tzset()
        try:
            body = client_with_certs.get("/metrics").text
        finally:
            monkeypatch.undo()
            time.tzset()

        (family,) = [
            f for f in text_string_to_metric_families(body)
            if f.name == "wg_manager_cert_not_after_seconds"
        ]
        (value,) = [s.value for s in family.samples if s.labels["serial"] == "111"]
        # Seeding and scraping take well under a minute; a TZ skew is hours.
        assert abs(value - expected) < 60
