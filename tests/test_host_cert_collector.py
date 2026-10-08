"""Tests for the SSH host-cert expiry gauge.

``wg_manager_host_cert_valid_before_seconds`` exposes each managed
host's SSH host-cert expiry so Prometheus can alert when rotation is
failing. Beat renews every cert ``SSH_HOST_CERT_RENEW_BEFORE_SECONDS``
(12h) ahead of expiry, so a cert that gets much closer than that means
the sweep's rotations are failing, or beat or the worker is down.

Without this, the only signal was ``host-cert rotation failed`` in the
worker logs. An outage longer than the renew window let several certs
expire unnoticed, and expired hosts can only be recovered by hand with
``bootstrap-host``.

The Celery task counters live in the worker process and aren't scraped
(only the API serves ``/metrics``), so the gauge is read from the DB on
each scrape, like ``wg_manager_cert_not_after_seconds``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi.testclient import TestClient
from prometheus_client.parser import text_string_to_metric_families
from sqlmodel import Session

_METRIC = "wg_manager_host_cert_valid_before_seconds"

_EXPIRY = datetime(2026, 10, 6, 18, 4, 24, tzinfo=timezone.utc)


@pytest.fixture()
def scraped(engine: Any) -> dict[tuple[str, str], tuple[dict, float]]:  # noqa: ARG001
    """Seed hosts in every interesting state, scrape, and index the samples.

    :return: ``{(kind, id): (labels, value)}`` for each gauge sample.
    """
    from wg_manager import db as db_module
    from wg_manager.main import app
    from wg_manager.models import Client, NodeStatus, Server, SSHKey

    with Session(db_module.engine) as session:
        key = SSHKey(name="lab", tenant_id=1)
        session.add(key)
        session.commit()
        session.refresh(key)

        hub = Server(
            ssh_key_id=key.id,
            hostname="65.52.211.113",
            ssh_username="azureuser",
            endpoint_host="65.52.211.113",
            subnet="10.8.0.0/24",
            address="10.8.0.1/24",
            status=NodeStatus.ready,
            host_cert_valid_before=_EXPIRY,
        )
        session.add(hub)
        session.commit()
        session.refresh(hub)

        def client(name: str, **kw: Any) -> None:
            fields: dict[str, Any] = {
                "hostname": f"{name}.lan",
                "server_id": hub.id,
                "ssh_key_id": key.id,
                "status": NodeStatus.ready,
                "host_cert_valid_before": _EXPIRY + timedelta(hours=1),
            }
            fields.update(kw)
            session.add(Client(name=name, **fields))

        client("pihole-0")
        # Rows the sweep never rotates must not be alerted on.
        client("phone", is_manual=True)
        client("mid-provision", status=NodeStatus.pending)
        client("broken", status=NodeStatus.error)
        # Cert state unknown: nothing to compare against.
        client("legacy", host_cert_valid_before=None)
        session.commit()

    body = TestClient(app).get("/metrics").text
    samples: dict[tuple[str, str], tuple[dict, float]] = {}
    for family in text_string_to_metric_families(body):
        if family.name != _METRIC:
            continue
        for sample in family.samples:
            labels = dict(sample.labels)
            samples[(labels["kind"], labels["name"])] = (labels, sample.value)
    return samples


class TestHostCertGauge:
    """One sample per ready, SSH-managed host with a known cert expiry."""

    def test_server_and_ready_client_are_emitted(self, scraped) -> None:
        """The hub and the ready SSH client both appear."""
        assert ("server", "65.52.211.113") in scraped
        assert ("client", "pihole-0") in scraped

    def test_rows_the_sweep_skips_are_excluded(self, scraped) -> None:
        """Manual, non-ready and unknown-expiry rows produce no sample.

        The sweep only rotates ready SSH rows, so alerting on the rest
        would page for certs nothing is supposed to renew.
        """
        for name in ("phone", "mid-provision", "broken", "legacy"):
            assert ("client", name) not in scraped, name

    def test_value_is_valid_before_as_utc_epoch(self, scraped) -> None:
        """The sample is the UTC epoch of ``host_cert_valid_before``."""
        _labels, value = scraped[("server", "65.52.211.113")]
        assert value == _EXPIRY.timestamp()

    def test_labels_identify_the_host(self, scraped) -> None:
        """Enough labels for the alert to say which host and how to reach it."""
        labels, _value = scraped[("client", "pihole-0")]
        assert labels["hostname"] == "pihole-0.lan"
        assert labels["id"].isdigit()
