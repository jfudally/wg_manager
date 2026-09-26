"""Tests for the expired-enrollment-token sweeper (Phase 3f hardening).

:func:`wg_manager.tasks.sweep_enrollment_tokens_task` runs on Celery beat
every ``ENROLL_TOKEN_SWEEP_INTERVAL_SECONDS`` and deletes tokens that
expired or were revoked more than ``ENROLL_TOKEN_RETENTION_SECONDS`` ago.
Live tokens, and dead ones still inside the grace period (so they stay
visible in ``GET /v1/enrollment-tokens``), are kept. History survives
in the audit table.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlmodel import Session, select

from wg_manager.enrollment import mint_token
from wg_manager.models import EnrollmentToken, NodeStatus, Server, SSHKey

_DAY = 86400


def _ago(seconds: float) -> datetime:
    """Naive-UTC timestamp ``seconds`` in the past (DB column shape)."""
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).replace(tzinfo=None)


@pytest.fixture
def seeded(client: TestClient, engine: Any) -> dict[str, int]:
    """One token per case; returns name → id.

    ``client`` is requested so the app's DB wiring points at the test
    engine the task reads through (same as the host-cert sweep tests).
    """
    with Session(engine) as s:
        key = SSHKey(name="ops", tenant_id=1)
        s.add(key)
        s.commit()
        s.refresh(key)
        hub = Server(
            hostname="hub.example.com", ssh_username="ubuntu", ssh_key_id=key.id,
            endpoint_host="hub.example.com", public_key="HUBPUB=",
            status=NodeStatus.ready, tenant_id=1,
            subnet="10.9.0.0/24", address="10.9.0.1/24",
        )
        s.add(hub)
        s.commit()
        s.refresh(hub)

        cases: dict[str, dict[str, Any]] = {
            "live": {},
            "exhausted-live": {"use_count": 1},
            "expired-recent": {"expires_at": _ago(3600)},
            "expired-old": {"expires_at": _ago(8 * _DAY)},
            "revoked-recent": {"revoked_at": _ago(3600)},
            "revoked-old": {"revoked_at": _ago(8 * _DAY)},
        }
        ids: dict[str, int] = {}
        for name, values in cases.items():
            row, _ = mint_token(
                s, server=hub, ssh_key=key, ssh_username="wgmgr",
                name_prefix="web", ttl_seconds=3600, max_uses=1,
                created_by_cn=None,
            )
            for k, v in values.items():
                setattr(row, k, v)
            ids[name] = int(row.id or 0)
        s.commit()
    return ids


def _remaining(engine: Any) -> set[int]:
    with Session(engine) as s:
        return {int(r.id or 0) for r in s.exec(select(EnrollmentToken)).all()}


class TestSweep:
    """Default retention is 7 days; "old" = 8 days, "recent" = 1 hour."""

    def test_deletes_only_tokens_dead_for_longer_than_retention(
        self, seeded: dict[str, int], engine: Any
    ) -> None:
        from wg_manager.tasks import sweep_enrollment_tokens_task

        result = sweep_enrollment_tokens_task()

        old = {seeded["expired-old"], seeded["revoked-old"]}
        assert set(result["deleted"]) == old
        assert _remaining(engine) == set(seeded.values()) - old

    def test_retention_comes_from_settings(
        self, seeded: dict[str, int], engine: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With a 60 s retention, the hour-old dead tokens go too."""
        from wg_manager.tasks import sweep_enrollment_tokens_task

        monkeypatch.setenv("ENROLL_TOKEN_RETENTION_SECONDS", "60")
        sweep_enrollment_tokens_task()

        assert _remaining(engine) == {seeded["live"], seeded["exhausted-live"]}

    def test_second_run_is_a_no_op(self, seeded: dict[str, int], engine: Any) -> None:
        from wg_manager.tasks import sweep_enrollment_tokens_task

        sweep_enrollment_tokens_task()
        assert sweep_enrollment_tokens_task()["deleted"] == []

    def test_logs_a_summary(
        self, seeded: dict[str, int], caplog: pytest.LogCaptureFixture
    ) -> None:
        import logging

        from wg_manager.tasks import sweep_enrollment_tokens_task

        caplog.set_level(logging.INFO, logger="wg_manager.tasks")
        sweep_enrollment_tokens_task()
        assert any(
            "enrollment-token sweep: deleted 2" in r.getMessage() for r in caplog.records
        )


class TestBeatWiring:
    def test_sweep_is_on_the_beat_schedule(self) -> None:
        from wg_manager.celery_app import celery_app
        from wg_manager.config import Settings

        entry = celery_app.conf.beat_schedule["sweep-enrollment-tokens"]
        assert entry["task"] == "wg_manager.tasks.sweep_enrollment_tokens"
        assert entry["schedule"] == float(Settings().enroll_token_sweep_interval_seconds)


class TestSettings:
    def test_defaults(self) -> None:
        from wg_manager.config import Settings

        s = Settings()
        assert s.enroll_token_retention_seconds == 7 * _DAY
        assert s.enroll_token_sweep_interval_seconds == 3600

    @pytest.mark.parametrize(
        "env",
        [
            {"ENROLL_TOKEN_RETENTION_SECONDS": "-1"},
            {"ENROLL_TOKEN_SWEEP_INTERVAL_SECONDS": "0"},
        ],
    )
    def test_rejects_nonsense(
        self, env: dict[str, str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from wg_manager.config import Settings

        for k, v in env.items():
            monkeypatch.setenv(k, v)
        with pytest.raises(ValidationError):
            Settings()


class TestProdCompose:
    """beat runs the sweep, so it must see the operator's overrides."""

    def test_beat_passes_sweeper_settings_through(self) -> None:
        from pathlib import Path

        import yaml

        from tests.test_compose_prod_overlay import _ComposeLoader, _env

        root = Path(__file__).resolve().parents[1]
        doc = yaml.load(
            (root / "docker-compose.prod.yml").read_text(), Loader=_ComposeLoader
        )
        env = _env(doc["services"]["beat"])
        assert env["ENROLL_TOKEN_RETENTION_SECONDS"] == (
            "${ENROLL_TOKEN_RETENTION_SECONDS:-604800}"
        )
        assert env["ENROLL_TOKEN_SWEEP_INTERVAL_SECONDS"] == (
            "${ENROLL_TOKEN_SWEEP_INTERVAL_SECONDS:-3600}"
        )
        example = (root / ".env.prod.example").read_text()
        assert "# ENROLL_TOKEN_RETENTION_SECONDS=604800" in example
