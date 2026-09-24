"""Tests for automatic host-cert rotation (the Celery beat sweep).

:class:`wg_manager.ssh.KnownHostsCAPolicy` now rejects expired host
certs. With the default 24h ``SSH_HOST_CERT_TTL_SECONDS`` and no
automatic renewal, that would lock wg-manager out of every host a day
after its last provision/rotation — and an expired host can't even be
rotated (rotation needs a trusted session), only re-bootstrapped.

:func:`wg_manager.tasks.rotate_expiring_host_certs_task` closes that
loop. Celery beat runs it every ``SSH_HOST_CERT_ROTATION_INTERVAL_SECONDS``;
it fans out one rotation task per ready server / SSH client whose cert
expires within ``SSH_HOST_CERT_RENEW_BEFORE_SECONDS`` (or whose cert
state is unknown). These tests pin the selection rules, the fan-out's
failure isolation, the beat wiring, and the settings guard rails.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from wg_manager.models import Client, NodeStatus, SSHKey, Server


def _utc(hours_from_now: float) -> datetime:
    """Naive-UTC timestamp ``hours_from_now`` away (DB column shape)."""
    return (datetime.now(timezone.utc) + timedelta(hours=hours_from_now)).replace(
        tzinfo=None
    )


@pytest.fixture
def seeded(client: TestClient, engine: Any) -> dict[str, int]:
    """Seed hubs + clients covering every selection case. Returns name → id.

    ``client`` is requested so the app's DB dependency points at the
    test engine the task reads through.
    """
    ids: dict[str, int] = {}
    with Session(engine) as s:
        key = SSHKey(name="lab", tenant_id=1)
        s.add(key)
        s.commit()
        s.refresh(key)

        def server(name: str, valid_before: datetime | None, status: NodeStatus) -> Server:
            row = Server(
                hostname=f"{name}.example.com",
                ssh_username="ubuntu",
                ssh_key_id=key.id,
                endpoint_host=f"{name}.example.com",
                status=status,
                host_cert_serial=1 if valid_before else None,
                host_cert_valid_before=valid_before,
            )
            s.add(row)
            return row

        hubs = {
            "hub-expiring": server("hub-expiring", _utc(2), NodeStatus.ready),
            "hub-expired": server("hub-expired", _utc(-1), NodeStatus.ready),
            "hub-unknown": server("hub-unknown", None, NodeStatus.ready),
            "hub-fresh": server("hub-fresh", _utc(20), NodeStatus.ready),
            "hub-error": server("hub-error", _utc(2), NodeStatus.error),
        }
        s.commit()
        for name, row in hubs.items():
            s.refresh(row)
            ids[name] = int(row.id)

        def spoke(
            name: str,
            valid_before: datetime | None,
            *,
            manual: bool = False,
            status: NodeStatus = NodeStatus.ready,
        ) -> Client:
            row = Client(
                name=name,
                hostname=None if manual else f"{name}.example.com",
                ssh_username=None if manual else "ubuntu",
                ssh_key_id=None if manual else key.id,
                server_id=ids["hub-fresh"],
                is_manual=manual,
                status=status,
                host_cert_serial=1 if valid_before else None,
                host_cert_valid_before=valid_before,
            )
            s.add(row)
            return row

        spokes = {
            "cli-expiring": spoke("cli-expiring", _utc(2)),
            "cli-unknown": spoke("cli-unknown", None),
            "cli-fresh": spoke("cli-fresh", _utc(20)),
            "cli-manual": spoke("cli-manual", None, manual=True),
            "cli-pending": spoke("cli-pending", _utc(2), status=NodeStatus.pending),
        }
        s.commit()
        for name, row in spokes.items():
            s.refresh(row)
            ids[name] = int(row.id)
    return ids


@pytest.fixture
def recorded_dispatches(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[int]]:
    """Replace both rotation tasks' ``.delay`` with recorders (no SSH)."""
    from wg_manager import tasks as tasks_module

    calls: dict[str, list[int]] = {"server": [], "client": []}

    class _Result:
        id = "fake"

    def _record(kind: str):
        def _delay(row_id: int) -> _Result:
            calls[kind].append(row_id)
            return _Result()

        return _delay

    monkeypatch.setattr(tasks_module.rotate_host_cert_task, "delay", _record("server"))
    monkeypatch.setattr(
        tasks_module.rotate_client_host_cert_task, "delay", _record("client")
    )
    return calls


class TestSweepSelection:
    """Renew-window is 12h (default); fresh = 20h left, expiring = 2h left."""

    def test_rotates_ready_servers_that_are_expiring_expired_or_unknown(
        self, seeded: dict[str, int], recorded_dispatches: dict[str, list[int]]
    ) -> None:
        from wg_manager.tasks import rotate_expiring_host_certs_task

        result = rotate_expiring_host_certs_task()

        expected = {seeded["hub-expiring"], seeded["hub-expired"], seeded["hub-unknown"]}
        assert set(recorded_dispatches["server"]) == expected
        assert set(result["servers"]) == expected

    def test_rotates_ready_ssh_clients_only(
        self, seeded: dict[str, int], recorded_dispatches: dict[str, list[int]]
    ) -> None:
        """Manual clients (no SSH) and non-ready rows are never dispatched."""
        from wg_manager.tasks import rotate_expiring_host_certs_task

        result = rotate_expiring_host_certs_task()

        expected = {seeded["cli-expiring"], seeded["cli-unknown"]}
        assert set(recorded_dispatches["client"]) == expected
        assert set(result["clients"]) == expected

    def test_renew_window_comes_from_settings(
        self,
        seeded: dict[str, int],
        recorded_dispatches: dict[str, list[int]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A 1h window leaves the 2h-left rows alone."""
        from wg_manager.tasks import rotate_expiring_host_certs_task

        monkeypatch.setenv("SSH_HOST_CERT_RENEW_BEFORE_SECONDS", "3600")
        monkeypatch.setenv("SSH_HOST_CERT_ROTATION_INTERVAL_SECONDS", "600")
        rotate_expiring_host_certs_task()

        assert seeded["hub-expiring"] not in recorded_dispatches["server"]
        assert seeded["hub-expired"] in recorded_dispatches["server"]
        assert seeded["cli-expiring"] not in recorded_dispatches["client"]

    def test_one_failed_dispatch_does_not_stop_the_sweep(
        self, seeded: dict[str, int], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A broker hiccup on one row is logged and reported; the rest still go out."""
        from wg_manager import tasks as tasks_module
        from wg_manager.tasks import rotate_expiring_host_certs_task

        sent: list[int] = []

        class _Result:
            id = "fake"

        def _flaky(row_id: int) -> _Result:
            if row_id == seeded["hub-expired"]:
                raise ConnectionError("broker unavailable")
            sent.append(row_id)
            return _Result()

        monkeypatch.setattr(tasks_module.rotate_host_cert_task, "delay", _flaky)
        monkeypatch.setattr(
            tasks_module.rotate_client_host_cert_task, "delay", lambda _id: _Result()
        )

        result = rotate_expiring_host_certs_task()

        assert seeded["hub-expiring"] in sent and seeded["hub-unknown"] in sent
        assert result["failed"] == [
            {"kind": "server", "id": seeded["hub-expired"], "error": "broker unavailable"}
        ]


class TestBeatWiring:
    def test_sweep_is_on_the_beat_schedule(self) -> None:
        from wg_manager.celery_app import celery_app
        from wg_manager.config import Settings

        entry = celery_app.conf.beat_schedule["rotate-expiring-host-certs"]
        assert entry["task"] == "wg_manager.tasks.rotate_expiring_host_certs"
        assert entry["schedule"] == float(
            Settings().ssh_host_cert_rotation_interval_seconds
        )


class TestSettingsGuardRails:
    """Misconfigured windows would let certs expire between sweeps."""

    def test_defaults_are_consistent(self) -> None:
        from wg_manager.config import Settings

        s = Settings()
        assert s.ssh_host_cert_rotation_interval_seconds < s.ssh_host_cert_renew_before_seconds
        assert s.ssh_host_cert_renew_before_seconds < s.ssh_host_cert_ttl_seconds

    def test_renew_window_must_be_shorter_than_ttl(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pydantic import ValidationError

        from wg_manager.config import Settings

        monkeypatch.setenv("SSH_HOST_CERT_TTL_SECONDS", "3600")
        monkeypatch.setenv("SSH_HOST_CERT_RENEW_BEFORE_SECONDS", "3600")
        monkeypatch.setenv("SSH_HOST_CERT_ROTATION_INTERVAL_SECONDS", "600")
        with pytest.raises(ValidationError, match="RENEW_BEFORE"):
            Settings()

    def test_interval_must_be_shorter_than_renew_window(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pydantic import ValidationError

        from wg_manager.config import Settings

        monkeypatch.setenv("SSH_HOST_CERT_RENEW_BEFORE_SECONDS", "3600")
        monkeypatch.setenv("SSH_HOST_CERT_ROTATION_INTERVAL_SECONDS", "3600")
        with pytest.raises(ValidationError, match="ROTATION_INTERVAL"):
            Settings()
