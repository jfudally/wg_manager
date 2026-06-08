"""Tests for the combined bootstrap-then-provision flow.

Phase 2c CP4.5 separated bootstrap from provisioning so an operator
could verify the install landed before committing a ``server`` row.
This cycle merges them back into one operator action:

* The Register-server form gains an optional "Bootstrap this host
  first" section. When the operator pastes their OOB SSH key,
  :func:`wg_manager.tasks.provision_server_task` runs
  :func:`bootstrap_host` against the box BEFORE opening the CA-mode
  provision session. Same key never leaves the request; the API
  encrypts it before queueing.
* When the operator leaves the bootstrap section blank,
  ``provision_server_task`` behaves exactly as it did before: opens
  the CA-mode runner, which fails cleanly if the host hasn't been
  bootstrapped yet. The "you forgot to bootstrap" error path stays
  the same.

These tests pin both halves so a future refactor can't silently
break the merged flow or re-introduce the two-action requirement.
"""

from __future__ import annotations

from typing import Any
from unittest import mock

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from tests.conftest import FakeSSHRunner
from wg_manager.crypto import make_backend
from wg_manager.models import NodeStatus, Server


# Real ed25519 host pubkey so the LocalDevSSHCA actually mints a
# parseable host cert against it.
_HOST_PUBKEY = (
    "ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAINcv8wY+y8d0KcKZ6t6S/n7JoYx7M3jzqu7K2YgQGvD7"
    " root@combined-target.example.com"
)


class _RecordingBootstrapRunner:
    """Stand-in for :class:`BootstrapSSHRunner` capturing the key_pem.

    Pins that the task threads the decrypted PEM through to the
    runner constructor (not a path, not a stored credential — the
    operator's one-shot upload).
    """

    CONSTRUCTIONS: list[dict[str, Any]] = []

    def __init__(self, **kwargs: Any) -> None:
        _RecordingBootstrapRunner.CONSTRUCTIONS.append(kwargs)
        self.kwargs = kwargs

    def __enter__(self) -> "_RecordingBootstrapRunner":
        return self

    def __exit__(self, *_: Any) -> None:
        return None

    def sudo(self, cmd: str, check: bool = True) -> Any:
        class _Result:
            def __init__(self, rc: int, stdout: str, stderr: str) -> None:
                self.rc, self.stdout, self.stderr = rc, stdout, stderr

        if "ssh_host_ed25519_key.pub" in cmd:
            return _Result(0, _HOST_PUBKEY + "\n", "")
        return _Result(0, "", "")

    def run(self, cmd: str, check: bool = True) -> Any:
        class _Result:
            def __init__(self, rc: int, stdout: str, stderr: str) -> None:
                self.rc, self.stdout, self.stderr = rc, stdout, stderr

        return _Result(0, "", "")

    def write_file(
        self, path: str, content: str, mode: str = "644", sudo: bool = True
    ) -> Any:
        class _Result:
            def __init__(self, rc: int, stdout: str, stderr: str) -> None:
                self.rc, self.stdout, self.stderr = rc, stdout, stderr

        return _Result(0, "", "")


@pytest.fixture(autouse=True)
def _reset_bootstrap_runner() -> None:
    _RecordingBootstrapRunner.CONSTRUCTIONS = []


def _register_host_pubkey(host: str, pubkey: str = _HOST_PUBKEY) -> None:
    """Make FakeSSHRunner's `cat ssh_host_ed25519_key.pub` return ``pubkey``."""
    FakeSSHRunner.OUTPUTS[(host, "ssh_host_ed25519_key.pub")] = pubkey + "\n"


def _encrypt(plaintext: str, context: str) -> str:
    return make_backend().encrypt(plaintext.encode("utf-8"), context=context)


class TestProvisionBootstrapsWhenPemSupplied:
    """A registration carrying bootstrap material lays down CA trust first."""

    def test_bootstrap_runs_before_provision_when_pem_supplied(
        self,
        client: TestClient,
        session: Session,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The bootstrap runner is constructed with the decrypted PEM.

        Asserts the seam exists: when the router queues
        ``provision_server_task`` with ``bootstrap_pem_ciphertext`` +
        context, the task decrypts and hands the plaintext PEM to a
        :class:`BootstrapSSHRunner`. The runner records the
        ``key_pem`` it saw so the assertion is direct rather than a
        side-effect probe.
        """
        from wg_manager import tasks as tasks_module

        monkeypatch.setattr(
            tasks_module, "BootstrapSSHRunner", _RecordingBootstrapRunner
        )
        _register_host_pubkey("combined-target.example.com")

        # Register an SSH key + drive POST /servers with the new
        # bootstrap fields. The eager Celery flow drives the task to
        # completion inside the request.
        key_id = int(client.post("/ssh-keys", json={"name": "combined"}).json()["id"])
        plaintext_pem = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "ABCDEF\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        )
        resp = client.post(
            "/servers",
            json={
                "hostname": "combined-target.example.com",
                "ssh_username": "ubuntu",
                "ssh_key_id": key_id,
                "endpoint_host": "combined-target.example.com",
                "bootstrap_ssh_key_pem": plaintext_pem,
            },
        )
        assert resp.status_code == 202, resp.text

        # The bootstrap runner was constructed exactly once, with the
        # decrypted PEM the operator submitted.
        assert len(_RecordingBootstrapRunner.CONSTRUCTIONS) == 1, (
            f"expected one BootstrapSSHRunner construction, got "
            f"{len(_RecordingBootstrapRunner.CONSTRUCTIONS)}"
        )
        built = _RecordingBootstrapRunner.CONSTRUCTIONS[0]
        assert built["key_pem"] == plaintext_pem
        # The runner takes the PEM in-memory, not a path on disk.
        assert built.get("key_path") is None
        # Provision used the FakeSSHRunner (CA-mode); the bootstrap
        # runner was a separate session.
        assert FakeSSHRunner.COMMANDS, (
            "provision step must still run after bootstrap — the CA-mode "
            "session was not invoked"
        )

    def test_provision_skips_bootstrap_when_pem_omitted(
        self,
        client: TestClient,
        session: Session,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Today's two-action flow stays valid: no PEM → no bootstrap.

        Provisioning still works against a box that the operator
        bootstrapped separately (CLI, prior dashboard run). The
        bootstrap runner is never instantiated when the PEM is
        absent, which keeps the existing path overhead-free for the
        already-bootstrapped fleet.
        """
        from wg_manager import tasks as tasks_module

        monkeypatch.setattr(
            tasks_module, "BootstrapSSHRunner", _RecordingBootstrapRunner
        )

        key_id = int(client.post("/ssh-keys", json={"name": "no-bootstrap"}).json()["id"])
        resp = client.post(
            "/servers",
            json={
                "hostname": "already-bootstrapped.example.com",
                "ssh_username": "ubuntu",
                "ssh_key_id": key_id,
                "endpoint_host": "already-bootstrapped.example.com",
            },
        )
        assert resp.status_code == 202, resp.text

        assert _RecordingBootstrapRunner.CONSTRUCTIONS == [], (
            "BootstrapSSHRunner must not be instantiated when no "
            "bootstrap PEM was supplied"
        )

    def test_bootstrap_failure_marks_row_error_and_skips_provision(
        self,
        client: TestClient,
        session: Session,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A bad PEM fails the task cleanly without running provision.

        If bootstrap blows up (bad PEM, no sudo, refused), the CA-mode
        runner can't possibly succeed — the host still doesn't trust
        the CA. We surface the bootstrap error and mark the row
        ``error`` so the operator sees the actual reason in the
        polling UI, instead of two cascading SSH-error lines.

        Under the test suite's eager Celery config
        (``task_eager_propagates=True`` in ``conftest.py``), a task
        ``RuntimeError`` re-raises out of ``delay()`` and surfaces
        as a 500 from the TestClient. We catch it and inspect the
        row state separately; the production path (real worker
        consuming from Valkey) records this as a FAILURE on the
        ``AsyncResult`` and returns the task ID promptly — there's
        no equivalent 500 in prod.
        """
        from wg_manager import tasks as tasks_module
        from wg_manager.ssh import SSHConnectionError

        class _BrokenBootstrap(_RecordingBootstrapRunner):
            def __enter__(self) -> "_BrokenBootstrap":
                raise SSHConnectionError(
                    "SSH authentication failed for ubuntu@target: bad key",
                    host="target",
                    port=22,
                )

        monkeypatch.setattr(tasks_module, "BootstrapSSHRunner", _BrokenBootstrap)

        key_id = int(client.post("/ssh-keys", json={"name": "broken-pem"}).json()["id"])
        with pytest.raises(RuntimeError, match="provisioning failed.*bad key"):
            client.post(
                "/servers",
                json={
                    "hostname": "target",
                    "ssh_username": "ubuntu",
                    "ssh_key_id": key_id,
                    "endpoint_host": "target",
                    "bootstrap_ssh_key_pem": "garbage",
                },
            )

        # Provision never ran — no FakeSSHRunner commands captured.
        assert FakeSSHRunner.COMMANDS == [], (
            "provision must not run when bootstrap fails — got "
            f"{FakeSSHRunner.COMMANDS!r}"
        )
        # The row was created in pending state by the router and then
        # flipped to error by the failed task. Inspect via a fresh
        # session against the same engine.
        from wg_manager.db import engine
        with Session(engine) as fresh:
            row = fresh.exec(
                __import__("sqlmodel").select(Server).where(Server.hostname == "target")
            ).one_or_none()
            assert row is not None, "row must exist after register, even on bootstrap failure"
            assert row.status == NodeStatus.error
