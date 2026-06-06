"""Tests for the ``POST /bootstrap-host`` API endpoint.

The endpoint is the API-side surface the dashboard uses to install
the SSH CA trust + a host cert on a fresh target host. It accepts the
operator's long-lived bootstrap SSH key in the request body, encrypts
it via the configured crypto backend before queueing, and dispatches
:func:`wg_manager.tasks.bootstrap_host_task` so the actual SSH work
runs out-of-band on the Celery worker.

Contract:

* Required fields (``hostname``, ``ssh_user``, ``ssh_key_pem``) are
  validated up front; missing values return 422 before any crypto /
  Celery round-trip.
* The PEM body is never logged, never written to disk, never echoed
  back in the response — the response carries only the dispatched
  task ID.
* The task is dispatched with **ciphertext**, not the raw PEM. A
  worker pulling the message off the broker can't recover the key
  without the crypto backend's keys.
* Sensible defaults (``ssh_port=22``, ``ttl_seconds`` from settings,
  ``principal=hostname``) mirror the CLI's defaults so the dashboard
  form can leave them blank.
"""

from __future__ import annotations

from typing import Any
from unittest import mock

import pytest
from fastapi.testclient import TestClient

from wg_manager.crypto import make_backend


class TestBootstrapHostEndpoint:
    """``POST /bootstrap-host`` validates input, encrypts, dispatches."""

    def test_endpoint_dispatches_task_with_encrypted_pem(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Happy path: 202 + task_id; task receives ciphertext, not plaintext.

        Asserts the inversion-of-control invariant: the router does
        the encryption (which it can — it has the crypto backend
        configured for the API process), so the Celery task layer
        receives an opaque blob and the broker sees nothing useful.
        """
        from wg_manager.routers import bootstrap as bootstrap_router

        captured: dict[str, Any] = {}

        class _FakeAsyncResult:
            id = "fake-task-id-abc123"

        def fake_delay(**kwargs: Any) -> _FakeAsyncResult:
            captured.update(kwargs)
            return _FakeAsyncResult()

        monkeypatch.setattr(
            bootstrap_router.bootstrap_host_task, "delay", fake_delay
        )

        pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nABCDEF\n-----END OPENSSH PRIVATE KEY-----\n"
        resp = client.post(
            "/bootstrap-host",
            json={
                "hostname": "fresh-vpn.example.com",
                "ssh_user": "ubuntu",
                "ssh_key_pem": pem,
            },
        )

        assert resp.status_code == 202, resp.text
        body = resp.json()
        assert body["task_id"] == "fake-task-id-abc123"
        # The PEM never appears in the response — defence in depth.
        assert pem not in resp.text

        # The task call received ciphertext, not the PEM body.
        assert "pem_ciphertext" in captured
        assert captured["pem_ciphertext"] != pem
        # The ciphertext decrypts back to the original PEM under the
        # documented context — the round-trip works.
        plaintext = make_backend().decrypt(
            captured["pem_ciphertext"], context=captured["pem_context"]
        ).decode("utf-8")
        assert plaintext == pem

        # Defaults are applied so the dashboard form can omit them.
        assert captured["ssh_port"] == 22
        assert captured["principal"] == "fresh-vpn.example.com"
        assert captured["passphrase_ciphertext"] is None

    def test_endpoint_rejects_missing_required_fields(
        self, client: TestClient
    ) -> None:
        """422 on a body that's missing required fields — no Celery round-trip."""
        resp = client.post(
            "/bootstrap-host",
            json={"hostname": "only-hostname.example.com"},
        )
        assert resp.status_code == 422

    def test_endpoint_overrides_for_principal_and_port(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Optional fields override the defaults — the CLI parity contract."""
        from wg_manager.routers import bootstrap as bootstrap_router

        captured: dict[str, Any] = {}

        class _FakeAsyncResult:
            id = "fake-task-id"

        def fake_delay(**kwargs: Any) -> _FakeAsyncResult:
            captured.update(kwargs)
            return _FakeAsyncResult()

        monkeypatch.setattr(
            bootstrap_router.bootstrap_host_task, "delay", fake_delay
        )

        resp = client.post(
            "/bootstrap-host",
            json={
                "hostname": "65.52.211.113",
                "ssh_user": "azureuser",
                "ssh_port": 2222,
                "principal": "vpn-az-east.internal",
                "ttl_seconds": 3600,
                "ssh_key_pem": "fake-pem",
                "ssh_key_passphrase": "secret-pass",
            },
        )
        assert resp.status_code == 202, resp.text

        assert captured["ssh_port"] == 2222
        assert captured["principal"] == "vpn-az-east.internal"
        assert captured["ttl_seconds"] == 3600
        # Passphrase is also encrypted before queueing.
        assert captured["passphrase_ciphertext"] is not None
        decrypted = make_backend().decrypt(
            captured["passphrase_ciphertext"],
            context=captured["passphrase_context"],
        ).decode("utf-8")
        assert decrypted == "secret-pass"
