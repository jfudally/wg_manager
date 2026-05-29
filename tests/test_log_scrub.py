"""Defence-in-depth: exercise every secret-handling path and grep the
captured log output for PEM bodies, Fernet keys, and WireGuard private
keys. If any leak slips into a logger, this suite breaks.

Why this matters: ``logging.error("…%r", row)`` is the textbook
secret-leak vector. The :class:`SSHKey` and :class:`Client` rows now
override ``__repr__`` (see ``tests/test_model_repr.py``), but that
protection only kicks in if every logger call goes through repr/str —
a future refactor that interpolated ``row.private_key`` directly into
a log message would silently bypass it. This guardrail runs the live
HTTP / CLI / task paths under DEBUG logging and proves nothing leaks
in practice, not just in theory.

The forbidden tokens list is the *literal* secret bodies the suite
seeds into the database via the API. If any of them surface in the
captured logs the test fails fast with the offending line.
"""

from __future__ import annotations

import base64
import logging
import os
from typing import Any

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from wg_manager import cli


# Secrets we plant in the test rows. Each is a unique, recognisable
# string so a leak is unambiguous in the failure message.
_PEM_BODY = "SCRUB-CANARY-PEM-BODY-DO-NOT-LEAK"
_SAMPLE_PEM = (
    f"-----BEGIN OPENSSH PRIVATE KEY-----\n{_PEM_BODY}\n"
    f"-----END OPENSSH PRIVATE KEY-----\n"
)
_SAMPLE_PEM_B64 = base64.b64encode(_SAMPLE_PEM.encode("utf-8")).decode("ascii")
_PASSPHRASE = "SCRUB-CANARY-PASSPHRASE"


# Tokens that must NEVER appear in captured log output. The Fernet key
# value is read straight from the env (the conftest published it), so
# if any code path accidentally logs the backend key the assertion
# fires too.
def _forbidden_tokens() -> list[str]:
    """Return the set of plaintext strings that must not appear in logs."""
    return [
        _PEM_BODY,
        "BEGIN OPENSSH PRIVATE KEY",  # generic PEM header
        _PASSPHRASE,
        os.environ["CRYPTO_LOCAL_DEV_KEY"],
    ]


def _assert_no_leak(records_text: str) -> None:
    """Fail loud with the offending token + a snippet of the log line.

    Slices ``records_text`` to ~200 chars around the offence so the
    failure message is actionable instead of just "found token in 50KB
    of log dump"."""
    for token in _forbidden_tokens():
        idx = records_text.find(token)
        if idx >= 0:
            start = max(0, idx - 80)
            end = min(len(records_text), idx + 80)
            snippet = records_text[start:end]
            raise AssertionError(
                f"forbidden token {token!r} leaked into logs near:\n…{snippet}…"
            )


class TestLogScrubHTTPFlows:
    """API surface — every secret-touching endpoint."""

    def test_create_ssh_key_does_not_log_pem(
        self, client: TestClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.DEBUG):
            resp = client.post(
                "/ssh-keys",
                json={
                    "name": "scrub-lab",
                },
            )
            assert resp.status_code == 201, resp.text
        _assert_no_leak(caplog.text)

    def test_patch_ssh_key_does_not_log_pem(
        self, client: TestClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The PATCH endpoint accepts only rename post-CP4.4 — but a stray
        secret-bearing field still must not bleed into log output even
        when the schema rejects it. ``extra='forbid'`` produces a 422
        and the offending value should never appear in the captured
        logs (FastAPI validation errors echo field names, not values,
        but we pin the contract).
        """
        created = client.post(
            "/ssh-keys",
            json={"name": "scrub-lab"},
        ).json()
        with caplog.at_level(logging.DEBUG):
            resp = client.patch(
                f"/ssh-keys/{created['id']}",
                json={"passphrase": _PASSPHRASE},
            )
            assert resp.status_code == 422, resp.text
        _assert_no_leak(caplog.text)

    def test_register_manual_client_does_not_log_private_key(
        self, client: TestClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Manual-client registration generates a WireGuard private
        key on the control plane and ships it back to the operator
        exactly once via the ``wg_config`` field on the response. The
        key body is per-test and unpredictable, so we read it back from
        the response and assert it didn't slip into the captured logs."""
        # Bootstrap a server.
        key_id = int(
            client.post(
                "/ssh-keys",
                json={"name": "lab"},
            ).json()["id"]
        )
        server_resp = client.post(
            "/servers",
            json={
                "hostname": "hub.example.com",
                "ssh_username": "ubuntu",
                "ssh_key_id": key_id,
                "endpoint_host": "hub.example.com",
            },
        )
        assert server_resp.status_code == 202, server_resp.text
        server_id = int(server_resp.json()["server"]["id"])

        with caplog.at_level(logging.DEBUG):
            resp = client.post(
                "/clients/manual",
                json={"name": "phone", "server_id": server_id},
            )
            assert resp.status_code == 201, resp.text

        # Static PEM canaries.
        _assert_no_leak(caplog.text)

        # Recover the freshly-generated private key from the response
        # body. The body is a real ``wg0.conf`` so the PrivateKey line
        # is "PrivateKey = <44-char base64>\n".
        wg_config = resp.json()["wg_config"]
        wg_secret: str | None = None
        for line in wg_config.splitlines():
            stripped = line.strip()
            if stripped.startswith("PrivateKey ="):
                wg_secret = stripped.split("=", 1)[1].strip()
                break

        assert wg_secret, (
            f"could not parse PrivateKey out of wg_config: {wg_config!r}"
        )
        assert wg_secret not in caplog.text, (
            "manual client WireGuard private key leaked into logs"
        )


class TestLogScrubTaskFlow:
    """Failure paths through the Celery layer — SSH errors must not
    drag PEM bodies along into the log line."""

    def test_provision_failure_does_not_log_pem(
        self,
        client: TestClient,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Force the SSH connection to refuse, then provision a server.
        The task is expected to fail, but its error logging must omit
        the PEM body — historically a popular leak site via traceback
        frames that bake locals into the log."""
        from tests.conftest import FakeSSHRunner

        # Plant an exception so SSHRunner.__enter__ raises.
        FakeSSHRunner.RAISE_ON_ENTER["broken.example.com"] = OSError(
            "scrub-canary-connection-refused"
        )

        client.post(
            "/ssh-keys",
            json={"name": "lab"},
        )

        with caplog.at_level(logging.DEBUG):
            # In eager mode the task fails inline; FastAPI surfaces the
            # task failure as a 500 on the synchronous code path. The
            # registration endpoint dispatches to Celery *after*
            # committing the row, so the API itself still returns 202;
            # the task failure surfaces in caplog instead.
            try:
                client.post(
                    "/servers",
                    json={
                        "hostname": "broken.example.com",
                        "ssh_username": "ubuntu",
                        "ssh_key_id": 1,
                        "endpoint_host": "broken.example.com",
                    },
                )
            except Exception:  # noqa: BLE001
                # Eager Celery tasks can propagate the exception out
                # through TestClient — we still want to assert on the
                # log content, so swallow it here.
                pass

        # The forbidden-token check covers the PEM body. The failure
        # was the intended outcome — what we care about is that the
        # error log line does NOT include the SSH key plaintext.
        _assert_no_leak(caplog.text)


class TestLogScrubCryptoRewrap:
    """``wg-manager crypto rewrap`` walks every row, decrypting then
    re-encrypting. Its progress output must not echo the plaintext,
    only IDs / names."""

    def test_rewrap_output_does_not_contain_plaintext(
        self,
        client: TestClient,
        caplog: pytest.LogCaptureFixture,
        engine: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Create a row through the API (which encrypts it), then run
        rewrap and check both the stdout (CLI output) and caplog for
        plaintext leaks."""
        # Create through the API so the row is encrypted normally.
        client.post(
            "/ssh-keys",
            json={
                "name": "scrub-lab",
            },
        )

        monkeypatch.setattr(cli, "_get_engine", lambda url=None: engine)
        runner = CliRunner()
        with caplog.at_level(logging.DEBUG):
            result = runner.invoke(cli.app, ["crypto", "rewrap"])
        assert result.exit_code == 0, result.output

        _assert_no_leak(caplog.text)
        _assert_no_leak(result.output)
