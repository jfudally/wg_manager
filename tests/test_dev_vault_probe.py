"""Tests for :mod:`tests.dev_vault` — the "is this the dev Vault?" probe.

The Vault-backed tests (crypto, PKI, SSH CA, e2e) default to
``http://127.0.0.1:8200``. On a host that also runs the prod stack,
that address is the **production** Vault, and the old probe (any answer
from ``sys/health``) sent the dev root token to it and tried to mount
engines. The probe must only accept a dev-mode server, and must decide
without sending a token.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from tests.dev_vault import dev_vault_available


class _StubVault:
    """A one-endpoint HTTP stub for ``GET /v1/sys/seal-status``.

    ``status`` and ``body`` set the reply; ``requests`` records each
    request's path and headers so tests can assert no token was sent.
    """

    def __init__(self) -> None:
        self.status = 200
        self.body: str = ""
        self.requests: list[tuple[str, dict[str, str]]] = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 (http.server API)
                stub.requests.append((self.path, dict(self.headers)))
                payload = stub.body.encode()
                self.send_response(stub.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args: object) -> None:  # keep pytest output quiet
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.addr = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def reply(self, **fields: object) -> None:
        """Answer with a seal-status JSON body built from ``fields``."""
        self.body = json.dumps(fields)

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def stub() -> Iterator[_StubVault]:
    s = _StubVault()
    yield s
    s.close()


class TestDevVaultAvailable:
    def test_accepts_an_unsealed_dev_mode_server(self, stub: _StubVault) -> None:
        # What `vault server -dev` (hashicorp/vault:1.18) reports.
        stub.reply(initialized=True, sealed=False, storage_type="inmem")
        assert dev_vault_available(stub.addr) is True

    @pytest.mark.parametrize("storage", ["raft", "file", "consul"])
    def test_rejects_a_server_with_persistent_storage(
        self, stub: _StubVault, storage: str
    ) -> None:
        # Prod's vault.hcl uses raft: that is the server on rv's 8200.
        stub.reply(initialized=True, sealed=False, storage_type=storage)
        assert dev_vault_available(stub.addr) is False

    def test_rejects_a_sealed_server(self, stub: _StubVault) -> None:
        stub.reply(initialized=True, sealed=True, storage_type="inmem")
        assert dev_vault_available(stub.addr) is False

    def test_rejects_a_reply_without_storage_type(self, stub: _StubVault) -> None:
        stub.reply(initialized=True, sealed=False)
        assert dev_vault_available(stub.addr) is False

    @pytest.mark.parametrize(
        ("status", "body"), [(200, "not json"), (200, "[]"), (404, "{}"), (503, "{}")]
    )
    def test_rejects_odd_replies(
        self, stub: _StubVault, status: int, body: str
    ) -> None:
        stub.status, stub.body = status, body
        assert dev_vault_available(stub.addr) is False

    def test_nothing_listening(self) -> None:
        assert dev_vault_available("http://127.0.0.1:1") is False

    def test_sends_no_token(self, stub: _StubVault) -> None:
        # The decision must not hand any token to a server that may be
        # production, even though the dev token is public.
        stub.reply(initialized=True, sealed=False, storage_type="raft")
        dev_vault_available(stub.addr)
        assert [path for path, _ in stub.requests] == ["/v1/sys/seal-status"]
        for _, headers in stub.requests:
            lowered = {k.lower() for k in headers}
            assert "x-vault-token" not in lowered
            assert "authorization" not in lowered


class TestCallersUseTheProbe:
    """Every Vault-backed test module gates on the shared probe."""

    @pytest.mark.parametrize(
        "module",
        ["test_crypto.py", "test_pki.py", "test_ssh_ca.py", "e2e/conftest.py"],
    )
    def test_module_uses_dev_vault_available(self, module: str) -> None:
        from pathlib import Path

        text = (Path(__file__).parent / module).read_text()
        assert "dev_vault_available" in text, module
        assert "sys/health" not in text, module
