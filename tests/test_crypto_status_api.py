"""Tests for ``GET /crypto/status``.

The status endpoint powers the dashboard's "Crypto status" panel. After
Alembic 0008 dropped the sshkey ciphertext columns and 0009 dropped the
manual-client private-key ciphertext column, no wg-manager table holds
encrypted secret material at rest. The endpoint shrinks accordingly
to reporting only the backend identity and current key version — the
two facts the dashboard still surfaces and the operator still cares
about (e.g. "is Vault healthy?"; "did my Transit rotation land?").

This test pins the response shape so the dashboard can rely on it,
and asserts the historical per-table counters are gone (so any future
regression that re-adds them will surface during PR review rather than
in the dashboard).
"""

from __future__ import annotations

from fastapi.testclient import TestClient


class TestCryptoStatus:
    def test_reports_backend_and_key_version(self, client: TestClient) -> None:
        """Identifies the active backend and its current key version."""
        resp = client.get("/crypto/status")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["backend"] == "local-dev"
        assert body["key_version"] == 1

    def test_response_shape_is_stable(self, client: TestClient) -> None:
        """Lock the JSON shape so the dashboard can rely on it. The
        response is intentionally minimal — the per-table counters
        that lived here pre-0009 are gone because no row carries
        ciphertext any more."""
        body = client.get("/crypto/status").json()
        assert set(body.keys()) == {"backend", "key_version"}
        assert isinstance(body["backend"], str)
        assert isinstance(body["key_version"], int)
        # The historical counters must not creep back in via a future
        # regression — the dashboard panel relies on the new shape.
        for retired in (
            "client_encrypted",
            "client_legacy",
            "sshkey_encrypted",
            "sshkey_legacy",
        ):
            assert retired not in body
