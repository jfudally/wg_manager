"""Phase 3c — public API versioning (``/v1`` namespace + deprecation policy).

Every router that shipped under an unprefixed path (``/servers``,
``/clients``, ``/ssh-keys``, ``/certs``, ``/tenants``, ``/audit``,
``/crypto``, ``/tasks``) is now **dual-mounted** at the same path
under ``/v1`` so existing CLI / dashboard / third-party integrations
keep working while new callers can opt into the explicit version.

The unprefixed paths get a deprecation envelope (RFC 9745):

* ``Deprecation: true`` on every response from the legacy paths.
* ``Sunset: <RFC 7231 date>`` naming the date the unprefixed path
  will be removed. The date is settings-driven so operators can
  extend the window without a code change.
* ``Link: <https://...>; rel="deprecation"`` pointing at the
  ``docs/api-versioning.md`` policy.
* One structured ``api.deprecation`` audit line per request so SIEM
  / log greppers can quantify legacy-path usage.

The ``/v1`` paths do **not** carry the deprecation envelope. The
``/openapi.json`` continues to surface both surfaces; ``/v1/openapi.json``
filters to just the v1 paths so a v1-only generator (e.g. a typed
OpenAPI client) doesn't accidentally consume legacy operations.
"""

from __future__ import annotations

from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Dual-mount: every router answers at both prefixes
# ---------------------------------------------------------------------------


_DUAL_MOUNT_GETS = [
    "/ssh-keys",
    "/servers",
    "/clients",
    "/tenants",
    "/certs",
]


class TestDualMount:
    """Each shipped router answers under both ``/<resource>`` and
    ``/v1/<resource>``. Status codes and response bodies match so a
    caller that flips from one to the other sees identical behaviour
    (modulo the deprecation envelope on the legacy path)."""

    def test_legacy_and_v1_list_servers_return_same_body(
        self, client: TestClient
    ) -> None:
        legacy = client.get("/servers")
        v1 = client.get("/v1/servers")
        assert legacy.status_code == 200, legacy.text
        assert v1.status_code == 200, v1.text
        assert legacy.json() == v1.json()

    def test_legacy_and_v1_list_ssh_keys_return_same_body(
        self, client: TestClient
    ) -> None:
        legacy = client.get("/ssh-keys")
        v1 = client.get("/v1/ssh-keys")
        assert legacy.status_code == 200, legacy.text
        assert v1.status_code == 200, v1.text
        assert legacy.json() == v1.json()

    def test_legacy_and_v1_list_tenants_return_same_body(
        self, client: TestClient
    ) -> None:
        """``/tenants`` GET is gated by the auth deps; without an
        operator override the dual-mounted endpoints both 401. The
        invariant is "identical status code + identical body" —
        whether the underlying handler admits or rejects, the dual
        mount must agree."""
        legacy = client.get("/tenants")
        v1 = client.get("/v1/tenants")
        assert legacy.status_code == v1.status_code
        assert legacy.json() == v1.json()


# ---------------------------------------------------------------------------
# Deprecation envelope on legacy paths only
# ---------------------------------------------------------------------------


class TestDeprecationEnvelope:
    """Legacy unprefixed paths carry RFC 9745 ``Deprecation`` +
    ``Sunset`` + ``Link`` headers; ``/v1`` paths do not.

    The deprecation date is settings-driven (``API_LEGACY_SUNSET_DATE``)
    so operators can extend the window without a code change.
    """

    def test_legacy_get_carries_deprecation_header(
        self, client: TestClient
    ) -> None:
        resp = client.get("/servers")
        assert resp.headers.get("Deprecation") == "true"

    def test_legacy_get_carries_sunset_header(
        self, client: TestClient
    ) -> None:
        resp = client.get("/servers")
        sunset = resp.headers.get("Sunset")
        assert sunset is not None and sunset != ""

    def test_legacy_get_carries_deprecation_link(
        self, client: TestClient
    ) -> None:
        resp = client.get("/servers")
        link = resp.headers.get("Link")
        assert link is not None
        assert 'rel="deprecation"' in link
        # The link target points at the operator-facing policy doc.
        assert "api-versioning" in link

    def test_v1_path_has_no_deprecation_header(
        self, client: TestClient
    ) -> None:
        resp = client.get("/v1/servers")
        assert "Deprecation" not in resp.headers
        assert "Sunset" not in resp.headers

    def test_legacy_post_also_carries_deprecation(
        self, client: TestClient
    ) -> None:
        """The envelope rides on writes too — not just reads — so
        operators see the warning regardless of which verb their
        integration uses."""
        resp = client.post("/ssh-keys", json={"name": "deprecated-call"})
        # Whether 201 or 4xx, the header lands on the response.
        assert resp.headers.get("Deprecation") == "true"


# ---------------------------------------------------------------------------
# Audit emission on legacy hits
# ---------------------------------------------------------------------------


class TestLegacyAuditLine:
    """One ``api.deprecation`` audit line per request that hits a
    legacy path. Lets operators run a Splunk / SIEM query to find
    callers that still need migration."""

    def test_legacy_get_emits_audit_line(
        self,
        client: TestClient,
        caplog: object,
    ) -> None:
        import logging
        import pytest

        c = caplog  # type: pytest.LogCaptureFixture  # noqa: F841

        with caplog.at_level(  # type: ignore[attr-defined]
            logging.WARNING, logger="wg_manager.audit"
        ):
            client.get("/servers")

        joined = "\n".join(
            r.getMessage() for r in caplog.records  # type: ignore[attr-defined]
        )
        assert "api.deprecation" in joined
        assert "/servers" in joined

    def test_v1_get_does_not_emit_deprecation_audit(
        self,
        client: TestClient,
        caplog: object,
    ) -> None:
        import logging

        with caplog.at_level(  # type: ignore[attr-defined]
            logging.WARNING, logger="wg_manager.audit"
        ):
            client.get("/v1/servers")

        joined = "\n".join(
            r.getMessage() for r in caplog.records  # type: ignore[attr-defined]
        )
        assert "api.deprecation" not in joined


# ---------------------------------------------------------------------------
# OpenAPI surface
# ---------------------------------------------------------------------------


class TestOpenAPISurface:
    """``/openapi.json`` continues to surface both spaces; the
    explicit ``/v1/openapi.json`` filters to just v1 paths with a
    pinned ``info.version``."""

    def test_root_openapi_lists_both_paths(self, client: TestClient) -> None:
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        paths = resp.json().get("paths", {})
        assert "/servers" in paths
        assert "/v1/servers" in paths

    def test_v1_openapi_filters_to_v1_paths_only(
        self, client: TestClient
    ) -> None:
        resp = client.get("/v1/openapi.json")
        assert resp.status_code == 200
        spec = resp.json()
        paths = spec.get("paths", {})
        # Every path key starts with /v1.
        non_v1 = [p for p in paths if not p.startswith("/v1")]
        assert non_v1 == [], (
            f"v1 spec must only contain /v1 paths; found {non_v1}"
        )
        # Includes the dual-mounted resources.
        assert any(p.startswith("/v1/servers") for p in paths)
        assert any(p.startswith("/v1/ssh-keys") for p in paths)

    def test_v1_openapi_pins_info_version(self, client: TestClient) -> None:
        resp = client.get("/v1/openapi.json")
        spec = resp.json()
        # Cycle 1 ships v1 — semver "1.0" as the contract floor.
        assert spec.get("info", {}).get("version") == "1.0"
