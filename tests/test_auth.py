"""Tests for :mod:`wg_manager.auth` — Phase 2d CP2 mTLS surface.

The auth module is the seam between uvicorn's TLS-terminated socket
and the wg-manager request handlers. CP2 splits the surface into three
pieces that each get their own test class:

* :class:`TestParseSubject` — the pure ``parse_subject_from_pem``
  helper. Pins the :class:`CertSubject` value-object shape so the
  middleware and the CP3 ``Operator`` resolver can rely on a stable
  contract.
* :class:`TestExtractFromScope` — the ASGI-scope adapter. Pins the
  TLS-extension shape we read (``scope["extensions"]["tls"]
  ["client_cert_chain"]``) and the soft-failure behaviour on missing /
  empty / malformed input.
* :class:`TestMTLSMiddleware` — the live middleware exercised through
  a FastAPI :class:`TestClient`. Covers the three branches that
  matter operationally: ``tls_required=False`` (test / dev posture),
  ``tls_required=True`` + no cert (production attacker shape), and
  ``tls_required=True`` + valid cert (production happy path), plus
  the OPTIONS-preflight bypass that lets the dashboard's CORS
  preflight succeed before the browser has sent the client cert.

The fixture uses :class:`wg_manager.pki.LocalDevPKI` to mint real
certs — same code path the production VaultPKI surface uses, just
with the in-process CA — so the parser is exercised against the byte
shape it will see in production rather than a mocked stand-in.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import pytest

from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient
from starlette.types import ASGIApp, Receive, Scope, Send

from wg_manager.auth import (
    AuthError,
    CertSubject,
    MTLSAuthMiddleware,
    extract_subject_from_scope,
    parse_subject_from_pem,
    require_subject,
)
from wg_manager.config import Settings
from wg_manager.pki import LocalDevPKI


def _scope_with_chain(chain: list[str]) -> dict:
    """Build a minimal ASGI scope carrying a TLS extension chain.

    Mirrors the on-the-wire shape uvicorn 0.32+ produces under
    ``--ssl-cert-reqs 2`` — keep this helper local to the test module
    so the production code never sees test scaffolding.
    """
    return {
        "type": "http",
        "method": "GET",
        "path": "/servers",
        "extensions": {"tls": {"client_cert_chain": chain}},
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def ca() -> LocalDevPKI:
    """A fresh in-process CA hierarchy per test."""
    return LocalDevPKI.generate()


# ---------------------------------------------------------------------------
# parse_subject_from_pem
# ---------------------------------------------------------------------------


class TestParseSubject:
    """``parse_subject_from_pem`` parses a leaf cert PEM into ``CertSubject``."""

    def test_parses_cn_sans_serial_validity(self, ca: LocalDevPKI) -> None:
        """A freshly-issued client cert round-trips to a ``CertSubject``
        with matching CN, SANs, serial, and tz-aware validity window."""
        before = datetime.now(timezone.utc)
        cert = ca.issue_client_cert(
            common_name="ops@wg.local",
            sans=["ops@wg.local", "127.0.0.1"],
            ttl_seconds=300,
        )

        subject = parse_subject_from_pem(cert.cert_pem)

        assert isinstance(subject, CertSubject)
        assert subject.common_name == "ops@wg.local"
        assert "ops@wg.local" in subject.sans
        assert "127.0.0.1" in subject.sans
        assert subject.serial == cert.serial
        assert subject.cert_pem.strip() == cert.cert_pem.strip()
        # Validity is tz-aware UTC so a CP3 audit-log timestamp comparison
        # doesn't trip a "naive vs aware" TypeError.
        assert subject.not_before.tzinfo is not None
        assert subject.not_after.tzinfo is not None
        # 5-minute TTL — should expire within the window plus issuer skew.
        assert subject.not_after <= before + timedelta(seconds=300) + timedelta(
            seconds=120
        )

    def test_empty_string_raises_value_error(self) -> None:
        """An empty PEM body is operator error — fail loudly."""
        with pytest.raises(ValueError):
            parse_subject_from_pem("")

    def test_garbage_bytes_raise_value_error(self) -> None:
        """Non-cert input must fail with :class:`ValueError`, not a
        cryptography-library internal exception type that callers don't
        know to catch."""
        with pytest.raises(ValueError):
            parse_subject_from_pem("not a cert\nat all\n")


# ---------------------------------------------------------------------------
# extract_subject_from_scope
# ---------------------------------------------------------------------------


class TestExtractFromScope:
    """``extract_subject_from_scope`` reads the ASGI-TLS extension."""

    def test_chain_with_valid_cert_returns_subject(
        self, ca: LocalDevPKI
    ) -> None:
        """A scope carrying a real cert PEM yields a matching subject."""
        cert = ca.issue_client_cert(
            common_name="ops@wg.local",
            sans=["ops@wg.local"],
            ttl_seconds=300,
        )
        scope = _scope_with_chain([cert.cert_pem])

        subject = extract_subject_from_scope(scope)

        assert subject is not None
        assert subject.common_name == "ops@wg.local"
        assert subject.serial == cert.serial

    def test_missing_extensions_key_returns_none(self) -> None:
        """A scope without an ``extensions`` key (e.g. a plain-HTTP
        request) yields ``None`` rather than raising."""
        scope = {"type": "http", "method": "GET", "path": "/servers"}
        assert extract_subject_from_scope(scope) is None

    def test_empty_chain_returns_none(self) -> None:
        """The TLS extension key is present but the chain list is empty —
        treat as 'no client cert' so the middleware can 401."""
        scope = _scope_with_chain([])
        assert extract_subject_from_scope(scope) is None

    def test_malformed_pem_returns_none_and_logs(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A corrupt PEM in the chain must not crash the middleware path;
        it logs a warning and returns ``None`` so the request gets a
        clean 401 instead of a 500."""
        caplog.set_level(logging.WARNING, logger="wg_manager.auth")
        scope = _scope_with_chain(["-----BEGIN CERTIFICATE-----\nGARBAGE\n"])

        assert extract_subject_from_scope(scope) is None
        joined = "\n".join(r.getMessage() for r in caplog.records)
        assert "malformed client cert" in joined


# ---------------------------------------------------------------------------
# MTLSAuthMiddleware
# ---------------------------------------------------------------------------


class _ScopeInjector:
    """Test-only ASGI middleware: stamp a fixed PEM chain on every scope.

    The production extractor reads ``scope["extensions"]["tls"]
    ["client_cert_chain"]`` — uvicorn populates that under
    ``--ssl-cert-reqs 2``. :class:`starlette.testclient.TestClient`
    speaks plain HTTP and never sets the extension, so the middleware
    under test never sees a cert without help. This shim sits *between*
    ``TestClient`` and :class:`MTLSAuthMiddleware`, injecting whatever
    chain the test wants exercised. Lives in the test module so the
    production ``wg_manager.auth`` surface never references test
    scaffolding.
    """

    def __init__(self, app: ASGIApp, chain: list[str]) -> None:
        self._app = app
        self._chain = chain

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if scope.get("type") == "http" and self._chain:
            scope = dict(scope)
            extensions = dict(scope.get("extensions") or {})
            extensions["tls"] = {"client_cert_chain": list(self._chain)}
            scope["extensions"] = extensions
        await self._app(scope, receive, send)


def _build_app(
    *, tls_required: bool, inject_chain: list[str] | None = None
) -> FastAPI:
    """Build a minimal FastAPI app wired through ``MTLSAuthMiddleware``.

    Two routes:

    * ``GET /open`` — reads ``request.state.cert_subject`` directly so
      the test can assert the middleware stashed the subject.
    * ``GET /protected`` — depends on :func:`require_subject` so the
      test can prove the FastAPI-dep enforcement path works in
      addition to the middleware short-circuit.
    """
    application = FastAPI()
    settings = Settings(tls_required=tls_required)
    application.add_middleware(MTLSAuthMiddleware, settings=settings)
    if inject_chain is not None:
        application.add_middleware(_ScopeInjector, chain=inject_chain)

    @application.get("/open")
    def open_route(request: Request) -> dict:
        subject = getattr(request.state, "cert_subject", None)
        return {
            "cn": subject.common_name if subject else None,
            "serial": subject.serial if subject else None,
        }

    @application.get("/protected")
    def protected_route(
        subject: CertSubject = Depends(require_subject),
    ) -> dict:
        return {"cn": subject.common_name}

    return application


class TestMTLSMiddleware:
    """End-to-end middleware behaviour exercised through ``TestClient``."""

    def test_tls_not_required_passes_through_without_cert(self) -> None:
        """In the test / dev posture every request succeeds and the
        cert_subject slot is ``None``."""
        client = TestClient(_build_app(tls_required=False))

        resp = client.get("/open")

        assert resp.status_code == 200
        assert resp.json() == {"cn": None, "serial": None}

    def test_tls_required_no_cert_returns_401(self) -> None:
        """Production posture: a request with no cert on the scope is
        rejected before the route runs, with a stable JSON body."""
        client = TestClient(_build_app(tls_required=True))

        resp = client.get("/open")

        assert resp.status_code == 401
        assert resp.json() == {"detail": "client cert required"}

    def test_tls_required_with_injected_cert_returns_subject(
        self, ca: LocalDevPKI
    ) -> None:
        """Happy path: an injected client cert chain shows up on
        ``request.state.cert_subject`` with the expected CN and serial."""
        cert = ca.issue_client_cert(
            common_name="ops@wg.local",
            sans=["ops@wg.local"],
            ttl_seconds=300,
        )
        client = TestClient(
            _build_app(tls_required=True, inject_chain=[cert.cert_pem])
        )

        resp = client.get("/open")

        assert resp.status_code == 200
        assert resp.json() == {"cn": "ops@wg.local", "serial": cert.serial}

    def test_options_preflight_bypasses_enforcement(self) -> None:
        """OPTIONS preflight must succeed without a cert so the dashboard's
        CORS negotiation works before the browser sends the cert."""
        client = TestClient(_build_app(tls_required=True))

        # Use a plain OPTIONS — TestClient doesn't run the CORS middleware
        # here (we didn't add it on the minimal test app), but the
        # MTLSAuthMiddleware short-circuit on method=='OPTIONS' is what
        # we're pinning, independent of CORS.
        resp = client.options("/open")

        # 405 or 200 are both acceptable signals that the request made it
        # past the middleware — what we're proving is "no 401 from
        # MTLSAuthMiddleware". A 401 would mean preflight is blocked.
        assert resp.status_code != 401

    def test_require_subject_dep_yields_subject(self, ca: LocalDevPKI) -> None:
        """The ``Depends(require_subject)`` path returns the stashed
        subject when one is present."""
        cert = ca.issue_client_cert(
            common_name="ops@wg.local", sans=["ops@wg.local"], ttl_seconds=300
        )
        client = TestClient(
            _build_app(tls_required=True, inject_chain=[cert.cert_pem])
        )

        resp = client.get("/protected")

        assert resp.status_code == 200
        assert resp.json() == {"cn": "ops@wg.local"}

    def test_require_subject_dep_raises_401_without_subject(self) -> None:
        """In the test / dev posture (``tls_required=False``) the middleware
        leaves ``request.state.cert_subject = None``; a router that opts
        into :func:`require_subject` still 401s, proving the dep is an
        independent enforcement point."""
        client = TestClient(_build_app(tls_required=False))

        resp = client.get("/protected")

        assert resp.status_code == 401
        assert resp.json() == {"detail": "client cert required"}


# ---------------------------------------------------------------------------
# AuthError shape
# ---------------------------------------------------------------------------


class TestAuthError:
    """``AuthError`` is the typed 401 used by :func:`require_subject`."""

    def test_default_status_and_detail(self) -> None:
        err = AuthError()
        assert err.status_code == 401
        assert err.detail == "client cert required"

    def test_detail_can_be_overridden(self) -> None:
        err = AuthError(detail="please present an operator cert")
        assert err.detail == "please present an operator cert"
