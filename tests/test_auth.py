"""Tests for :mod:`wg_manager.auth` — Phase 2d CP2 + CP3.2 mTLS surface.

The auth module is the seam between uvicorn's TLS-terminated socket
and the wg-manager request handlers. CP2 split the surface into three
pieces; CP3.2 layers the operator-registry tightening on top so a
*valid* Vault-signed cert with an *unknown* CN is no longer waved
through. Each piece has its own test class:

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
* :class:`TestOperatorRegistryEnforcement` (CP3.2) — pins the
  Operator-registry tightening: unknown CN → 401, disabled row →
  401, active row → 200 with the row stashed on
  ``request.state.operator``, and the bootstrap-CN self-register path
  that closes the chicken-and-egg gap CP3.1 left behind.
* :class:`TestRequireRoleDependency` (CP3.2) — pins the role-filtered
  variant of the FastAPI dep so handlers can gate mutations behind
  ``admin`` without re-implementing the lookup.

The fixture uses :class:`wg_manager.pki.LocalDevPKI` to mint real
certs — same code path the production VaultPKI surface uses, just
with the in-process CA — so the parser is exercised against the byte
shape it will see in production rather than a mocked stand-in.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient
from sqlmodel import Session
from starlette.types import ASGIApp, Receive, Scope, Send

import json

from wg_manager.auth import (
    AuthError,
    CertSubject,
    MTLSAuthMiddleware,
    extract_subject_from_scope,
    parse_subject_from_pem,
    require_role,
    require_subject,
)
from wg_manager.config import Settings
from wg_manager.models import (
    Certificate,
    CertificateType,
    Operator,
    OperatorRole,
    OperatorStatus,
)
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
    *,
    tls_required: bool,
    inject_chain: list[str] | None = None,
    settings: Settings | None = None,
) -> FastAPI:
    """Build a minimal FastAPI app wired through ``MTLSAuthMiddleware``.

    Routes:

    * ``GET /open`` — reads ``request.state.cert_subject`` and
      ``request.state.operator`` directly so the test can assert the
      middleware stashed both.
    * ``GET /protected`` — depends on :func:`require_subject` so the
      test can prove the FastAPI-dep enforcement path works in
      addition to the middleware short-circuit.
    * ``GET /admin-only`` — depends on
      ``require_role(OperatorRole.admin)`` so CP3.2's role-gated dep
      can be exercised end-to-end.

    :param settings: Override the :class:`Settings` instance the
        middleware captures at construction time. Tests use this to
        pin the bootstrap CN without leaking via ``monkeypatch.setenv``
        (which would also affect any other middleware that re-reads
        :class:`Settings` mid-request).
    """
    application = FastAPI()
    app_settings = settings or Settings(tls_required=tls_required)
    application.add_middleware(MTLSAuthMiddleware, settings=app_settings)
    if inject_chain is not None:
        application.add_middleware(_ScopeInjector, chain=inject_chain)

    @application.get("/open")
    def open_route(request: Request) -> dict:
        subject = getattr(request.state, "cert_subject", None)
        op = getattr(request.state, "operator", None)
        return {
            "cn": subject.common_name if subject else None,
            "serial": subject.serial if subject else None,
            "operator_cn": op.cn if op else None,
            "operator_role": op.role.value if op else None,
            "operator_status": op.status.value if op else None,
        }

    @application.get("/protected")
    def protected_route(
        subject: CertSubject = Depends(require_subject),
    ) -> dict:
        return {"cn": subject.common_name}

    @application.get("/admin-only")
    def admin_route(
        subject: CertSubject = Depends(require_role(OperatorRole.admin)),
    ) -> dict:
        return {"cn": subject.common_name}

    @application.get("/admin-or-auditor")
    def admin_or_auditor_route(
        subject: CertSubject = Depends(
            require_role(OperatorRole.admin, OperatorRole.auditor)
        ),
    ) -> dict:
        return {"cn": subject.common_name}

    return application


def _add_operator(
    session: Session,
    cn: str,
    *,
    role: OperatorRole = OperatorRole.operator,
    status: OperatorStatus = OperatorStatus.active,
) -> Operator:
    """Insert an Operator row directly so the CP3.2 middleware admits the cert.

    Lives in the test module so the production
    :class:`MTLSAuthMiddleware` never depends on test scaffolding. The
    fixture chain (``engine`` → ``session``) swaps the module-level
    :data:`wg_manager.db.engine` for the in-memory SQLite engine, so
    rows inserted here are exactly what the middleware reads on the
    next request.
    """
    row = Operator(cn=cn, role=role, status=status)
    session.add(row)
    session.commit()
    session.refresh(row)
    return row


class TestMTLSMiddleware:
    """End-to-end middleware behaviour exercised through ``TestClient``."""

    def test_tls_not_required_passes_through_without_cert(self) -> None:
        """In the test / dev posture every request succeeds and both
        cert_subject and operator slots are ``None``."""
        client = TestClient(_build_app(tls_required=False))

        resp = client.get("/open")

        assert resp.status_code == 200
        body = resp.json()
        assert body["cn"] is None
        assert body["serial"] is None
        assert body["operator_cn"] is None

    def test_tls_required_no_cert_returns_401(self) -> None:
        """Production posture: a request with no cert on the scope is
        rejected before the route runs, with a stable JSON body."""
        client = TestClient(_build_app(tls_required=True))

        resp = client.get("/open")

        assert resp.status_code == 401
        assert resp.json() == {"detail": "client cert required"}

    def test_tls_required_with_injected_cert_returns_subject(
        self, ca: LocalDevPKI, session: Session
    ) -> None:
        """Happy path: an injected client cert chain shows up on
        ``request.state.cert_subject`` with the expected CN and serial.

        Post-CP3.2 the middleware also consults the Operator registry,
        so the test pre-registers the row before the request so the
        cert is admitted.
        """
        _add_operator(session, "ops@wg.local", role=OperatorRole.admin)
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
        body = resp.json()
        assert body["cn"] == "ops@wg.local"
        assert body["serial"] == cert.serial
        # CP3.2 also stashes the resolved Operator row.
        assert body["operator_cn"] == "ops@wg.local"
        assert body["operator_role"] == "admin"
        assert body["operator_status"] == "active"

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

    def test_require_subject_dep_yields_subject(
        self, ca: LocalDevPKI, session: Session
    ) -> None:
        """The ``Depends(require_subject)`` path returns the stashed
        subject when one is present.

        Post-CP3.2 the middleware also consults the Operator registry,
        so pre-register the row before the request.
        """
        _add_operator(session, "ops@wg.local")
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


# ---------------------------------------------------------------------------
# CP3.2 — Operator registry tightening
# ---------------------------------------------------------------------------


class TestOperatorRegistryEnforcement:
    """Phase 2d CP3.2 tightens :class:`MTLSAuthMiddleware`.

    Before CP3.2 any cert that validated against the configured CA
    bundle was waved through — the gap CP2 explicitly left for the CP3
    arc (see ``SECURITY.md``, threat T-7). CP3.1 landed the
    ``Operator`` registry table; CP3.2 wires the middleware up to it.

    The contract pinned here:

    * A valid cert whose CN isn't in the ``operator`` table gets a 401
      with a stable JSON body (``"operator not registered"``).
    * A valid cert whose CN belongs to a ``status='disabled'`` row gets
      a 401 with a distinct body (``"operator disabled"``) so an
      operator looking at a packet capture can tell the two cases
      apart.
    * A valid cert for an ``active`` operator passes through with both
      :class:`CertSubject` and the resolved :class:`Operator` stashed
      on ``request.state`` so handlers can read either.
    * The ``AUTH_BOOTSTRAP_OPERATOR_CN`` setting closes the chicken-
      and-egg gap CP3.1 left: when the registry is empty and the first
      request bears the bootstrap CN, the middleware self-registers
      the row before admitting the request. A mismatched bootstrap CN
      still 401s — the env knob is a single-CN allow-list, not a
      blanket "register any first comer".
    * OPTIONS preflight bypasses the lookup entirely (the browser
      can't send the cert until preflight clears).
    * ``tls_required=False`` short-circuits the lookup so the dev /
      test posture is unchanged.
    """

    def test_unknown_cn_returns_401(
        self, ca: LocalDevPKI, engine: Any
    ) -> None:
        """The registry is empty; a valid cert is still rejected."""
        cert = ca.issue_client_cert(
            common_name="stranger@wg.local",
            sans=["stranger@wg.local"],
            ttl_seconds=300,
        )
        client = TestClient(
            _build_app(tls_required=True, inject_chain=[cert.cert_pem])
        )

        resp = client.get("/open")

        assert resp.status_code == 401
        assert resp.json() == {"detail": "operator not registered"}

    def test_disabled_operator_returns_401(
        self, ca: LocalDevPKI, session: Session
    ) -> None:
        """A row exists but is soft-deleted — refuse with a distinct body."""
        _add_operator(
            session, "ops@wg.local", status=OperatorStatus.disabled
        )
        cert = ca.issue_client_cert(
            common_name="ops@wg.local",
            sans=["ops@wg.local"],
            ttl_seconds=300,
        )
        client = TestClient(
            _build_app(tls_required=True, inject_chain=[cert.cert_pem])
        )

        resp = client.get("/open")

        assert resp.status_code == 401
        assert resp.json() == {"detail": "operator disabled"}

    def test_active_operator_returns_200_and_stashes_row(
        self, ca: LocalDevPKI, session: Session
    ) -> None:
        """Happy path: CN matches an active row → request proceeds."""
        _add_operator(
            session, "ops@wg.local", role=OperatorRole.operator
        )
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
        body = resp.json()
        assert body["operator_cn"] == "ops@wg.local"
        assert body["operator_role"] == "operator"
        assert body["operator_status"] == "active"

    def test_bootstrap_cn_self_registers_first_request(
        self, ca: LocalDevPKI, engine: Any, session: Session
    ) -> None:
        """Empty registry + bootstrap CN match → request creates the row.

        A second request with the same cert finds the existing row
        rather than creating a duplicate (the unique CN index would
        otherwise raise).
        """
        cert = ca.issue_client_cert(
            common_name="bootstrap@wg.local",
            sans=["bootstrap@wg.local"],
            ttl_seconds=300,
        )
        settings = Settings(
            tls_required=True,
            auth_bootstrap_operator_cn="bootstrap@wg.local",
            auth_bootstrap_operator_role="admin",
        )
        client = TestClient(
            _build_app(
                tls_required=True,
                inject_chain=[cert.cert_pem],
                settings=settings,
            )
        )

        first = client.get("/open")
        second = client.get("/open")

        assert first.status_code == 200, first.text
        assert second.status_code == 200, second.text
        assert first.json()["operator_cn"] == "bootstrap@wg.local"
        assert first.json()["operator_role"] == "admin"
        # Only one row should exist post-bootstrap.
        from sqlmodel import select

        rows = session.exec(
            select(Operator).where(Operator.cn == "bootstrap@wg.local")
        ).all()
        assert len(rows) == 1, (
            f"bootstrap self-register must be idempotent; got {rows!r}"
        )

    def test_bootstrap_cn_mismatch_still_401(
        self, ca: LocalDevPKI, engine: Any
    ) -> None:
        """The bootstrap knob is a single-CN allow-list, not a free pass."""
        cert = ca.issue_client_cert(
            common_name="intruder@wg.local",
            sans=["intruder@wg.local"],
            ttl_seconds=300,
        )
        settings = Settings(
            tls_required=True,
            auth_bootstrap_operator_cn="bootstrap@wg.local",
            auth_bootstrap_operator_role="admin",
        )
        client = TestClient(
            _build_app(
                tls_required=True,
                inject_chain=[cert.cert_pem],
                settings=settings,
            )
        )

        resp = client.get("/open")

        assert resp.status_code == 401
        assert resp.json() == {"detail": "operator not registered"}

    def test_options_preflight_bypasses_operator_lookup(
        self, engine: Any
    ) -> None:
        """OPTIONS short-circuits before any DB hit — there is no row to
        look up and the browser hasn't sent a cert yet.
        """
        client = TestClient(_build_app(tls_required=True))

        resp = client.options("/open")

        assert resp.status_code != 401

    def test_tls_not_required_skips_operator_lookup(self) -> None:
        """Dev / test posture: no DB hit, both state slots are ``None``."""
        client = TestClient(_build_app(tls_required=False))

        resp = client.get("/open")

        assert resp.status_code == 200
        body = resp.json()
        assert body["cn"] is None
        assert body["operator_cn"] is None


class TestRequireRoleDependency:
    """Phase 2d CP3.2 — handlers gate mutations behind a role.

    ``require_role(*roles)`` is the factory the dashboard / routers use
    to declare "this endpoint is admin-only" (or
    "admin-or-auditor", …). It builds on
    :func:`require_subject`'s 401-when-no-cert behaviour and adds a 403
    when the operator's role isn't in the allow-list.
    """

    def test_admin_route_blocks_operator_role_with_403(
        self, ca: LocalDevPKI, session: Session
    ) -> None:
        """An ``operator``-role cert hitting an admin-only route is 403."""
        _add_operator(
            session, "ops@wg.local", role=OperatorRole.operator
        )
        cert = ca.issue_client_cert(
            common_name="ops@wg.local",
            sans=["ops@wg.local"],
            ttl_seconds=300,
        )
        client = TestClient(
            _build_app(tls_required=True, inject_chain=[cert.cert_pem])
        )

        resp = client.get("/admin-only")

        assert resp.status_code == 403
        assert resp.json() == {"detail": "role not permitted"}

    def test_admin_route_allows_admin_role(
        self, ca: LocalDevPKI, session: Session
    ) -> None:
        """The same route with an admin cert succeeds."""
        _add_operator(
            session, "boss@wg.local", role=OperatorRole.admin
        )
        cert = ca.issue_client_cert(
            common_name="boss@wg.local",
            sans=["boss@wg.local"],
            ttl_seconds=300,
        )
        client = TestClient(
            _build_app(tls_required=True, inject_chain=[cert.cert_pem])
        )

        resp = client.get("/admin-only")

        assert resp.status_code == 200
        assert resp.json() == {"cn": "boss@wg.local"}

    def test_role_filter_accepts_iterable(
        self, ca: LocalDevPKI, session: Session
    ) -> None:
        """``require_role(admin, auditor)`` admits either role."""
        _add_operator(
            session, "sec@wg.local", role=OperatorRole.auditor
        )
        cert = ca.issue_client_cert(
            common_name="sec@wg.local",
            sans=["sec@wg.local"],
            ttl_seconds=300,
        )
        client = TestClient(
            _build_app(tls_required=True, inject_chain=[cert.cert_pem])
        )

        resp = client.get("/admin-or-auditor")

        assert resp.status_code == 200
        assert resp.json() == {"cn": "sec@wg.local"}

    def test_role_filter_401s_when_tls_not_required(self) -> None:
        """``tls_required=False`` leaves both state slots None — the
        role filter must still 401 (cert missing) rather than 403
        (role mismatch), since there's no identity to compare against.
        """
        client = TestClient(_build_app(tls_required=False))

        resp = client.get("/admin-only")

        assert resp.status_code == 401
        assert resp.json() == {"detail": "client cert required"}


# ---------------------------------------------------------------------------
# Phase 2d CP5 — structured audit emission + revoked-cert gate
# ---------------------------------------------------------------------------


def _parse_audit_lines(records: list[logging.LogRecord]) -> list[dict]:
    """Filter ``caplog`` records to ``wg_manager.audit`` lines + JSON-decode.

    The middleware's audit emission writes one JSON object per
    decision to the ``wg_manager.audit`` named logger. Tests use
    ``caplog`` with ``set_level(logging.WARNING, logger="wg_manager.audit")``
    to capture; this helper picks out *only* the audit records (the
    suite also configures the module-level ``wg_manager.auth`` logger,
    which is a different stream) and parses each one as JSON so the
    assertions read fields by name rather than substring-matching.
    """
    out: list[dict] = []
    for rec in records:
        if rec.name != "wg_manager.audit":
            continue
        try:
            out.append(json.loads(rec.getMessage()))
        except json.JSONDecodeError:  # pragma: no cover — defensive
            continue
    return out


class TestAuditEmission:
    """Phase 2d CP5 — every admission decision emits one audit line.

    The acceptance suite under ``tests/e2e/tls/`` asserts the audit
    line shows up on a *live* uvicorn process's stderr; these unit
    tests pin the contract end-to-end through ``TestClient`` so the
    e2e suite can rely on a stable JSON shape.
    """

    def test_admit_path_emits_auth_admit_line(
        self,
        ca: LocalDevPKI,
        session: Session,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A successful auth emits ``event=auth.admit`` with cn/serial/role."""
        _add_operator(session, "ops@wg.local", role=OperatorRole.admin)
        cert = ca.issue_client_cert(
            common_name="ops@wg.local",
            sans=["ops@wg.local"],
            ttl_seconds=300,
        )
        client = TestClient(
            _build_app(tls_required=True, inject_chain=[cert.cert_pem])
        )

        with caplog.at_level(logging.WARNING, logger="wg_manager.audit"):
            resp = client.get("/open")

        assert resp.status_code == 200
        lines = _parse_audit_lines(caplog.records)
        admits = [r for r in lines if r["event"] == "auth.admit"]
        assert len(admits) == 1, lines
        record = admits[0]
        assert record["cn"] == "ops@wg.local"
        assert record["serial"] == str(cert.serial)
        assert record["role"] == "admin"
        assert record["method"] == "GET"
        assert record["path"] == "/open"

    def test_no_cert_path_emits_client_cert_required_reject(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Bare no-cert request emits ``reason=client-cert-required``."""
        client = TestClient(_build_app(tls_required=True))

        with caplog.at_level(logging.WARNING, logger="wg_manager.audit"):
            resp = client.get("/open")

        assert resp.status_code == 401
        lines = _parse_audit_lines(caplog.records)
        rejects = [r for r in lines if r["event"] == "auth.reject"]
        assert len(rejects) == 1
        assert rejects[0]["reason"] == "client-cert-required"
        assert rejects[0]["method"] == "GET"
        assert rejects[0]["path"] == "/open"

    def test_unknown_cn_emits_operator_not_registered_reject(
        self,
        ca: LocalDevPKI,
        engine: Any,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """An unknown-CN cert emits ``reason=operator-not-registered``."""
        cert = ca.issue_client_cert(
            common_name="stranger@wg.local",
            sans=["stranger@wg.local"],
            ttl_seconds=300,
        )
        client = TestClient(
            _build_app(tls_required=True, inject_chain=[cert.cert_pem])
        )

        with caplog.at_level(logging.WARNING, logger="wg_manager.audit"):
            resp = client.get("/open")

        assert resp.status_code == 401
        rejects = [
            r for r in _parse_audit_lines(caplog.records)
            if r["event"] == "auth.reject"
        ]
        assert len(rejects) == 1
        assert rejects[0]["reason"] == "operator-not-registered"
        assert rejects[0]["cn"] == "stranger@wg.local"
        assert rejects[0]["serial"] == str(cert.serial)

    def test_disabled_operator_emits_operator_disabled_reject(
        self,
        ca: LocalDevPKI,
        session: Session,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A disabled-status row emits ``reason=operator-disabled``."""
        _add_operator(
            session,
            "ex-ops@wg.local",
            role=OperatorRole.operator,
            status=OperatorStatus.disabled,
        )
        cert = ca.issue_client_cert(
            common_name="ex-ops@wg.local",
            sans=["ex-ops@wg.local"],
            ttl_seconds=300,
        )
        client = TestClient(
            _build_app(tls_required=True, inject_chain=[cert.cert_pem])
        )

        with caplog.at_level(logging.WARNING, logger="wg_manager.audit"):
            resp = client.get("/open")

        assert resp.status_code == 401
        rejects = [
            r for r in _parse_audit_lines(caplog.records)
            if r["event"] == "auth.reject"
        ]
        assert len(rejects) == 1
        assert rejects[0]["reason"] == "operator-disabled"
        assert rejects[0]["cn"] == "ex-ops@wg.local"


class TestRevokedCertGate:
    """Phase 2d CP5 — a revoked audit-registry row produces a 401 + audit line.

    The gate consults the ``certificate`` table by serial. A serial
    that's *not* in the registry (bootstrap path, legacy cert minted
    outside the audit registry) is admitted on the strength of the
    operator row alone — that's the chicken-and-egg-safe stance.
    """

    def _seed_certificate_row(
        self,
        session: Session,
        operator: Operator,
        cert: Any,
        *,
        revoked: bool,
    ) -> Certificate:
        """Insert a Certificate row that mirrors the one ``POST /certs`` writes.

        Set ``revoked=True`` to simulate the post-``POST /certs/{id}/revoke``
        state without having to mint via the API.
        """
        row = Certificate(
            serial=str(cert.serial),
            cert_type=CertificateType.cli,
            operator_id=operator.id,
            common_name=cert.common_name,
            sans=",".join(cert.sans),
            not_before=cert.not_before,
            not_after=cert.not_after,
            revoked=revoked,
            revoked_at=(
                datetime.now(timezone.utc) if revoked else None
            ),
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        return row

    def test_revoked_serial_returns_401_with_audit_line(
        self,
        ca: LocalDevPKI,
        session: Session,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A revoked row → 401 ``operator cert revoked`` + matching audit line."""
        operator = _add_operator(
            session, "ops@wg.local", role=OperatorRole.admin
        )
        cert = ca.issue_client_cert(
            common_name="ops@wg.local",
            sans=["ops@wg.local"],
            ttl_seconds=300,
        )
        self._seed_certificate_row(session, operator, cert, revoked=True)
        client = TestClient(
            _build_app(tls_required=True, inject_chain=[cert.cert_pem])
        )

        with caplog.at_level(logging.WARNING, logger="wg_manager.audit"):
            resp = client.get("/open")

        assert resp.status_code == 401
        assert resp.json() == {"detail": "operator cert revoked"}
        rejects = [
            r for r in _parse_audit_lines(caplog.records)
            if r["event"] == "auth.reject"
        ]
        assert len(rejects) == 1
        assert rejects[0]["reason"] == "operator-cert-revoked"
        assert rejects[0]["serial"] == str(cert.serial)
        assert rejects[0]["cn"] == "ops@wg.local"

    def test_unrevoked_registry_row_admits_with_audit_line(
        self,
        ca: LocalDevPKI,
        session: Session,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A non-revoked row is admitted (the gate is opt-out, not opt-in)."""
        operator = _add_operator(
            session, "ops@wg.local", role=OperatorRole.admin
        )
        cert = ca.issue_client_cert(
            common_name="ops@wg.local",
            sans=["ops@wg.local"],
            ttl_seconds=300,
        )
        self._seed_certificate_row(session, operator, cert, revoked=False)
        client = TestClient(
            _build_app(tls_required=True, inject_chain=[cert.cert_pem])
        )

        with caplog.at_level(logging.WARNING, logger="wg_manager.audit"):
            resp = client.get("/open")

        assert resp.status_code == 200
        admits = [
            r for r in _parse_audit_lines(caplog.records)
            if r["event"] == "auth.admit"
        ]
        assert len(admits) == 1

    def test_cert_without_registry_row_admits(
        self,
        ca: LocalDevPKI,
        session: Session,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """No registry row → admit. Keeps the bootstrap chain open.

        The bootstrap-CN's self-mint and any legacy operator cert
        from before CP3.3 never wrote a ``certificate`` row, so the
        gate has to treat "no row" as "not revoked." A future
        tightening could move this to "strict mode" via a setting,
        but that would break the chicken-and-egg path on a fresh
        install.
        """
        _add_operator(session, "boot@wg.local", role=OperatorRole.admin)
        cert = ca.issue_client_cert(
            common_name="boot@wg.local",
            sans=["boot@wg.local"],
            ttl_seconds=300,
        )
        # NOTE: deliberately *no* _seed_certificate_row call.
        client = TestClient(
            _build_app(tls_required=True, inject_chain=[cert.cert_pem])
        )

        with caplog.at_level(logging.WARNING, logger="wg_manager.audit"):
            resp = client.get("/open")

        assert resp.status_code == 200
