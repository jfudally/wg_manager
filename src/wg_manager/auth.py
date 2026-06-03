"""Phase 2d CP2 + CP3.2 mTLS authentication layer.

This module is the seam between uvicorn's TLS-terminated socket and
the wg-manager FastAPI handlers. It does four jobs:

1. **Parse** a leaf cert PEM into a frozen :class:`CertSubject` value
   object (``parse_subject_from_pem``).
2. **Extract** the client cert off the ASGI scope that uvicorn hands
   us per request (``extract_subject_from_scope``) — uvicorn 0.32+
   surfaces the peer cert chain via the ASGI-TLS extension at
   ``scope["extensions"]["tls"]["client_cert_chain"]``.
3. **Enforce** the "every request carries a client cert *and* the cert
   belongs to a registered, active operator" invariant via
   :class:`MTLSAuthMiddleware`. CP3.2 added the registry tightening
   on top of CP2's bare cert-presence check.
4. **Yield** the resolved identity to FastAPI handlers via
   :func:`require_subject` (any active operator) and
   :func:`require_role` (operator + role allow-list).

The middleware is gated by :attr:`wg_manager.config.Settings.tls_required`
so the test suite (which uses :class:`starlette.testclient.TestClient`
and never speaks TLS) can disable it. Production posture is
``TLS_REQUIRED=true`` — see ``.env.example``.

CP3.2 reads the ``operator`` table on every cert-bearing request to
decide admission. The bootstrap path — controlled by
:attr:`Settings.auth_bootstrap_operator_cn` — auto-registers the very
first cert that matches the configured CN, so an empty registry
doesn't lock the operator out of their own API.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable

from cryptography import x509
from fastapi import HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

from wg_manager import db as db_module
from wg_manager.audit import audit_logger, emit as _emit_audit
from wg_manager.config import Settings
from wg_manager.models import Certificate, Operator, OperatorRole, OperatorStatus

logger = logging.getLogger(__name__)

# Re-exports for backward compatibility. Phase 2d CP5 wired the audit
# logger + emit function in this module; Phase 2e cycle 2 relocated
# them to :mod:`wg_manager.audit` so the middleware here, the
# bootstrap orchestrator in :mod:`wg_manager.bootstrap_ssh`, and the
# new ``audit.persist`` helper all share one implementation. The
# re-export keeps existing import sites (``from wg_manager.auth
# import _emit_audit``) and the per-call-site byte format intact.
__all_audit_reexports__ = ("audit_logger", "_emit_audit")


# ---------------------------------------------------------------------------
# Value object
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CertSubject:
    """The operator identity behind a single TLS-terminated request.

    Frozen so a router that stashes this on ``request.state`` can't be
    silently mutated by a downstream middleware or handler. Mirrors the
    shape of :class:`wg_manager.pki.Cert` minus the private-key field —
    by the time the cert reaches us over the wire we've never had the
    matching private key (the operator did), so there's nothing to drop.

    :ivar common_name: The CN baked into the cert subject. Operator
        identifier in CP2; CP3's ``Operator`` resolver uses this as the
        join key.
    :ivar sans: SAN list (DNS + IP, stringified). A future authorisation
        layer can match on these in addition to / instead of the CN.
    :ivar serial: Issuer-assigned serial. Useful for the CP3 audit log
        ("operator X acted via cert #<serial>") and for revocation
        lookups against the CP2/CP4 CRL.
    :ivar not_before: Validity-window start (UTC, tz-aware).
    :ivar not_after: Validity-window end (UTC, tz-aware). A renewal job
        looking for "certs about to expire" sleeps until this minus
        a jitter.
    :ivar cert_pem: The original cert PEM body. Re-exposed so CP3's
        ``Certificate`` registry can persist the exact bytes that
        authenticated the request without re-encoding.
    """

    common_name: str
    sans: tuple[str, ...]
    serial: int
    not_before: datetime
    not_after: datetime
    cert_pem: str


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AuthError(HTTPException):
    """Raised when a request lacks a client cert under ``tls_required=True``.

    Subclasses :class:`fastapi.HTTPException` so FastAPI's standard
    exception handler renders the 401 response uniformly. Used by
    :func:`require_subject` for the router-side enforcement path; the
    middleware short-circuits with :class:`JSONResponse` directly
    because it runs before the FastAPI exception-handler chain.
    """

    def __init__(self, detail: str = "client cert required") -> None:
        """Build a 401 with a stable detail message.

        :param detail: Human-readable error string. Kept short so it
            doesn't accidentally leak request shape into the response.
        """
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=detail
        )


# ---------------------------------------------------------------------------
# Parser — PEM → CertSubject
# ---------------------------------------------------------------------------


def _sans_from_cert(cert: x509.Certificate) -> tuple[str, ...]:
    """Return the SAN strings on ``cert`` in declaration order.

    Mirrors the round-trip shape of :func:`wg_manager.pki._san_extension`
    so a cert minted by :class:`wg_manager.pki.LocalDevPKI` parses back
    to exactly the SAN tuple that was requested at issue time.
    """
    try:
        ext = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
    except x509.ExtensionNotFound:
        return ()
    out: list[str] = []
    for entry in ext.value:
        if isinstance(entry, x509.DNSName):
            out.append(entry.value)
        elif isinstance(entry, x509.IPAddress):
            out.append(str(entry.value))
    return tuple(out)


def _common_name(cert: x509.Certificate) -> str:
    """Return the first CN attribute on the subject; empty string if absent.

    Empty string rather than ``None`` so :class:`CertSubject` doesn't
    grow an optional field — every cert wg-manager issues carries a
    CN, and a cert without one is operator error that the caller can
    surface in the audit log.
    """
    for attr in cert.subject:
        if attr.oid == x509.NameOID.COMMON_NAME:
            return str(attr.value)
    return ""


def parse_subject_from_pem(pem: str) -> CertSubject:
    """Parse a leaf-cert PEM body into a :class:`CertSubject`.

    Pure helper — no I/O, no env access — so the middleware and the
    CP3 ``Operator`` resolver can both call it on whatever PEM bytes
    they have in hand.

    :param pem: A single leaf-cert PEM body (the on-wire encoding
        uvicorn passes through ASGI). Leading / trailing whitespace
        is tolerated.
    :returns: The parsed identity.
    :raises ValueError: When ``pem`` is empty or not a valid X.509
        certificate. We normalise cryptography-library exceptions
        (which can be :class:`ValueError`, :class:`TypeError`, or a
        backend-internal type depending on the input shape) into a
        single :class:`ValueError` so callers only need one ``except``
        clause.
    """
    if not pem or not pem.strip():
        raise ValueError("cert pem is empty")
    try:
        cert = x509.load_pem_x509_certificate(pem.encode())
    except (ValueError, TypeError) as exc:
        raise ValueError(f"not a valid x509 certificate: {exc}") from exc
    return CertSubject(
        common_name=_common_name(cert),
        sans=_sans_from_cert(cert),
        serial=cert.serial_number,
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        cert_pem=pem,
    )


# ---------------------------------------------------------------------------
# ASGI scope adapter — uvicorn → CertSubject
# ---------------------------------------------------------------------------


def extract_subject_from_scope(scope: dict[str, Any]) -> CertSubject | None:
    """Pull the client cert subject off an ASGI scope.

    Reads ``scope["extensions"]["tls"]["client_cert_chain"]`` (the
    `ASGI-TLS extension <https://asgi.readthedocs.io/en/latest/extensions.html#tls>`_)
    and returns the parsed subject of the **first** cert in the chain.
    Uvicorn 0.32+ populates this when started with ``--ssl-cert-reqs 2``.

    :param scope: The ASGI scope dict for the current request.
    :returns: The parsed subject, or ``None`` when the extension is
        missing, the chain is empty, or the first PEM doesn't parse.
        Returning ``None`` (rather than raising) keeps the middleware
        decision logic in one place: "no subject" is the failure case
        regardless of *why* the subject couldn't be read.
    """
    extensions = scope.get("extensions") or {}
    tls = extensions.get("tls") or {}
    chain = tls.get("client_cert_chain") or []
    if not chain:
        return None
    first = chain[0]
    if not first:
        return None
    try:
        return parse_subject_from_pem(first)
    except ValueError as exc:
        # Log at WARNING — a malformed cert in the chain is suspicious
        # (uvicorn shouldn't surface one unless the client genuinely
        # sent garbage) but mustn't crash the middleware path. The
        # request will still get a 401 because we return None.
        logger.warning("malformed client cert in ASGI scope: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Middleware + dependency
# ---------------------------------------------------------------------------


class MTLSAuthMiddleware(BaseHTTPMiddleware):
    """Enforce per-request client-cert auth + operator-registry admission.

    Decision order:

    * ``tls_required=False`` — passthrough; sets
      ``request.state.cert_subject = None`` and
      ``request.state.operator = None``. This is the test / dev
      posture.
    * ``request.method == "OPTIONS"`` — CORS preflight. The browser
      negotiates CORS *before* it sends the cert, so a 401 here
      breaks the entire dashboard. We let preflight through with both
      state slots set to ``None``.
    * ``tls_required=True`` and no cert on the scope — 401 with
      ``"client cert required"``.
    * CP3.2: cert present but CN not in the ``operator`` registry —
      401 with ``"operator not registered"``. The
      :attr:`Settings.auth_bootstrap_operator_cn` knob can opt one CN
      into self-register on the first such request.
    * CP3.2: cert present, row found, but ``status='disabled'`` —
      401 with ``"operator disabled"``. The distinct body lets the
      operator distinguish "I forgot to register" from "I was
      revoked" without grepping the audit log.

    We return :class:`JSONResponse` directly rather than raising
    :class:`AuthError` because middleware runs before FastAPI's
    exception-handler chain; raising would surface as a 500.

    Happy path stashes the parsed :class:`CertSubject` on
    ``request.state.cert_subject`` and the resolved (detached)
    :class:`Operator` on ``request.state.operator`` so handlers can
    read either via :func:`require_subject` / :func:`require_role` or
    directly off ``request.state``.
    """

    def __init__(self, app: ASGIApp, settings: Settings | None = None) -> None:
        """Bind to the application and capture the settings snapshot.

        :param app: The ASGI app this middleware wraps.
        :param settings: Optional override; defaults to a fresh
            :class:`Settings` (which re-reads the env / ``.env``). The
            settings object is captured at construction time so a
            mid-flight env-var flip doesn't change enforcement —
            matches the rest of the wg_manager codebase, where
            ``Settings`` is read once at app boot.
        """
        super().__init__(app)
        self._settings = settings or Settings()

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        """Run the decision chain before forwarding to the app.

        Phase 2d CP5 layered structured audit emission on every branch
        (admit + every reject reason) via :func:`_emit_audit`. The
        ``passthrough`` / preflight branches stay silent because they
        carry no auth signal — emitting on them would just drown the
        audit stream in noise for the CORS-OPTIONS workload.
        """
        if not self._settings.tls_required:
            request.state.cert_subject = None
            request.state.operator = None
            return await call_next(request)
        if request.method == "OPTIONS":
            request.state.cert_subject = None
            request.state.operator = None
            return await call_next(request)
        method = request.method
        path = request.url.path
        subject = extract_subject_from_scope(dict(request.scope))
        if subject is None:
            _emit_audit(
                "auth.reject",
                reason="client-cert-required",
                method=method,
                path=path,
            )
            return JSONResponse(
                {"detail": "client cert required"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        operator = self._resolve_operator(subject)
        if operator is None:
            _emit_audit(
                "auth.reject",
                reason="operator-not-registered",
                cn=subject.common_name,
                serial=str(subject.serial),
                method=method,
                path=path,
            )
            return JSONResponse(
                {"detail": "operator not registered"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        if operator.status != OperatorStatus.active:
            _emit_audit(
                "auth.reject",
                reason="operator-disabled",
                cn=subject.common_name,
                serial=str(subject.serial),
                method=method,
                path=path,
            )
            return JSONResponse(
                {"detail": "operator disabled"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        # CP5.3 — every cert that the audit registry knows about is
        # subject to revocation enforcement. A cert that was never
        # written to the registry (the bootstrap CN's self-mint, a
        # legacy operator cert from before CP3.3) is admitted on the
        # strength of its operator row alone, so the chicken-and-egg
        # bootstrap path stays open. Lookup is by serial-as-string
        # because :attr:`Certificate.serial` is ``String(64)`` (X.509
        # serials can exceed signed-INT64 and the column has to round-
        # trip Vault's serials too).
        if self._serial_is_revoked(subject.serial):
            _emit_audit(
                "auth.reject",
                reason="operator-cert-revoked",
                cn=subject.common_name,
                serial=str(subject.serial),
                method=method,
                path=path,
            )
            return JSONResponse(
                {"detail": "operator cert revoked"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        request.state.cert_subject = subject
        request.state.operator = operator
        _emit_audit(
            "auth.admit",
            cn=subject.common_name,
            serial=str(subject.serial),
            role=operator.role.value,
            method=method,
            path=path,
        )
        return await call_next(request)

    def _serial_is_revoked(self, serial: int) -> bool:
        """Return ``True`` iff the audit registry has a revoked row for ``serial``.

        Reads the ``certificate`` table — the same row
        ``POST /certs/{id}/revoke`` flips — so revocation enforcement
        is consistent with the audit trail and with the Vault PKI CRL
        the row's revoke action also updates. A serial that's *not*
        in the registry is treated as not-revoked (the bootstrap path,
        legacy operator certs).

        Opens its own short-lived session against the module-level
        engine, mirroring :meth:`_resolve_operator` so the test suite
        and the live API exercise the same code path. We swallow
        :class:`Exception` to a "treat as not-revoked" stance only on
        explicit driver errors — a revoked-row miss must never
        accidentally admit a revoked cert.
        """
        try:
            with Session(db_module.engine) as session:
                row = session.exec(
                    select(Certificate).where(
                        Certificate.serial == str(serial)
                    )
                ).first()
        except Exception as exc:  # pragma: no cover — defensive
            logger.warning(
                "certificate-registry lookup for serial=%s failed: %s",
                serial,
                exc,
            )
            return False
        return bool(row and row.revoked)

    def _resolve_operator(self, subject: CertSubject) -> Operator | None:
        """Look up — and optionally bootstrap — the operator for ``subject``.

        Opens a short-lived :class:`Session` against the module-level
        :data:`wg_manager.db.engine`. The test suite swaps the engine
        for an in-memory SQLite handle via the ``engine`` fixture, so
        the same code path is exercised in both modes.

        Returns a *detached* :class:`Operator` instance — we snapshot
        the row into a plain :class:`Operator` (no session attached)
        so handlers that read ``request.state.operator`` after the
        session has closed don't trigger a lazy-load
        ``DetachedInstanceError``.

        :returns: The resolved operator, or ``None`` when no row
            exists and the bootstrap path doesn't apply.
        """
        with Session(db_module.engine) as session:
            row = session.exec(
                select(Operator).where(Operator.cn == subject.common_name)
            ).first()
            if row is None:
                row = self._maybe_bootstrap(session, subject)
                if row is None:
                    return None
            return Operator(
                id=row.id,
                cn=row.cn,
                display_name=row.display_name,
                role=row.role,
                status=row.status,
                created_at=row.created_at,
            )

    def _maybe_bootstrap(
        self, session: Session, subject: CertSubject
    ) -> Operator | None:
        """Self-register ``subject`` when its CN matches the bootstrap knob.

        The bootstrap path solves the chicken-and-egg gap CP3.1 left:
        with mTLS enforced and the registry empty, there is no
        authenticated path to insert the first row. Setting
        ``AUTH_BOOTSTRAP_OPERATOR_CN`` opts one specific CN into
        self-register on first contact; every other unknown CN still
        gets a 401.

        Bootstrap is *not* a "register any first comer" — the CN must
        match exactly. Operators are expected to unset (or rotate) the
        env var once the row exists and additional operators are
        added through the dashboard / CLI follow-on.

        Race condition: two concurrent first requests could both miss
        the row and both try to insert. The unique CN index on
        :class:`Operator` would raise :class:`IntegrityError` on the
        loser; we catch it, re-query, and return the winning row so
        both requests succeed.
        """
        bootstrap_cn = self._settings.auth_bootstrap_operator_cn
        if not bootstrap_cn or bootstrap_cn != subject.common_name:
            return None
        try:
            role = OperatorRole(self._settings.auth_bootstrap_operator_role)
        except ValueError:
            logger.warning(
                "auth_bootstrap_operator_role %r is not a valid OperatorRole",
                self._settings.auth_bootstrap_operator_role,
            )
            return None
        row = Operator(
            cn=subject.common_name,
            display_name=f"bootstrap:{subject.common_name}",
            role=role,
            status=OperatorStatus.active,
        )
        session.add(row)
        try:
            session.commit()
            session.refresh(row)
        except IntegrityError:
            # Lost the bootstrap race — the row exists now, re-fetch.
            session.rollback()
            row = session.exec(
                select(Operator).where(Operator.cn == subject.common_name)
            ).first()
        return row


def require_subject(request: Request) -> CertSubject:
    """FastAPI dependency: yield the cert subject or raise 401.

    A router that wants to enforce "this endpoint must see a client
    cert even when ``tls_required=False``" (e.g. a future audit-only
    handler) can declare ``Depends(require_subject)``. In the
    ``tls_required=True`` path the middleware has already stashed
    the subject; this dep is the read-side accessor.

    :param request: Injected by FastAPI.
    :returns: The cert subject set by :class:`MTLSAuthMiddleware`.
    :raises AuthError: When no subject is on the request state.
    """
    subject = getattr(request.state, "cert_subject", None)
    if subject is None:
        raise AuthError()
    return subject


def require_role(*roles: OperatorRole):
    """Build a FastAPI dependency that admits only the listed roles.

    The factory shape (rather than a single ``role=`` kwarg on
    :func:`require_subject`) means a handler can declare
    ``Depends(require_role(OperatorRole.admin, OperatorRole.auditor))``
    directly. Handlers that don't care about role still use the
    plain :func:`require_subject` dep — the two APIs compose, they
    don't replace each other.

    Error mapping:

    * No cert on the request → 401 ``"client cert required"`` (via
      :func:`require_subject`).
    * Cert present but no operator stashed (shouldn't happen under
      ``tls_required=True`` — the middleware admits or rejects
      atomically — but defensive against a future passthrough mode)
      → 401 ``"operator unknown"``.
    * Operator present but role not in ``roles`` → 403
      ``"role not permitted"``.

    :param roles: Allow-list of :class:`OperatorRole` values. Passing
        zero roles is operator error and rejected with
        :class:`ValueError` at factory-build time so a typo can't
        accidentally turn the gate into a passthrough.
    :returns: A FastAPI dependency callable that yields the
        :class:`CertSubject` on success.
    :raises ValueError: When called with no role arguments.
    """
    if not roles:
        raise ValueError(
            "require_role() must be called with at least one OperatorRole"
        )
    allowed = frozenset(roles)

    def _dep(request: Request) -> CertSubject:
        subject = require_subject(request)
        op: Operator | None = getattr(request.state, "operator", None)
        if op is None:
            raise AuthError(detail="operator unknown")
        if op.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="role not permitted",
            )
        return subject

    return _dep


__all__ = [
    "AuthError",
    "CertSubject",
    "MTLSAuthMiddleware",
    "extract_subject_from_scope",
    "parse_subject_from_pem",
    "require_role",
    "require_subject",
]
