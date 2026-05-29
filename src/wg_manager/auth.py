"""Phase 2d CP2 mTLS authentication layer.

This module is the seam between uvicorn's TLS-terminated socket and
the wg-manager FastAPI handlers. It does three jobs:

1. **Parse** a leaf cert PEM into a frozen :class:`CertSubject` value
   object (``parse_subject_from_pem``).
2. **Extract** the client cert off the ASGI scope that uvicorn hands
   us per request (``extract_subject_from_scope``) — uvicorn 0.32+
   surfaces the peer cert chain via the ASGI-TLS extension at
   ``scope["extensions"]["tls"]["client_cert_chain"]``.
3. **Enforce** the "every request carries a client cert" invariant
   via :class:`MTLSAuthMiddleware` and the
   :func:`require_subject` FastAPI dependency.

The middleware is gated by :attr:`wg_manager.config.Settings.tls_required`
so the test suite (which uses :class:`starlette.testclient.TestClient`
and never speaks TLS) can disable it. Production posture is
``TLS_REQUIRED=true`` — see ``.env.example``.

CP2 returns a :class:`CertSubject` value object rather than resolving
to an ``Operator`` row; the row lives in CP3 (Alembic 0009). Keeping
the seam value-object-shaped now means CP3 can layer the resolver on
top without rewriting the middleware or the handler dependencies.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from fastapi import HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

from wg_manager.config import Settings

logger = logging.getLogger(__name__)


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
    """Enforce per-request client-cert auth when ``tls_required=True``.

    Three short-circuits:

    * ``tls_required=False`` — passthrough; sets
      ``request.state.cert_subject = None``. This is the
      test / dev posture.
    * ``request.method == "OPTIONS"`` — CORS preflight. The browser
      negotiates CORS *before* it sends the cert, so a 401 here
      breaks the entire dashboard. We let preflight through (it
      carries no auth-sensitive data) with ``cert_subject = None``.
    * ``tls_required=True`` and no cert on the scope — return 401
      directly via :class:`JSONResponse`. We don't raise
      :class:`AuthError` because middleware runs before FastAPI's
      exception-handler chain; raising would surface as a 500.

    Happy path stashes the parsed :class:`CertSubject` on
    ``request.state.cert_subject`` so handlers can read it via
    :func:`require_subject` or directly off ``request.state``.
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
        """Run the three-branch decision before forwarding to the app."""
        if not self._settings.tls_required:
            request.state.cert_subject = None
            return await call_next(request)
        if request.method == "OPTIONS":
            request.state.cert_subject = None
            return await call_next(request)
        subject = extract_subject_from_scope(dict(request.scope))
        if subject is None:
            return JSONResponse(
                {"detail": "client cert required"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        request.state.cert_subject = subject
        return await call_next(request)


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


__all__ = [
    "AuthError",
    "CertSubject",
    "MTLSAuthMiddleware",
    "extract_subject_from_scope",
    "parse_subject_from_pem",
    "require_subject",
]
