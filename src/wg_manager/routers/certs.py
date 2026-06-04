"""/certs router — Phase 2d CP3.4 HTTP surface over the certificate registry.

CP3.3 shipped the direct-DB :class:`wg_manager.models.Certificate`
table and a ``wg-manager certs`` CLI (issue / revoke / list) that wraps
:mod:`wg_manager.pki` to mint leaf certs without going through the
API. The CLI closes the bootstrap chicken-and-egg — the API listener's
own server cert has to exist before the API can come up — and stays
the canonical path for first-install / disaster-recovery workflows.

This router is the *steady-state* layer the dashboard's
``/certificates`` page calls into. Everything the CLI does is now
available over HTTP, gated by the same mTLS + operator-registry checks
the rest of the API enforces:

* ``GET /certs/whoami`` — returns the cert subject the API actually
  saw (parsed off the live TLS scope, not whatever the operator's
  cert file claims locally) plus the resolved :class:`Operator` row.
  This is the splash that lets a freshly-imported browser PKCS#12
  prove the handshake worked end-to-end. Gated by
  :func:`wg_manager.auth.require_subject` only — any active operator
  can call it regardless of role.
* ``GET /certs`` — lists every audit row (live + revoked). Gated by
  :func:`_require_admin_or_auditor` so day-to-day operators (who
  manage peers, not certs) can't enumerate the inventory.
* ``POST /certs`` — issues a new leaf via :func:`PKIBackend.issue_*`
  and persists the audit row in the same transaction. Admin only.
  ``dashboard`` certs additionally return a base64-encoded PKCS#12
  bundle the browser can save as a single import file.
* ``POST /certs/{id}/revoke`` — flips ``revoked`` / stamps
  ``revoked_at`` and tells the PKI backend's CRL. Admin only.
  Idempotent: revoking an already-revoked row returns 200 with the
  same body so a dashboard retry after a flaky network is safe.

Role gating uses :func:`_get_operator` (reads the snapshot
:class:`MTLSAuthMiddleware` stashes on ``request.state.operator``)
plus per-role wrapper deps. The wrappers — rather than the
:func:`wg_manager.auth.require_role` factory — are what
the endpoints declare as their ``Depends(...)``. That gives tests a
stable, per-router override point and keeps the role-mapping logic
co-located with the endpoint that enforces it.

For testability, three module-level deps are exported as
``_get_operator``, ``_RequireAdmin``, and ``_RequireAdminOrAuditor``.
The leading underscore signals "private to wg_manager.routers.certs
+ tests"; production callers should compose against
:mod:`wg_manager.auth` instead.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Annotated, Any

from cryptography import x509
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    NoEncryption,
    load_pem_private_key,
    pkcs12,
)
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlmodel import Session, select

from wg_manager import audit
from wg_manager.auth import CertSubject, require_subject
from wg_manager.db import get_session
from wg_manager.deps import get_pki_backend
from wg_manager.models import (
    Certificate,
    CertificateType,
    Operator,
    OperatorRole,
    Tenant,
)
from wg_manager.pki import Cert, PKIBackend
from wg_manager.schemas import (
    CertificateIssueRequest,
    CertificateIssueResponse,
    CertificateRead,
    CertificateRevokeResponse,
    WhoAmIResponse,
)

router = APIRouter(prefix="/certs", tags=["certs"])


# ---------------------------------------------------------------------------
# Role-gating deps
# ---------------------------------------------------------------------------
#
# Co-locating the role check with the router that uses it (rather than
# composing :func:`wg_manager.auth.require_role` directly at each
# endpoint) gives tests one stable override point per role tier and
# keeps the rule literally next to the endpoint that enforces it.


def _get_operator(request: Request) -> Operator:
    """Return the :class:`Operator` stashed by ``MTLSAuthMiddleware``.

    ``MTLSAuthMiddleware`` does the heavy lifting (cert validation,
    registry lookup, status check) and parks a detached
    :class:`Operator` snapshot on ``request.state.operator`` for the
    handler chain. This dep is the read-side accessor — a 401 here
    means the request reached the handler without going through the
    middleware (e.g. ``TLS_REQUIRED=false`` in tests *and* the test
    forgot to override this dep), which is operator/test error rather
    than a runtime auth failure.
    """
    operator = getattr(request.state, "operator", None)
    if operator is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="operator unknown",
        )
    return operator


def _RequireAdmin(  # noqa: N802 — capitalised so call sites read like a type
    operator: Annotated[Operator, Depends(_get_operator)],
) -> Operator:
    """Admit only :attr:`OperatorRole.admin`.

    Gates issuance and revocation. Auditors get a 403 — listing is
    fine for the read tier but mutating the cert inventory is not.
    """
    if operator.role != OperatorRole.admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="role not permitted",
        )
    return operator


def _RequireAdminOrAuditor(  # noqa: N802
    operator: Annotated[Operator, Depends(_get_operator)],
) -> Operator:
    """Admit :attr:`OperatorRole.admin` or :attr:`OperatorRole.auditor`.

    Gates the list / read endpoints. Plain operators (the day-to-day
    "manage peers" role) cannot enumerate the cert inventory.
    """
    if operator.role not in (OperatorRole.admin, OperatorRole.auditor):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="role not permitted",
        )
    return operator


# ---------------------------------------------------------------------------
# Cert-type profiles (mirrors the CLI's _CERT_PROFILES)
# ---------------------------------------------------------------------------
#
# Re-declared here rather than imported so the CLI module isn't a
# runtime dep of the router. The shape — default SANs, default TTL,
# whether an operator FK is required, whether the leaf gets serverAuth
# vs clientAuth — must stay in sync with
# :data:`wg_manager.cli._CERT_PROFILES`; a regression test pins both.

_CERT_PROFILES: dict[CertificateType, dict[str, Any]] = {
    CertificateType.api: {
        "ttl_days": 30,
        "default_sans": ["127.0.0.1", "localhost"],
        "requires_operator": False,
        "server_eku": True,
    },
    CertificateType.cli: {
        "ttl_days": 365,
        "default_sans": None,  # populated from common_name at call time
        "requires_operator": True,
        "server_eku": False,
    },
    CertificateType.dashboard: {
        "ttl_days": 365,
        "default_sans": None,
        "requires_operator": True,
        "server_eku": False,
    },
    CertificateType.mysql: {
        "ttl_days": 30,
        "default_sans": ["mysql", "127.0.0.1", "localhost"],
        "requires_operator": False,
        "server_eku": True,
    },
    CertificateType.mysql_client: {
        "ttl_days": 30,
        "default_sans": None,  # populated from common_name at call time
        "requires_operator": False,
        "server_eku": False,
    },
}


def _resolve_sans(
    cert_type: CertificateType,
    common_name: str,
    sans: list[str] | None,
) -> list[str]:
    """Explicit > type default > [CN] (cli/dashboard).

    Mirrors :func:`wg_manager.cli.certs_issue`'s resolution rule
    verbatim so the wire body and the CLI body produce identical leafs.
    """
    profile = _CERT_PROFILES[cert_type]
    if sans:
        return list(sans)
    if profile["default_sans"] is not None:
        return list(profile["default_sans"])
    return [common_name]


def _resolve_operator_fk(
    cert_type: CertificateType,
    common_name: str,
    operator_cn: str | None,
    session: Session,
) -> int | None:
    """Look up the operator FK for ``cli`` / ``dashboard`` issuance.

    For ``api`` / ``mysql`` the row is owned by the service, not a
    human, and this returns ``None``. For ``cli`` / ``dashboard`` the
    lookup is keyed on ``operator_cn`` (or ``common_name`` when
    omitted, matching the CLI default). A miss aborts the request
    with 422 — no PKI round-trip happens and the registry stays
    untouched.
    """
    profile = _CERT_PROFILES[cert_type]
    if not profile["requires_operator"]:
        return None
    target_cn = operator_cn or common_name
    row = session.exec(
        select(Operator).where(Operator.cn == target_cn)
    ).first()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=(
                f"no operator registered with CN {target_cn!r} — register "
                f"the operator first via the Operators page or "
                f"`wg-manager operators add --cn {target_cn}`"
            ),
        )
    return int(row.id or 0)


def _mint_leaf(
    backend: PKIBackend,
    cert_type: CertificateType,
    common_name: str,
    sans: list[str],
    ttl_seconds: int,
) -> Cert:
    """Dispatch to :meth:`PKIBackend.issue_server_cert` or
    :meth:`issue_client_cert` based on the cert-type profile.
    """
    profile = _CERT_PROFILES[cert_type]
    if profile["server_eku"]:
        return backend.issue_server_cert(
            common_name=common_name, sans=sans, ttl_seconds=ttl_seconds
        )
    return backend.issue_client_cert(
        common_name=common_name, sans=sans, ttl_seconds=ttl_seconds
    )


def _build_pkcs12(cert: Cert, password: str) -> str:
    """Bundle key + leaf + chain into a base64 PKCS#12 string.

    Browsers (Chrome / Firefox / Safari) all consume PKCS#12 natively,
    so a single file lands the dashboard cert into the operator's
    keystore without a multi-step import dance. Empty ``password``
    yields an unencrypted bundle — matches the CLI default and is
    fine for a freshly-issued cert that's about to be passworded by
    the OS keystore on import.

    The output is wrapped in base64 so it can ride inside the JSON
    response body unchanged; the dashboard does a single
    ``atob(...) → Blob → download`` to materialise the ``.p12`` file.
    """
    leaf = x509.load_pem_x509_certificate(cert.cert_pem.encode())
    key = load_pem_private_key(cert.private_pem.encode(), password=None)
    chain_certs = (
        x509.load_pem_x509_certificates(cert.chain_pem.encode())
        if cert.chain_pem.strip()
        else []
    )
    encryption = (
        BestAvailableEncryption(password.encode())
        if password
        else NoEncryption()
    )
    blob = pkcs12.serialize_key_and_certificates(
        name=cert.common_name.encode(),
        key=key,
        cert=leaf,
        cas=chain_certs,
        encryption_algorithm=encryption,
    )
    return base64.b64encode(blob).decode("ascii")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/whoami", response_model=WhoAmIResponse)
def whoami(
    subject: Annotated[CertSubject, Depends(require_subject)],
    operator: Annotated[Operator, Depends(_get_operator)],
) -> WhoAmIResponse:
    """Return the cert subject the API actually saw, plus the operator row.

    The dashboard's "Who am I?" splash renders this verbatim. A
    successful 200 here is operationally meaningful — it proves the
    PKCS#12 the operator just imported was accepted by the API's mTLS
    listener and matched against an active operator row.
    """
    return WhoAmIResponse(
        cn=subject.common_name,
        serial=str(subject.serial),
        sans=list(subject.sans),
        not_before=subject.not_before,
        not_after=subject.not_after,
        operator_cn=operator.cn,
        operator_role=operator.role,
        operator_status=operator.status,
    )


@router.get("", response_model=list[CertificateRead])
def list_certs(
    _: Annotated[Operator, Depends(_RequireAdminOrAuditor)],
    session: Annotated[Session, Depends(get_session)],
) -> list[Certificate]:
    """List every certificate audit row, newest insertion last.

    Returns the live + revoked union — the dashboard filters client-
    side so an auditor reviewing history can see both. The CLI's
    ``wg-manager certs list`` returns the same rows in the same shape;
    the table-renderer at ``web/app/certificates/page.tsx`` is the
    only intentional difference (JSON vs. UI).
    """
    rows = session.exec(select(Certificate).order_by(Certificate.id)).all()
    return list(rows)


@router.post(
    "",
    response_model=CertificateIssueResponse,
    status_code=status.HTTP_201_CREATED,
)
def issue_cert(
    payload: CertificateIssueRequest,
    _: Annotated[Operator, Depends(_RequireAdmin)],
    session: Annotated[Session, Depends(get_session)],
    backend: Annotated[PKIBackend, Depends(get_pki_backend)],
) -> CertificateIssueResponse:
    """Mint a new leaf cert and record the audit row.

    All side effects happen in a single logical transaction: the
    operator lookup, the PKI round-trip, and the row insert. A failure
    on any step leaves the registry untouched so a partially-issued
    cert doesn't show up in the dashboard as "live but you don't have
    the key for it" — the next attempt can retry cleanly.

    The private key is surfaced **once** in the response body; the
    server keeps no copy. Loss of that body means re-issuing.
    """
    profile = _CERT_PROFILES[payload.cert_type]
    # Phase 3b cycle 5 — ``tenant_slug`` only valid on operator /
    # service-client (clientAuth) cert types. Reject early so a
    # mis-aimed request can't bake a confusing ``tenant:<slug>`` SAN
    # into a serverAuth listener cert.
    if payload.tenant_slug is not None and profile["server_eku"]:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=(
                f"tenant_slug is not allowed for cert_type "
                f"{payload.cert_type.value!r} — only cli + dashboard "
                f"certs carry a tenant binding"
            ),
        )
    operator_id = _resolve_operator_fk(
        payload.cert_type, payload.common_name, payload.operator_cn, session
    )
    sans = _resolve_sans(payload.cert_type, payload.common_name, payload.sans)
    ttl_days = payload.ttl_days or profile["ttl_days"]
    ttl_seconds = ttl_days * 24 * 60 * 60

    # Phase 3b cycle 5 — resolve the tenant slug + append the SAN.
    tenant_id: int | None = None
    if payload.tenant_slug is not None:
        tenant_row = session.exec(
            select(Tenant).where(Tenant.slug == payload.tenant_slug)
        ).first()
        if tenant_row is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=(
                    f"no tenant with slug {payload.tenant_slug!r}"
                ),
            )
        tenant_id = int(tenant_row.id or 0)
        sans = [*sans, f"tenant:{payload.tenant_slug}"]

    cert = _mint_leaf(
        backend,
        payload.cert_type,
        payload.common_name,
        sans,
        ttl_seconds,
    )

    pkcs12_b64: str | None = None
    if payload.cert_type == CertificateType.dashboard:
        pkcs12_b64 = _build_pkcs12(cert, payload.pkcs12_password)

    row = Certificate(
        serial=str(cert.serial),
        cert_type=payload.cert_type,
        operator_id=operator_id,
        common_name=cert.common_name,
        sans=",".join(cert.sans),
        not_before=cert.not_before,
        not_after=cert.not_after,
        tenant_id=tenant_id,
    )
    session.add(row)
    session.commit()
    session.refresh(row)

    return CertificateIssueResponse(
        certificate=CertificateRead.model_validate(row),
        cert_pem=cert.cert_pem,
        private_pem=cert.private_pem,
        chain_pem=cert.chain_pem,
        pkcs12_b64=pkcs12_b64,
    )


@router.post(
    "/{cert_id}/renew",
    response_model=CertificateIssueResponse,
    status_code=status.HTTP_201_CREATED,
)
def renew_cert(
    cert_id: int,
    _: Annotated[Operator, Depends(_RequireAdmin)],
    session: Annotated[Session, Depends(get_session)],
    backend: Annotated[PKIBackend, Depends(get_pki_backend)],
) -> CertificateIssueResponse:
    """Mint a fresh leaf with the same identity as ``cert_id``.

    Phase 2d CP4.3. The original audit row stays intact so the trail
    captures the rotation; a *new* row is recorded for the fresh
    leaf. The response body carries the same envelope as
    ``POST /certs`` so a dashboard's renew button can reuse the
    artefact-download panel verbatim.

    The new leaf preserves the original's identity contract:

    - ``cert_type`` is identical (clientAuth-vs-serverAuth EKU stays).
    - ``common_name`` and ``sans`` are copied byte-for-byte.
    - ``operator_id`` (for ``cli``/``dashboard`` rows) is preserved
      so the dashboard still shows "X's cert" next to the new row.
    - ``not_after - not_before`` is preserved, so a 30-day cert
      renews into another 30-day cert (not the cert-type default).

    Side effects: a 422 is returned for revoked rows (renewing them
    would mint a cert for an identity the operator already
    decommissioned). A 404 is returned for unknown IDs.

    PKCS#12 archives are re-built for ``dashboard`` certs using an
    *unencrypted* archive (matching the CLI default). Operators who
    need a password should renew via the CLI; the API path is the
    systemd-timer flow that runs without a human in the loop.
    """
    row = session.get(Certificate, cert_id)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"certificate id={cert_id} not found",
        )
    if row.revoked:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=(
                f"certificate id={cert_id} is revoked; renewal is "
                "not supported for revoked certs — issue a fresh "
                "leaf via POST /certs"
            ),
        )

    sans = [s for s in row.sans.split(",") if s]
    ttl_seconds = max(1, int((row.not_after - row.not_before).total_seconds()))
    cert = _mint_leaf(
        backend,
        row.cert_type,
        row.common_name,
        sans,
        ttl_seconds,
    )

    pkcs12_b64: str | None = None
    if row.cert_type == CertificateType.dashboard:
        # Systemd-timer renewal can't ask for a password; mint an
        # unencrypted bundle so the flow is fully automated. Operators
        # who want a passworded archive should renew via the CLI.
        pkcs12_b64 = _build_pkcs12(cert, password="")

    new_row = Certificate(
        serial=str(cert.serial),
        cert_type=row.cert_type,
        operator_id=row.operator_id,
        common_name=cert.common_name,
        sans=",".join(cert.sans),
        not_before=cert.not_before,
        not_after=cert.not_after,
        out_cert_path=row.out_cert_path,
        out_key_path=row.out_key_path,
        out_chain_path=row.out_chain_path,
    )
    session.add(new_row)
    session.commit()
    session.refresh(new_row)

    return CertificateIssueResponse(
        certificate=CertificateRead.model_validate(new_row),
        cert_pem=cert.cert_pem,
        private_pem=cert.private_pem,
        chain_pem=cert.chain_pem,
        pkcs12_b64=pkcs12_b64,
    )


@router.post(
    "/{cert_id}/revoke",
    response_model=CertificateRevokeResponse,
)
def revoke_cert(
    cert_id: int,
    request: Request,
    _: Annotated[Operator, Depends(_RequireAdmin)],
    session: Annotated[Session, Depends(get_session)],
    backend: Annotated[PKIBackend, Depends(get_pki_backend)],
) -> CertificateRevokeResponse:
    """Revoke an issued cert by row id.

    Two-step under the hood: tells the PKI backend to add the serial
    to its CRL, then flips ``revoked`` and stamps ``revoked_at`` on the
    audit row. Idempotent — calling it on an already-revoked row
    returns 200 with the same body so a dashboard retry after a flaky
    network is safe. The original ``revoked_at`` timestamp is
    preserved so the audit trail reflects the first revocation event,
    not the last retry.

    Phase 2e cycle 3 emits one ``certificate.revoke`` audit row on
    the **first** revoke only; idempotent retries don't add a second
    row so the application audit trail stays one-row-per-event.
    """
    row = session.get(Certificate, cert_id)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"certificate id={cert_id} not found",
        )

    if not row.revoked:
        # Backend first — if the CRL update fails we want the row to
        # still say "live", not "revoked but the CRL never got the
        # update". The opposite order would let a CRL flip linger
        # while the audit row claimed the cert was still good.
        before = row.model_dump(mode="json")
        backend.revoke_cert(serial=int(row.serial))
        row.revoked = True
        row.revoked_at = datetime.now(timezone.utc)
        session.add(row)
        session.flush()
        session.refresh(row)
        audit.persist(
            session,
            event="certificate.revoke",
            **audit.actor_from_request(request),
            resource_type="certificate",
            resource_id=row.id,
            action="revoke",
            before=before,
            after=row.model_dump(mode="json"),
            payload={"serial": row.serial, "common_name": row.common_name},
            tenant_id=row.tenant_id,
        )
        session.commit()
        session.refresh(row)

    return CertificateRevokeResponse(
        certificate=CertificateRead.model_validate(row),
    )


__all__ = ["router"]
