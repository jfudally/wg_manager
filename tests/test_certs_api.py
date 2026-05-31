"""Tests for the Phase 2d CP3.4 ``/certs`` HTTP surface.

CP3.3 shipped the direct-DB :class:`wg_manager.models.Certificate`
registry, the ``wg-manager certs`` CLI, and the ``wg-manager operators``
bootstrap CLI. CP3.4 lifts the same shape into HTTP so the dashboard
(``web/app/certificates``) can issue, revoke, and inspect certs through
the mTLS-protected API.

Endpoints under test:

* ``GET /certs/whoami`` — returns the cert subject the API saw plus
  the resolved :class:`Operator`. Powers the dashboard's "Who am I?"
  splash and proves the mTLS handshake worked end-to-end.
* ``GET /certs`` — list every audit row (live + revoked). Admin or
  auditor only.
* ``POST /certs`` — issue a new leaf via :mod:`wg_manager.pki` and
  record the audit row. Admin only. ``api`` / ``mysql`` types are
  service certs (no operator FK); ``cli`` / ``dashboard`` require a
  registered :class:`Operator` matching ``operator_cn`` (default:
  ``common_name``). ``dashboard`` type additionally returns a
  base64-encoded PKCS#12 bundle so the browser can save it as a
  single import file.
* ``POST /certs/{id}/revoke`` — flips the row's ``revoked`` flag and
  calls the backend CRL. Idempotent: revoking an already-revoked row
  returns 200 with the same shape.

The conftest defaults to ``TLS_REQUIRED=false`` so the production
:class:`MTLSAuthMiddleware` is in passthrough mode for the test
suite. We exercise role enforcement by overriding the router-level
``require_subject`` / ``_RequireAdmin`` / ``_RequireAdminOrAuditor``
dependencies — the auth contract itself is pinned by
``tests/test_auth.py``; this file pins the router contract.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from wg_manager import db as db_module
from wg_manager.auth import CertSubject, require_subject
from wg_manager.main import app
from wg_manager.models import (
    Certificate,
    CertificateType,
    Operator,
    OperatorRole,
    OperatorStatus,
)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _make_subject(cn: str) -> CertSubject:
    """Build a synthetic CertSubject for dependency-override use.

    The router only reads CN / serial / SANs / validity / cert_pem off
    the subject; the test substitutes a stable triple so assertions on
    the ``/whoami`` response don't have to track random serials.
    """
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return CertSubject(
        common_name=cn,
        sans=(cn, "127.0.0.1"),
        serial=4242424242,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=365),
        cert_pem=f"---fake-pem-for-{cn}---",
    )


def _insert_operator(
    cn: str,
    role: OperatorRole = OperatorRole.admin,
    status: OperatorStatus = OperatorStatus.active,
) -> Operator:
    """Insert an Operator row on the test engine and return a detached snapshot.

    The snapshot mirrors what :meth:`MTLSAuthMiddleware._resolve_operator`
    hands to the request — session-free, so handlers reading
    ``request.state.operator`` after the session has closed don't
    trigger a lazy-load.
    """
    with Session(db_module.engine) as session:
        row = Operator(cn=cn, role=role, status=status)
        session.add(row)
        session.commit()
        session.refresh(row)
        return Operator(
            id=row.id,
            cn=row.cn,
            display_name=row.display_name,
            role=row.role,
            status=row.status,
            created_at=row.created_at,
        )


def _override_auth(
    *,
    operator: Operator,
    subject: CertSubject | None = None,
    role_deps: Iterable[Any] = (),
) -> None:
    """Patch the router's auth deps so the request looks authenticated.

    ``role_deps`` is the list of role-gated FastAPI dep callables the
    router exposes at module level (``_RequireAdmin`` etc.). Each one
    is overridden to return the same canned subject so a single test
    can hit any endpoint regardless of role-gate.
    """
    canned = subject or _make_subject(operator.cn)
    app.dependency_overrides[require_subject] = lambda: canned
    from wg_manager.routers import certs as certs_router

    app.dependency_overrides[certs_router._get_operator] = lambda: operator
    for dep in role_deps:
        app.dependency_overrides[dep] = lambda: canned


@pytest.fixture()
def as_admin(client: TestClient) -> tuple[TestClient, Operator]:
    """``client`` fixture wrapped so every endpoint sees an admin operator."""
    from wg_manager.routers import certs as certs_router

    operator = _insert_operator("ops@wg.local", role=OperatorRole.admin)
    _override_auth(
        operator=operator,
        role_deps=(
            certs_router._RequireAdmin,
            certs_router._RequireAdminOrAuditor,
        ),
    )
    return client, operator


@pytest.fixture()
def as_auditor(client: TestClient) -> tuple[TestClient, Operator]:
    """``client`` fixture for an auditor — read-only access."""
    from wg_manager.routers import certs as certs_router

    operator = _insert_operator(
        "audit@wg.local", role=OperatorRole.auditor
    )
    # Auditor cannot issue/revoke; the admin-only dep is intentionally
    # NOT overridden so a wrong-role call to those endpoints raises 403
    # via the real ``require_role`` path.
    canned = _make_subject(operator.cn)
    app.dependency_overrides[require_subject] = lambda: canned
    app.dependency_overrides[certs_router._get_operator] = lambda: operator
    app.dependency_overrides[certs_router._RequireAdminOrAuditor] = (
        lambda: canned
    )
    return client, operator


@pytest.fixture()
def as_operator(client: TestClient) -> tuple[TestClient, Operator]:
    """``client`` fixture for a plain operator — neither admin nor auditor.

    Used to assert ``POST /certs`` and ``GET /certs`` reject the role
    via the production ``require_role`` factory rather than via the
    test override.
    """
    operator = _insert_operator("user@wg.local", role=OperatorRole.operator)
    canned = _make_subject(operator.cn)
    app.dependency_overrides[require_subject] = lambda: canned
    from wg_manager.routers import certs as certs_router

    app.dependency_overrides[certs_router._get_operator] = lambda: operator
    # Deliberately do NOT override the role-gated deps — they should
    # 403 the plain-operator role.
    return client, operator


def _row_count() -> int:
    with Session(db_module.engine) as session:
        return len(list(session.exec(select(Certificate)).all()))


def _row_by_serial(serial: str) -> Certificate | None:
    with Session(db_module.engine) as session:
        return session.exec(
            select(Certificate).where(Certificate.serial == serial)
        ).first()


# ---------------------------------------------------------------------------
# GET /certs/whoami
# ---------------------------------------------------------------------------


class TestWhoAmI:
    """The dashboard splash that proves mTLS worked end-to-end."""

    def test_returns_subject_and_operator(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, operator = as_admin
        resp = client.get("/certs/whoami")

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["cn"] == operator.cn
        assert body["serial"] == "4242424242"
        assert "127.0.0.1" in body["sans"]
        assert body["operator_cn"] == operator.cn
        assert body["operator_role"] == "admin"
        assert body["operator_status"] == "active"
        # The validity window is surfaced so the splash can show the
        # operator how long the cert they imported is good for.
        assert "not_before" in body
        assert "not_after" in body

    def test_auditor_can_see_their_own_subject(
        self, as_auditor: tuple[TestClient, Operator]
    ) -> None:
        """Whoami is gated by ``require_subject`` only — any active
        operator may call it regardless of role."""
        client, _ = as_auditor
        resp = client.get("/certs/whoami")
        assert resp.status_code == 200, resp.text
        assert resp.json()["operator_role"] == "auditor"


# ---------------------------------------------------------------------------
# GET /certs
# ---------------------------------------------------------------------------


class TestListCerts:
    """``GET /certs`` returns every audit row, gated to admin + auditor."""

    def _seed_one(self, cert_type: CertificateType = CertificateType.api) -> str:
        """Insert a Certificate row directly and return its serial.

        Tests use this when they care about the read side and don't
        want to round-trip through the POST issue path (which exercises
        the PKI backend).
        """
        with Session(db_module.engine) as session:
            now = datetime.now(timezone.utc)
            row = Certificate(
                serial="12345678901234567890",
                cert_type=cert_type,
                operator_id=None,
                common_name="127.0.0.1",
                sans="127.0.0.1,localhost",
                not_before=now,
                not_after=now + timedelta(days=30),
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return row.serial

    def test_admin_sees_every_row(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        self._seed_one()
        resp = client.get("/certs")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert isinstance(body, list)
        assert len(body) == 1
        row = body[0]
        # Stable shape the dashboard table renders against.
        for key in (
            "id",
            "serial",
            "cert_type",
            "operator_id",
            "common_name",
            "sans",
            "not_before",
            "not_after",
            "revoked",
            "revoked_at",
            "created_at",
        ):
            assert key in row
        assert row["cert_type"] == "api"
        assert row["revoked"] is False
        assert row["revoked_at"] is None

    def test_auditor_sees_every_row(
        self, as_auditor: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_auditor
        self._seed_one()
        resp = client.get("/certs")
        assert resp.status_code == 200, resp.text
        assert len(resp.json()) == 1

    def test_plain_operator_is_forbidden(
        self, as_operator: tuple[TestClient, Operator]
    ) -> None:
        """The operator role can register peers but not enumerate the
        cert inventory — the auditor role is the read tier."""
        client, _ = as_operator
        self._seed_one()
        resp = client.get("/certs")
        assert resp.status_code == 403
        assert resp.json() == {"detail": "role not permitted"}


# ---------------------------------------------------------------------------
# POST /certs
# ---------------------------------------------------------------------------


class TestIssueCert:
    """``POST /certs`` mints a leaf cert and records the audit row."""

    def test_issue_api_cert_happy_path(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        """``api`` is the easiest path — service cert, no operator FK,
        defaults populate SAN + TTL when the operator omits them."""
        client, _ = as_admin
        resp = client.post(
            "/certs",
            json={
                "cert_type": "api",
                "common_name": "127.0.0.1",
                "sans": ["127.0.0.1", "localhost"],
                "ttl_days": 30,
            },
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        # Response surfaces the audit row + the cert material.
        assert "certificate" in body
        assert "cert_pem" in body and "BEGIN CERTIFICATE" in body["cert_pem"]
        assert "private_pem" in body and (
            "PRIVATE KEY" in body["private_pem"]
        )
        assert "chain_pem" in body and "BEGIN CERTIFICATE" in body["chain_pem"]
        # PKCS#12 is reserved for the dashboard type.
        assert body.get("pkcs12_b64") is None

        cert_row = body["certificate"]
        assert cert_row["cert_type"] == "api"
        assert cert_row["operator_id"] is None
        assert cert_row["common_name"] == "127.0.0.1"
        assert cert_row["revoked"] is False

        # Audit row landed in the DB.
        assert _row_count() == 1
        # The leaf parses and has serverAuth EKU.
        leaf = x509.load_pem_x509_certificate(body["cert_pem"].encode())
        ekus = leaf.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
        assert ExtendedKeyUsageOID.SERVER_AUTH in list(ekus)
        # The audit serial matches the leaf.
        assert cert_row["serial"] == str(leaf.serial_number)

    def test_issue_cli_cert_binds_to_operator(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        """``cli`` certs carry the operator FK so the dashboard can
        render "X's CLI cert" next to the row."""
        client, admin = as_admin
        resp = client.post(
            "/certs",
            json={
                "cert_type": "cli",
                "common_name": admin.cn,
                "ttl_days": 365,
            },
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["certificate"]["cert_type"] == "cli"
        assert body["certificate"]["operator_id"] == admin.id
        leaf = x509.load_pem_x509_certificate(body["cert_pem"].encode())
        ekus = leaf.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
        assert ExtendedKeyUsageOID.CLIENT_AUTH in list(ekus)

    def test_issue_dashboard_cert_returns_pkcs12(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        """``dashboard`` certs ship a base64 PKCS#12 the browser can save.

        The PKCS#12 is encrypted with ``pkcs12_password`` when supplied
        (otherwise unencrypted, which matches the CLI default).
        """
        client, admin = as_admin
        resp = client.post(
            "/certs",
            json={
                "cert_type": "dashboard",
                "common_name": admin.cn,
                "ttl_days": 365,
                "pkcs12_password": "hunter2",
            },
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["certificate"]["cert_type"] == "dashboard"
        assert body["certificate"]["operator_id"] == admin.id
        assert body["pkcs12_b64"]
        # Round-trip the PKCS#12 to prove it's a valid bundle.
        p12_bytes = base64.b64decode(body["pkcs12_b64"])
        key, leaf, chain = pkcs12.load_key_and_certificates(
            p12_bytes, b"hunter2"
        )
        assert key is not None
        assert leaf is not None
        assert chain is not None and len(chain) >= 1
        # Serial matches the audit row.
        assert body["certificate"]["serial"] == str(leaf.serial_number)

    def test_issue_cli_unknown_operator_cn_returns_422(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        """Operator-bound types refuse issuance when the CN doesn't
        match any registered :class:`Operator` row."""
        client, _ = as_admin
        resp = client.post(
            "/certs",
            json={
                "cert_type": "cli",
                "common_name": "ghost@wg.local",
                "operator_cn": "ghost@wg.local",
            },
        )
        assert resp.status_code == 422
        # The error mentions the missing CN so the operator can fix it.
        assert "ghost@wg.local" in resp.text
        # No partial side effect on the DB.
        assert _row_count() == 0

    def test_issue_dashboard_without_pkcs12_password_still_works(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        """The CLI accepts an empty password (unencrypted PKCS#12);
        the API mirrors that — the bundle is still produced."""
        client, admin = as_admin
        resp = client.post(
            "/certs",
            json={
                "cert_type": "dashboard",
                "common_name": admin.cn,
            },
        )
        assert resp.status_code == 201, resp.text
        # The bundle still parses with an empty-string password.
        p12_bytes = base64.b64decode(resp.json()["pkcs12_b64"])
        key, leaf, _chain = pkcs12.load_key_and_certificates(p12_bytes, None)
        assert key is not None and leaf is not None

    def test_issue_mysql_client_cert_happy_path(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        """Phase 2d CP4.2 — ``mysql-client`` is a service-principal
        clientAuth cert with no operator FK. The app + worker present
        it to MySQL to satisfy ``require_secure_transport=ON``.
        """
        client, _ = as_admin
        resp = client.post(
            "/certs",
            json={
                "cert_type": "mysql-client",
                "common_name": "wg-manager-app",
                "ttl_days": 30,
            },
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["certificate"]["cert_type"] == "mysql-client"
        assert body["certificate"]["operator_id"] is None
        # The leaf carries clientAuth (not serverAuth — that's mysql's job).
        leaf = x509.load_pem_x509_certificate(body["cert_pem"].encode())
        ekus = leaf.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
        assert ExtendedKeyUsageOID.CLIENT_AUTH in list(ekus)
        assert ExtendedKeyUsageOID.SERVER_AUTH not in list(ekus)
        # No PKCS#12 — only the dashboard type ships that.
        assert body.get("pkcs12_b64") is None
        assert _row_count() == 1

    def test_issue_rejects_invalid_cert_type(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        resp = client.post(
            "/certs",
            json={"cert_type": "bogus", "common_name": "x"},
        )
        assert resp.status_code == 422
        assert _row_count() == 0

    def test_plain_operator_cannot_issue(
        self, as_operator: tuple[TestClient, Operator]
    ) -> None:
        """The operator role is denied issuance — admins only."""
        client, _ = as_operator
        resp = client.post(
            "/certs",
            json={"cert_type": "api", "common_name": "127.0.0.1"},
        )
        assert resp.status_code == 403
        assert resp.json() == {"detail": "role not permitted"}
        assert _row_count() == 0

    def test_auditor_cannot_issue(
        self, as_auditor: tuple[TestClient, Operator]
    ) -> None:
        """The auditor role can read but never mutate."""
        client, _ = as_auditor
        resp = client.post(
            "/certs",
            json={"cert_type": "api", "common_name": "127.0.0.1"},
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# POST /certs/{id}/revoke
# ---------------------------------------------------------------------------


class TestRevokeCert:
    """``POST /certs/{id}/revoke`` flips the row + the CRL."""

    def _seed_via_api(self, client: TestClient) -> dict[str, Any]:
        """Issue an api cert through the endpoint so revoke has a real
        backend-issued serial to look up on the CRL."""
        resp = client.post(
            "/certs",
            json={
                "cert_type": "api",
                "common_name": "127.0.0.1",
                "sans": ["127.0.0.1"],
                "ttl_days": 30,
            },
        )
        assert resp.status_code == 201, resp.text
        return resp.json()["certificate"]

    def test_revoke_marks_row_and_returns_200(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        cert_row = self._seed_via_api(client)
        cert_id = cert_row["id"]

        resp = client.post(f"/certs/{cert_id}/revoke")
        assert resp.status_code == 200, resp.text

        body = resp.json()
        assert body["certificate"]["revoked"] is True
        assert body["certificate"]["revoked_at"] is not None

        # DB reflects the flip.
        row = _row_by_serial(cert_row["serial"])
        assert row is not None
        assert row.revoked is True
        assert row.revoked_at is not None

    def test_revoke_idempotent(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        """Revoking an already-revoked row returns 200, not 409 — the
        dashboard can re-issue the call safely after a flaky network."""
        client, _ = as_admin
        cert_row = self._seed_via_api(client)
        cert_id = cert_row["id"]

        first = client.post(f"/certs/{cert_id}/revoke")
        second = client.post(f"/certs/{cert_id}/revoke")
        assert first.status_code == 200, first.text
        assert second.status_code == 200, second.text
        # ``revoked_at`` is set on the first call; the second call
        # leaves it alone so the audit timestamp reflects the original
        # revocation event.
        first_at = first.json()["certificate"]["revoked_at"]
        second_at = second.json()["certificate"]["revoked_at"]
        assert first_at == second_at

    def test_revoke_unknown_id_returns_404(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        resp = client.post("/certs/9999/revoke")
        assert resp.status_code == 404

    def test_plain_operator_cannot_revoke(
        self, as_operator: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_operator
        resp = client.post("/certs/1/revoke")
        assert resp.status_code == 403

    def test_auditor_cannot_revoke(
        self, as_auditor: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_auditor
        resp = client.post("/certs/1/revoke")
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# POST /certs/{id}/renew — Phase 2d CP4.3
# ---------------------------------------------------------------------------


class TestRenewCert:
    """``POST /certs/{id}/renew`` mints a fresh leaf with the same identity.

    Renewal is the systemd-timer-friendly path: the original audit
    row stays intact (so the trail captures the rotation), a new row
    is recorded for the freshly-minted leaf, and the response body
    carries the same shape as ``POST /certs`` (cert/key/chain + the
    new audit row). The walker form (``wg-manager certs renew``)
    walks the registry and calls this endpoint per due cert.
    """

    def _seed_via_api(self, client: TestClient) -> dict[str, Any]:
        resp = client.post(
            "/certs",
            json={
                "cert_type": "api",
                "common_name": "127.0.0.1",
                "sans": ["127.0.0.1", "localhost"],
                "ttl_days": 30,
            },
        )
        assert resp.status_code == 201, resp.text
        return resp.json()["certificate"]

    def test_renew_returns_new_cert_and_row(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        original = self._seed_via_api(client)
        original_id = original["id"]

        resp = client.post(f"/certs/{original_id}/renew")
        assert resp.status_code == 201, resp.text
        body = resp.json()

        # The response carries the same envelope as POST /certs.
        assert "cert_pem" in body and "BEGIN CERTIFICATE" in body["cert_pem"]
        assert "private_pem" in body and "PRIVATE KEY" in body["private_pem"]
        assert "chain_pem" in body and "BEGIN CERTIFICATE" in body["chain_pem"]

        # A new audit row exists; the original is untouched.
        new_row = body["certificate"]
        assert new_row["id"] != original_id
        assert new_row["serial"] != original["serial"]
        assert new_row["cert_type"] == original["cert_type"]
        assert new_row["common_name"] == original["common_name"]
        assert new_row["sans"] == original["sans"]
        assert new_row["revoked"] is False

        # Both rows are now in the registry.
        assert _row_count() == 2

        # Original row stays put — that's the audit trail.
        original_after = _row_by_serial(original["serial"])
        assert original_after is not None
        assert original_after.revoked is False

    def test_renew_preserves_original_ttl_window_length(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        """The new cert's lifetime matches the original's so a 30-day
        leaf renews into another 30-day leaf, not a default-365-day
        one."""
        client, _ = as_admin
        original = self._seed_via_api(client)
        original_window = (
            datetime.fromisoformat(original["not_after"].replace("Z", "+00:00"))
            - datetime.fromisoformat(
                original["not_before"].replace("Z", "+00:00")
            )
        )

        resp = client.post(f"/certs/{original['id']}/renew")
        assert resp.status_code == 201, resp.text
        new_row = resp.json()["certificate"]
        new_window = (
            datetime.fromisoformat(
                new_row["not_after"].replace("Z", "+00:00")
            )
            - datetime.fromisoformat(
                new_row["not_before"].replace("Z", "+00:00")
            )
        )
        # The PKI backend adds a few seconds of clock-skew leeway on
        # each issuance so the windows aren't bit-exact equal — but
        # they must round-trip to the same number of days (a default-
        # TTL renewal would land at 365 days, an order of magnitude
        # off from the 30 the original cert carried).
        assert new_window.days == original_window.days
        assert abs(new_window - original_window) <= timedelta(minutes=5)

    def test_renew_unknown_id_returns_404(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_admin
        resp = client.post("/certs/9999/renew")
        assert resp.status_code == 404

    def test_renew_revoked_returns_422(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        """A revoked cert is by definition retired — renewing it would
        mint a fresh leaf for an identity the operator already
        decommissioned. Refuse with 422 + a clear message."""
        client, _ = as_admin
        original = self._seed_via_api(client)
        revoke = client.post(f"/certs/{original['id']}/revoke")
        assert revoke.status_code == 200, revoke.text

        resp = client.post(f"/certs/{original['id']}/renew")
        assert resp.status_code == 422, resp.text
        assert "revoked" in resp.text.lower()

    def test_renew_cli_cert_preserves_operator_fk(
        self, as_admin: tuple[TestClient, Operator]
    ) -> None:
        """``cli``/``dashboard`` rows stay bound to their original
        :class:`Operator` after renewal — that's how the dashboard
        keeps showing "X's CLI cert" next to the new row."""
        client, admin = as_admin
        issue = client.post(
            "/certs",
            json={
                "cert_type": "cli",
                "common_name": admin.cn,
                "ttl_days": 365,
            },
        )
        assert issue.status_code == 201, issue.text
        original = issue.json()["certificate"]
        assert original["operator_id"] == admin.id

        resp = client.post(f"/certs/{original['id']}/renew")
        assert resp.status_code == 201, resp.text
        assert resp.json()["certificate"]["operator_id"] == admin.id

    def test_plain_operator_cannot_renew(
        self, as_operator: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_operator
        resp = client.post("/certs/1/renew")
        assert resp.status_code == 403

    def test_auditor_cannot_renew(
        self, as_auditor: tuple[TestClient, Operator]
    ) -> None:
        client, _ = as_auditor
        resp = client.post("/certs/1/renew")
        assert resp.status_code == 403
