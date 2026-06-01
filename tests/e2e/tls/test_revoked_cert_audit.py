"""CP5 acceptance #3 — a revoked cert is refused with a 401 + audit line.

End-to-end revocation lifecycle exercised against the live mTLS
listener:

1. The bootstrap admin's cert (minted via :class:`LocalDevPKI` to
   match the :attr:`Settings.auth_bootstrap_operator_cn` knob) hits
   the API for the first time — the middleware self-registers it,
   admits the request, emits an ``auth.admit`` audit line.

2. The bootstrap admin issues a fresh ``cli`` cert via
   ``POST /certs``. The new cert lands a row in the audit registry.

3. The new cert hits ``/certs/whoami`` — admit + audit line. This is
   the "before revocation" baseline.

4. The bootstrap admin revokes the new row via
   ``POST /certs/{id}/revoke``. The CRL is updated server-side and
   the ``certificate.revoked`` flag flips.

5. The new cert hits ``/certs/whoami`` again — the middleware's
   revoked-serial gate reads the flipped row and 401s with body
   ``{"detail": "operator cert revoked"}`` plus a corresponding
   ``auth.reject`` audit line on stderr.

The "CRL re-pull" framing in the ROADMAP maps to "the audit registry
row is the canonical source of truth" — the middleware reads it on
every request, so there is no caching layer to invalidate. The
PKI-backend CRL is what `mysqld` and other downstream verifiers
consume; for wg-manager's own auth gate the row flip *is* the CRL
event.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from tests.e2e.tls.conftest import LiveAPIEnv


def _bootstrap_admin_pair(env: LiveAPIEnv) -> tuple[Path, Path]:
    """Mint + persist a client cert under the bootstrap-operator CN.

    The first cert-bearing request with this CN self-registers an
    ``admin`` operator row, which then has POST /certs / revoke
    privileges.
    """
    cert = env.mint_client_cert(env.bootstrap_operator_cn, ttl_seconds=600)
    return env.write_pem_files(cert, label="bootstrap-admin")


def _last_audit_record(
    env: LiveAPIEnv, *, event: str, **fields: str
) -> dict | None:
    """Return the last audit-line JSON record matching ``event`` + ``fields``.

    The audit emitter writes one JSON object per decision to stderr
    (see :func:`wg_manager.auth._emit_audit`). This helper parses every
    line, keeps the ones that look like our JSON shape, and returns
    the most recent record that matches all supplied ``fields``.
    ``None`` if no match — the caller's assertion turns that into a
    readable failure.
    """
    stderr_text = env.read_stderr()
    last: dict | None = None
    for raw in stderr_text.splitlines():
        raw = raw.strip()
        if not raw.startswith("{"):
            continue
        try:
            record = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        if record.get("event") != event:
            continue
        if all(record.get(k) == v for k, v in fields.items()):
            last = record
    return last


@pytest.fixture
def bootstrap_admin_client(
    live_api_server: LiveAPIEnv,
) -> httpx.Client:
    """Yield an mTLS-authenticated httpx client as the bootstrap admin.

    Used by every test in this module — the bootstrap CN is the only
    identity the harness gives admin powers to, so issuing + revoking
    has to ride through here.
    """
    cert_path, key_path = _bootstrap_admin_pair(live_api_server)
    ctx = live_api_server.make_client_ssl_context(cert_path, key_path)
    with httpx.Client(
        base_url=live_api_server.base_url,
        verify=ctx,
        timeout=10.0,
    ) as client:
        yield client


def _issue_cli_cert(
    admin: httpx.Client, cn: str, *, sans: list[str] | None = None
) -> dict:
    """Mint a ``cli`` cert via ``POST /certs`` and return the response body.

    ``cli`` cert type because it's the smallest body the registry will
    write a row for — ``api`` doesn't take an operator FK; ``dashboard``
    would force a PKCS#12 build we don't need here.
    """
    resp = admin.post(
        "/certs",
        json={
            "cert_type": "cli",
            "common_name": cn,
            "sans": sans or [cn],
            "ttl_days": 1,
            "operator_cn": cn,
        },
    )
    assert resp.status_code == 201, (
        f"POST /certs failed: {resp.status_code} {resp.text}"
    )
    return resp.json()


def test_revoked_cert_is_rejected_with_audit_line(
    live_api_server: LiveAPIEnv,
    bootstrap_admin_client: httpx.Client,
) -> None:
    """The full e2e lifecycle — issue, use, revoke, use again.

    Pins:

    * Step 2 (admit before revoke) → 200 + ``auth.admit`` audit line
      naming the new cert's serial.
    * Step 4 (revoke) → 200 from ``POST /certs/{id}/revoke``.
    * Step 5 (admit after revoke) → 401 ``"operator cert revoked"`` +
      ``auth.reject`` audit line with
      ``reason="operator-cert-revoked"`` naming the same serial.
    """
    # First, register the operator the cli cert will belong to. The
    # bootstrap admin is one operator; the cli cert's CN is a fresh
    # identity, so we need a row for it in the registry before the
    # cli cert can authenticate. Use operators add via the API would
    # require an extra endpoint; instead, route through the
    # bootstrap CN — issue the cli cert against the *bootstrap* CN
    # itself so the existing self-registered row admits it.
    bootstrap_cn = live_api_server.bootstrap_operator_cn

    # Step 1: drive the first admin request so the bootstrap row is
    # self-registered before we issue.
    whoami = bootstrap_admin_client.get("/certs/whoami")
    assert whoami.status_code == 200, whoami.text

    # Step 2: bootstrap admin mints a fresh cli cert. Reuse the
    # bootstrap CN so the resulting cert authenticates as the
    # already-active admin operator — keeps the test focused on
    # revocation, not on multi-operator setup.
    issue_body = _issue_cli_cert(bootstrap_admin_client, bootstrap_cn)
    new_cert_pem = issue_body["cert_pem"]
    new_key_pem = issue_body["private_pem"]
    new_serial = issue_body["certificate"]["serial"]
    new_id = issue_body["certificate"]["id"]

    # Persist the new cert + key alongside the bootstrap pair so
    # httpx can present them. The acceptance harness's tmp dir is
    # session-scoped so the path stays valid through teardown.
    new_cert_path = live_api_server.tmp_dir / "tester.crt"
    new_key_path = live_api_server.tmp_dir / "tester.key"
    new_cert_path.write_text(new_cert_pem)
    new_key_path.write_text(new_key_pem)
    new_key_path.chmod(0o600)

    # Step 3 — before revoke: the new cert authenticates cleanly.
    live_api_server.reset_stderr()
    tester_ctx = live_api_server.make_client_ssl_context(
        new_cert_path, new_key_path
    )
    with httpx.Client(
        base_url=live_api_server.base_url,
        verify=tester_ctx,
        timeout=10.0,
    ) as tester:
        baseline = tester.get("/certs/whoami")
    assert baseline.status_code == 200, baseline.text
    admit_record = _last_audit_record(
        live_api_server,
        event="auth.admit",
        serial=str(new_serial),
    )
    assert admit_record is not None, (
        "expected an auth.admit audit line for the pre-revoke request; "
        f"stderr was:\n{live_api_server.read_stderr()[-2000:]}"
    )
    assert admit_record["cn"] == bootstrap_cn
    assert admit_record["role"] == "admin"

    # Step 4: revoke the new row via the API.
    live_api_server.reset_stderr()
    revoke_resp = bootstrap_admin_client.post(f"/certs/{new_id}/revoke")
    assert revoke_resp.status_code == 200, revoke_resp.text
    assert revoke_resp.json()["certificate"]["revoked"] is True

    # Step 5 — after revoke: the new cert is rejected at the middleware.
    live_api_server.reset_stderr()
    new_ctx_after_revoke = live_api_server.make_client_ssl_context(
        new_cert_path, new_key_path
    )
    with httpx.Client(
        base_url=live_api_server.base_url,
        verify=new_ctx_after_revoke,
        timeout=10.0,
    ) as tester:
        after_revoke = tester.get("/certs/whoami")
    assert after_revoke.status_code == 401
    assert after_revoke.json() == {"detail": "operator cert revoked"}
    reject_record = _last_audit_record(
        live_api_server,
        event="auth.reject",
        reason="operator-cert-revoked",
        serial=str(new_serial),
    )
    assert reject_record is not None, (
        "expected an auth.reject audit line with "
        "reason=operator-cert-revoked for the post-revoke request; "
        f"stderr was:\n{live_api_server.read_stderr()[-2000:]}"
    )
    assert reject_record["cn"] == bootstrap_cn
    assert reject_record["path"] == "/certs/whoami"


def test_bootstrap_admin_unaffected_by_revoked_sibling(
    live_api_server: LiveAPIEnv,
    bootstrap_admin_client: httpx.Client,
) -> None:
    """Revoking one cert doesn't break the admin who issued it.

    A regression guard: the revoked-serial gate is per-cert, not
    per-operator. The bootstrap cert (which never had a registry row
    minted for it) must continue admitting after we've revoked a
    sibling cert that *did* have a row.
    """
    bootstrap_cn = live_api_server.bootstrap_operator_cn
    # Prime the bootstrap row.
    bootstrap_admin_client.get("/certs/whoami")

    issue_body = _issue_cli_cert(bootstrap_admin_client, bootstrap_cn)
    new_id = issue_body["certificate"]["id"]
    bootstrap_admin_client.post(f"/certs/{new_id}/revoke")

    # Bootstrap admin still works.
    resp = bootstrap_admin_client.get("/certs/whoami")
    assert resp.status_code == 200
