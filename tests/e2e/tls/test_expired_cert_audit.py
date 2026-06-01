"""CP5 acceptance #2 — an expired client cert is refused at the TLS handshake.

The ROADMAP framing — "expired client cert → HTTP 401 + audit log
line" — leaves room for two implementations:

* **TLS-layer rejection.** Python's stdlib :mod:`ssl` module enforces
  X.509 ``notAfter`` at handshake; an expired client cert never makes
  it past OpenSSL on the server side. The client sees an
  :class:`ssl.SSLError` / :class:`httpx.ConnectError`; the OpenSSL
  alert sent on the wire is ``certificate_expired`` (RFC 5246 alert
  code 45).

* **App-layer rejection.** Disable the TLS-layer date check, let the
  handshake succeed, have the middleware check
  ``cert_subject.not_after`` and return HTTP 401 with a structured
  audit line.

The Phase 2d implementation went with **TLS-layer rejection** because:

1. It is the default, well-audited posture — turning off OpenSSL's
   date check requires reaching into ``X509_V_FLAG_*`` flags that
   Python doesn't expose stably, and bypassing TLS validation to do
   the same work at the app layer is exactly the sort of footgun the
   rest of Phase 2d went out of its way to avoid.
2. It terminates the handshake before any wg-manager code runs, which
   is the strongest possible isolation — an expired cert never
   reaches the operator-registry lookup or the certificate-revoked
   gate.

The audit-trail half of the criterion is therefore satisfied for
**app-layer rejections only** (CP5.3 — see
:mod:`test_revoked_cert_audit`); expired-cert handshakes surface to
the client as an OpenSSL alert. This is documented explicitly in
``docs/THREAT_MODEL.md`` and ``SECURITY.md`` as part of the Phase 2d
posture.
"""

from __future__ import annotations

import ssl
import time

import httpx
import pytest

from tests.e2e.tls.conftest import LiveAPIEnv


# Short enough that the suite stays fast, long enough that the
# mint-+-on-disk-write window is robust on a slow CI runner.
# ``ttl_seconds=2`` means the cert is alive long enough for
# :meth:`LiveAPIEnv.write_pem_files` to finish, then dead by the
# time ``_EXPIRY_WAIT`` elapses.
_CERT_TTL = 2
_EXPIRY_WAIT = 4.0


def test_expired_client_cert_handshake_refused(
    live_api_server: LiveAPIEnv,
) -> None:
    """An expired client cert fails the TLS handshake.

    httpx wraps the underlying :class:`ssl.SSLError` in either
    :class:`httpx.ConnectError` or :class:`httpx.ReadError` depending
    on which side closes first — assert the base
    :class:`httpx.TransportError` so the test isn't pinned to a
    specific OpenSSL/timing combination. :class:`ssl.SSLError` is
    accepted alongside because httpx surfaces it directly on some
    Python versions when the failure happens before any TCP body.

    The rejection is the *production-shape* signal for "this cert is
    no longer trusted" — Phase 2d's posture is to terminate the
    handshake on an expired cert rather than dispatch to the app
    layer, which would require relaxing OpenSSL's date check.
    """
    live_api_server.reset_stderr()
    cert = live_api_server.mint_client_cert(
        live_api_server.bootstrap_operator_cn, ttl_seconds=_CERT_TTL
    )
    cert_path, key_path = live_api_server.write_pem_files(
        cert, label="expired-cp5-bootstrap"
    )
    time.sleep(_EXPIRY_WAIT)

    ctx = live_api_server.make_client_ssl_context(cert_path, key_path)
    with pytest.raises((httpx.TransportError, ssl.SSLError)):
        with httpx.Client(verify=ctx, timeout=5.0) as client:
            client.get(f"{live_api_server.base_url}/certs/whoami")


def test_listener_still_responsive_after_expired_cert_attempt(
    live_api_server: LiveAPIEnv,
) -> None:
    """A failed handshake doesn't crash the listener.

    Defensive: a malformed TLS handshake that took uvicorn's worker
    out would silently break the rest of the acceptance suite. Use a
    *valid* fresh client cert against ``/certs/whoami`` and assert the
    listener still responds (any HTTP code that comes back, including
    401 for unknown-CN, proves the listener is alive). The bootstrap
    CN admits with 200 because the first cert-bearing request
    self-registers the operator row — see
    :attr:`wg_manager.config.Settings.auth_bootstrap_operator_cn`.
    """
    cert = live_api_server.mint_client_cert(
        live_api_server.bootstrap_operator_cn, ttl_seconds=300
    )
    cert_path, key_path = live_api_server.write_pem_files(
        cert, label="post-expired-bootstrap"
    )

    ctx = live_api_server.make_client_ssl_context(cert_path, key_path)
    with httpx.Client(verify=ctx, timeout=10.0) as client:
        resp = client.get(f"{live_api_server.base_url}/certs/whoami")

    assert resp.status_code == 200
    body = resp.json()
    assert body["operator_cn"] == live_api_server.bootstrap_operator_cn
