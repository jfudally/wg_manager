"""Phase 2d CP5 — TLS / mTLS acceptance suite.

The four CP5 acceptance criteria each get one test module under this
package:

* :mod:`test_plain_http_refused` — a plain-HTTP connect is refused.
* :mod:`test_expired_cert_audit` — an expired client cert is rejected
  with HTTP 401 and the rejection is captured in the audit log.
* :mod:`test_revoked_cert_audit` — a revoked cert is rejected with HTTP
  401 after the CRL re-pull; the rejection is captured in the audit
  log.
* :mod:`test_mysql_rotation_under_load` — the API does not drop
  requests when MySQL's server cert is hot-swapped mid-load.

All four ride the session-scoped :func:`live_api_server` fixture
declared in :mod:`tests.e2e.tls.conftest` so uvicorn comes up exactly
once per ``make test-e2e-tls`` run. The bucket is gated by the
``e2e_tls`` pytest marker and deselected from the fast ``make test``
invocation.
"""
