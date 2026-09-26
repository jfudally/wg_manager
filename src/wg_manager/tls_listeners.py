"""uvicorn TLS settings for each wg-manager listener.

wg-manager runs two HTTPS listeners with deliberately different
client-cert policies, and this module is the one place that encodes
them so the difference is explicit and testable:

* **Operator API** (:func:`api_ssl_kwargs`) — mTLS. The client cert is
  demanded at the TLS handshake whenever ``TLS_REQUIRED=true``; the
  :class:`wg_manager.auth.MTLSAuthMiddleware` then maps it to an
  operator.
* **Enrollment** (:func:`enroll_ssl_kwargs`, Phase 3f) — server-auth
  TLS only. A freshly launched host has no client cert yet; it proves
  itself with a single-use enrollment token in the request instead.
  This listener serves :func:`wg_manager.enroll_app.create_enroll_app`,
  which mounts nothing but the enrollment route and health probes.

Both return keyword arguments for :func:`uvicorn.run` /
:class:`uvicorn.Config`.
"""

from __future__ import annotations

import ssl
from typing import Any

from wg_manager.config import Settings


def api_ssl_kwargs(settings: Settings) -> dict[str, Any]:
    """Build uvicorn SSL kwargs for the mTLS operator listener.

    :param settings: Resolved settings; reads the ``tls_*`` fields.
    :return: ``ssl_certfile`` / ``ssl_keyfile`` / ``ssl_ca_certs`` /
        ``ssl_cert_reqs``. ``ssl_cert_reqs`` is ``CERT_REQUIRED`` when
        ``tls_required`` is set, otherwise ``CERT_OPTIONAL`` (TLS
        terminated but client certs not enforced — dev only).
    """
    return {
        "ssl_certfile": settings.tls_cert_pem,
        "ssl_keyfile": settings.tls_key_pem,
        "ssl_ca_certs": settings.tls_ca_bundle_pem,
        "ssl_cert_reqs": (
            ssl.CERT_REQUIRED if settings.tls_required else ssl.CERT_OPTIONAL
        ),
    }


def enroll_ssl_kwargs(settings: Settings) -> dict[str, Any]:
    """Build uvicorn SSL kwargs for the enrollment listener.

    Reuses the operator listener's server cert/key so a host verifies
    the same identity on both ports. It never asks for a client cert,
    regardless of ``tls_required``, and loads no CA bundle. Without a
    CA bundle the server's CertificateRequest can't advertise the
    operator CA's name to anonymous callers.

    :param settings: Resolved settings; reads ``tls_cert_pem`` and
        ``tls_key_pem``.
    :return: ``ssl_certfile`` / ``ssl_keyfile`` / ``ssl_cert_reqs``
        (always ``CERT_NONE``).
    """
    return {
        "ssl_certfile": settings.tls_cert_pem,
        "ssl_keyfile": settings.tls_key_pem,
        "ssl_cert_reqs": ssl.CERT_NONE,
    }
