"""Canonical entry point: ``python -m wg_manager`` runs the API with mTLS.

This is the production / dev runner. Reads
:class:`wg_manager.config.Settings` for the TLS paths, refuses to
start without them, then hands off to :func:`uvicorn.run` with
``ssl_cert_reqs=ssl.CERT_REQUIRED`` so uvicorn drops connections that
don't present a client cert at the TLS handshake. The
:mod:`wg_manager._tls_uvicorn` shim — imported transitively via
``wg_manager.main`` — backfills the ASGI-TLS extension so the
:class:`wg_manager.auth.MTLSAuthMiddleware` sees the cert subject.

The Makefile ``run`` target invokes this module so operators get the
same code path as CI. The previous direct-uvicorn invocation was
removed (the "plain-HTTP listener is removed" piece of the Phase 2d
CP2 goal): there is no longer a sanctioned wg-manager command that
serves plain HTTP.
"""

from __future__ import annotations

import ssl
import sys

import uvicorn

from wg_manager.config import settings


def main() -> int:
    """Validate TLS settings, start uvicorn with mTLS, return exit code."""
    missing = [
        name
        for name, value in (
            ("TLS_CERT_PEM", settings.tls_cert_pem),
            ("TLS_KEY_PEM", settings.tls_key_pem),
            ("TLS_CA_BUNDLE_PEM", settings.tls_ca_bundle_pem),
        )
        if not value
    ]
    if missing:
        print(
            "ERROR: the following TLS env vars must be set to run wg-manager: "
            + ", ".join(missing),
            file=sys.stderr,
        )
        print(
            "       Quickest dev path: make tls-issue-dev && "
            "see README 'Running with TLS'.",
            file=sys.stderr,
        )
        return 2

    # ``settings.tls_required`` is a separate setting from the uvicorn
    # SSL flags so a developer can run with TLS terminated but no
    # client-cert enforcement (rare, but useful when bringing up a
    # new operator). Production should set both to ``true``.
    uvicorn.run(
        "wg_manager.main:app",
        host=settings.bind_host,
        port=settings.bind_port,
        reload=True,
        ssl_certfile=settings.tls_cert_pem,
        ssl_keyfile=settings.tls_key_pem,
        ssl_ca_certs=settings.tls_ca_bundle_pem,
        ssl_cert_reqs=(
            ssl.CERT_REQUIRED if settings.tls_required else ssl.CERT_OPTIONAL
        ),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
