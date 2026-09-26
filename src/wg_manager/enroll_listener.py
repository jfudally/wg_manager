"""Phase 3f: ``python -m wg_manager.enroll_listener`` runs the enrollment port.

This is the second HTTPS listener, alongside the mTLS operator API
started by ``python -m wg_manager``. It serves
:func:`wg_manager.enroll_app.create_enroll_app` using server-auth TLS
only (:func:`wg_manager.tls_listeners.enroll_ssl_kwargs`). That lets a
freshly launched host, which has no client cert yet, reach
``POST /v1/enroll`` from outside the VPN.

It uses the operator API's server cert and key (``TLS_CERT_PEM`` /
``TLS_KEY_PEM``), so hosts pin the same identity on both ports. It
binds ``ENROLL_BIND_HOST:ENROLL_BIND_PORT`` (default
``127.0.0.1:8001``). Exposing it publicly is a deployment decision
made in compose or the firewall, not here.

It won't start without the server cert and key. There is no
plain-HTTP enrollment mode, because the token in the request body
must never cross the wire unencrypted.
"""

from __future__ import annotations

import logging
import sys

import uvicorn

from wg_manager.config import Settings
from wg_manager.tls_listeners import enroll_ssl_kwargs

logger = logging.getLogger(__name__)


def main(settings: Settings | None = None) -> int:
    """Validate TLS settings and run the enrollment listener.

    :param settings: Settings override for tests; ``None`` reads the
        environment.
    :return: ``0`` after uvicorn exits cleanly, ``2`` when the server
        cert or key is missing.
    """
    settings = settings or Settings()
    missing = [
        name
        for name, value in (
            ("TLS_CERT_PEM", settings.tls_cert_pem),
            ("TLS_KEY_PEM", settings.tls_key_pem),
        )
        if not value
    ]
    if missing:
        logger.error(
            "enrollment listener needs a server cert; unset: %s",
            ", ".join(missing),
        )
        return 2

    uvicorn.run(
        "wg_manager.enroll_app:create_enroll_app",
        factory=True,
        host=settings.enroll_bind_host,
        port=settings.enroll_bind_port,
        **enroll_ssl_kwargs(settings),
    )
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sys.exit(main())
