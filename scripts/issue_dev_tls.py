#!/usr/bin/env python
"""Mint local-dev TLS server + client certs for ``make run`` (Phase 2d CP2).

This is a throwaway helper. It uses :class:`wg_manager.pki.LocalDevPKI`
to write five PEM files under ``tls/``:

* ``tls/server.crt`` — the API listener's server cert (serverAuth EKU,
  SAN ``127.0.0.1`` + ``localhost``). Pair with ``tls/server.key`` and
  pass to uvicorn via ``--ssl-certfile`` / ``--ssl-keyfile``.
* ``tls/server.key`` — server private key.
* ``tls/ca-bundle.crt`` — the CA bundle uvicorn trusts when verifying
  the *client* cert (i.e. the operator). Same bundle the curl below
  passes to ``--cacert``.
* ``tls/client.crt`` — an operator-style client cert (clientAuth EKU,
  CN ``dev-operator``). Curl with ``--cert tls/client.crt``.
* ``tls/client.key`` — client private key. Curl with ``--key``.

Re-run any time — the directory is wiped first so a partial previous
run can't leave a stale cert paired with a fresh key.

Usage::

    make tls-issue-dev
    export TLS_REQUIRED=true \\
           TLS_CERT_PEM=tls/server.crt \\
           TLS_KEY_PEM=tls/server.key \\
           TLS_CA_BUNDLE_PEM=tls/ca-bundle.crt
    make run

Smoke::

    curl --cacert tls/ca-bundle.crt --cert tls/client.crt --key tls/client.key \\
         https://127.0.0.1:8000/crypto/status
    # Without the client cert, the TLS handshake fails (uvicorn
    # enforces --ssl-cert-reqs 2).

**Delete this script** once Phase 2d CP3 ships the production
``wg-manager certs issue --type {api,cli}`` CLI — the production path
will mint certs against Vault PKI, not the in-process LocalDevPKI.
"""

from __future__ import annotations

import sys
from pathlib import Path

from wg_manager.pki import LocalDevPKI

_TLS_DIR = Path(__file__).resolve().parent.parent / "tls"

# 30 days — long enough that a developer's running dev server doesn't
# expire mid-session, short enough that an accidentally-committed cert
# isn't a long-lived footgun. The CP3 production CLI will default
# shorter.
_DEV_TTL_SECONDS = 30 * 24 * 60 * 60

# SANs the dev server cert advertises so a curl against either
# `127.0.0.1` or `localhost` passes hostname verification. The
# bare-domain `localhost` is the historical macOS / Linux loopback
# alias; the IP form is what the FastAPI default binds to.
_SERVER_SANS = ["127.0.0.1", "localhost"]
_SERVER_CN = "127.0.0.1"
_CLIENT_CN = "dev-operator"
_CLIENT_SANS = ["dev-operator"]


def _write(path: Path, body: str, *, mode: int = 0o600) -> None:
    """Write ``body`` to ``path`` with the given permission mode."""
    path.write_text(body)
    path.chmod(mode)


def main() -> int:
    """Mint the five PEMs and write them under ``tls/``."""
    _TLS_DIR.mkdir(parents=True, exist_ok=True)
    for existing in _TLS_DIR.glob("*"):
        if existing.is_file():
            existing.unlink()

    ca = LocalDevPKI.generate()
    server = ca.issue_server_cert(
        common_name=_SERVER_CN,
        sans=_SERVER_SANS,
        ttl_seconds=_DEV_TTL_SECONDS,
    )
    client = ca.issue_client_cert(
        common_name=_CLIENT_CN,
        sans=_CLIENT_SANS,
        ttl_seconds=_DEV_TTL_SECONDS,
    )

    _write(_TLS_DIR / "ca-bundle.crt", ca.ca_bundle_pem, mode=0o644)
    _write(_TLS_DIR / "server.crt", server.cert_pem, mode=0o644)
    _write(_TLS_DIR / "server.key", server.private_pem, mode=0o600)
    _write(_TLS_DIR / "client.crt", client.cert_pem, mode=0o644)
    _write(_TLS_DIR / "client.key", client.private_pem, mode=0o600)

    print(f"[OK] dev TLS material written to {_TLS_DIR}")
    print(f"     server CN={_SERVER_CN}, SANs={_SERVER_SANS}")
    print(f"     client CN={_CLIENT_CN} (serial={client.serial})")
    print(f"     valid through {server.not_after.isoformat()}")
    print()
    print("Next:")
    print("  export TLS_REQUIRED=true \\")
    print("         TLS_CERT_PEM=tls/server.crt \\")
    print("         TLS_KEY_PEM=tls/server.key \\")
    print("         TLS_CA_BUNDLE_PEM=tls/ca-bundle.crt")
    print("  make run")
    return 0


if __name__ == "__main__":
    sys.exit(main())
