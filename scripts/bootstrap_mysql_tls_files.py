"""One-shot bootstrap that mints MySQL server + client TLS material.

The documented Phase 2d CP4.2 procedure
(``docs/migrations/2d-mysql-tls.md``) assumes the operator has a
working DB connection at the time they run ``make mysql-tls-issue`` +
``wg-manager certs issue --type mysql-client``. That fails on a
deployment where ``require_secure_transport=ON`` was turned on before
the certs were minted — the chicken-and-egg the CLI flows can't
break alone.

This script breaks the cycle by going **straight to the PKI backend**
and writing the four PEM files the bind-mounts read on next compose
restart. It does **not** record audit rows in the ``certificate``
table — that's deliberate. Once the DB is reachable again (post-
bootstrap), an operator can re-mint the same identities through the
normal ``wg-manager certs issue`` path to land the audit rows;
this script's job is to get the operator unstuck, not to be the
canonical issuance path.

Run from the repo root:

    uv run python scripts/bootstrap_mysql_tls_files.py

Outputs (overwrites if present):

* ``tls/mysql/server.crt`` / ``server.key`` — mysqld leaf + key
* ``tls/mysql/ca.crt`` — CA bundle mysqld advertises to clients
* ``tls/mysql/client.crt`` / ``client.key`` — app/worker client cert
* ``tls/mysql/client-ca.crt`` — same CA bundle, named to match the
  ``DATABASE_TLS_CA_PEM`` env var the doc points operators at

Server cert covers the SANs the compose service is reachable at
(``localhost``, ``127.0.0.1``, ``mysql``, ``wg_manager_mysql``) so
both an in-container call and a host-side smoke (``mysql -h 127.0.0.1
-P 3307 ...``) verify cleanly.
"""

from __future__ import annotations

import sys
from pathlib import Path

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)

from wg_manager.pki import make_pki_backend

_REPO_ROOT = Path(__file__).resolve().parent.parent
_TLS_DIR = _REPO_ROOT / "tls" / "mysql"

_SERVER_CN = "localhost"
_SERVER_SANS = ["localhost", "127.0.0.1", "mysql", "wg_manager_mysql"]
_CLIENT_CN = "wg-manager-app"
_CLIENT_SANS = ["wg-manager-app"]
_TTL_SECONDS = 30 * 24 * 60 * 60  # 30 days; matches the CLI default


def _to_pkcs8_pem(pem: str) -> str:
    """Return ``pem`` re-encoded as an unencrypted PKCS#8 PEM.

    Vault's PKI backend returns EC private keys wrapped in SEC1
    (``-----BEGIN EC PRIVATE KEY-----``), which MySQL 8.4 rejects at
    TLS init with ``[ERROR] [MY-000059] [Server] SSL error: Unable
    to get private key from '/etc/mysql/certs/server.key'``. Every
    modern OpenSSL build accepts PKCS#8 (``-----BEGIN PRIVATE KEY-----``),
    so we normalise on the way out.

    Idempotent — a PEM that's already PKCS#8 round-trips as PKCS#8.
    RSA / EC / Ed25519 inputs are all handled by
    :func:`cryptography.hazmat.primitives.serialization.load_pem_private_key`.
    """
    key = load_pem_private_key(pem.encode(), password=None)
    return key.private_bytes(
        Encoding.PEM,
        PrivateFormat.PKCS8,
        NoEncryption(),
    ).decode()


def _write(path: Path, contents: str, *, mode: int = 0o644) -> None:
    path.write_text(contents)
    path.chmod(mode)
    print(f"  wrote {path.relative_to(_REPO_ROOT)} ({mode:#o})")


def main() -> int:
    _TLS_DIR.mkdir(parents=True, exist_ok=True)
    backend = make_pki_backend()

    print(f"PKI backend: {type(backend).__name__}")

    print("Minting MySQL server cert ...")
    server = backend.issue_server_cert(
        common_name=_SERVER_CN,
        sans=_SERVER_SANS,
        ttl_seconds=_TTL_SECONDS,
    )
    _write(_TLS_DIR / "server.crt", server.cert_pem)
    _write(_TLS_DIR / "server.key", _to_pkcs8_pem(server.private_pem), mode=0o600)
    _write(_TLS_DIR / "ca.crt", server.chain_pem)

    print("Minting MySQL client cert ...")
    client = backend.issue_client_cert(
        common_name=_CLIENT_CN,
        sans=_CLIENT_SANS,
        ttl_seconds=_TTL_SECONDS,
    )
    _write(_TLS_DIR / "client.crt", client.cert_pem)
    _write(_TLS_DIR / "client.key", _to_pkcs8_pem(client.private_pem), mode=0o600)
    _write(_TLS_DIR / "client-ca.crt", client.chain_pem)

    print()
    print("done. next steps:")
    print("  docker compose restart mysql")
    print("  export DATABASE_TLS_REQUIRED=true")
    print("  export DATABASE_TLS_CA_PEM=tls/mysql/client-ca.crt")
    print("  export DATABASE_TLS_CERT_PEM=tls/mysql/client.crt")
    print("  export DATABASE_TLS_KEY_PEM=tls/mysql/client.key")
    print("  make migrate")
    return 0


if __name__ == "__main__":
    sys.exit(main())
