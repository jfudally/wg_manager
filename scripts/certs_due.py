#!/usr/bin/env python3
"""Report whether any prod TLS leaf is due for rotation.

Run by ``scripts/certs_rotate_if_due.sh`` (``make certs-rotate-if-due``)
inside a ``bootstrap-app`` container, which has ``cryptography`` and the
``./tls`` + ``./scripts`` bind-mounts. It reads PEM files only: no DB,
no Vault, so it works even when the certs it's checking have already
broken the MySQL connection.

A leaf is *due* once ``--threshold-pct`` of its lifetime has elapsed
(same convention as ``wg-manager certs renew --due``). CA certs in a
file are ignored: ``make certs-rotate`` re-mints leaves, not the CA,
so an ageing CA would otherwise trigger a rotate-and-restart on every
run.

By default only the leaves ``make certs-rotate`` rewrites are checked
(:data:`DEFAULT_LEAVES`, relative to ``--tls-dir``); checking anything
else could loop forever (due → rotate → still due).

Exit codes (the wrapper's contract):

* :data:`EXIT_OK` (0) — nothing due
* :data:`EXIT_DUE` (10) — at least one leaf due; chosen to stay clear
  of docker / compose's own failure codes (1, 125–127)
* :data:`EXIT_ERROR` (2) — the check couldn't run (missing or
  unparseable file, file with no leaf cert)
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509

EXIT_OK = 0
EXIT_ERROR = 2
EXIT_DUE = 10

#: Leaves rewritten by ``scripts/prod_rotate_certs.sh``, relative to the
#: TLS dir. MySQL ones come from ``bootstrap_mysql_tls_files.py``.
DEFAULT_LEAVES = (
    "mysql/server.crt",
    "mysql/client.crt",
    "server.crt",
    "client.crt",
)

log = logging.getLogger("certs_due")


def _is_ca(cert: x509.Certificate) -> bool:
    """Return ``True`` when ``cert`` carries ``BasicConstraints: CA:TRUE``."""
    try:
        ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        return bool(ext.value.ca)
    except x509.ExtensionNotFound:
        return False


def elapsed_pct(cert: x509.Certificate, now: datetime) -> float:
    """Percentage of ``cert``'s validity window that has elapsed at ``now``.

    Can exceed 100 for an expired cert. A zero-length window is treated
    as fully elapsed so a malformed cert is reported rather than ignored.
    """
    start = cert.not_valid_before_utc
    window = (cert.not_valid_after_utc - start).total_seconds()
    if window <= 0:
        return 100.0
    return (now - start).total_seconds() / window * 100


def check_file(path: Path, threshold_pct: float, now: datetime) -> bool:
    """Return ``True`` if any leaf cert in ``path`` is past ``threshold_pct``.

    :raises OSError: ``path`` can't be read.
    :raises ValueError: ``path`` has no parseable PEM cert, or no leaf.
    """
    certs = x509.load_pem_x509_certificates(path.read_bytes())
    leaves = [c for c in certs if not _is_ca(c)]
    if not leaves:
        raise ValueError("no leaf certificate in file (only CA certs)")
    due = False
    for cert in leaves:
        pct = elapsed_pct(cert, now)
        is_due = pct >= threshold_pct
        due = due or is_due
        log.log(
            logging.WARNING if is_due else logging.INFO,
            "%s %s: %.0f%% of lifetime elapsed, expires %s",
            "DUE" if is_due else "ok ",
            path,
            pct,
            cert.not_valid_after_utc.isoformat(),
        )
    return due


def main(argv: list[str] | None = None) -> int:
    """Check the given (or default) cert files; return an ``EXIT_*`` code."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "files",
        nargs="*",
        type=Path,
        help="PEM files (default: the certs-rotate leaves)",
    )
    parser.add_argument("--tls-dir", type=Path, default=Path("/app/tls"))
    parser.add_argument("--threshold-pct", type=float, default=50.0)
    args = parser.parse_args(argv)

    files = args.files or [args.tls_dir / rel for rel in DEFAULT_LEAVES]
    now = datetime.now(timezone.utc)
    any_due = False
    for path in files:
        try:
            any_due = check_file(path, args.threshold_pct, now) or any_due
        except (OSError, ValueError) as exc:
            # Fail loud: an unreadable cert is exactly when an operator
            # needs to look, and rotating blind might not fix it.
            log.error("cannot check %s: %s", path, exc)
            return EXIT_ERROR
    return EXIT_DUE if any_due else EXIT_OK


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    sys.exit(main())
