"""Phase 3f: enrollment-token primitives and business rules.

Holds everything about enrollment tokens that isn't HTTP-shaped, so
both routers stay thin:

* the operator-side minting router (:mod:`wg_manager.routers.enrollment_tokens`),
* the host-side redemption route on the enrollment listener
  (:mod:`wg_manager.enroll_app`).

Tokens are ``wgmenr_`` + 32 random bytes (urlsafe base64). The prefix
makes a leaked token easy to recognise in logs and secret scanners.
Only :func:`hash_token` output is persisted.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from sqlmodel import Session

from wg_manager.models import EnrollmentToken, Server, SSHKey

TOKEN_PREFIX = "wgmenr_"


def generate_token() -> str:
    """Return a fresh plaintext enrollment token.

    :return: ``wgmenr_`` followed by 256 bits of urlsafe-base64 entropy.
    """
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Return the SHA-256 hex digest stored in place of ``token``.

    A plain (unsalted, unstretched) hash is appropriate here: the input
    is 256 bits of randomness, not a human password, so brute force
    isn't a concern and a deterministic hash is what makes it usable as
    the unique lookup key on redemption.

    :param token: Plaintext token.
    :return: 64-char lowercase hex digest.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def as_utc(value: datetime) -> datetime:
    """Normalise ``value`` to an aware UTC datetime.

    SQLite (tests, dev) returns ``DateTime`` columns naive even when an
    aware value was written. Comparing naive against aware raises, so
    every expiry comparison goes through this helper.

    :param value: A naive (assumed UTC) or aware datetime.
    :return: The same instant as an aware UTC datetime.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def mint_token(
    session: Session,
    *,
    server: Server,
    ssh_key: SSHKey,
    ssh_username: str,
    name_prefix: str,
    ttl_seconds: int,
    max_uses: int,
    created_by_cn: str | None,
) -> tuple[EnrollmentToken, str]:
    """Create an :class:`EnrollmentToken` row and return it with the plaintext.

    The caller has already validated and authorised the request; this
    only builds the row. It adds the row to ``session`` and flushes so
    the id is populated, but doesn't commit: the router commits
    together with the audit row.

    :param session: Active session.
    :param server: Hub the token enrolls hosts into. Its ``tenant_id``
        is copied onto the token.
    :param ssh_key: SSH role the worker will use for enrolled hosts.
    :param ssh_username: Remote account for the worker's user cert.
    :param name_prefix: Prefix for enrolled client names.
    :param ttl_seconds: Seconds until the token expires.
    :param max_uses: Number of hosts the token may enroll.
    :param created_by_cn: Minting operator's CN, for provenance.
    :return: ``(row, plaintext_token)``. The plaintext exists only in
        this return value; it's never stored.
    """
    token = generate_token()
    row = EnrollmentToken(
        tenant_id=server.tenant_id,
        server_id=int(server.id or 0),
        ssh_key_id=int(ssh_key.id or 0),
        ssh_username=ssh_username,
        name_prefix=name_prefix,
        token_hash=hash_token(token),
        max_uses=max_uses,
        use_count=0,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds),
        created_by_cn=created_by_cn,
    )
    session.add(row)
    session.flush()
    return row, token
