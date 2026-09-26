"""Phase 3f: enrollment-token primitives and business rules.

Holds everything about enrollment tokens that isn't HTTP-shaped, so
both routers stay thin:

* the operator-side mint / list / revoke router
  (:mod:`wg_manager.routers.enrollment_tokens`),
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

from sqlalchemy import ColumnElement, and_, update
from sqlmodel import Session, col, select

from wg_manager.models import EnrollmentToken, EnrollmentTokenStatus, Server, SSHKey

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


def find_token(session: Session, token: str) -> EnrollmentToken | None:
    """Look up the row for plaintext ``token`` by its hash.

    :param session: Active session.
    :param token: Plaintext token from the ``Authorization`` header.
    :return: The row, or ``None`` if no token hashes to it.
    """
    return session.exec(
        select(EnrollmentToken).where(EnrollmentToken.token_hash == hash_token(token))
    ).first()


def is_expired(row: EnrollmentToken, now: datetime | None = None) -> bool:
    """Return ``True`` once ``row`` is at or past its expiry.

    :param row: Token row.
    :param now: Override for tests; defaults to the current UTC time.
    """
    now = now or datetime.now(timezone.utc)
    return as_utc(row.expires_at) <= now


def token_status(
    row: EnrollmentToken, now: datetime | None = None
) -> EnrollmentTokenStatus:
    """Derive ``row``'s state; see :class:`EnrollmentTokenStatus` for precedence.

    :param row: Token row.
    :param now: Override for tests; defaults to the current UTC time.
    """
    if row.revoked_at is not None:
        return EnrollmentTokenStatus.revoked
    if is_expired(row, now):
        return EnrollmentTokenStatus.expired
    if row.use_count >= row.max_uses:
        return EnrollmentTokenStatus.exhausted
    return EnrollmentTokenStatus.active


def active_filter(now: datetime | None = None) -> ColumnElement[bool]:
    """SQL twin of ``token_status(row) is active``, for list queries.

    :param now: Override for tests; defaults to the current UTC time.
    """
    now = now or datetime.now(timezone.utc)
    return and_(
        col(EnrollmentToken.revoked_at).is_(None),
        # Compared naive: SQLite stores these naive (see as_utc).
        col(EnrollmentToken.expires_at) > now.replace(tzinfo=None),
        col(EnrollmentToken.use_count) < col(EnrollmentToken.max_uses),
    )


def revoke_token(
    session: Session, row: EnrollmentToken, *, revoked_by_cn: str | None
) -> bool:
    """Mark ``row`` revoked unless it already is.

    Doesn't commit: the router commits together with the audit row. A
    redemption already in flight is still stopped, because
    :func:`consume_token` re-checks ``revoked_at`` in its guarded
    ``UPDATE``.

    :param session: Active session.
    :param row: Token to revoke.
    :param revoked_by_cn: Revoking operator's CN, for provenance.
    :return: ``True`` if this call revoked it; ``False`` if it was
        already revoked (the row is left untouched, so repeat calls are
        idempotent).
    """
    if row.revoked_at is not None:
        return False
    row.revoked_at = datetime.now(timezone.utc)
    row.revoked_by_cn = revoked_by_cn
    session.add(row)
    session.flush()
    return True


def consume_token(session: Session, row: EnrollmentToken) -> bool:
    """Atomically take one use of ``row``; return ``False`` if none are left.

    Runs a single guarded ``UPDATE … SET use_count = use_count + 1
    WHERE id = :id AND use_count < max_uses AND revoked_at IS NULL``
    and checks the rowcount.
    That makes the check and the increment one statement, so two
    concurrent redemptions of a single-use token can't both succeed on
    any backend, and a revoke committed after the caller loaded ``row``
    still wins. The update joins the caller's transaction and is
    undone if the caller rolls back, which is how a failed enrollment
    gives its use back.

    :param session: Active session (transaction owned by the caller).
    :param row: The token row found by :func:`find_token`.
    :return: ``True`` if a use was taken.
    """
    result = session.exec(  # type: ignore[call-overload]
        update(EnrollmentToken)
        .where(EnrollmentToken.id == row.id)
        .where(EnrollmentToken.use_count < EnrollmentToken.max_uses)
        .where(col(EnrollmentToken.revoked_at).is_(None))
        .values(use_count=EnrollmentToken.use_count + 1)
    )
    return bool(result.rowcount == 1)
