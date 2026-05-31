"""SQLModel tables for wg-manager."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import BigInteger, Column, UniqueConstraint
from sqlalchemy import Text  # re-exported for the manual-client column below
from sqlmodel import Field, SQLModel


class NodeStatus(str, Enum):
    """Lifecycle state of a provisioned node.

    :cvar pending: Row created but provisioning has not yet completed.
    :cvar ready: Node is fully provisioned and in service.
    :cvar error: Provisioning failed; see API error payload for details.
    """

    pending = "pending"
    ready = "ready"
    error = "error"


class OperatorRole(str, Enum):
    """Coarse-grained role attached to an :class:`Operator`.

    Phase 2d CP3 introduces the registry so :class:`wg_manager.auth.MTLSAuthMiddleware`
    can reject *valid* Vault-signed client certs whose CN isn't on the
    allow-list. The role is captured at registration time and surfaced
    to handlers via ``require_subject`` so the API can gate mutating
    routes behind ``admin``, read-only routes behind ``auditor``, etc.
    The first slice ships the column only — the actual authz gates
    land in a follow-up sub-slice.

    :cvar admin: Can register/disable other operators, issue + revoke
        any certificate, and run every mutating endpoint.
    :cvar operator: Day-to-day: register peers, run discovery, issue
        and revoke their *own* certificates. Cannot manage the
        operator registry itself.
    :cvar auditor: Read-only. Can list rows, view audit logs, and
        inspect cert metadata; refused on every mutation.

    Subclassing ``str`` keeps the enum JSON-serialisable as its value
    (``"admin"`` / ``"operator"`` / ``"auditor"``) — the schema layer
    relies on that so dashboards and CLI clients see plain string
    literals.
    """

    admin = "admin"
    operator = "operator"
    auditor = "auditor"


class CertificateType(str, Enum):
    """Logical purpose of an issued X.509 leaf cert.

    Phase 2d CP3.3 introduces the :class:`Certificate` registry so the
    operator can answer "which certs are currently live, who do they
    belong to, when do they expire, has any of them been revoked?"
    without grepping Vault. The cert type drives both the EKU the PKI
    backend applies at issue time (server- vs. client-auth) and which
    SAN defaults / TTL the CLI suggests.

    :cvar api: ``serverAuth`` — terminates the FastAPI mTLS listener
        (paired with the uvicorn ``--ssl-certfile`` flag). SANs are
        the listener's hostnames + bind IPs; not owned by an
        :class:`Operator`.
    :cvar cli: ``clientAuth`` — an operator presents this when calling
        the API from the wg-manager CLI (curl / httpx with
        ``--cert``). Owned by an :class:`Operator`; CN is the operator
        CN the registry keys on.
    :cvar dashboard: ``clientAuth`` — same shape as :attr:`cli` but
        exported as a PKCS#12 archive for browser import (Chrome /
        Firefox / Safari all consume the PKCS#12 form natively).
        Owned by an :class:`Operator`.
    :cvar mysql: ``serverAuth`` — MySQL server cert (Phase 2d CP4).
        SANs are the DB hostnames the app + worker dial. Not owned by
        an :class:`Operator`.
    :cvar mysql_client: ``clientAuth`` — service cert the app + worker
        present back to MySQL once ``require_secure_transport=ON`` is
        enforced (Phase 2d CP4.2). The wire enum value is
        ``"mysql-client"`` so the JSON shape stays kebab-case and
        consistent with how operators write SAN lists. Not owned by an
        :class:`Operator` — these are service principals.

    Subclassing ``str`` keeps the enum JSON-serialisable as its value
    so dashboards and CLI clients see plain string literals.
    """

    api = "api"
    cli = "cli"
    dashboard = "dashboard"
    mysql = "mysql"
    mysql_client = "mysql-client"


class OperatorStatus(str, Enum):
    """Lifecycle of an :class:`Operator` row.

    Disabling is the supported way to revoke an operator's API access
    without losing the audit-log linkage that a hard delete would
    sever. The middleware (when the CP3 tightening lands) treats
    ``disabled`` as "401 even with a valid cert chain".

    :cvar active: The operator can authenticate against the API.
    :cvar disabled: Soft-deleted. The row remains so the audit log
        keeps linking past actions to the CN, but the middleware will
        refuse new requests.
    """

    active = "active"
    disabled = "disabled"


class SSHKeyMode(str, Enum):
    """How wg-manager authenticates to hosts that use a given :class:`SSHKey`.

    Phase 2c CP4.1 introduces this as a per-row switch so a fleet can
    migrate to the SSH CA host-by-host rather than via the global
    ``SSH_AUTH_MODE`` flag CP2 shipped.

    :cvar legacy: The row carries an encrypted private key in
        ``private_key_ct``; the task layer decrypts it and authenticates
        via the historical Phase 2b path. This is the default for any
        row inserted before CP4.1.
    :cvar ca: The row is a label only; no plaintext private material
        lives on it. Each connection mints a short-lived user cert from
        the SSH CA (see :mod:`wg_manager.ssh_ca`) and presents it to
        the host. CP4.2's ``wg-manager ssh migrate-to-ca`` is the
        supported way to flip a row from ``legacy`` to ``ca`` because
        the operation has to install CA trust on every server first.

    Subclassing ``str`` keeps the enum JSON-serialisable as its value
    (``"legacy"`` / ``"ca"``) — the schema layer in CP4.1c relies on
    that so dashboards and CLI clients see plain string literals.
    """

    legacy = "legacy"
    ca = "ca"


def _utcnow() -> datetime:
    """Return the current UTC timestamp.

    :return: An aware ``datetime`` in UTC.
    :rtype: datetime
    """
    return datetime.now(tz=timezone.utc)


class SSHKey(SQLModel, table=True):
    """Named SSH role used to provision nodes.

    Phase 2c closed with Alembic revision 0008 dropping the row's
    ciphertext columns. The row is now a *name-and-mode label*: the
    task layer mints a fresh user cert from the SSH CA at every
    connection (see :mod:`wg_manager.ssh_ca`) and never reads a
    persisted secret off the row. Operators register a row by name;
    the binding to actual key material lives in Vault's SSH CA
    configuration.

    :attr:`mode` is kept around (rather than dropped wholesale) so a
    future variant — e.g. a per-row Vault role override or a yet-to-
    arrive third backend — has somewhere to land without another
    Alembic revision. Every row created post-CP4.4 defaults to
    :attr:`SSHKeyMode.ca`.

    :ivar mode: Always ``ca`` in the post-CP4.4 schema. ``legacy``
        remains in the enum to preserve historical migration
        readability; any attempt to create a new row with
        ``mode='legacy'`` is rejected at the router layer.
    """

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    # Phase 2c CP4.4 — every row is CA-mode now. The default flipped
    # from ``legacy`` to ``ca`` once Alembic 0008 dropped the
    # ciphertext columns that legacy mode depended on.
    mode: SSHKeyMode = Field(default=SSHKeyMode.ca)
    created_at: datetime = Field(default_factory=_utcnow)

    def __repr__(self) -> str:
        return (
            f"SSHKey(id={self.id!r}, name={self.name!r}, "
            f"mode={self.mode!r}, created_at={self.created_at!r})"
        )

    __str__ = __repr__


class Server(SQLModel, table=True):
    """WireGuard hub node.

    Phase 2c CP3 grows six host-cert columns that hold the SSH CA's
    latest issuance for this server. None of them is required at row
    creation time — they stay NULL on registration and are populated
    only after provisioning installs the cert on the host. Callers
    creating a row by hand (the registration router, tests) do not
    need to set them, and the dashboard treats NULL values as "no host
    cert minted yet" so a Phase 2b row continues to render correctly.

    :ivar host_cert_pem: The full OpenSSH-formatted host certificate
        wg-manager handed to the host, as last installed. Stored
        verbatim so the audit log / dashboard can render the exact
        bytes that were issued.
    :ivar host_cert_serial: Serial the CA recorded for the latest
        host cert. Operators use this to correlate a dashboard row
        with Vault's audit log when a rotation is in flight.
    :ivar host_cert_principals: Comma-separated principals embedded
        in the cert (typically the hostname + any aliases). Comma list
        rather than JSON to keep the SQLite/MySQL schemas identical
        and to match the pattern :attr:`Server.address` already uses.
    :ivar host_cert_valid_after: When the cert became valid (per the
        cert body, not when wg-manager installed it). Equal to
        :attr:`host_cert_valid_before` minus the TTL.
    :ivar host_cert_valid_before: Cert expiry. The dashboard turns
        this into a "rotate now" badge once it crosses 50% of the TTL
        window. Operators can re-mint at any time via
        ``POST /servers/{id}/rotate-host-cert``.
    :ivar host_cert_ca_public_key: The CA public key (OpenSSH single
        line) that signed the cert, captured at signing time. A
        deliberate redundancy: if the operator rotates the SSH CA in
        Vault, this column lets the dashboard surface the rows whose
        host certs are still pinned to the old CA and need re-minting.
    """

    id: int | None = Field(default=None, primary_key=True)
    hostname: str
    ssh_port: int = 22
    ssh_username: str
    ssh_key_id: int = Field(foreign_key="sshkey.id")
    endpoint_host: str
    endpoint_port: int = 51820
    interface: str = "wg0"
    subnet: str = "10.9.0.0/24"
    address: str = "10.9.0.1/24"
    public_key: str = ""
    status: NodeStatus = Field(default=NodeStatus.pending)
    created_at: datetime = Field(default_factory=_utcnow)
    # Phase 2c CP3 — host cert snapshot. See class docstring.
    host_cert_pem: str | None = Field(
        default=None, sa_column=Column(Text, nullable=True)
    )
    # ``secrets.randbits(63)`` (used by both LocalDevSSHCA and the OpenSSH
    # serial field) regularly exceeds the 32-bit ``Integer`` range MySQL
    # would otherwise infer. Pin BigInteger so the column survives
    # serials > 2³¹-1 on MySQL as well as SQLite (which doesn't care).
    host_cert_serial: int | None = Field(
        default=None, sa_column=Column(BigInteger, nullable=True)
    )
    host_cert_principals: str | None = Field(default=None)
    host_cert_valid_after: datetime | None = Field(default=None)
    host_cert_valid_before: datetime | None = Field(default=None)
    host_cert_ca_public_key: str | None = Field(
        default=None, sa_column=Column(Text, nullable=True)
    )


class Client(SQLModel, table=True):
    """WireGuard spoke node attached to a :class:`Server`.

    Clients come in two flavours that share the same row layout:

    * **SSH-provisioned (default).** wg-manager dials the device over SSH
      to install WireGuard and write its config. ``hostname``,
      ``ssh_username`` and ``ssh_key_id`` are required; the device-side
      keypair is generated on the device and only the public key flows
      back into the row. ``is_manual`` is ``False``.

    * **Manual.** For devices wg-manager cannot reach over SSH (phones,
      IoT, locked-down embedded boxes). The keypair is generated
      server-side; the wg0.conf body (with the private key inline) is
      returned to the operator **exactly once** on the
      ``POST /clients/manual`` response and the private key is then
      dropped — the row carries only the public key. The SSH
      connection fields are unused and may be ``NULL``.
      ``is_manual`` is ``True``.

    Both kinds count against the same IPAM pool — see
    :func:`wg_manager.ipam.allocate_client_ip`.

    The ``private_key_ct`` column that held the encrypt-at-rest
    ciphertext of the manual-client private key was dropped in Alembic
    0009: wg-manager has no operational use for a manual device's
    private key once the operator has captured the config (we can't
    log into the device), so persisting it was pure liability.

    :ivar is_manual: ``True`` when the row was created via the manual
        registration flow. Manual rows skip provisioning and instead
        ship their config to the operator for hand-install.
    """

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    hostname: str | None = None
    ssh_port: int = 22
    ssh_username: str | None = None
    ssh_key_id: int | None = Field(default=None, foreign_key="sshkey.id")
    server_id: int = Field(foreign_key="server.id")
    address: str = ""
    public_key: str = ""
    is_manual: bool = Field(default=False)
    status: NodeStatus = Field(default=NodeStatus.pending)
    created_at: datetime = Field(default_factory=_utcnow)

    def __repr__(self) -> str:
        return (
            f"Client(id={self.id!r}, name={self.name!r}, "
            f"hostname={self.hostname!r}, server_id={self.server_id!r}, "
            f"address={self.address!r}, public_key={self.public_key!r}, "
            f"is_manual={self.is_manual!r}, status={self.status!r}, "
            f"created_at={self.created_at!r})"
        )

    __str__ = __repr__


class Operator(SQLModel, table=True):
    """Registered API caller, keyed by the CN on their client certificate.

    Phase 2d CP2 made mTLS mandatory but accepted any cert that
    validated against the configured CA bundle — a gap explicitly
    flagged in ``SECURITY.md`` (threat T-7, partial close). CP3 closes
    that gap: only CNs that appear in this table as ``status='active'``
    are admitted by :class:`wg_manager.auth.MTLSAuthMiddleware`. The
    role attached to the row gates downstream authorization
    (mutations vs. reads vs. registry management).

    The first slice ships the table only — the middleware tightening
    and ``Certificate`` registry land in subsequent CP3 sub-slices so
    each step is reviewable in isolation.

    :ivar cn: The Common Name lifted from the client cert's Subject.
        Unique and indexed; stored verbatim (case-sensitive — the DB
        default — to match how cert subjects are usually keyed).
    :ivar display_name: Optional human-readable label for the
        dashboard. The CN is the canonical identifier; this field
        exists so operators don't have to read ``ops@wg.local`` when
        they meant "Ops Team".
    :ivar role: Coarse permission tier. Defaults to
        :attr:`OperatorRole.operator` (principle of least privilege —
        admins must be set explicitly).
    :ivar status: Lifecycle state. Defaults to
        :attr:`OperatorStatus.active`; disabling a row revokes API
        access without breaking audit-log linkage.
    """

    id: int | None = Field(default=None, primary_key=True)
    cn: str = Field(index=True, unique=True)
    display_name: str | None = Field(default=None)
    role: OperatorRole = Field(default=OperatorRole.operator)
    status: OperatorStatus = Field(default=OperatorStatus.active)
    created_at: datetime = Field(default_factory=_utcnow)

    def __repr__(self) -> str:
        return (
            f"Operator(id={self.id!r}, cn={self.cn!r}, "
            f"display_name={self.display_name!r}, role={self.role!r}, "
            f"status={self.status!r}, created_at={self.created_at!r})"
        )

    __str__ = __repr__


class DiscoveredPeer(SQLModel, table=True):
    """A WireGuard peer observed on a :class:`Server` via ``wg show <iface> dump``.

    Discovered peers are populated by the discovery task — wg-manager learns
    about them by reading the server's runtime peer list, **not** by managing
    them directly. They carry no SSH credentials and cannot be re-provisioned.
    A discovered peer whose ``public_key`` matches a managed :class:`Client`
    on the same server is flagged with ``is_managed=True`` so the operator
    can tell at a glance which observed peers are also under wg-manager
    control.

    Uniqueness is enforced on ``(server_id, public_key)`` so re-running
    discovery upserts existing rows instead of duplicating them.
    """

    __table_args__ = (
        UniqueConstraint("server_id", "public_key", name="uq_discoveredpeer_server_pubkey"),
    )

    id: int | None = Field(default=None, primary_key=True)
    server_id: int = Field(foreign_key="server.id", index=True)
    public_key: str = Field(index=True)
    allowed_ips: str = ""
    endpoint: str | None = None
    last_handshake_at: datetime | None = None
    rx_bytes: int = 0
    tx_bytes: int = 0
    persistent_keepalive: int | None = None
    is_managed: bool = False
    first_seen_at: datetime = Field(default_factory=_utcnow)
    last_seen_at: datetime = Field(default_factory=_utcnow)


class Certificate(SQLModel, table=True):
    """Audit record for every leaf cert wg-manager has issued.

    Phase 2d CP3.3 introduces the registry so an operator can answer
    "which certs are live, who do they belong to, when do they expire,
    which have been revoked?" without grepping Vault. CP3.4 layers the
    ``/certs`` HTTP surface + dashboard page on top; CP4 layers the
    renewal job. CP3.3 ships the *write* side (``wg-manager certs
    issue/revoke``) and the table; the *read* side is the
    ``wg-manager certs list`` printout for now.

    Operator linkage is **nullable**: ``cli`` / ``dashboard`` certs are
    owned by a specific :class:`Operator` (the CN matches and the row
    points at it), but ``api`` / ``mysql`` server certs are service
    certs with no human owner — the FK stays ``NULL`` for those.

    The row does **not** store the cert PEM or the private key. The
    PEM lives on the disk path the operator wrote it to at issue time
    (or in Vault, depending on the backend); the private key is
    surfaced once at issue time and never persisted server-side. This
    keeps the registry small, makes the table safe to ship in backups,
    and means a leaked SQLite dump doesn't compromise any cert
    material — only metadata.

    Revocation lifecycle is **two-step**: ``revoke_cert`` on the
    backend (Vault PKI CRL) and a row flip on this table. A row with
    ``revoked=True`` is the audit trail; the CRL pull is what causes a
    presenting peer to be rejected at handshake time. Keeping the row
    after revocation (rather than hard-deleting) is what lets the
    audit log say "operator X revoked serial Y on date Z".

    :ivar serial: Issuer-assigned serial, stored as the decimal-string
        rendering of the X.509 integer. Unique across the lifetime of
        the table — Vault won't re-issue a colliding serial, and the
        local-dev backend uses
        ``cryptography.x509.random_serial_number`` (160 bits) so a
        collision is statistically impossible. We pin a string column
        (rather than ``BigInteger``) because cryptography's 160-bit
        serial overflows SQLite's signed-INT64 and Vault's serials
        regularly exceed it too; the int round-trips losslessly via
        :func:`int` at the CLI boundary.
    :ivar cert_type: One of :class:`CertificateType`. Drives the EKU
        the PKI applies + the default SAN/TTL the CLI suggests.
    :ivar operator_id: FK to :class:`Operator` for ``cli`` /
        ``dashboard`` certs; ``NULL`` for ``api`` / ``mysql``.
    :ivar common_name: CN baked into the cert subject. Kept here so
        ``wg-manager certs list`` doesn't have to re-parse the cert
        PEM.
    :ivar sans: Comma-separated SAN list. Matches the storage style
        :class:`Server.address` already uses to keep the
        SQLite/MySQL/PostgreSQL schemas identical.
    :ivar not_before: Validity-window start (UTC, tz-aware).
    :ivar not_after: Validity-window end (UTC, tz-aware). CP4's
        renewal job sleeps until ``not_after - jitter``.
    :ivar revoked: Audit flag flipped by ``wg-manager certs revoke``.
        Always set in the same transaction as the backend
        :meth:`PKIBackend.revoke_cert` call so the row and the CRL
        agree.
    :ivar revoked_at: When the operator flipped :attr:`revoked`.
        ``NULL`` for live certs.
    :ivar created_at: When the row was inserted (which is when the
        cert was issued).
    """

    id: int | None = Field(default=None, primary_key=True)
    serial: str = Field(unique=True, index=True, max_length=64)
    cert_type: CertificateType = Field(index=True)
    operator_id: int | None = Field(
        default=None, foreign_key="operator.id", index=True
    )
    common_name: str = Field(index=True)
    sans: str = Field(default="")
    not_before: datetime
    not_after: datetime
    revoked: bool = Field(default=False, index=True)
    revoked_at: datetime | None = Field(default=None)
    created_at: datetime = Field(default_factory=_utcnow)

    def __repr__(self) -> str:
        return (
            f"Certificate(id={self.id!r}, serial={self.serial!r}, "
            f"cert_type={self.cert_type!r}, "
            f"operator_id={self.operator_id!r}, "
            f"common_name={self.common_name!r}, "
            f"not_after={self.not_after!r}, revoked={self.revoked!r})"
        )

    __str__ = __repr__
