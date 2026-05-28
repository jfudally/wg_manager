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
      server-side and stored on the row so the operator can re-export
      the rendered ``wg0.conf`` (see ``GET /clients/{id}/config``). The
      SSH connection fields are unused and may be ``NULL``.
      ``is_manual`` is ``True``.

    Both kinds count against the same IPAM pool — see
    :func:`wg_manager.ipam.allocate_client_ip`.

    :ivar is_manual: ``True`` when the row was created via the manual
        registration flow. Manual rows skip provisioning and instead
        ship their config to the operator for hand-install.
    :ivar private_key_ct: Ciphertext of the manual client's WireGuard
        private key (post-Phase-2b; the plaintext column was dropped
        in Alembic 0005). ``NULL`` for SSH-provisioned clients —
        their key never leaves the device.
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
    private_key_ct: str | None = Field(
        default=None,
        sa_column=Column(Text, nullable=True),
    )
    is_manual: bool = Field(default=False)
    status: NodeStatus = Field(default=NodeStatus.pending)
    created_at: datetime = Field(default_factory=_utcnow)

    def __repr__(self) -> str:
        return (
            f"Client(id={self.id!r}, name={self.name!r}, "
            f"hostname={self.hostname!r}, server_id={self.server_id!r}, "
            f"address={self.address!r}, public_key={self.public_key!r}, "
            f"private_key_ct={'<set>' if self.private_key_ct else None}, "
            f"is_manual={self.is_manual!r}, status={self.status!r}, "
            f"created_at={self.created_at!r})"
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
