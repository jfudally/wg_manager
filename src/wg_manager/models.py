"""SQLModel tables for wg-manager."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import Column, Text, UniqueConstraint
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


def _utcnow() -> datetime:
    """Return the current UTC timestamp.

    :return: An aware ``datetime`` in UTC.
    :rtype: datetime
    """
    return datetime.now(tz=timezone.utc)


class SSHKey(SQLModel, table=True):
    """Stored SSH credential used to provision nodes.

    Phase 2b closed with Alembic revision 0005 dropping the legacy
    plaintext columns; every secret on this row now lives only in the
    ``_ct`` ciphertext columns and is wrapped via
    :mod:`wg_manager.crypto`. Callers obtain the decrypted material
    through :func:`wg_manager.crypto.resolve_sshkey_private` and
    :func:`wg_manager.crypto.resolve_sshkey_passphrase`; the row itself
    no longer carries any plaintext attribute.
    """

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    private_key_ct: str | None = Field(
        default=None,
        sa_column=Column(Text, nullable=True),
    )
    passphrase_ct: str | None = None
    created_at: datetime = Field(default_factory=_utcnow)

    def __repr__(self) -> str:
        return (
            f"SSHKey(id={self.id!r}, name={self.name!r}, "
            # ``_ct`` columns are encrypted blobs and safe to log, but we
            # still render them as "<set>" / "None" because the raw blob
            # bodies are 200+ bytes of base64 noise that crowds out useful
            # debug info. Whether the column is populated is the bit
            # operators actually want to see at a glance.
            f"private_key_ct={'<set>' if self.private_key_ct else None}, "
            f"passphrase_ct={'<set>' if self.passphrase_ct else None}, "
            f"created_at={self.created_at!r})"
        )

    __str__ = __repr__


class Server(SQLModel, table=True):
    """WireGuard hub node."""

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
