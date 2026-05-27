"""Request/response schemas (non-table pydantic models)."""

from __future__ import annotations

from datetime import datetime
from ipaddress import AddressValueError, IPv4Network, NetmaskValueError
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from wg_manager.models import NodeStatus, SSHKeyMode


# Smallest prefix length that still leaves usable host space for a server
# (``.1``) plus at least one client. ``IPv4Network("10.0.0.0/30").hosts()``
# yields exactly two addresses; ``/31`` and ``/32`` would yield zero or one
# and break IPAM downstream.
_MAX_SUBNET_PREFIX = 30


def _parse_strict_subnet(value: str) -> IPv4Network:
    """Validate ``value`` as a network-aligned IPv4 CIDR usable for WireGuard.

    Strict parsing rejects host-bit-set inputs like ``10.0.0.5/24`` so an
    operator typo can't silently coerce to ``10.0.0.0/24``. Prefix lengths
    tighter than ``/30`` are rejected because IPAM needs at least two host
    addresses.

    :param value: A CIDR string such as ``"10.42.0.0/24"``.
    :type value: str
    :return: The parsed network.
    :rtype: IPv4Network
    :raises ValueError: If ``value`` is not a network-aligned IPv4 CIDR
        with a prefix length of ``/30`` or larger.
    """
    try:
        network = IPv4Network(value, strict=True)
    except (AddressValueError, NetmaskValueError, ValueError) as exc:
        raise ValueError(f"invalid IPv4 subnet {value!r}: {exc}") from exc
    if network.prefixlen > _MAX_SUBNET_PREFIX:
        raise ValueError(
            f"subnet {value!r} is too narrow — need /{_MAX_SUBNET_PREFIX} or "
            "larger so the server and at least one client fit",
        )
    return network


# ---------------------------------------------------------------------------
# SSH keys
# ---------------------------------------------------------------------------


class SSHKeyCreate(BaseModel):
    """Payload for registering a new SSH key.

    The private key body must be base64-encoded so newlines and other control
    characters in the PEM body do not break JSON encoding on the client side.
    The SSH username is **not** part of the credential — it is supplied per
    target host when registering a server or client.
    """

    name: str
    private_key_b64: str
    passphrase: str | None = None


class SSHKeyUpdate(BaseModel):
    """Partial-update payload for ``PATCH /ssh-keys/{id}``.

    All fields are optional — omitted or null fields are left unchanged on
    the underlying row (we use ``exclude_unset=True, exclude_none=True``
    in the router, matching :class:`ServerUpdate` / :class:`ClientUpdate`).
    To *clear* a previously-set passphrase, delete and recreate the key
    rather than trying to send an empty string; the existing key body
    would still be encrypted under the old passphrase and become
    unusable.

    :ivar name: New display name. Must be unique across SSH keys; a
        collision with a different key's name produces 409.
    :ivar passphrase: New passphrase. Stored as-is — the operator is
        responsible for making sure it actually unlocks
        ``private_key_b64`` (if both are sent in the same request, they
        are both applied without cross-validation).
    :ivar private_key_b64: Replacement private key body, base64-encoded
        for transport safety. The decoded PEM overwrites the existing
        ``private_key`` column on the row. Invalid base64 produces 422.
    """

    name: str | None = None
    passphrase: str | None = None
    private_key_b64: str | None = None


class SSHKeyRead(BaseModel):
    """Public view of an SSH key — never exposes the private key body.

    ``encrypted`` is a derived view of the ciphertext column: ``True``
    when ``SSHKey.private_key_ct`` is populated. The dashboard uses
    this to render the per-row "encrypted" badge from Phase 2b
    checkpoint 3 without having to call ``/crypto/status`` for every
    row. Post-Alembic-0005 every row should report ``True`` in steady
    state; a ``False`` here flags a row that was inserted bypassing
    the encryption seam (direct INSERT, restored old backup).

    ``mode`` (Phase 2c CP4.1) is the row's per-key auth mode. A
    ``legacy`` row authenticates via the stored ciphertext key; a
    ``ca`` row mints a fresh user cert from the SSH CA at every
    connection. Drives the dashboard "SSH roles" badge and the
    rollout-progress view that ships in CP4.3.
    """

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    created_at: datetime
    encrypted: bool = False
    mode: SSHKeyMode = SSHKeyMode.legacy

    @model_validator(mode="before")
    @classmethod
    def _derive_encrypted(cls, value: Any) -> Any:
        # When fed an ORM row, derive ``encrypted`` from the ciphertext
        # column (which is not part of the public schema). Already-dict
        # inputs pass through untouched so the model is still
        # constructible from a plain JSON payload.
        if hasattr(value, "private_key_ct"):
            return {
                "id": value.id,
                "name": value.name,
                "created_at": value.created_at,
                "encrypted": value.private_key_ct is not None,
                # ``mode`` is populated on the ORM row by CP4.1's
                # migration (defaults to ``legacy``); surface it
                # verbatim so the dashboard reads the row's truth and
                # not an inferred value.
                "mode": value.mode,
            }
        return value


# ---------------------------------------------------------------------------
# Servers
# ---------------------------------------------------------------------------


class ServerCreate(BaseModel):
    """Payload for registering a new WireGuard server.

    :ivar subnet: Optional IPv4 CIDR that defines the WireGuard network.
        When omitted the API falls back to ``settings.default_subnet`` so
        existing callers see the legacy ``10.9.0.0/24`` default. Must be
        network-aligned (no host bits set) and have a prefix length of
        ``/30`` or larger so IPAM can hand out at least one client IP.
    """

    hostname: str
    ssh_port: int = 22
    ssh_username: str
    ssh_key_id: int
    endpoint_host: str
    endpoint_port: int = 51820
    interface: str = "wg0"
    subnet: str | None = None

    @field_validator("subnet")
    @classmethod
    def _validate_subnet(cls, value: str | None) -> str | None:
        """Reject malformed, host-bits-set or too-narrow subnet values."""
        if value is None:
            return None
        return str(_parse_strict_subnet(value))


class ServerUpdate(BaseModel):
    """Partial-update payload for ``PATCH /servers/{id}``.

    Only operator-supplied connection metadata is editable. Provisioning
    artefacts (``subnet``, ``address``, ``public_key``, ``status``) and the
    interface name (changing it would orphan the running tunnel) are
    deliberately excluded — any unknown keys in the payload are silently
    ignored by pydantic's default behaviour.

    :ivar hostname: New SSH hostname for the control plane to dial.
    :ivar ssh_port: New SSH port.
    :ivar ssh_username: New SSH login username.
    :ivar ssh_key_id: Reassign the stored SSH credential.
    :ivar endpoint_host: New public WireGuard endpoint hostname. Existing
        client configs become stale until each client is reprovisioned.
    :ivar endpoint_port: New public WireGuard UDP port. Same stale-config
        caveat applies as ``endpoint_host``.
    """

    hostname: str | None = None
    ssh_port: int | None = None
    ssh_username: str | None = None
    ssh_key_id: int | None = None
    endpoint_host: str | None = None
    endpoint_port: int | None = None


class ServerRead(BaseModel):
    """Serialized view of a :class:`wg_manager.models.Server`."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    hostname: str
    ssh_port: int
    ssh_username: str
    ssh_key_id: int
    endpoint_host: str
    endpoint_port: int
    interface: str
    subnet: str
    address: str
    public_key: str
    status: NodeStatus
    created_at: datetime


# ---------------------------------------------------------------------------
# Clients
# ---------------------------------------------------------------------------


class ClientCreate(BaseModel):
    """Payload for registering a new WireGuard client."""

    name: str
    hostname: str
    ssh_port: int = 22
    ssh_username: str
    ssh_key_id: int
    server_id: int


class ClientUpdate(BaseModel):
    """Partial-update payload for ``PATCH /clients/{id}``.

    Only operator-supplied fields are editable. ``server_id`` is treated
    as immutable because changing it would invalidate the auto-allocated
    IP, the wg keypair, and the hub-side peer entry — delete + re-register
    is the safe path if a client needs to move between hubs. ``address``,
    ``public_key`` and ``status`` are provisioning artefacts and are
    intentionally absent here; pydantic silently drops any unknown keys.

    :ivar name: New display name. Must be unique across all clients.
    :ivar hostname: New SSH hostname for the worker to dial.
    :ivar ssh_port: New SSH port.
    :ivar ssh_username: New SSH login username.
    :ivar ssh_key_id: Reassign the stored SSH credential.
    """

    name: str | None = None
    hostname: str | None = None
    ssh_port: int | None = None
    ssh_username: str | None = None
    ssh_key_id: int | None = None


class ClientManualCreate(BaseModel):
    """Payload for ``POST /clients/manual``.

    Manual clients are devices wg-manager cannot reach over SSH (phones,
    IoT boxes, anything where pushing a config requires a human). The
    SSH credential fields are intentionally absent — wg-manager generates
    the WireGuard keypair server-side and ships the resulting config back
    to the operator for hand-install.

    :ivar name: Unique client name (same uniqueness rule as the
        SSH-provisioned flow).
    :ivar server_id: ID of the hub the client will connect to. The
        server must already be in ``ready`` state because its public
        key is baked into the rendered config.
    """

    name: str
    server_id: int


class ClientRead(BaseModel):
    """Serialized view of a :class:`wg_manager.models.Client`.

    Manual rows leave the SSH connection fields ``NULL`` and set
    ``is_manual=True``. The stored private key is **never** exposed
    here — fetch the full config via ``GET /clients/{id}/config``
    instead.
    """

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    hostname: str | None
    ssh_port: int
    ssh_username: str | None
    ssh_key_id: int | None
    server_id: int
    address: str
    public_key: str
    is_manual: bool
    status: NodeStatus
    created_at: datetime


# ---------------------------------------------------------------------------
# Async task envelopes
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Discovered peers
# ---------------------------------------------------------------------------


class DiscoveredPeerRead(BaseModel):
    """Serialized view of a :class:`wg_manager.models.DiscoveredPeer`.

    ``is_managed`` indicates whether the peer's public key also matches a
    managed :class:`wg_manager.models.Client` row on the same server.
    """

    model_config = ConfigDict(from_attributes=True)

    id: int
    server_id: int
    public_key: str
    allowed_ips: str
    endpoint: str | None
    last_handshake_at: datetime | None
    rx_bytes: int
    tx_bytes: int
    persistent_keepalive: int | None
    is_managed: bool
    first_seen_at: datetime
    last_seen_at: datetime


class DiscoverResponse(BaseModel):
    """202 response for ``POST /servers/{id}/discover``: row + task ID."""

    task_id: str
    server: ServerRead


class DiscoverAllResponse(BaseModel):
    """202 response for ``POST /servers/discover-all``: just the task ID.

    Per-server outcomes — including which hosts were unreachable — appear
    on the task's final ``result`` payload at ``GET /tasks/{task_id}``.
    """

    task_id: str
    server_count: int


class ServerRegisterResponse(BaseModel):
    """202 response for ``POST /servers``: row + Celery task ID to poll."""

    task_id: str
    server: ServerRead


class HostCertRotateResponse(BaseModel):
    """202 response for ``POST /servers/{id}/rotate-host-cert``.

    Phase 2c CP3.3. Same shape as :class:`ServerRegisterResponse` —
    the row is returned alongside the dispatched task so the dashboard
    can immediately render "rotation in flight" without re-fetching.
    The row's ``host_cert_*`` columns reflect the *previous* cert at
    202 time; poll ``GET /tasks/{task_id}`` for the new serial /
    ``valid_before`` reported by the task result.

    :ivar task_id: Celery task ID of the dispatched
        :func:`wg_manager.tasks.rotate_host_cert_task`.
    :ivar server: The server row at dispatch time.
    """

    task_id: str
    server: ServerRead


class ClientRegisterResponse(BaseModel):
    """202 response for ``POST /clients``: row + Celery task ID to poll."""

    task_id: str
    client: ClientRead


class ClientManualRegisterResponse(BaseModel):
    """201 response for ``POST /clients/manual``.

    The row is persisted in ``ready`` state immediately (no SSH
    provisioning to wait on), and a follow-up
    :func:`wg_manager.tasks.reconfigure_server_task` is dispatched to
    rewrite the hub's ``wg0.conf`` so the new peer is admitted. The
    returned ``task_id`` belongs to that reconfigure task.

    :ivar task_id: Celery task ID of the hub-reconfigure follow-up.
    :ivar client: The persisted manual client row.
    """

    task_id: str
    client: ClientRead


class ClientDeleteResponse(BaseModel):
    """202 response for ``DELETE /clients/{id}``.

    The row is gone by the time this is returned; the ``task_id`` belongs
    to the follow-up :func:`wg_manager.tasks.reconfigure_server_task` that
    rewrites the hub's ``wg0.conf`` so the deleted peer can no longer
    connect. Poll ``GET /tasks/{task_id}`` to confirm the hub picked up
    the change.

    :ivar client_id: The id of the row that was deleted (echoed back for
        client-side bookkeeping).
    :ivar server_id: The hub the deleted client was attached to.
    """

    task_id: str
    client_id: int
    server_id: int


class TaskStatusResponse(BaseModel):
    """Snapshot of a Celery task's lifecycle.

    :ivar task_id: The Celery task ID.
    :ivar state: One of PENDING, STARTED, SUCCESS, FAILURE, REVOKED, RETRY.
    :ivar result: Task return value when ``state == "SUCCESS"``.
    :ivar error: Exception string when ``state == "FAILURE"``.
    """

    task_id: str
    state: str
    result: dict[str, Any] | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# Crypto status
# ---------------------------------------------------------------------------


class CryptoStatusResponse(BaseModel):
    """Snapshot of encryption-at-rest state for the dashboard panel.

    Returned by ``GET /crypto/status``. The shape is stable on purpose —
    the Next.js dashboard renders these fields verbatim and its
    contract test in ``tests/test_crypto_status_api.py`` pins the keys.
    Add new fields freely; do not rename or remove the existing ones
    without bumping the UI in the same change.

    :ivar backend: Active backend name (``"local-dev"`` or
        ``"vault-transit"``). Maps 1:1 to
        :attr:`wg_manager.crypto.CryptoBackend.name`.
    :ivar key_version: Currently-active key version. ``1`` for local-dev
        (no rotation); Transit ``latest_version`` for vault. After a
        rotation the value bumps and the operator should run
        ``wg-manager crypto rewrap`` to migrate older ciphertext.
    :ivar sshkey_encrypted: Number of ``SSHKey`` rows whose
        ``private_key_ct`` column is populated.
    :ivar sshkey_legacy: Number of ``SSHKey`` rows that still hold only
        plaintext (ciphertext is ``NULL`` but ``private_key`` is set).
        Operators want this at zero before applying the future
        drop-plaintext migration.
    :ivar client_encrypted: Manual-client rows whose
        ``private_key_ct`` is populated.
    :ivar client_legacy: Manual-client rows still on plaintext only.
        SSH-provisioned clients are counted in neither bucket — they
        have no key material the control plane stores.
    """

    backend: str
    key_version: int
    sshkey_encrypted: int
    sshkey_legacy: int
    client_encrypted: int
    client_legacy: int
