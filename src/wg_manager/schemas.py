"""Request/response schemas (non-table pydantic models)."""

from __future__ import annotations

from datetime import datetime
from ipaddress import AddressValueError, IPv4Network, NetmaskValueError
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator

from wg_manager.models import (
    CertificateType,
    NodeStatus,
    OperatorRole,
    OperatorStatus,
    SSHKeyMode,
)


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
    """Payload for registering a new SSH role.

    Post-Phase-2c-CP4.4 the row is name-and-mode only — the task
    layer mints a fresh user cert from the SSH CA at every
    connection, so no private-key body lands here. The body is
    explicitly ``extra="forbid"`` so an upgrader still sending
    ``private_key_b64`` / ``passphrase`` from a prior release gets a
    clear 422 instead of a silently-ignored field that lulls them
    into thinking the credential was stored.
    """

    model_config = ConfigDict(extra="forbid")

    name: str


class SSHKeyUpdate(BaseModel):
    """Partial-update payload for ``PATCH /ssh-keys/{id}``.

    Renames only. The pre-CP4.4 PATCH used to accept
    ``private_key_b64`` and ``passphrase`` for in-place credential
    rotation; those columns no longer exist, so the fields are
    rejected with 422 (``extra="forbid"``) rather than silently
    dropped. Operators replacing a credential should delete and
    recreate the role.

    :ivar name: New display name. Must be unique across SSH roles; a
        collision with a different role's name produces 409.
    """

    model_config = ConfigDict(extra="forbid")

    name: str | None = None


class SSHKeyRead(BaseModel):
    """Public view of an SSH role.

    Pre-CP4.4 this surfaced an ``encrypted`` flag derived from the
    row's ciphertext column. Post-CP4.4 the ciphertext columns are
    gone and the flag is meaningless — it's removed from the public
    schema. ``mode`` is kept (always ``ca`` in the post-CP4.4 schema)
    so the dashboard's per-row badge keeps rendering and so a future
    backend variant has a place to land.
    """

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    created_at: datetime
    mode: SSHKeyMode = SSHKeyMode.ca


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

    Post-redesign the rendered ``wg0.conf`` body — including the
    freshly-generated private key — is returned **once** as
    ``wg_config``. The control plane intentionally does not persist
    the private key (manual clients are devices wg-manager cannot
    log into, so the server has no operational use for it), so this
    response is the only moment the body can be captured. If the
    operator loses it before installing on the device, the only
    recovery is to ``DELETE`` the row and register a fresh manual
    client. See the retirement of the former
    ``GET /clients/{id}/config`` route for context.

    :ivar task_id: Celery task ID of the hub-reconfigure follow-up.
    :ivar client: The persisted manual client row.
    :ivar wg_config: Full body of the rendered ``wg0.conf``,
        suitable for hand-install (e.g. via the WireGuard app's
        "import from file" flow on phones, or
        ``/etc/wireguard/wg0.conf`` on Linux).
    """

    task_id: str
    client: ClientRead
    wg_config: str


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
    """Snapshot of the encryption-at-rest backend for the dashboard panel.

    Returned by ``GET /crypto/status``. After Alembic 0008 (sshkey
    ciphertext columns gone) and 0009 (manual-client private-key
    ciphertext column gone), there is no row-level secret material
    persisted on any wg-manager table. The CryptoBackend itself stays
    bootstrapped because it is the canonical substrate for any future
    encrypted-at-rest column — this endpoint reports its identity and
    current key version so the dashboard can show whether Vault is
    healthy and whether a rotation has happened.

    The Next.js dashboard renders these fields verbatim; the contract
    test in ``tests/test_crypto_status_api.py`` pins the keys.

    :ivar backend: Active backend name (``"local-dev"`` or
        ``"vault-transit"``). Maps 1:1 to
        :attr:`wg_manager.crypto.CryptoBackend.name`.
    :ivar key_version: Currently-active key version. ``1`` for local-dev
        (no rotation); Transit ``latest_version`` for vault. After a
        Transit rotation the value bumps — nothing on disk needs
        rewrapping today (no row carries ciphertext), but the bump is
        still a useful operator signal that the rotation landed.
    """

    backend: str
    key_version: int


# ---------------------------------------------------------------------------
# Certificates — Phase 2d CP3.4
# ---------------------------------------------------------------------------


class WhoAmIResponse(BaseModel):
    """Splash payload returned by ``GET /certs/whoami``.

    The dashboard renders this above the Certificates table so a
    freshly-imported PKCS#12 visibly proves the mTLS handshake worked
    — the operator sees the CN, serial, and validity window the API
    *actually saw* on the cert chain, not what the cert file on their
    disk claims.

    :ivar cn: Common Name lifted from the client cert's subject.
    :ivar serial: Issuer-assigned serial, rendered as a decimal
        string (Vault's serials regularly exceed signed-INT64, so the
        wire format mirrors the audit-table column).
    :ivar sans: Subject Alternative Names embedded in the cert, in
        declaration order.
    :ivar not_before: Validity-window start (UTC, tz-aware).
    :ivar not_after: Validity-window end (UTC, tz-aware).
    :ivar operator_cn: The CN of the resolved :class:`Operator` row.
        Identical to :attr:`cn` for a well-formed handshake.
    :ivar operator_role: ``admin`` / ``operator`` / ``auditor`` — drives
        which buttons the dashboard renders on the page.
    :ivar operator_status: ``active`` / ``disabled``. ``disabled``
        would already 401 at the middleware, so a 200 ``whoami`` body
        always carries ``active`` — included so the dashboard splash
        can render the field unconditionally without an empty slot.
    """

    cn: str
    serial: str
    sans: list[str]
    not_before: datetime
    not_after: datetime
    operator_cn: str
    operator_role: OperatorRole
    operator_status: OperatorStatus


class CertificateRead(BaseModel):
    """Public view of a :class:`wg_manager.models.Certificate` row.

    Mirrors the storage shape one-to-one: ``serial`` and ``sans`` keep
    their string encoding so a client that calls the JSON CLI
    (``wg-manager certs list``) and the API path can compare results
    field-for-field without re-formatting.
    """

    model_config = ConfigDict(from_attributes=True)

    id: int
    serial: str
    cert_type: CertificateType
    operator_id: int | None
    common_name: str
    sans: str
    not_before: datetime
    not_after: datetime
    revoked: bool
    revoked_at: datetime | None
    created_at: datetime
    # Phase 2d CP4.3 — populated when the row was minted via
    # ``wg-manager certs issue --out-cert ...``. ``NULL`` for rows
    # minted via ``POST /certs`` (the API never writes to disk) and
    # for ``dashboard`` PKCS#12 archives. The renewal walker consults
    # these to know where to rewrite the leaf in place.
    out_cert_path: str | None = None
    out_key_path: str | None = None
    out_chain_path: str | None = None


class CertificateIssueRequest(BaseModel):
    """Payload for ``POST /certs``.

    Field defaults mirror the CLI's ``_CERT_PROFILES`` table so a caller
    can fire-and-forget the minimum body (``cert_type`` +
    ``common_name``) and get the same artefact the operator would get
    from ``wg-manager certs issue --type ... --cn ...``.

    :ivar cert_type: Which kind of leaf to mint. The four shipped
        values drive both the EKU the PKI backend applies and the
        default SAN/TTL the API picks when those fields are omitted.
    :ivar common_name: CN baked into the cert subject.
    :ivar sans: Subject Alternative Names. When omitted the API uses
        a type-specific default (``api`` → ``127.0.0.1`` +
        ``localhost``; ``mysql`` → ``mysql`` + loopback;
        ``cli`` / ``dashboard`` → the CN).
    :ivar ttl_days: Validity window in days. Defaults: ``api`` /
        ``mysql`` = 30, ``cli`` / ``dashboard`` = 365.
    :ivar operator_cn: Operator CN this cert belongs to (``cli`` +
        ``dashboard`` only). Defaults to :attr:`common_name`; must
        match a registered :class:`wg_manager.models.Operator` row or
        the request is refused with 422.
    :ivar pkcs12_password: Password used to encrypt the PKCS#12 bundle
        returned for ``dashboard`` certs. Empty string yields an
        unencrypted bundle (matches the CLI default).
    """

    model_config = ConfigDict(extra="forbid")

    cert_type: CertificateType
    common_name: str
    sans: list[str] | None = None
    ttl_days: int | None = None
    operator_cn: str | None = None
    pkcs12_password: str = ""


class CertificateIssueResponse(BaseModel):
    """Body returned by ``POST /certs``.

    Carries both the audit row (so the dashboard's table can render
    the new entry without re-fetching) and the cert material itself
    (the *only* moment the private key is ever surfaced — the server
    persists no copy). For ``dashboard`` issuance the body
    additionally carries :attr:`pkcs12_b64`, a base64-encoded PKCS#12
    archive the browser can save as a single import file.

    :ivar certificate: The newly-recorded audit row.
    :ivar cert_pem: PEM body of the issued leaf certificate.
    :ivar private_pem: PEM body of the matching private key. The
        client should store this securely and never round-trip it
        through wg-manager again.
    :ivar chain_pem: PEM concatenation of the issuing chain
        (intermediate + root).
    :ivar pkcs12_b64: Base64 of the PKCS#12 bundle. ``None`` for
        ``api`` / ``cli`` / ``mysql``; populated for ``dashboard``.
    """

    certificate: CertificateRead
    cert_pem: str
    private_pem: str
    chain_pem: str
    pkcs12_b64: str | None = None


class CertificateRevokeResponse(BaseModel):
    """Body returned by ``POST /certs/{id}/revoke``.

    Idempotent: calling it on an already-revoked row returns 200 with
    the same row shape so the dashboard can re-issue the call after a
    flaky network without surfacing a confusing error. The ``revoked``
    flag is ``True`` on success regardless of whether this call or a
    prior one flipped it.
    """

    certificate: CertificateRead


# ---------------------------------------------------------------------------
# Audit log — Phase 2e cycle 4
# ---------------------------------------------------------------------------


class AuditEventRead(BaseModel):
    """Public view of an :class:`wg_manager.models.AuditEvent` row.

    Mirrors the storage shape one-to-one with one intentional
    difference: ``payload`` comes back as a parsed ``dict`` (or
    ``None``) rather than the compact-JSON string the column stores.
    Centralising the parse on the server keeps every consumer — the
    dashboard, an auditor's ``jq``-pipeline session, a future SIEM
    backfill job — agreeing on the dict shape rather than each
    re-parsing the string locally.

    Hashes are surfaced as their hex digest (or ``None`` on create /
    delete polarities) so an auditor can compare against an external
    canonical-JSON computation of the underlying resource state.

    :ivar id: Row primary key.
    :ivar ts: When the event was emitted, UTC. The endpoint pages
        newest-first on this column.
    :ivar event: Slug of the form ``<resource>.<action>``.
    :ivar actor_cn: CN from the mTLS cert that authorised the
        mutation; ``None`` for system-origin events.
    :ivar actor_serial: Cert serial as decimal string; ``None`` for
        system-origin events.
    :ivar actor_role: :class:`OperatorRole` value at action time
        (string-encoded); ``None`` for system-origin events.
    :ivar resource_type: Coarse bucket (``server`` / ``client`` /
        ``ssh_key`` / ``certificate`` / ``crypto``).
    :ivar resource_id: Row id of the affected resource, or ``None``
        for global-scope events.
    :ivar action: Verb (``create`` / ``update`` / ``delete`` /
        ``revoke`` / ``rotate``).
    :ivar before_hash: SHA-256 hex of the pre-mutation row, or ``None``
        on create.
    :ivar after_hash: SHA-256 hex of the post-mutation row, or ``None``
        on delete.
    :ivar payload: Parsed payload dict, or ``None``. Stripped of
        secret material by the persistence helper's caller.
    :ivar request_id: Correlation ID lifted from the request, or a
        ``uuid4`` for system-origin events.
    """

    id: int
    ts: datetime
    event: str
    actor_cn: str | None
    actor_serial: str | None
    actor_role: str | None
    resource_type: str
    resource_id: int | None
    action: str
    before_hash: str | None
    after_hash: str | None
    payload: dict[str, Any] | None
    request_id: str | None


class AuditEventListResponse(BaseModel):
    """Envelope returned by ``GET /audit``.

    Carries the page of rows alongside the full ``total`` matching the
    request's filter — the dashboard renders a correct ``Showing X-Y
    of Z`` line and pagination controls without a second request. The
    envelope echoes ``limit`` and ``offset`` so a thin client (the
    dashboard, a CLI session piping into ``jq``) can confirm the page
    it actually got matches what it asked for.

    :ivar items: One page of audit rows, newest-first.
    :ivar total: Count of rows matching the filter across all pages.
    :ivar limit: The page size honoured for ``items``.
    :ivar offset: The offset honoured for ``items``.
    """

    items: list[AuditEventRead]
    total: int
    limit: int
    offset: int


# ---------------------------------------------------------------------------
# Tenants — Phase 3b cycle 2
# ---------------------------------------------------------------------------


class TenantCreate(BaseModel):
    """Body for ``POST /tenants``.

    Slug is optional: when omitted the router derives a kebab-case
    form from ``name`` so a simple ``{"name": "Acme"}`` body works.
    """

    model_config = ConfigDict(extra="forbid")

    name: str
    slug: str | None = None


class TenantRead(BaseModel):
    """Public view of a :class:`wg_manager.models.Tenant` row."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    slug: str
    created_at: datetime


class OperatorTenantAttachRequest(BaseModel):
    """Body for ``POST /tenants/{slug}/operators``.

    Defaults the per-tenant role to ``operator`` (principle of least
    privilege) — admins must be set explicitly per tenant too.
    """

    model_config = ConfigDict(extra="forbid")

    cn: str
    role: OperatorRole = OperatorRole.operator


class OperatorTenantRead(BaseModel):
    """Public view of an :class:`wg_manager.models.OperatorTenant` join row.

    Surfaces the resolved tenant slug / name + operator CN alongside
    the join's per-tenant role so the dashboard renders the table
    without a second lookup.
    """

    model_config = ConfigDict(from_attributes=True)

    id: int
    tenant_id: int
    tenant_slug: str
    tenant_name: str
    operator_id: int
    operator_cn: str
    role: OperatorRole
    created_at: datetime
