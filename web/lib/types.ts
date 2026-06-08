/**
 * TypeScript shapes that mirror the FastAPI / pydantic schemas exposed by
 * the wg-manager control plane. Keep these in sync with
 * `src/wg_manager/schemas.py` — when the backend grows fields, update
 * here too. We hand-author rather than generate from OpenAPI to keep the
 * dashboard's dependency surface tiny; if drift becomes a problem,
 * `openapi-typescript` is the obvious next step.
 */

export type NodeStatus = "pending" | "ready" | "error";

/**
 * Per-row SSH auth mode. Phase 2c CP4.4 retired the historical
 * `legacy` stored-key path — the row is now name-and-mode only, and
 * every connection mints a short-lived user cert from the SSH CA.
 * The literal is kept (rather than narrowed to `"ca"`) so a future
 * variant — e.g. a Vault-issued mode — has somewhere to land.
 */
export type SSHKeyMode = "ca";

export interface SSHKey {
  id: number;
  name: string;
  created_at: string;
  /**
   * Per-row auth mode. Post-CP4.4 every row is `"ca"`; the field
   * survives so the dashboard's per-row badge keeps rendering and so
   * a future backend variant has a place to land.
   */
  mode: SSHKeyMode;
  /**
   * Phase 3b cycle 3 — tenant FK on the row. Nullable for legacy
   * rows; pre-cycle-1 rows backfilled by Alembic 0014 carry
   * `tenant_id=1` (the default tenant).
   */
  tenant_id: number | null;
}

export interface SSHKeyCreate {
  name: string;
  /**
   * Phase 3b cycle 5 — optional tenant the row should land in. When
   * omitted: super-admin / single-tenant operator → auto-derived;
   * multi-tenant operator → 422.
   */
  tenant_id?: number;
}

/**
 * Partial-update payload for `PATCH /ssh-keys/{id}`. Phase 2c CP4.4
 * dropped the row's secret-bearing columns, so the only mutable
 * field left is the role's display name. Sending any other field
 * earns a 422 from the backend (`extra="forbid"` on the schema).
 */
export interface SSHKeyUpdate {
  name?: string;
}

export interface Server {
  id: number;
  hostname: string;
  ssh_port: number;
  ssh_username: string;
  ssh_key_id: number;
  endpoint_host: string;
  endpoint_port: number;
  interface: string;
  subnet: string;
  address: string;
  public_key: string;
  status: NodeStatus;
  created_at: string;
  /**
   * Phase 2c CP3.1 — snapshot of the SSH host certificate the control
   * plane last issued for this server, captured at provisioning /
   * rotation time. All five fields are present together (or all NULL
   * on a Phase 2b row whose operator hasn't opted into CA mode yet).
   */
  host_cert_serial?: number | null;
  /** Comma-separated principals embedded in the host cert. */
  host_cert_principals?: string | null;
  /** ISO-8601 string. NotBefore on the cert. */
  host_cert_valid_after?: string | null;
  /** ISO-8601 string. NotAfter — the rotation deadline. */
  host_cert_valid_before?: string | null;
  /**
   * Full OpenSSH-formatted host cert body. Surfaced so the dashboard
   * can copy/inspect on demand without re-fetching; not rendered by
   * default.
   */
  host_cert_pem?: string | null;
  /**
   * The CA public key that signed the cert, captured at signing time.
   * Used to flag rows pinned to a CA that's since been rotated.
   */
  host_cert_ca_public_key?: string | null;
  /**
   * Phase 3b cycle 3 — tenant FK. Nullable; backfilled rows carry
   * `tenant_id=1`.
   */
  tenant_id?: number | null;
}

/**
 * 202 response for `POST /servers/{id}/rotate-host-cert`. Same shape
 * as {@link ServerRegisterResponse} — the server row is returned at
 * dispatch time (its host_cert columns still reflect the previous
 * cert); poll `GET /tasks/{task_id}` for the freshly-minted serial /
 * `valid_before`.
 */
export interface HostCertRotateResponse {
  task_id: string;
  server: Server;
}

export interface ServerCreate {
  hostname: string;
  ssh_port?: number;
  ssh_username: string;
  ssh_key_id: number;
  endpoint_host: string;
  endpoint_port?: number;
  interface?: string;
  /**
   * Optional IPv4 CIDR for the WireGuard network. Omit to use the API's
   * default (configured via `DEFAULT_SUBNET`, ships as `10.9.0.0/24`).
   * Must be network-aligned (no host bits set) and `/30` or larger.
   */
  subnet?: string;
  /**
   * Phase 3b cycle 5 — tenant the server lands in. Optional; same
   * resolution rules as `SSHKeyCreate.tenant_id`. The chosen tenant's
   * `subnet_pool` is what `subnet` must fall inside.
   */
  tenant_id?: number;
  /**
   * Optional operator OOB SSH private key (PEM body). When present, the
   * registration task runs `bootstrap_host()` against the box BEFORE the
   * CA-mode provision session, laying down the SSH CA trust + signed
   * host cert + sshd drop-in in one round-trip. Encrypted via the API's
   * crypto backend before queueing — never persisted, never echoed in
   * responses. Omit when the host was already bootstrapped (CLI, baked
   * AMI, etc.); the API falls through to today's behaviour and the
   * provision step fails cleanly with "host cert signed by an
   * untrusted CA" if the box isn't ready yet.
   */
  bootstrap_ssh_key_pem?: string;
  /**
   * Optional passphrase protecting `bootstrap_ssh_key_pem`. Has no
   * meaning when the PEM is absent — the API rejects this case at
   * schema time.
   */
  bootstrap_ssh_key_passphrase?: string;
}

/**
 * Partial-update payload for `PATCH /servers/{id}`. Every field is
 * optional — only the keys present on the wire are applied server-side.
 * Provisioning artefacts (subnet, address, public_key, status, interface)
 * are intentionally absent: the backend would ignore them anyway.
 */
export interface ServerUpdate {
  hostname?: string;
  ssh_port?: number;
  ssh_username?: string;
  ssh_key_id?: number;
  endpoint_host?: string;
  endpoint_port?: number;
}

/**
 * Either an SSH-provisioned client (the default flow) or a manual
 * client (registered without SSH, for devices wg-manager can't reach —
 * phones, IoT, ...). Manual rows are distinguished by `is_manual=true`
 * and have NULL SSH connection fields because the operator installs
 * the rendered `wg0.conf` by hand instead of letting wg-manager push it.
 */
export interface Client {
  id: number;
  name: string;
  /** NULL for manual clients. */
  hostname: string | null;
  ssh_port: number;
  /** NULL for manual clients. */
  ssh_username: string | null;
  /** NULL for manual clients. */
  ssh_key_id: number | null;
  server_id: number;
  address: string;
  public_key: string;
  /** True when the row was created via `POST /clients/manual`. */
  is_manual: boolean;
  status: NodeStatus;
  created_at: string;
  /**
   * Phase 3b cycle 3 — tenant FK. Nullable; backfilled rows carry
   * `tenant_id=1`.
   */
  tenant_id?: number | null;
}

export interface ClientCreate {
  name: string;
  hostname: string;
  ssh_port?: number;
  ssh_username: string;
  ssh_key_id: number;
  server_id: number;
}

/**
 * Payload for `POST /clients/manual`. Manual clients are registered
 * without any SSH credentials — wg-manager generates the WireGuard
 * keypair on the server side and returns a `wg0.conf` body the
 * operator installs on the device by hand.
 */
export interface ClientManualCreate {
  name: string;
  server_id: number;
}

/**
 * Partial-update payload for `PATCH /clients/{id}`. Provisioning
 * artefacts (server_id, address, public_key, status) are intentionally
 * absent — the backend ignores them anyway.
 */
export interface ClientUpdate {
  name?: string;
  hostname?: string;
  ssh_port?: number;
  ssh_username?: string;
  ssh_key_id?: number;
}

/**
 * 202 response from `DELETE /clients/{id}`. The row is gone; the task_id
 * belongs to the follow-up hub reconfigure that drops the peer entry
 * from `wg0.conf`.
 */
export interface ClientDeleteResponse {
  task_id: string;
  client_id: number;
  server_id: number;
}

export interface DiscoveredPeer {
  id: number;
  server_id: number;
  public_key: string;
  allowed_ips: string;
  endpoint: string | null;
  last_handshake_at: string | null;
  rx_bytes: number;
  tx_bytes: number;
  persistent_keepalive: number | null;
  is_managed: boolean;
  first_seen_at: string;
  last_seen_at: string;
}

/** Envelope returned by 202 responses that dispatched a Celery task. */
export interface TaskEnvelope<T> {
  task_id: string;
  /** Any additional resource(s) the endpoint returns alongside the task. */
  payload?: T;
}

export interface ServerRegisterResponse {
  task_id: string;
  server: Server;
}

export interface ClientRegisterResponse {
  task_id: string;
  client: Client;
}

/**
 * 201 response from `POST /clients/manual`. The row is already in
 * `ready` state — `task_id` belongs to the follow-up hub reconfigure
 * that adds the new peer to the server's running `wg0.conf`.
 *
 * `wg_config` is the rendered `wg0.conf` body (with the
 * server-generated private key inline). Post-redesign the control
 * plane does not persist that private key, so this response is the
 * only moment the body can be captured. The dashboard must surface
 * it prominently with copy/download affordances; if the operator
 * dismisses the success state before saving the body, the only
 * recovery is to delete the row and register a fresh manual client
 * (which mints a new keypair and reconfigures the hub).
 */
export interface ClientManualRegisterResponse {
  task_id: string;
  client: Client;
  wg_config: string;
}

export interface DiscoverResponse {
  task_id: string;
  server: Server;
}

export interface DiscoverAllResponse {
  task_id: string;
  server_count: number;
}

export type TaskState =
  | "PENDING"
  | "STARTED"
  | "SUCCESS"
  | "FAILURE"
  | "REVOKED"
  | "RETRY";

export interface TaskStatus {
  task_id: string;
  state: TaskState;
  result: Record<string, unknown> | null;
  error: string | null;
}

/**
 * Response from `GET /crypto/status`. Powers the "Crypto status" panel
 * on the dashboard — reports the active encryption-at-rest backend
 * identity and current key version.
 *
 * After Alembic 0008 (sshkey ciphertext columns gone) and 0009
 * (manual-client private-key ciphertext column gone), no wg-manager
 * row holds persisted secret material. The response shrinks to just
 * the backend identity and current key version — the two facts the
 * operator still cares about ("is Vault healthy?"; "did my Transit
 * rotation land?").
 *
 * Keep in sync with `CryptoStatusResponse` in
 * `src/wg_manager/schemas.py` — the backend pins this shape with a
 * contract test in `tests/test_crypto_status_api.py`.
 */
export interface CryptoStatus {
  backend: string;
  key_version: number;
}

// ---------------------------------------------------------------------------
// Certificates — Phase 2d CP3.4
// ---------------------------------------------------------------------------

/** Logical purpose of a leaf cert — mirrors `CertificateType` in
 *  `src/wg_manager/models.py`. ``mysql-client`` is the Phase 2d CP4.2
 *  service cert the app + worker present to a TLS-enforcing MySQL. */
export type CertificateType =
  | "api"
  | "cli"
  | "dashboard"
  | "mysql"
  | "mysql-client";

/** Operator role the API sees on the calling cert — mirrors
 *  `OperatorRole` in `src/wg_manager/models.py`. Drives which controls
 *  the dashboard exposes (issue/revoke are admin-only). */
export type OperatorRole = "admin" | "operator" | "auditor";

/** Operator lifecycle state. Disabled operators would already 401 at
 *  the middleware, so a 200 `whoami` body always carries `active` —
 *  the field stays for future expansion. */
export type OperatorStatus = "active" | "disabled";

/**
 * Splash payload returned by ``GET /certs/whoami``.
 *
 * Keep in sync with `WhoAmIResponse` in `src/wg_manager/schemas.py`.
 * The dashboard's "Who am I?" splash renders this verbatim so a
 * freshly-imported PKCS#12 visibly proves the mTLS handshake worked.
 */
export interface WhoAmI {
  cn: string;
  serial: string;
  sans: string[];
  not_before: string;
  not_after: string;
  operator_cn: string;
  operator_role: OperatorRole;
  operator_status: OperatorStatus;
}

/**
 * Audit-table row for an issued certificate.
 *
 * Keep in sync with `CertificateRead` in `src/wg_manager/schemas.py`.
 */
export interface Certificate {
  id: number;
  serial: string;
  cert_type: CertificateType;
  operator_id: number | null;
  common_name: string;
  /** Comma-separated SAN list — matches the storage style the table
   *  uses on the backend so JSON CLI output and dashboard rendering
   *  agree on the wire shape. Split client-side when listing. */
  sans: string;
  not_before: string;
  not_after: string;
  revoked: boolean;
  revoked_at: string | null;
  created_at: string;
  /**
   * Phase 3b cycle 3 — tenant FK. Nullable; backfilled rows carry
   * `tenant_id=1`.
   */
  tenant_id?: number | null;
}

/** Body for ``POST /certs``. Mirrors `CertificateIssueRequest`. */
export interface CertificateIssueRequest {
  cert_type: CertificateType;
  common_name: string;
  sans?: string[];
  ttl_days?: number;
  operator_cn?: string;
  /** Password used to encrypt the PKCS#12 bundle for `dashboard`
   *  certs. Empty string yields an unencrypted bundle (matches the
   *  CLI default). Ignored for other cert types. */
  pkcs12_password?: string;
  /**
   * Phase 3b cycle 5 — tenant slug to bake into the leaf as a
   * `tenant:<slug>` SAN. Allowed only for `cli` / `dashboard`
   * cert types.
   */
  tenant_slug?: string;
}

/** Response for ``POST /certs``. Mirrors `CertificateIssueResponse`. */
export interface CertificateIssueResponse {
  certificate: Certificate;
  cert_pem: string;
  private_pem: string;
  chain_pem: string;
  /** Base64-encoded PKCS#12 bundle. Populated only for `dashboard`
   *  cert_type; null otherwise. */
  pkcs12_b64: string | null;
}

/** Response for ``POST /certs/{id}/revoke``. Idempotent — calling it
 *  on an already-revoked row returns the same shape. */
export interface CertificateRevokeResponse {
  certificate: Certificate;
}

// --- Audit log (Phase 2e cycle 4) ---

/**
 * One row in the application audit log.
 *
 * Mirrors `AuditEventRead` in `src/wg_manager/schemas.py`. The audit
 * log is hash-only: `before_hash` / `after_hash` are SHA-256 hex of
 * the canonical-JSON resource state pre/post-mutation, never the raw
 * row, so the table is safe to ship in backups.
 *
 * The `payload` field is a parsed JSON dict (the backend pre-decodes
 * the column's compact-JSON string into the wire shape). Callers
 * strip secret material before persistence; the value here is safe
 * to render in the dashboard.
 */
export interface AuditEvent {
  id: number;
  /** ISO-8601 UTC timestamp. */
  ts: string;
  /** Slug of the form `<resource>.<action>` (e.g. `server.create`). */
  event: string;
  /** CN from the operator's mTLS cert; `null` for system-origin events. */
  actor_cn: string | null;
  /** Cert serial as decimal string; `null` for system-origin events. */
  actor_serial: string | null;
  /** OperatorRole at action time; `null` for system-origin events. */
  actor_role: string | null;
  /** Coarse bucket (`server` / `client` / `ssh_key` / `certificate` / `crypto`). */
  resource_type: string;
  /** Row id of the affected resource; `null` for global-scope events. */
  resource_id: number | null;
  /** Verb (`create` / `update` / `delete` / `revoke` / `rotate`). */
  action: string;
  /** SHA-256 hex of the pre-mutation row; `null` on create. */
  before_hash: string | null;
  /** SHA-256 hex of the post-mutation row; `null` on delete. */
  after_hash: string | null;
  /** Parsed payload dict; `null` if the row didn't carry one. */
  payload: Record<string, unknown> | null;
  /** Correlation id; `null` for system-origin events. */
  request_id: string | null;
}

/**
 * Filters for `GET /audit`. Each field is AND-combined server-side;
 * `since` / `until` is a half-open window (`ts >= since AND ts < until`)
 * so adjacent ranges don't double-count the boundary row.
 */
export interface AuditEventListParams {
  event?: string;
  actor_cn?: string;
  resource_type?: string;
  resource_id?: number;
  /** ISO-8601 lower bound, inclusive. */
  since?: string;
  /** ISO-8601 upper bound, exclusive. */
  until?: string;
  /** Page size. Default 100; backend caps at 500. */
  limit?: number;
  /** Page offset. Default 0. */
  offset?: number;
}

/**
 * Envelope returned by `GET /audit`. Mirrors `AuditEventListResponse`
 * in `src/wg_manager/schemas.py`. Carries `total` so the dashboard can
 * render a correct "Showing X-Y of Z" line without a second request.
 */
export interface AuditEventList {
  items: AuditEvent[];
  /** Count of rows matching the filter across all pages. */
  total: number;
  limit: number;
  offset: number;
}

// ---------------------------------------------------------------------------
// Tenants — Phase 3b cycle 2
// ---------------------------------------------------------------------------

/**
 * One tenant namespace. Mirrors `TenantRead` in
 * `src/wg_manager/schemas.py`. The `default` tenant (`id=1`,
 * `slug='default'`) is created by Alembic 0014; every Phase-3b-cycle-1
 * row is back-filled to point at it.
 */
export interface Tenant {
  id: number;
  name: string;
  slug: string;
  /**
   * Phase 3b cycle 4 — CIDR carving the tenant's slice of the
   * WireGuard IP space. Every server's subnet must lie inside the
   * pool; pools must be disjoint across tenants.
   */
  subnet_pool: string;
  /** ISO-8601 UTC timestamp. */
  created_at: string;
}

/** Body for `POST /tenants`. Slug derives from `name` when omitted. */
export interface TenantCreate {
  name: string;
  slug?: string;
  /**
   * CIDR pool (Phase 3b cycle 4). Optional — when omitted the row
   * carries the model default (`10.0.0.0/8`).
   */
  subnet_pool?: string;
}

/** Body for `PATCH /tenants/{slug}` (Phase 3b cycle 4). */
export interface TenantUpdate {
  subnet_pool?: string;
}

/**
 * One operator ↔ tenant join. Mirrors `OperatorTenantRead`. Exposes the
 * resolved tenant slug / name + operator CN so the dashboard renders
 * the table without a second lookup against `Tenant` / `Operator`.
 */
export interface OperatorTenantRead {
  id: number;
  tenant_id: number;
  tenant_slug: string;
  tenant_name: string;
  operator_id: number;
  operator_cn: string;
  role: OperatorRole;
  /** ISO-8601 UTC timestamp the join was created. */
  created_at: string;
}

/** Body for `POST /tenants/{slug}/operators`. */
export interface OperatorTenantAttachRequest {
  cn: string;
  role?: OperatorRole;
}
