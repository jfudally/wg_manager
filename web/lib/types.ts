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
 * Per-row SSH auth mode (Phase 2c CP4.1). A `legacy` row still
 * carries an encrypted private-key body in `private_key_ct` and
 * authenticates via the historical Phase 2b path; a `ca` row is a
 * label only — every connection mints a short-lived user cert from
 * the SSH CA and presents that instead.
 */
export type SSHKeyMode = "legacy" | "ca";

export interface SSHKey {
  id: number;
  name: string;
  created_at: string;
  /**
   * True when the row's ciphertext column is populated — i.e. the
   * private key body went through the encryption seam at create or
   * update time. Post-Phase-2b checkpoint 3 every row should report
   * `true` in steady state; `false` flags an orphan that needs
   * rewrapping. The Crypto Status panel surfaces the aggregate count.
   */
  encrypted: boolean;
  /**
   * Per-row auth mode. Defaults to `legacy` on every existing row
   * after Alembic 0007 backfills, and flips to `ca` once an operator
   * runs `wg-manager ssh migrate-to-ca <id>` (CP4.2). Drives the
   * "SSH roles" badge + migration affordance on the keys page.
   */
  mode: SSHKeyMode;
}

export interface SSHKeyCreate {
  name: string;
  private_key_b64: string;
  passphrase?: string | null;
}

/**
 * Partial-update payload for `PATCH /ssh-keys/{id}`. Each field is
 * optional — only keys present on the wire are applied server-side, and
 * `null` is treated the same as "omitted" (the backend strips both).
 *
 * Replacing `private_key_b64` does NOT auto-reprovision servers/clients
 * that still reference this credential — they pick up the new key on the
 * next SSH-touching call (provision / reprovision / discover).
 */
export interface SSHKeyUpdate {
  name?: string;
  passphrase?: string;
  private_key_b64?: string;
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
 */
export interface ClientManualRegisterResponse {
  task_id: string;
  client: Client;
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
 * on the dashboard — shows which backend is wrapping secrets at rest,
 * the current key version, and per-table counts of encrypted vs
 * legacy rows. Operators use the legacy counts to decide whether to
 * run `wg-manager crypto rewrap` (or, before applying Alembic 0005,
 * `crypto migrate`).
 *
 * Keep in sync with `CryptoStatusResponse` in
 * `src/wg_manager/schemas.py` — the backend pins this shape with a
 * contract test in `tests/test_crypto_status_api.py`.
 */
export interface CryptoStatus {
  backend: string;
  key_version: number;
  sshkey_encrypted: number;
  sshkey_legacy: number;
  client_encrypted: number;
  client_legacy: number;
}
