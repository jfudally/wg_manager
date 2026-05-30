/**
 * Thin typed fetch wrapper around the wg-manager FastAPI control plane.
 *
 * All callers go through this module — never use `fetch()` directly from
 * a component — so error handling, JSON parsing, and base URL resolution
 * happen in exactly one place.
 */

import type {
  Certificate,
  CertificateIssueRequest,
  CertificateIssueResponse,
  CertificateRevokeResponse,
  Client,
  ClientCreate,
  ClientDeleteResponse,
  ClientManualCreate,
  ClientManualRegisterResponse,
  ClientRegisterResponse,
  ClientUpdate,
  CryptoStatus,
  DiscoverAllResponse,
  DiscoveredPeer,
  DiscoverResponse,
  HostCertRotateResponse,
  SSHKey,
  SSHKeyCreate,
  SSHKeyUpdate,
  Server,
  ServerCreate,
  ServerRegisterResponse,
  ServerUpdate,
  TaskStatus,
  WhoAmI,
} from "./types";

/**
 * Resolved at module load. Defaults to the same-origin BFF path
 * ``/api/proxy`` so the browser issues plain-HTTP same-origin requests
 * and the Next.js Node runtime (see
 * :file:`app/api/proxy/[...path]/route.ts`) presents the mTLS client
 * cert to the FastAPI control plane. Set
 * ``NEXT_PUBLIC_WG_MANAGER_API`` to bypass the proxy (e.g. when
 * pointing at a non-mTLS staging host), but the default is the right
 * choice for any dev/prod where the API listener requires mTLS — which
 * is the Phase 2d CP2 contract.
 */
export const API_BASE =
  process.env.NEXT_PUBLIC_WG_MANAGER_API ?? "/api/proxy";

/** Thrown when the API returns a non-2xx response. */
export class ApiError extends Error {
  readonly status: number;
  readonly detail: unknown;
  constructor(status: number, detail: unknown, message?: string) {
    super(message ?? `API error ${status}`);
    this.status = status;
    this.detail = detail;
  }
}

interface RequestOptions {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  body?: unknown;
  signal?: AbortSignal;
}

/**
 * Issue a JSON request against the control plane. Throws {@link ApiError}
 * on any non-2xx response — components should let TanStack Query catch
 * and surface those rather than handling them inline.
 */
export async function request<T>(
  path: string,
  opts: RequestOptions = {},
): Promise<T> {
  const url = `${API_BASE}${path}`;
  const response = await fetch(url, {
    method: opts.method ?? "GET",
    headers: opts.body ? { "Content-Type": "application/json" } : undefined,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    signal: opts.signal,
  });

  if (response.status === 204) {
    return undefined as T;
  }

  const text = await response.text();
  const parsed = text ? safeJsonParse(text) : null;

  if (!response.ok) {
    const detailMessage =
      typeof parsed === "object" && parsed && "detail" in parsed
        ? String((parsed as { detail: unknown }).detail)
        : text || response.statusText;
    throw new ApiError(response.status, parsed, detailMessage);
  }

  return parsed as T;
}

/**
 * Issue a request whose response body is plain text rather than JSON.
 *
 * Used by endpoints like ``/clients/export/ssh-config`` that return a
 * ``text/plain`` body intended to be displayed verbatim or piped to a
 * file. Mirrors :func:`request`'s error semantics — non-2xx still throws
 * {@link ApiError} with the parsed JSON detail when one is available.
 */
export async function requestText(
  path: string,
  opts: RequestOptions = {},
): Promise<string> {
  const url = `${API_BASE}${path}`;
  const response = await fetch(url, {
    method: opts.method ?? "GET",
    headers: opts.body ? { "Content-Type": "application/json" } : undefined,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    signal: opts.signal,
  });
  const text = await response.text();
  if (!response.ok) {
    const parsed = text ? safeJsonParse(text) : null;
    const detailMessage =
      typeof parsed === "object" && parsed && "detail" in parsed
        ? String((parsed as { detail: unknown }).detail)
        : text || response.statusText;
    throw new ApiError(response.status, parsed, detailMessage);
  }
  return text;
}

function safeJsonParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

// ---------------------------------------------------------------------------
// Endpoints. One function per HTTP route the dashboard uses. They exist
// so the React Query keys / mutations have a single source of truth.
// ---------------------------------------------------------------------------

/** Base64-encode an SSH private key body for the API payload. */
export function b64encode(value: string): string {
  if (typeof window !== "undefined" && typeof window.btoa === "function") {
    return window.btoa(value);
  }
  // Node / SSR fallback. Buffer is always present on the server.
  return Buffer.from(value, "utf-8").toString("base64");
}

export const api = {
  /** Liveness check — confirms the API is reachable. */
  async health(): Promise<boolean> {
    try {
      await request<unknown>("/docs");
      return true;
    } catch {
      return false;
    }
  },

  // --- SSH keys ---
  listSshKeys: () => request<SSHKey[]>("/ssh-keys"),
  createSshKey: (payload: SSHKeyCreate) =>
    request<SSHKey>("/ssh-keys", { method: "POST", body: payload }),
  /**
   * Partial-update an SSH key. Send only the fields the operator changed
   * — the backend treats omitted and `null` fields identically and leaves
   * them untouched on the row. To clear a previously-set passphrase the
   * caller must delete and recreate; the existing key body would still be
   * encrypted under the old passphrase otherwise.
   */
  updateSshKey: (id: number, payload: SSHKeyUpdate) =>
    request<SSHKey>(`/ssh-keys/${id}`, { method: "PATCH", body: payload }),
  deleteSshKey: (id: number) =>
    request<void>(`/ssh-keys/${id}`, { method: "DELETE" }),

  // --- Servers ---
  listServers: () => request<Server[]>("/servers"),
  getServer: (id: number) => request<Server>(`/servers/${id}`),
  registerServer: (payload: ServerCreate) =>
    request<ServerRegisterResponse>("/servers", {
      method: "POST",
      body: payload,
    }),
  reprovisionServer: (id: number) =>
    request<ServerRegisterResponse>(`/servers/${id}/reprovision`, {
      method: "POST",
    }),
  /**
   * Re-mint and install the server's SSH host certificate (Phase 2c
   * CP3.3). Returns 202 with `{task_id, server}`; the row's
   * `host_cert_*` columns update once the task completes — poll via
   * `taskStatus(task_id)` to see the new serial / `valid_before`.
   *
   * Fails with `ApiError(status=409)` when the server's SSH key is
   * not in CA mode (Phase 2c CP4.1 moved this precondition from the
   * global `SSH_AUTH_MODE` env var to the per-row `SSHKey.mode`).
   * Surface the error's `detail` to the operator — the message names
   * the exact `wg-manager ssh migrate-to-ca <id>` command to run.
   */
  rotateHostCert: (id: number) =>
    request<HostCertRotateResponse>(`/servers/${id}/rotate-host-cert`, {
      method: "POST",
    }),
  /**
   * Partial-update a server. Pass only the fields the operator changed —
   * the backend ignores everything else.
   */
  updateServer: (id: number, payload: ServerUpdate) =>
    request<Server>(`/servers/${id}`, { method: "PATCH", body: payload }),
  /**
   * Delete a server. The default refuses with 409 if managed clients are
   * still attached; pass ``force=true`` to cascade-delete clients and
   * discovered peers along with the server.
   */
  deleteServer: (id: number, force: boolean = false) =>
    request<void>(`/servers/${id}${force ? "?force=true" : ""}`, {
      method: "DELETE",
    }),
  discoverServer: (id: number) =>
    request<DiscoverResponse>(`/servers/${id}/discover`, { method: "POST" }),
  discoverAllServers: () =>
    request<DiscoverAllResponse>("/servers/discover-all", { method: "POST" }),
  listDiscoveredPeers: (serverId: number) =>
    request<DiscoveredPeer[]>(`/servers/${serverId}/discovered-peers`),
  listAllDiscoveredPeers: () =>
    request<DiscoveredPeer[]>("/servers/discovered-peers/all"),

  // --- Clients ---
  listClients: () => request<Client[]>("/clients"),
  registerClient: (payload: ClientCreate) =>
    request<ClientRegisterResponse>("/clients", {
      method: "POST",
      body: payload,
    }),
  /**
   * Register a client we won't SSH into — phones, IoT, anything where
   * wg-manager can't push a config over SSH. The control plane
   * generates a WireGuard keypair, allocates an IP, persists the row
   * in ``ready`` state with ``is_manual=true``, dispatches a hub
   * reconfigure (returned task_id) so the new peer is admitted, and
   * returns the rendered ``wg0.conf`` body inline as
   * ``wg_config``.
   *
   * Post-redesign the control plane does **not** persist the
   * device's private key — this response is the only moment the
   * ``wg_config`` body can be captured. If the operator dismisses
   * the UI before saving it, the only recovery is to delete the row
   * and re-register (which mints a fresh keypair and reconfigures
   * the hub).
   */
  registerManualClient: (payload: ClientManualCreate) =>
    request<ClientManualRegisterResponse>("/clients/manual", {
      method: "POST",
      body: payload,
    }),
  reprovisionClient: (id: number) =>
    request<ClientRegisterResponse>(`/clients/${id}/reprovision`, {
      method: "POST",
    }),
  /** Partial-update a client. Only the supplied fields are PATCHed. */
  updateClient: (id: number, payload: ClientUpdate) =>
    request<Client>(`/clients/${id}`, { method: "PATCH", body: payload }),
  /**
   * Delete a client and trigger a hub reconfigure. The returned task_id
   * belongs to the follow-up reconfigure_server_task — poll it to confirm
   * the hub's wg0.conf was rewritten without the deleted peer.
   */
  deleteClient: (id: number) =>
    request<ClientDeleteResponse>(`/clients/${id}`, { method: "DELETE" }),
  /**
   * Render an ``~/.ssh/config`` block for every registered client.
   *
   * The body is plain text (one entry per client; ``Host <name>.vpn``,
   * ``HostName <wg-ip>``, ``User <ssh_username>``, ``IdentityFile
   * ~/.ssh/<key-name>``), intended to be displayed verbatim, copied to
   * the clipboard, or downloaded as a file. Returns an empty string when
   * no clients are registered.
   */
  exportSshConfig: () => requestText("/clients/export/ssh-config"),

  // --- Tasks ---
  taskStatus: (taskId: string) =>
    request<TaskStatus>(`/tasks/${taskId}`),

  // --- Crypto ---
  /**
   * Snapshot of the encryption-at-rest layer: which backend is
   * active, its current key version, and per-table counts of rows
   * with ciphertext vs. legacy rows that bypassed the encryption
   * seam. Used by the dashboard's "Crypto status" panel and as a
   * pre-flight sanity check before applying the drop-plaintext
   * migration.
   */
  cryptoStatus: () => request<CryptoStatus>("/crypto/status"),

  // --- Certificates (Phase 2d CP3.4) ---
  /**
   * Return the cert subject the API saw on the current request, plus
   * the resolved operator row. The dashboard's "Who am I?" splash
   * renders the result verbatim — a 200 here is the visible proof
   * that the mTLS handshake worked end-to-end.
   */
  whoami: () => request<WhoAmI>("/certs/whoami"),
  /** List every cert audit row (live + revoked). Admin / auditor. */
  listCertificates: () => request<Certificate[]>("/certs"),
  /**
   * Issue a new leaf cert via the configured PKI backend and record
   * the audit row. Admin only. The private key in the response body
   * is the *only* copy — the server keeps none.
   *
   * For `cert_type: "dashboard"` the response additionally carries a
   * base64-encoded PKCS#12 bundle (`pkcs12_b64`) that the operator
   * imports into their browser.
   */
  issueCertificate: (payload: CertificateIssueRequest) =>
    request<CertificateIssueResponse>("/certs", {
      method: "POST",
      body: payload,
    }),
  /**
   * Revoke an issued cert by row id. Admin only. Two-step under the
   * hood (CRL update + row flip) but exposed as one request to the
   * dashboard. Idempotent — a retry after a flaky network is safe.
   */
  revokeCertificate: (id: number) =>
    request<CertificateRevokeResponse>(`/certs/${id}/revoke`, {
      method: "POST",
    }),
};
