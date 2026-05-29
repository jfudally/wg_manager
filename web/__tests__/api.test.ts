/**
 * Smoke tests for the typed API client. Stubs `fetch` rather than
 * standing up MSW — the surface area is small enough that hand-rolled
 * stubs are clearer than configuring a server.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, api, b64encode, request } from "@/lib/api";

function makeResponse(
  status: number,
  body: unknown,
  ok = status >= 200 && status < 300,
): Response {
  return {
    status,
    ok,
    statusText: ok ? "OK" : "ERR",
    text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
  } as unknown as Response;
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("request()", () => {
  it("parses a JSON body on 200", async () => {
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValue(
      makeResponse(200, [{ id: 1, name: "lab" }]),
    );

    const result = await request<Array<{ id: number; name: string }>>(
      "/ssh-keys",
    );

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://test.local/ssh-keys",
      expect.objectContaining({ method: "GET" }),
    );
    expect(result).toEqual([{ id: 1, name: "lab" }]);
  });

  it("throws ApiError with detail message on 4xx", async () => {
    vi.spyOn(global, "fetch").mockResolvedValue(
      makeResponse(409, { detail: "SSH key named 'lab' already exists" }, false),
    );

    await expect(api.createSshKey({ name: "lab" })).rejects.toMatchObject({
      // ApiError is a real class — also assert via instanceof.
      status: 409,
      message: "SSH key named 'lab' already exists",
    });
  });

  it("returns undefined on 204", async () => {
    vi.spyOn(global, "fetch").mockResolvedValue(
      makeResponse(204, "", true),
    );
    const result = await api.deleteSshKey(7);
    expect(result).toBeUndefined();
  });

  it("ApiError is throwable and catchable as that class", async () => {
    vi.spyOn(global, "fetch").mockResolvedValue(
      makeResponse(404, { detail: "Server not found" }, false),
    );
    try {
      await api.getServer(99);
      throw new Error("should have thrown");
    } catch (exc) {
      expect(exc).toBeInstanceOf(ApiError);
      expect((exc as ApiError).status).toBe(404);
    }
  });
});

describe("b64encode()", () => {
  it("matches Buffer for ASCII input", () => {
    expect(b64encode("hello")).toBe(Buffer.from("hello").toString("base64"));
  });

  it("round-trips a sample PEM body", () => {
    const pem =
      "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEBODY\n-----END OPENSSH PRIVATE KEY-----\n";
    const encoded = b64encode(pem);
    expect(Buffer.from(encoded, "base64").toString("utf-8")).toBe(pem);
  });
});

describe("endpoint paths", () => {
  it("discoverAllServers POSTs the right path", async () => {
    const fetchSpy = vi
      .spyOn(global, "fetch")
      .mockResolvedValue(
        makeResponse(202, { task_id: "abc", server_count: 3 }),
      );
    const r = await api.discoverAllServers();
    expect(r.task_id).toBe("abc");
    expect(fetchSpy).toHaveBeenCalledWith(
      "http://test.local/servers/discover-all",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("listDiscoveredPeers builds the per-server URL", async () => {
    const fetchSpy = vi
      .spyOn(global, "fetch")
      .mockResolvedValue(makeResponse(200, []));
    await api.listDiscoveredPeers(42);
    expect(fetchSpy).toHaveBeenCalledWith(
      "http://test.local/servers/42/discovered-peers",
      expect.any(Object),
    );
  });

  it("updateServer PATCHes only the supplied fields", async () => {
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValue(
      makeResponse(200, {
        id: 7,
        hostname: "renamed.example.com",
        ssh_port: 22,
        ssh_username: "ubuntu",
        ssh_key_id: 1,
        endpoint_host: "renamed.example.com",
        endpoint_port: 51820,
        interface: "wg0",
        subnet: "10.9.0.0/24",
        address: "10.9.0.1/24",
        public_key: "PUB",
        status: "ready",
        created_at: "2026-05-21T00:00:00Z",
      }),
    );
    const updated = await api.updateServer(7, {
      hostname: "renamed.example.com",
    });
    expect(updated.hostname).toBe("renamed.example.com");
    expect(fetchSpy).toHaveBeenCalledWith(
      "http://test.local/servers/7",
      expect.objectContaining({
        method: "PATCH",
        body: JSON.stringify({ hostname: "renamed.example.com" }),
      }),
    );
  });

  it("deleteServer issues DELETE with no force flag by default", async () => {
    const fetchSpy = vi
      .spyOn(global, "fetch")
      .mockResolvedValue(makeResponse(204, "", true));
    await api.deleteServer(7);
    expect(fetchSpy).toHaveBeenCalledWith(
      "http://test.local/servers/7",
      expect.objectContaining({ method: "DELETE" }),
    );
  });

  it("deleteServer adds ?force=true when requested", async () => {
    const fetchSpy = vi
      .spyOn(global, "fetch")
      .mockResolvedValue(makeResponse(204, "", true));
    await api.deleteServer(7, true);
    expect(fetchSpy).toHaveBeenCalledWith(
      "http://test.local/servers/7?force=true",
      expect.objectContaining({ method: "DELETE" }),
    );
  });

  it("updateClient PATCHes only the supplied fields", async () => {
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValue(
      makeResponse(200, {
        id: 3,
        name: "alpha-renamed",
        hostname: "alpha.example.com",
        ssh_port: 22,
        ssh_username: "ubuntu",
        ssh_key_id: 1,
        server_id: 1,
        address: "10.9.0.2/32",
        public_key: "PUB",
        status: "ready",
        created_at: "2026-05-21T00:00:00Z",
      }),
    );
    const updated = await api.updateClient(3, { name: "alpha-renamed" });
    expect(updated.name).toBe("alpha-renamed");
    expect(fetchSpy).toHaveBeenCalledWith(
      "http://test.local/clients/3",
      expect.objectContaining({
        method: "PATCH",
        body: JSON.stringify({ name: "alpha-renamed" }),
      }),
    );
  });

  it("updateSshKey PATCHes only the supplied fields", async () => {
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValue(
      makeResponse(200, {
        id: 4,
        name: "lab-renamed",
        created_at: "2026-05-21T00:00:00Z",
      }),
    );
    const updated = await api.updateSshKey(4, { name: "lab-renamed" });
    expect(updated.name).toBe("lab-renamed");
    expect(fetchSpy).toHaveBeenCalledWith(
      "http://test.local/ssh-keys/4",
      expect.objectContaining({
        method: "PATCH",
        body: JSON.stringify({ name: "lab-renamed" }),
      }),
    );
  });

  // Phase 2c CP4.4 retired the ``private_key_b64`` field on the
  // PATCH body — the row carries no key material, so the only
  // mutable field is ``name``. The rename case above already pins
  // that contract.

  it("exportSshConfig GETs the export endpoint and returns the raw body", async () => {
    const body =
      "Host alpha.vpn\n" +
      "    HostName 10.9.0.2\n" +
      "    User ubuntu\n" +
      "    IdentityFile ~/.ssh/lab\n";
    const fetchSpy = vi
      .spyOn(global, "fetch")
      .mockResolvedValue(makeResponse(200, body));
    const result = await api.exportSshConfig();
    expect(result).toBe(body);
    expect(fetchSpy).toHaveBeenCalledWith(
      "http://test.local/clients/export/ssh-config",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("exportSshConfig returns an empty string when no clients exist", async () => {
    vi.spyOn(global, "fetch").mockResolvedValue(makeResponse(200, ""));
    const result = await api.exportSshConfig();
    expect(result).toBe("");
  });

  it("registerManualClient POSTs to /clients/manual and returns wg_config", async () => {
    // Post-redesign: the rendered wg0.conf body is returned inline as
    // `wg_config` on the response. The dashboard surfaces it once via
    // ManualClientConfigPanel; the control plane no longer persists the
    // private key, so there is no GET /clients/{id}/config to re-fetch
    // from later.
    const wgConfig =
      "[Interface]\nPrivateKey = SECRET-WG-KEY=\nAddress = 10.9.0.4/32\n\n" +
      "[Peer]\nPublicKey = SRV=\nEndpoint = hub.example.com:51820\n" +
      "AllowedIPs = 10.9.0.0/24\nPersistentKeepalive = 25\n";
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValue(
      makeResponse(201, {
        task_id: "reconf-abc",
        client: {
          id: 9,
          name: "phone",
          hostname: null,
          ssh_port: 22,
          ssh_username: null,
          ssh_key_id: null,
          server_id: 1,
          address: "10.9.0.4/32",
          public_key: "PUBKEY_PHONE=",
          is_manual: true,
          status: "ready",
          created_at: "2026-05-27T00:00:00Z",
        },
        wg_config: wgConfig,
      }),
    );
    const result = await api.registerManualClient({
      name: "phone",
      server_id: 1,
    });
    expect(result.client.is_manual).toBe(true);
    expect(result.client.hostname).toBeNull();
    expect(result.wg_config).toBe(wgConfig);
    expect(fetchSpy).toHaveBeenCalledWith(
      "http://test.local/clients/manual",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ name: "phone", server_id: 1 }),
      }),
    );
  });

  it("cryptoStatus GETs /crypto/status and returns the panel payload", async () => {
    // Post-Alembic-0009 the response shape is just {backend, key_version} —
    // no row carries ciphertext any more, so the per-table counters are
    // gone.
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValue(
      makeResponse(200, {
        backend: "local-dev",
        key_version: 1,
      }),
    );
    const result = await api.cryptoStatus();
    expect(result.backend).toBe("local-dev");
    expect(result.key_version).toBe(1);
    expect(fetchSpy).toHaveBeenCalledWith(
      "http://test.local/crypto/status",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("listSshKeys exposes the per-row mode", async () => {
    // Phase 2c CP4.4 — the row carries `mode` (always `"ca"` post-
    // CP4.4) and no `encrypted` flag.
    vi.spyOn(global, "fetch").mockResolvedValue(
      makeResponse(200, [
        {
          id: 1,
          name: "lab",
          created_at: "2026-05-27T00:00:00Z",
          mode: "ca",
        },
      ]),
    );
    const rows = await api.listSshKeys();
    expect(rows[0].mode).toBe("ca");
  });

  it("rotateHostCert POSTs to /servers/{id}/rotate-host-cert", async () => {
    // Phase 2c CP3.3 — the dashboard's "Rotate host cert" button
    // calls this endpoint, gets back a {task_id, server} envelope,
    // and threads the task_id through TaskPoller like every other
    // server-side async action.
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValue(
      makeResponse(202, {
        task_id: "rotate-task-123",
        server: {
          id: 7,
          hostname: "hub.example.com",
          ssh_port: 22,
          ssh_username: "ubuntu",
          ssh_key_id: 1,
          endpoint_host: "hub.example.com",
          endpoint_port: 51820,
          interface: "wg0",
          subnet: "10.9.0.0/24",
          address: "10.9.0.1/24",
          public_key: "PUB",
          status: "ready",
          created_at: "2026-05-27T00:00:00Z",
          host_cert_serial: 123456789,
          host_cert_principals: "hub.example.com",
          host_cert_valid_after: "2026-05-27T00:00:00Z",
          host_cert_valid_before: "2026-05-28T00:00:00Z",
        },
      }),
    );

    const result = await api.rotateHostCert(7);

    expect(result.task_id).toBe("rotate-task-123");
    expect(result.server.id).toBe(7);
    expect(result.server.host_cert_serial).toBe(123456789);
    expect(fetchSpy).toHaveBeenCalledWith(
      "http://test.local/servers/7/rotate-host-cert",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("rotateHostCert surfaces a 409 from the API as ApiError", async () => {
    // The backend returns 409 when SSH_AUTH_MODE != "ca". The
    // dashboard catches this through the standard ApiError path and
    // renders the detail as the inline error message.
    vi.spyOn(global, "fetch").mockResolvedValue(
      makeResponse(
        409,
        {
          detail:
            "host-cert rotation requires SSH_AUTH_MODE=ca; current value is 'legacy'. See docs/vault-cookbook.md §3 for the CA-mode setup.",
        },
        false,
      ),
    );
    await expect(api.rotateHostCert(7)).rejects.toMatchObject({
      status: 409,
    });
  });

  // Phase 2c CP4.4 retired ``api.migrateKeyToCA`` (and the endpoint
  // it called) — every SSH role is CA-mode by construction now, so
  // there is no legacy → CA flip to drive from the dashboard.

  it("deleteClient returns the hub reconfigure task envelope", async () => {
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValue(
      makeResponse(202, { task_id: "abc", client_id: 3, server_id: 1 }),
    );
    const result = await api.deleteClient(3);
    expect(result).toEqual({
      task_id: "abc",
      client_id: 3,
      server_id: 1,
    });
    expect(fetchSpy).toHaveBeenCalledWith(
      "http://test.local/clients/3",
      expect.objectContaining({ method: "DELETE" }),
    );
  });
});
