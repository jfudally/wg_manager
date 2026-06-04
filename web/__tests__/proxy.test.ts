/**
 * Unit tests for the BFF proxy's request-forwarding contract.
 *
 * The proxy lives in :mod:`web/lib/proxy.ts` and is exercised end-to-end
 * by the Next.js Route Handler at ``app/api/proxy/[...path]/route.ts``.
 * Tests inject a fake :type:`UpstreamFetcher` so we can pin
 * method/url/headers/body wire-formatting without standing up a real
 * mTLS listener — the real :func:`makeMTlsFetcher` is exercised by the
 * dev server itself (Makefile ``make ui-dev`` against ``make run``).
 */

import { describe, expect, it } from "vitest";
import {
  forwardToUpstream,
  type UpstreamFetcher,
  type UpstreamRequest,
  type UpstreamResponse,
} from "@/lib/proxy";

interface FakeFetcher extends UpstreamFetcher {
  last?: UpstreamRequest;
}

function fakeFetcher(opts?: {
  status?: number;
  body?: string | Uint8Array;
  headers?: Record<string, string>;
}): FakeFetcher {
  const fn = (async (req: UpstreamRequest): Promise<UpstreamResponse> => {
    fn.last = req;
    const body =
      typeof opts?.body === "string"
        ? new TextEncoder().encode(opts.body)
        : opts?.body ?? new Uint8Array();
    return {
      status: opts?.status ?? 200,
      headers: new Headers(opts?.headers ?? { "content-type": "application/json" }),
      body,
    };
  }) as FakeFetcher;
  return fn;
}

describe("forwardToUpstream", () => {
  it("forwards GET to the upstream path + query and returns the body verbatim", async () => {
    const fetcher = fakeFetcher({ body: '[{"id":1,"name":"lab"}]' });

    const req = new Request(
      "http://localhost:3000/api/proxy/clients?force=true",
    );
    const res = await forwardToUpstream(
      req,
      ["clients"],
      "https://api.test:8000",
      fetcher,
    );

    // Phase 3c — BFF rewrites every path to the /v1 namespace.
    expect(fetcher.last?.url).toBe(
      "https://api.test:8000/v1/clients?force=true",
    );
    expect(fetcher.last?.method).toBe("GET");
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('[{"id":1,"name":"lab"}]');
    expect(res.headers.get("content-type")).toBe("application/json");
  });

  it("joins nested path segments with /", async () => {
    const fetcher = fakeFetcher({ status: 202 });

    const req = new Request(
      "http://localhost:3000/api/proxy/servers/7/discover",
      { method: "POST" },
    );
    await forwardToUpstream(
      req,
      ["servers", "7", "discover"],
      "https://api.test:8000",
      fetcher,
    );

    // Phase 3c — BFF rewrites every path to the /v1 namespace.
    expect(fetcher.last?.url).toBe(
      "https://api.test:8000/v1/servers/7/discover",
    );
    expect(fetcher.last?.method).toBe("POST");
  });

  it("does not double-prepend /v1 when the inbound path already carries it", async () => {
    const fetcher = fakeFetcher({});

    const req = new Request("http://localhost:3000/api/proxy/v1/clients");
    await forwardToUpstream(
      req,
      ["v1", "clients"],
      "https://api.test:8000",
      fetcher,
    );

    expect(fetcher.last?.url).toBe("https://api.test:8000/v1/clients");
  });

  it("forwards a JSON POST body byte-for-byte", async () => {
    const fetcher = fakeFetcher({
      status: 201,
      body: '{"task_id":"abc","server":{"id":1}}',
    });

    const payload = JSON.stringify({ hostname: "hub.example.com" });
    const req = new Request("http://localhost:3000/api/proxy/servers", {
      method: "POST",
      body: payload,
      headers: { "content-type": "application/json" },
    });
    const res = await forwardToUpstream(
      req,
      ["servers"],
      "https://api.test:8000",
      fetcher,
    );

    expect(fetcher.last?.method).toBe("POST");
    expect(new TextDecoder().decode(fetcher.last?.body)).toBe(payload);
    // content-type from the inbound request must survive the proxy hop.
    expect(fetcher.last?.headers["content-type"]).toBe("application/json");
    expect(res.status).toBe(201);
    const json = await res.json();
    expect(json.task_id).toBe("abc");
  });

  it("strips the inbound Host header so the upstream sees its own host", async () => {
    const fetcher = fakeFetcher({});

    const req = new Request("http://localhost:3000/api/proxy/clients", {
      // Browsers always set Host; if we forwarded it the upstream would
      // see "localhost:3000" instead of its own bound hostname.
      headers: { host: "localhost:3000", "x-trace": "keep-me" },
    });
    await forwardToUpstream(
      req,
      ["clients"],
      "https://api.test:8000",
      fetcher,
    );

    const fwd = fetcher.last?.headers ?? {};
    const lowerKeys = Object.keys(fwd).map((k) => k.toLowerCase());
    expect(lowerKeys).not.toContain("host");
    // Non-hop-by-hop headers must pass through untouched.
    expect(fwd["x-trace"]).toBe("keep-me");
  });

  it("surfaces non-2xx upstream status + body verbatim", async () => {
    const fetcher = fakeFetcher({
      status: 409,
      body: '{"detail":"SSH role \'lab\' already exists"}',
    });

    const req = new Request("http://localhost:3000/api/proxy/ssh-keys", {
      method: "POST",
      body: JSON.stringify({ name: "lab" }),
      headers: { "content-type": "application/json" },
    });
    const res = await forwardToUpstream(
      req,
      ["ssh-keys"],
      "https://api.test:8000",
      fetcher,
    );

    expect(res.status).toBe(409);
    const json = await res.json();
    expect(json.detail).toContain("already exists");
  });

  it("handles plain-text upstream responses (e.g. wg0.conf export)", async () => {
    // ``GET /clients/{id}/config`` returns ``text/plain``. The proxy
    // must surface the body unchanged and preserve the content-type so
    // the dashboard's ``requestText`` helper renders it verbatim.
    const wg0 =
      "[Interface]\nPrivateKey = abc=\nAddress = 10.9.0.4/32\n\n" +
      "[Peer]\nPublicKey = SRV=\nEndpoint = hub.example.com:51820\n";
    const fetcher = fakeFetcher({
      body: wg0,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });

    const req = new Request(
      "http://localhost:3000/api/proxy/clients/9/config",
    );
    const res = await forwardToUpstream(
      req,
      ["clients", "9", "config"],
      "https://api.test:8000",
      fetcher,
    );

    expect(await res.text()).toBe(wg0);
    expect(res.headers.get("content-type")).toBe("text/plain; charset=utf-8");
  });
});
