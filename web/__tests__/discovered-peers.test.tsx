/**
 * Component-level tests for the Discovered Peers page.
 *
 * The behaviour we pin here is the "clear results on a new run" contract:
 * when the operator dispatches a discovery run, the currently-displayed
 * peer list must be cleared immediately so the table never shows stale
 * rows from a previous pass while the new run is in flight. The backend
 * prunes vanished peers on its side; this is the matching frontend half
 * so the dashboard reflects "what was just discovered", not a leftover
 * snapshot.
 *
 * Like `audit.test.tsx`, fetch is stubbed per-test with a small router
 * rather than going through MSW.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  render,
  screen,
  cleanup,
  fireEvent,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import DiscoveredPeersPage from "@/app/discovered-peers/page";
import type { DiscoveredPeer } from "@/lib/types";

function makeFetchResponse(status: number, body: unknown): Response {
  return {
    status,
    ok: status >= 200 && status < 300,
    statusText: status === 200 ? "OK" : "ERR",
    text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
  } as unknown as Response;
}

function makePeer(overrides: Partial<DiscoveredPeer> = {}): DiscoveredPeer {
  return {
    id: 1,
    server_id: 1,
    public_key: "PEER_ALPHA_PUBKEY",
    allowed_ips: "10.9.0.2/32",
    endpoint: "203.0.113.10:51820",
    last_handshake_at: "2026-06-01T12:00:00Z",
    rx_bytes: 1024,
    tx_bytes: 2048,
    persistent_keepalive: 25,
    is_managed: false,
    first_seen_at: "2026-06-01T12:00:00Z",
    last_seen_at: "2026-06-01T12:00:00Z",
    ...overrides,
  };
}

function fetchRouter(
  routes: Array<[string, Response | ((url: string) => Response)]>,
): (url: string | URL, init?: RequestInit) => Promise<Response> {
  return async (input) => {
    const url = typeof input === "string" ? input : input.toString();
    for (const [needle, value] of routes) {
      if (url.includes(needle)) {
        return typeof value === "function" ? value(url) : value;
      }
    }
    return makeFetchResponse(404, { detail: `unstubbed ${url}` });
  };
}

function renderPage() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <DiscoveredPeersPage />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.restoreAllMocks();
  cleanup();
});

describe("Discovered peers page — clear results on a new run", () => {
  it("clears the displayed peer list when a discovery run is dispatched", async () => {
    // More-specific routes first: both discovered-peers and discover-all
    // paths contain the substring "/servers".
    vi.spyOn(global, "fetch").mockImplementation(
      fetchRouter([
        [
          "/servers/discovered-peers/all",
          makeFetchResponse(200, [
            makePeer({ id: 1, public_key: "PEER_ALPHA_PUBKEY" }),
            makePeer({ id: 2, public_key: "PEER_BETA_PUBKEY" }),
          ]),
        ],
        [
          "/servers/discover-all",
          makeFetchResponse(200, { task_id: "task-1", server_count: 1 }),
        ],
        ["/servers", makeFetchResponse(200, [])],
      ]) as typeof fetch,
    );

    renderPage();

    // Both peers render initially.
    expect(await screen.findByText(/PEER_ALPHA/)).toBeInTheDocument();
    expect(screen.getByText(/PEER_BETA/)).toBeInTheDocument();

    // Dispatch a discovery run.
    fireEvent.click(
      screen.getByRole("button", { name: /discover all servers/i }),
    );

    // The stale rows must clear immediately, falling back to the empty
    // state rather than continuing to show the previous pass's peers.
    await waitFor(() => {
      expect(screen.queryByText(/PEER_ALPHA/)).not.toBeInTheDocument();
      expect(screen.queryByText(/PEER_BETA/)).not.toBeInTheDocument();
    });
    expect(screen.getByText(/No peers discovered yet/i)).toBeInTheDocument();
  });
});
