/**
 * Component test for client host-cert rotation on the Clients page —
 * the twin of `servers-host-cert.test.tsx`.
 *
 * Pinned behaviours:
 *
 * 1. An SSH client with a minted cert shows the serial and an expiry
 *    hint. Client certs default to a 24h TTL, so sub-day expiries render
 *    in hours ("expires in 5h") rather than a useless "0d".
 * 2. SSH clients expose a "Rotate cert" button that POSTs to
 *    `/clients/{id}/rotate-host-cert`.
 * 3. Manual clients have no SSH access, so they get no Rotate button.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import ClientsPage from "@/app/clients/page";
import type { Client } from "@/lib/types";

function makeFetchResponse(status: number, body: unknown): Response {
  return {
    status,
    ok: status >= 200 && status < 300,
    statusText: status >= 200 && status < 300 ? "OK" : "ERR",
    text: async () => JSON.stringify(body),
  } as unknown as Response;
}

function hoursFromNow(hours: number): string {
  return new Date(Date.now() + hours * 60 * 60 * 1000).toISOString();
}

function makeClient(overrides: Partial<Client> = {}): Client {
  return {
    id: 1,
    name: "spoke",
    hostname: "spoke.example.com",
    ssh_port: 22,
    ssh_username: "ubuntu",
    ssh_key_id: 1,
    server_id: 7,
    address: "10.9.0.2/32",
    public_key: "PUB",
    is_manual: false,
    status: "ready",
    created_at: "2026-09-24T00:00:00Z",
    ...overrides,
  };
}

function stubApi(clients: Client[]) {
  return vi.spyOn(global, "fetch").mockImplementation((async (
    input: string | URL,
    init?: RequestInit,
  ) => {
    const url = typeof input === "string" ? input : input.toString();
    if (url.includes("/rotate-host-cert") && init?.method === "POST") {
      return makeFetchResponse(202, { task_id: "rot-1", client: clients[0] });
    }
    if (url.includes("/tasks/")) {
      return makeFetchResponse(200, { task_id: "rot-1", state: "PENDING" });
    }
    if (url.includes("/clients")) return makeFetchResponse(200, clients);
    return makeFetchResponse(200, []);
  }) as typeof fetch);
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <ClientsPage />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.restoreAllMocks();
  cleanup();
});

describe("Clients page — host cert", () => {
  it("shows the cert serial and a sub-day expiry in hours", async () => {
    stubApi([
      makeClient({
        host_cert_serial: 777000111,
        host_cert_valid_before: hoursFromNow(5.5),
      }),
    ]);
    renderPage();

    expect(await screen.findByText(/#777000111/)).toBeInTheDocument();
    expect(screen.getByText(/expires in (5|6)h/)).toBeInTheDocument();
  });

  it("POSTs to the rotate endpoint when Rotate cert is clicked", async () => {
    const fetchSpy = stubApi([makeClient({ id: 3 })]);
    renderPage();

    fireEvent.click(await screen.findByRole("button", { name: /rotate cert/i }));

    await waitFor(() => {
      const posts = fetchSpy.mock.calls.filter(
        ([url, init]) =>
          String(url).endsWith("/clients/3/rotate-host-cert") &&
          init?.method === "POST",
      );
      expect(posts.length).toBe(1);
    });
  });

  it("offers no Rotate cert button for manual clients", async () => {
    stubApi([
      makeClient({
        is_manual: true,
        hostname: null,
        ssh_username: null,
        ssh_key_id: null,
      }),
    ]);
    renderPage();

    expect(await screen.findByText("spoke")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /rotate cert/i }),
    ).not.toBeInTheDocument();
  });
});
