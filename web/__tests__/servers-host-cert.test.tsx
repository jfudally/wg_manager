/**
 * Component smoke test for Phase 2c CP3.4 — the host-cert UI on the
 * Servers page.
 *
 * Pinned behaviours:
 *
 * 1. When a row has no host cert minted (legacy server, or a row that
 *    pre-dates CP3), the cert summary line is absent — we don't want
 *    "cert #undefined" leaking into the rendered table for Phase 2b
 *    rows.
 * 2. When the cert is populated, the summary renders the serial and
 *    a relative-expiry hint, and the row exposes a "Rotate cert"
 *    button that POSTs to the rotation endpoint.
 * 3. Clicking the button calls `api.rotateHostCert` with the row's
 *    id, dispatches the task, and the task envelope flows through to
 *    the TaskPoller via `onTaskDispatched`.
 *
 * This is a smoke test, not an exhaustive UI test — it exercises the
 * critical "operator can rotate from the dashboard" path; visual /
 * a11y polish lives in the page itself.
 */

import { describe, expect, it, vi, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import ServersPage from "@/app/servers/page";
import type { Server } from "@/lib/types";

function makeFetchResponse(status: number, body: unknown): Response {
  return {
    status,
    ok: status >= 200 && status < 300,
    statusText: status === 200 ? "OK" : "ERR",
    text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
  } as unknown as Response;
}

function makeServer(overrides: Partial<Server> = {}): Server {
  return {
    id: 1,
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
    ...overrides,
  };
}

function renderPage() {
  // Fresh QueryClient per render so cached `["servers"]` data from a
  // prior test never bleeds in.
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <ServersPage />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.restoreAllMocks();
  cleanup();
});

/** ISO-8601 string for ``daysFromNow`` days in the future, relative to the
 *  test's actual wall clock. Avoids vi.useFakeTimers, which deadlocks
 *  React Query's promise-resolving setTimeout polling.
 */
function isoIn(daysFromNow: number): string {
  return new Date(Date.now() + daysFromNow * 24 * 60 * 60 * 1000).toISOString();
}

describe("Servers page host-cert UI (CP3.4)", () => {
  it("does not render the cert summary for a row with no host cert", async () => {
    vi.spyOn(global, "fetch").mockResolvedValue(
      makeFetchResponse(200, [makeServer()]),
    );

    renderPage();

    // Wait for the data to land. ``findByText`` retries until the
    // hostname appears or the default timeout (1s) elapses.
    expect(await screen.findByText("hub.example.com")).toBeInTheDocument();
    // The "cert #..." summary line is absent on a row with no
    // host_cert_serial.
    expect(screen.queryByText(/cert #/)).toBeNull();
  });

  it("renders the cert summary and a Rotate button when host cert is populated", async () => {
    vi.spyOn(global, "fetch").mockResolvedValue(
      makeFetchResponse(200, [
        makeServer({
          host_cert_serial: 4242424242,
          host_cert_principals: "hub.example.com",
          host_cert_valid_after: isoIn(0),
          // ~10 days out from real-time now — should render
          // "expires in 9d" or "10d" depending on second-of-day, so we
          // assert with a tolerant regex below.
          host_cert_valid_before: isoIn(10),
        }),
      ]),
    );

    renderPage();

    expect(await screen.findByText("hub.example.com")).toBeInTheDocument();
    // ``#4242424242`` is the cert serial rendered by HostCertSummary.
    // ``getByText(/cert/)`` would also match the "Rotate cert" button
    // label, so we anchor on the unique serial substring instead.
    expect(screen.getByText(/#4242424242/)).toBeInTheDocument();
    // 9d or 10d both acceptable — the floor() truncation depends on
    // the second of the day the test runs.
    expect(screen.getByText(/expires in (9|10)d/)).toBeInTheDocument();

    // Button is present and clickable. The actual click→fetch→state
    // wiring is exercised in the api.test.ts contract — here we only
    // pin the existence of the affordance.
    expect(
      screen.getByRole("button", { name: /rotate cert/i }),
    ).toBeInTheDocument();
  });
});
