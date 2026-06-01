/**
 * Component-level smoke tests for the Phase 2e cycle 4 Audit page.
 *
 * Four concerns we want pinned so a future refactor surfaces in PR
 * review rather than in a broken dashboard:
 *
 * 1. **Rows render.** Each audit event becomes a table row with its
 *    event slug, actor CN, resource binding, and action visible.
 * 2. **Empty state.** When there are zero rows the page renders an
 *    informative empty panel rather than a blank table.
 * 3. **Filters wire to the API.** Typing in the event filter (or
 *    resource_type filter) sends the value through as a query string
 *    on the next request — the dashboard's filter shape has to match
 *    the backend contract one-for-one.
 * 4. **Pagination control.** The "Next" button bumps `offset` by the
 *    current page size and the page issues a fresh request.
 *
 * Like `certificates.test.tsx`, fetch is stubbed per-test rather than
 * going through MSW — the surface is small and hand-rolled stubs are
 * clearer than a configured server.
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
import AuditPage from "@/app/audit/page";
import type { AuditEvent, AuditEventList } from "@/lib/types";

function makeFetchResponse(status: number, body: unknown): Response {
  return {
    status,
    ok: status >= 200 && status < 300,
    statusText: status === 200 ? "OK" : "ERR",
    text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
  } as unknown as Response;
}

function makeAuditEvent(overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    id: 1,
    ts: "2026-06-01T12:00:00Z",
    event: "server.create",
    actor_cn: "ops@wg.local",
    actor_serial: "4242424242",
    actor_role: "admin",
    resource_type: "server",
    resource_id: 7,
    action: "create",
    before_hash: null,
    after_hash: "a".repeat(64),
    payload: { hostname: "hub.example.com" },
    request_id: "req-1",
    ...overrides,
  };
}

function makeList(
  items: AuditEvent[],
  overrides: Partial<AuditEventList> = {},
): AuditEventList {
  return {
    items,
    total: items.length,
    limit: 100,
    offset: 0,
    ...overrides,
  };
}

function fetchRouter(
  routes: Record<
    string,
    Response | ((url: string, init?: RequestInit) => Response)
  >,
): (url: string | URL, init?: RequestInit) => Promise<Response> {
  return async (input, init) => {
    const url = typeof input === "string" ? input : input.toString();
    for (const [needle, value] of Object.entries(routes)) {
      if (url.includes(needle)) {
        return typeof value === "function" ? value(url, init) : value;
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
      <AuditPage />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.restoreAllMocks();
  cleanup();
});

describe("Audit page — row rendering", () => {
  it("renders one row per audit event", async () => {
    vi.spyOn(global, "fetch").mockImplementation(
      fetchRouter({
        "/audit": makeFetchResponse(
          200,
          makeList([
            makeAuditEvent({
              id: 10,
              event: "server.create",
              actor_cn: "alice@wg.local",
              resource_type: "server",
              resource_id: 7,
            }),
            makeAuditEvent({
              id: 11,
              event: "client.delete",
              actor_cn: "bob@wg.local",
              resource_type: "client",
              resource_id: 3,
              action: "delete",
            }),
          ]),
        ),
      }) as typeof fetch,
    );

    renderPage();

    expect(await screen.findByText("server.create")).toBeInTheDocument();
    expect(screen.getByText("client.delete")).toBeInTheDocument();
    expect(screen.getByText("alice@wg.local")).toBeInTheDocument();
    expect(screen.getByText("bob@wg.local")).toBeInTheDocument();
  });

  it("renders an empty state when the list is empty", async () => {
    vi.spyOn(global, "fetch").mockImplementation(
      fetchRouter({
        "/audit": makeFetchResponse(200, makeList([])),
      }) as typeof fetch,
    );

    renderPage();

    expect(
      await screen.findByText(/no audit events/i),
    ).toBeInTheDocument();
  });
});

describe("Audit page — filters", () => {
  it("typing in the event filter forwards the value as a query param", async () => {
    const fetchStub = vi.spyOn(global, "fetch").mockImplementation(
      fetchRouter({
        "/audit": makeFetchResponse(200, makeList([])),
      }) as typeof fetch,
    );

    renderPage();

    // Initial render fires one /audit call (no filter)
    await waitFor(() => {
      expect(
        fetchStub.mock.calls.filter(([url]) =>
          String(url).includes("/audit"),
        ).length,
      ).toBeGreaterThanOrEqual(1);
    });

    const eventInput = await screen.findByLabelText(/event/i);
    fireEvent.change(eventInput, { target: { value: "server.create" } });

    await waitFor(() => {
      const calls = fetchStub.mock.calls.filter(([url]) =>
        String(url).includes("event=server.create"),
      );
      expect(calls.length).toBeGreaterThan(0);
    });
  });

  it("typing in the actor CN filter forwards as actor_cn=", async () => {
    const fetchStub = vi.spyOn(global, "fetch").mockImplementation(
      fetchRouter({
        "/audit": makeFetchResponse(200, makeList([])),
      }) as typeof fetch,
    );

    renderPage();

    const actorInput = await screen.findByLabelText(/actor/i);
    fireEvent.change(actorInput, { target: { value: "alice@wg.local" } });

    await waitFor(() => {
      const calls = fetchStub.mock.calls.filter(([url]) =>
        String(url).includes("actor_cn=alice%40wg.local"),
      );
      expect(calls.length).toBeGreaterThan(0);
    });
  });
});

describe("Audit page — pagination", () => {
  it("Next button advances the offset by the current page size", async () => {
    const fetchStub = vi.spyOn(global, "fetch").mockImplementation(
      fetchRouter({
        "/audit": makeFetchResponse(
          200,
          makeList(
            Array.from({ length: 5 }, (_, i) =>
              makeAuditEvent({ id: 100 + i }),
            ),
            { total: 20, limit: 5, offset: 0 },
          ),
        ),
      }) as typeof fetch,
    );

    renderPage();

    // Wait for the first page to actually render — without this the
    // Next button can be picked up while still disabled (items
    // length 0 ⇒ hasNext false), which silently swallows the click.
    // All five rows share the same default slug; pin on the count.
    await screen.findAllByText("server.create");

    const nextButton = await screen.findByRole("button", { name: /next/i });
    fireEvent.click(nextButton);

    await waitFor(() => {
      const calls = fetchStub.mock.calls.filter(([url]) =>
        String(url).includes("offset=5"),
      );
      expect(calls.length).toBeGreaterThan(0);
    });
  });

  it("Prev button is disabled on the first page", async () => {
    vi.spyOn(global, "fetch").mockImplementation(
      fetchRouter({
        "/audit": makeFetchResponse(
          200,
          makeList([makeAuditEvent()], {
            total: 1,
            limit: 100,
            offset: 0,
          }),
        ),
      }) as typeof fetch,
    );

    renderPage();

    const prevButton = await screen.findByRole("button", { name: /prev/i });
    expect(prevButton).toBeDisabled();
  });
});
