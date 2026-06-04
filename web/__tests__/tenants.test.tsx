/**
 * Component-level smoke tests for the Phase 3b cycle 2 Tenants page.
 *
 * The dashboard slice covers the CRUD surface the cycle 2 backend
 * ships:
 *
 * 1. **List render.** Each tenant row appears with its name + slug.
 * 2. **Empty state.** Zero tenants → an informative panel (the
 *    Alembic 0014 default tenant means production never sees this
 *    in practice, but the page should still render cleanly).
 * 3. **Create form.** Submitting the form POSTs to `/tenants` with
 *    the typed name + slug.
 * 4. **Tenant detail — operator table.** Selecting a tenant fetches
 *    the per-tenant operator list and renders one row per attached
 *    operator with the per-tenant role.
 * 5. **Attach form.** Submitting the attach form POSTs to
 *    `/tenants/{slug}/operators`.
 * 6. **Detach button.** Clicking Detach issues a DELETE against
 *    `/tenants/{slug}/operators/{cn}`.
 *
 * Like `audit.test.tsx`, fetch is stubbed per-test rather than going
 * through MSW.
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
import TenantsPage from "@/app/tenants/page";
import type { OperatorTenantRead, Tenant } from "@/lib/types";

function makeFetchResponse(status: number, body: unknown): Response {
  return {
    status,
    ok: status >= 200 && status < 300,
    statusText: status >= 200 && status < 300 ? "OK" : "ERR",
    text: async () =>
      body === undefined
        ? ""
        : typeof body === "string"
          ? body
          : JSON.stringify(body),
  } as unknown as Response;
}

function makeTenant(overrides: Partial<Tenant> = {}): Tenant {
  return {
    id: 1,
    name: "Default",
    slug: "default",
    created_at: "2026-06-03T00:00:00Z",
    ...overrides,
  };
}

function makeOperatorTenant(
  overrides: Partial<OperatorTenantRead> = {},
): OperatorTenantRead {
  return {
    id: 1,
    tenant_id: 1,
    tenant_slug: "default",
    tenant_name: "Default",
    operator_id: 1,
    operator_cn: "ops@wg.local",
    role: "admin",
    created_at: "2026-06-03T00:00:00Z",
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
    // Match the most specific route first so e.g. /tenants/default/operators
    // beats the prefix /tenants.
    const sortedNeedles = Object.keys(routes).sort(
      (a, b) => b.length - a.length,
    );
    for (const needle of sortedNeedles) {
      if (url.includes(needle)) {
        const value = routes[needle];
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
      <TenantsPage />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.restoreAllMocks();
  cleanup();
});

describe("Tenants page — list render", () => {
  it("renders one row per tenant", async () => {
    vi.spyOn(global, "fetch").mockImplementation(
      fetchRouter({
        "/tenants": makeFetchResponse(200, [
          makeTenant({ id: 1, name: "Default", slug: "default" }),
          makeTenant({ id: 2, name: "Acme", slug: "acme" }),
        ]),
      }) as typeof fetch,
    );

    renderPage();

    expect(await screen.findByText("Default")).toBeInTheDocument();
    expect(screen.getByText("Acme")).toBeInTheDocument();
    // "default" / "acme" can appear in the page description / inputs too,
    // so scope to the per-row Select button which carries the slug verbatim.
    expect(
      screen.getByRole("button", { name: /select default/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /select acme/i }),
    ).toBeInTheDocument();
  });

  it("renders an empty state when the list is empty", async () => {
    vi.spyOn(global, "fetch").mockImplementation(
      fetchRouter({
        "/tenants": makeFetchResponse(200, []),
      }) as typeof fetch,
    );

    renderPage();

    expect(await screen.findByText(/no tenants/i)).toBeInTheDocument();
  });
});

describe("Tenants page — create form", () => {
  it("POSTs to /tenants on submit", async () => {
    const fetchStub = vi.spyOn(global, "fetch").mockImplementation(
      fetchRouter({
        "/tenants": (url, init) => {
          if (init?.method === "POST") {
            return makeFetchResponse(
              201,
              makeTenant({ id: 2, name: "Acme", slug: "acme" }),
            );
          }
          return makeFetchResponse(200, [
            makeTenant({ id: 1, name: "Default", slug: "default" }),
          ]);
        },
      }) as typeof fetch,
    );

    renderPage();

    await screen.findByText("Default");

    const nameInput = await screen.findByLabelText(/name/i);
    const slugInput = await screen.findByLabelText(/slug/i);
    fireEvent.change(nameInput, { target: { value: "Acme" } });
    fireEvent.change(slugInput, { target: { value: "acme" } });

    const submit = await screen.findByRole("button", { name: /create/i });
    fireEvent.click(submit);

    await waitFor(() => {
      const calls = fetchStub.mock.calls.filter(
        ([url, init]) =>
          String(url).endsWith("/tenants") && init?.method === "POST",
      );
      expect(calls.length).toBeGreaterThan(0);
      const lastCall = calls[calls.length - 1];
      const body = JSON.parse(String(lastCall[1]?.body));
      expect(body).toEqual({ name: "Acme", slug: "acme" });
    });
  });
});

describe("Tenants page — detail + operators", () => {
  it("renders attached operators after a row is selected", async () => {
    vi.spyOn(global, "fetch").mockImplementation(
      fetchRouter({
        "/tenants/acme/operators": makeFetchResponse(200, [
          makeOperatorTenant({
            tenant_slug: "acme",
            operator_cn: "alice@wg.local",
            role: "admin",
          }),
          makeOperatorTenant({
            id: 2,
            tenant_slug: "acme",
            operator_cn: "bob@wg.local",
            role: "auditor",
          }),
        ]),
        "/tenants": makeFetchResponse(200, [
          makeTenant({ id: 2, name: "Acme", slug: "acme" }),
        ]),
      }) as typeof fetch,
    );

    renderPage();

    const selectButton = await screen.findByRole("button", {
      name: /select acme/i,
    });
    fireEvent.click(selectButton);

    expect(await screen.findByText("alice@wg.local")).toBeInTheDocument();
    expect(screen.getByText("bob@wg.local")).toBeInTheDocument();
  });

  it("attach form POSTs to /tenants/{slug}/operators", async () => {
    const fetchStub = vi.spyOn(global, "fetch").mockImplementation(
      fetchRouter({
        "/tenants/acme/operators": (url, init) => {
          if (init?.method === "POST") {
            return makeFetchResponse(
              201,
              makeOperatorTenant({
                tenant_slug: "acme",
                operator_cn: "alice@wg.local",
                role: "operator",
              }),
            );
          }
          return makeFetchResponse(200, []);
        },
        "/tenants": makeFetchResponse(200, [
          makeTenant({ id: 2, name: "Acme", slug: "acme" }),
        ]),
      }) as typeof fetch,
    );

    renderPage();

    const selectButton = await screen.findByRole("button", {
      name: /select acme/i,
    });
    fireEvent.click(selectButton);

    const cnInput = await screen.findByLabelText(/operator cn/i);
    fireEvent.change(cnInput, { target: { value: "alice@wg.local" } });

    const submit = await screen.findByRole("button", { name: /attach/i });
    fireEvent.click(submit);

    await waitFor(() => {
      const calls = fetchStub.mock.calls.filter(
        ([url, init]) =>
          String(url).endsWith("/tenants/acme/operators") &&
          init?.method === "POST",
      );
      expect(calls.length).toBeGreaterThan(0);
      const lastCall = calls[calls.length - 1];
      const body = JSON.parse(String(lastCall[1]?.body));
      expect(body.cn).toBe("alice@wg.local");
    });
  });

  it("detach button DELETEs the join", async () => {
    const fetchStub = vi.spyOn(global, "fetch").mockImplementation(
      fetchRouter({
        "/tenants/acme/operators/alice@wg.local": makeFetchResponse(
          204,
          "",
        ),
        "/tenants/acme/operators": makeFetchResponse(200, [
          makeOperatorTenant({
            tenant_slug: "acme",
            operator_cn: "alice@wg.local",
            role: "operator",
          }),
        ]),
        "/tenants": makeFetchResponse(200, [
          makeTenant({ id: 2, name: "Acme", slug: "acme" }),
        ]),
      }) as typeof fetch,
    );

    renderPage();

    const selectButton = await screen.findByRole("button", {
      name: /select acme/i,
    });
    fireEvent.click(selectButton);

    const detach = await screen.findByRole("button", { name: /detach/i });
    fireEvent.click(detach);

    await waitFor(() => {
      const calls = fetchStub.mock.calls.filter(
        ([url, init]) =>
          String(url).endsWith("/tenants/acme/operators/alice@wg.local") &&
          init?.method === "DELETE",
      );
      expect(calls.length).toBeGreaterThan(0);
    });
  });
});
