/**
 * Component-level smoke tests for the Phase 2d CP3.4 Certificates page.
 *
 * Three concerns we want to pin so a future refactor surfaces in PR
 * review rather than in a broken dashboard:
 *
 * 1. **Splash renders the operator role the API saw.** The whole page
 *    keys off the "Who am I?" response — the issue/revoke buttons are
 *    admin-only, the inventory query 403s for plain operators, etc.
 *    If this stops surfacing the role we'll silently expose the wrong
 *    affordances.
 * 2. **Inventory table renders rows.** Live + revoked, with the
 *    Revoke action visible only to admins.
 * 3. **Revoke action POSTs to the right endpoint.** Confirms the page
 *    talks to `api.revokeCertificate(id)` and not some hand-rolled
 *    fetch.
 *
 * Like `servers-host-cert.test.tsx`, fetch is stubbed per-test rather
 * than going through MSW — the surface is small enough that the
 * hand-rolled stub is clearer than configuring a server.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import CertificatesPage from "@/app/certificates/page";
import type { Certificate, WhoAmI } from "@/lib/types";

function makeFetchResponse(status: number, body: unknown): Response {
  return {
    status,
    ok: status >= 200 && status < 300,
    statusText: status === 200 ? "OK" : "ERR",
    text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
  } as unknown as Response;
}

function makeWhoAmI(overrides: Partial<WhoAmI> = {}): WhoAmI {
  return {
    cn: "ops@wg.local",
    serial: "4242424242",
    sans: ["ops@wg.local", "127.0.0.1"],
    not_before: "2026-01-01T00:00:00Z",
    not_after: "2027-01-01T00:00:00Z",
    operator_cn: "ops@wg.local",
    operator_role: "admin",
    operator_status: "active",
    ...overrides,
  };
}

function makeCertificate(overrides: Partial<Certificate> = {}): Certificate {
  return {
    id: 1,
    serial: "1122334455",
    cert_type: "api",
    operator_id: null,
    common_name: "127.0.0.1",
    sans: "127.0.0.1,localhost",
    not_before: "2026-01-01T00:00:00Z",
    not_after: "2026-12-31T00:00:00Z",
    revoked: false,
    revoked_at: null,
    created_at: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

/**
 * Build a fetch stub that dispatches off the URL path. Each value is
 * the response object (or a function producing one). Anything not
 * matched falls through to a 404.
 */
function fetchRouter(
  routes: Record<string, Response | ((url: string, init?: RequestInit) => Response)>,
): (url: string | URL, init?: RequestInit) => Promise<Response> {
  return async (input, init) => {
    const url = typeof input === "string" ? input : input.toString();
    for (const [needle, value] of Object.entries(routes)) {
      if (url.endsWith(needle)) {
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
      <CertificatesPage />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.restoreAllMocks();
  cleanup();
});

describe("Certificates page — Who am I splash", () => {
  it("renders the resolved operator CN and role badge", async () => {
    vi.spyOn(global, "fetch").mockImplementation(
      fetchRouter({
        "/certs/whoami": makeFetchResponse(200, makeWhoAmI()),
        "/certs": makeFetchResponse(200, []),
      }) as typeof fetch,
    );

    renderPage();

    // The CN appears in both the splash and (potentially) error panels;
    // the role badge text "admin" is unique to the splash.
    expect(await screen.findByText("admin")).toBeInTheDocument();
    expect(screen.getAllByText("ops@wg.local").length).toBeGreaterThan(0);
    // Serial round-trips verbatim — it's the proof-of-handshake field.
    expect(screen.getByText("4242424242")).toBeInTheDocument();
  });

  it("surfaces the API error when whoami fails", async () => {
    vi.spyOn(global, "fetch").mockImplementation(
      fetchRouter({
        "/certs/whoami": makeFetchResponse(401, {
          detail: "operator not registered",
        }),
        "/certs": makeFetchResponse(401, { detail: "client cert required" }),
      }) as typeof fetch,
    );

    renderPage();

    expect(
      await screen.findByText(/mTLS handshake didn't surface an operator/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/operator not registered/i)).toBeInTheDocument();
  });
});

describe("Certificates page — inventory + revoke", () => {
  it("admin sees the inventory table and a per-row Revoke button", async () => {
    vi.spyOn(global, "fetch").mockImplementation(
      fetchRouter({
        "/certs/whoami": makeFetchResponse(200, makeWhoAmI()),
        "/certs": makeFetchResponse(200, [
          makeCertificate({ id: 7, serial: "11", common_name: "127.0.0.1" }),
          makeCertificate({
            id: 8,
            serial: "22",
            common_name: "ops@wg.local",
            cert_type: "cli",
            revoked: true,
            revoked_at: "2026-05-29T00:00:00Z",
          }),
        ]),
      }) as typeof fetch,
    );

    renderPage();

    // Both rows present.
    expect(await screen.findByText("127.0.0.1")).toBeInTheDocument();
    expect(screen.getByText("11")).toBeInTheDocument();
    expect(screen.getByText("22")).toBeInTheDocument();

    // Live row gets a Revoke button; revoked row doesn't.
    const revokeButtons = screen.getAllByRole("button", { name: /revoke/i });
    expect(revokeButtons.length).toBe(1);
    // Revoked row shows the "revoked" status badge.
    expect(screen.getByText(/revoked/i)).toBeInTheDocument();
  });

  it("auditor sees the inventory but no Revoke button", async () => {
    vi.spyOn(global, "fetch").mockImplementation(
      fetchRouter({
        "/certs/whoami": makeFetchResponse(
          200,
          makeWhoAmI({ operator_role: "auditor" }),
        ),
        "/certs": makeFetchResponse(200, [
          makeCertificate({ id: 7, serial: "11" }),
        ]),
      }) as typeof fetch,
    );

    renderPage();

    expect(await screen.findByText("127.0.0.1")).toBeInTheDocument();
    // Auditor — no admin controls.
    expect(screen.queryByRole("button", { name: /revoke/i })).toBeNull();
    expect(
      screen.queryByRole("button", { name: /issue new cert/i }),
    ).toBeNull();
  });

  it("clicking Revoke POSTs to /certs/{id}/revoke", async () => {
    // Confirm() auto-accepts so the click flows through.
    vi.spyOn(window, "confirm").mockReturnValue(true);

    const revokedRow = makeCertificate({
      id: 7,
      revoked: true,
      revoked_at: "2026-05-29T00:00:00Z",
    });
    const fetchStub = vi
      .spyOn(global, "fetch")
      .mockImplementation(
        fetchRouter({
          "/certs/whoami": makeFetchResponse(200, makeWhoAmI()),
          "/certs": makeFetchResponse(200, [
            makeCertificate({ id: 7, serial: "11" }),
          ]),
          "/certs/7/revoke": makeFetchResponse(200, {
            certificate: revokedRow,
          }),
        }) as typeof fetch,
      );

    renderPage();

    const revokeButton = await screen.findByRole("button", {
      name: /^revoke$/i,
    });
    fireEvent.click(revokeButton);

    await waitFor(() => {
      const revokeCalls = fetchStub.mock.calls.filter(([url]) =>
        String(url).endsWith("/certs/7/revoke"),
      );
      expect(revokeCalls.length).toBe(1);
      expect(revokeCalls[0][1]?.method).toBe("POST");
    });
  });
});

describe("Certificates page — admin issuance affordance", () => {
  it("admin sees the Issue button; auditor does not", async () => {
    vi.spyOn(global, "fetch").mockImplementation(
      fetchRouter({
        "/certs/whoami": makeFetchResponse(200, makeWhoAmI()),
        "/certs": makeFetchResponse(200, []),
      }) as typeof fetch,
    );

    renderPage();

    expect(
      await screen.findByRole("button", { name: /issue new cert/i }),
    ).toBeInTheDocument();
  });
});

describe("Certificates page — Phase 2d CP4.2 cert-type dropdown", () => {
  it("the Issue form lists every CertificateType, including mysql-client", async () => {
    vi.spyOn(global, "fetch").mockImplementation(
      fetchRouter({
        "/certs/whoami": makeFetchResponse(200, makeWhoAmI()),
        "/certs": makeFetchResponse(200, []),
      }) as typeof fetch,
    );

    renderPage();

    // Open the issue form so the cert-type <select> renders.
    fireEvent.click(
      await screen.findByRole("button", { name: /issue new cert/i }),
    );

    const select = await screen.findByLabelText(/cert type/i);
    const optionValues = Array.from(
      select.querySelectorAll("option"),
    ).map((opt) => (opt as HTMLOptionElement).value);
    expect(optionValues).toEqual([
      "api",
      "cli",
      "dashboard",
      "mysql",
      "mysql-client",
    ]);
  });
});
