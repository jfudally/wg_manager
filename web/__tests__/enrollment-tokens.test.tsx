/**
 * Component tests for the Phase 3f Enrollment tokens page.
 *
 * 1. **List render.** One row per token with hub, status badge, uses,
 *    and the allowed networks ("anywhere" when unbound).
 * 2. **Empty state.**
 * 3. **Active filter.** Toggling it re-queries with `?active=true`.
 * 4. **Mint.** The form POSTs the typed payload; `allowed_cidrs` is
 *    omitted when the textarea is blank.
 * 5. **One-time reveal.** The minted token is shown once, with a copy
 *    button, and disappears on dismiss.
 * 6. **Revoke.** Confirmed revokes POST to `/{id}/revoke`; revoked rows
 *    have no Revoke button.
 * 7. **Errors.** An API refusal (e.g. 403 for non-admins) is shown.
 *
 * Fetch is stubbed per test, like tenants.test.tsx.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import EnrollmentTokensPage from "@/app/enrollment-tokens/page";
import type { EnrollmentToken, Server, SSHKey } from "@/lib/types";

function res(status: number, body: unknown): Response {
  return {
    status,
    ok: status >= 200 && status < 300,
    statusText: status < 300 ? "OK" : "ERR",
    text: async () => (body === undefined ? "" : JSON.stringify(body)),
  } as unknown as Response;
}

function makeToken(overrides: Partial<EnrollmentToken> = {}): EnrollmentToken {
  return {
    id: 1,
    tenant_id: 1,
    server_id: 7,
    ssh_key_id: 3,
    ssh_username: "wgmgr",
    name_prefix: "web",
    max_uses: 5,
    use_count: 2,
    expires_at: "2026-09-27T00:00:00Z",
    created_by_cn: "ops@wg.local",
    created_at: "2026-09-26T00:00:00Z",
    revoked_at: null,
    revoked_by_cn: null,
    allowed_cidrs: null,
    status: "active",
    ...overrides,
  };
}

const HUB = {
  id: 7,
  hostname: "hub-eu.example.com",
  status: "ready",
  subnet: "10.9.0.0/24",
} as unknown as Server;
const PENDING_HUB = { ...HUB, id: 8, hostname: "hub-new", status: "pending" } as Server;
const KEY = { id: 3, name: "ops", mode: "ca" } as unknown as SSHKey;

type Route = Response | ((url: string, init?: RequestInit) => Response);

/** Route by URL substring, longest match first. */
function stubFetch(routes: Record<string, Route>) {
  return vi.spyOn(global, "fetch").mockImplementation((async (
    input: string | URL,
    init?: RequestInit,
  ) => {
    const url = String(input);
    for (const needle of Object.keys(routes).sort((a, b) => b.length - a.length)) {
      if (url.includes(needle)) {
        const r = routes[needle];
        return typeof r === "function" ? r(url, init) : r;
      }
    }
    return res(404, { detail: `unstubbed ${url}` });
  }) as typeof fetch);
}

function baseRoutes(tokens: EnrollmentToken[]): Record<string, Route> {
  return {
    "/servers": res(200, [HUB, PENDING_HUB]),
    "/ssh-keys": res(200, [KEY]),
    "/enrollment-tokens": res(200, tokens),
  };
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <EnrollmentTokensPage />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.restoreAllMocks();
  cleanup();
});

describe("Enrollment tokens page — list", () => {
  it("renders one row per token", async () => {
    stubFetch(
      baseRoutes([
        makeToken({ id: 11 }),
        makeToken({
          id: 12,
          status: "revoked",
          allowed_cidrs: ["203.0.113.0/24", "198.51.100.7/32"],
        }),
      ]),
    );
    renderPage();

    const row11 = (await screen.findByText("11")).closest("tr")!;
    expect(within(row11).getByText("hub-eu.example.com")).toBeInTheDocument();
    expect(within(row11).getByText("active")).toBeInTheDocument();
    expect(within(row11).getByText("2 / 5")).toBeInTheDocument();
    expect(within(row11).getByText(/anywhere/i)).toBeInTheDocument();

    const row12 = screen.getByText("12").closest("tr")!;
    expect(within(row12).getByText("revoked")).toBeInTheDocument();
    expect(within(row12).getByText(/203\.0\.113\.0\/24/)).toBeInTheDocument();
    expect(within(row12).getByText(/198\.51\.100\.7\/32/)).toBeInTheDocument();
  });

  it("shows an empty state", async () => {
    stubFetch(baseRoutes([]));
    renderPage();
    expect(await screen.findByText(/no enrollment tokens/i)).toBeInTheDocument();
  });

  it("re-queries with active=true when filtered", async () => {
    const fetchSpy = stubFetch(baseRoutes([makeToken()]));
    renderPage();
    await screen.findByText("hub-eu.example.com");

    fireEvent.click(screen.getByLabelText(/active only/i));

    await waitFor(() => {
      const urls = fetchSpy.mock.calls.map(([u]) => String(u));
      expect(urls.some((u) => u.includes("/enrollment-tokens?active=true"))).toBe(true);
    });
  });
});

async function openMintForm() {
  fireEvent.click(await screen.findByRole("button", { name: /mint token/i }));
  // Wait for the hub select to be populated.
  await screen.findByRole("option", { name: /hub-eu\.example\.com/ });
}

function fillMintForm(cidrs = "") {
  fireEvent.change(screen.getByLabelText(/^hub/i), { target: { value: "7" } });
  fireEvent.change(screen.getByLabelText(/ssh role/i), { target: { value: "3" } });
  fireEvent.change(screen.getByLabelText(/ssh user/i), { target: { value: "wgmgr" } });
  fireEvent.change(screen.getByLabelText(/name prefix/i), { target: { value: "web" } });
  fireEvent.change(screen.getByLabelText(/lifetime/i), { target: { value: "21600" } });
  fireEvent.change(screen.getByLabelText(/max uses/i), { target: { value: "5" } });
  fireEvent.change(screen.getByLabelText(/allowed networks/i), { target: { value: cidrs } });
}

function lastPostBody(fetchSpy: ReturnType<typeof stubFetch>): Record<string, unknown> {
  const posts = fetchSpy.mock.calls.filter(
    ([u, init]) => String(u).endsWith("/enrollment-tokens") && init?.method === "POST",
  );
  expect(posts.length).toBeGreaterThan(0);
  return JSON.parse(String(posts[posts.length - 1][1]?.body));
}

const MINTED = {
  id: 21,
  token: "wgmenr_SECRET-VALUE",
  server_id: 7,
  tenant_id: 1,
  max_uses: 5,
  expires_at: "2026-09-26T02:00:00Z",
};

function mintRoutes(tokens: EnrollmentToken[] = []): Record<string, Route> {
  return {
    ...baseRoutes(tokens),
    "/enrollment-tokens": (_u, init) =>
      init?.method === "POST" ? res(201, MINTED) : res(200, tokens),
  };
}

describe("Enrollment tokens page — mint", () => {
  it("only offers ready hubs", async () => {
    stubFetch(mintRoutes());
    renderPage();
    await openMintForm();
    expect(screen.queryByRole("option", { name: /hub-new/ })).toBeNull();
  });

  it("POSTs the typed payload, splitting networks one per line", async () => {
    const fetchSpy = stubFetch(mintRoutes());
    renderPage();
    await openMintForm();
    fillMintForm("203.0.113.0/24\n\n 198.51.100.7 \n");
    fireEvent.click(screen.getByRole("button", { name: /^mint$/i }));

    await waitFor(() =>
      expect(lastPostBody(fetchSpy)).toEqual({
        server_id: 7,
        ssh_key_id: 3,
        ssh_username: "wgmgr",
        name_prefix: "web",
        ttl_seconds: 21600,
        max_uses: 5,
        allowed_cidrs: ["203.0.113.0/24", "198.51.100.7"],
      }),
    );
  });

  it("omits allowed_cidrs when blank", async () => {
    const fetchSpy = stubFetch(mintRoutes());
    renderPage();
    await openMintForm();
    fillMintForm("   ");
    fireEvent.click(screen.getByRole("button", { name: /^mint$/i }));
    await waitFor(() => expect(lastPostBody(fetchSpy)).not.toHaveProperty("allowed_cidrs"));
  });

  it("shows the token once, with copy, until dismissed", async () => {
    stubFetch(mintRoutes());
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });
    renderPage();
    await openMintForm();
    fillMintForm();
    fireEvent.click(screen.getByRole("button", { name: /^mint$/i }));

    const field = await screen.findByDisplayValue("wgmenr_SECRET-VALUE");
    expect(field).toHaveAttribute("readonly");
    expect(screen.getByText(/shown exactly once/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /copy token/i }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith("wgmenr_SECRET-VALUE"));

    fireEvent.click(screen.getByRole("button", { name: /dismiss/i }));
    expect(screen.queryByDisplayValue("wgmenr_SECRET-VALUE")).toBeNull();
    expect(screen.queryByText(/wgmenr_SECRET-VALUE/)).toBeNull();
  });

  it("shows API refusals", async () => {
    stubFetch({
      ...baseRoutes([]),
      "/enrollment-tokens": (_u, init) =>
        init?.method === "POST"
          ? res(403, { detail: "role not permitted" })
          : res(200, []),
    });
    renderPage();
    await openMintForm();
    fillMintForm();
    fireEvent.click(screen.getByRole("button", { name: /^mint$/i }));
    expect(await screen.findByText(/role not permitted/i)).toBeInTheDocument();
  });
});

describe("Enrollment tokens page — revoke", () => {
  it("POSTs to /{id}/revoke after confirmation", async () => {
    const fetchSpy = stubFetch({
      ...baseRoutes([makeToken({ id: 11 })]),
      "/enrollment-tokens/11/revoke": res(200, makeToken({ id: 11, status: "revoked" })),
    });
    vi.spyOn(window, "confirm").mockReturnValue(true);
    renderPage();
    const row = (await screen.findByText("11")).closest("tr")!;
    fireEvent.click(within(row).getByRole("button", { name: /revoke/i }));

    await waitFor(() => {
      const calls = fetchSpy.mock.calls.filter(
        ([u, init]) => String(u).endsWith("/enrollment-tokens/11/revoke") && init?.method === "POST",
      );
      expect(calls).toHaveLength(1);
    });
  });

  it("does nothing when the confirmation is declined", async () => {
    const fetchSpy = stubFetch(baseRoutes([makeToken({ id: 11 })]));
    vi.spyOn(window, "confirm").mockReturnValue(false);
    renderPage();
    const row = (await screen.findByText("11")).closest("tr")!;
    fireEvent.click(within(row).getByRole("button", { name: /revoke/i }));
    expect(fetchSpy.mock.calls.some(([u]) => String(u).includes("/revoke"))).toBe(false);
  });

  it("has no revoke button on revoked tokens", async () => {
    stubFetch(baseRoutes([makeToken({ id: 12, status: "revoked" })]));
    renderPage();
    const row = (await screen.findByText("12")).closest("tr")!;
    expect(within(row).queryByRole("button", { name: /revoke/i })).toBeNull();
  });
});
