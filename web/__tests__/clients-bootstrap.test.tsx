/**
 * Component test for the "Bootstrap this host first" section on the
 * Register-client form — the client-side twin of the Register-server
 * bootstrap flow.
 *
 * Pinned behaviours:
 *
 * 1. When the operator expands the section and pastes a PEM (and an
 *    optional passphrase), `POST /clients` carries
 *    `bootstrap_ssh_key_pem` / `bootstrap_ssh_key_passphrase` so the
 *    backend can bootstrap the spoke before provisioning it.
 * 2. When the PEM is left blank, neither field is sent — the
 *    already-bootstrapped path stays byte-for-byte what it was, and a
 *    stray passphrase never trips the API's "passphrase requires PEM"
 *    422.
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

const PEM =
  "-----BEGIN OPENSSH PRIVATE KEY-----\nSPOKE\n-----END OPENSSH PRIVATE KEY-----\n";

function makeFetchResponse(status: number, body: unknown): Response {
  return {
    status,
    ok: status >= 200 && status < 300,
    statusText: status >= 200 && status < 300 ? "OK" : "ERR",
    text: async () => JSON.stringify(body),
  } as unknown as Response;
}

/** Stub every endpoint the Clients page touches; returns the fetch spy. */
function stubApi() {
  return vi.spyOn(global, "fetch").mockImplementation((async (
    input: string | URL,
    init?: RequestInit,
  ) => {
    const url = typeof input === "string" ? input : input.toString();
    if (url.includes("/ssh-keys")) {
      return makeFetchResponse(200, [{ id: 1, name: "lab" }]);
    }
    if (url.includes("/servers")) {
      return makeFetchResponse(200, [
        {
          id: 7,
          hostname: "hub.example.com",
          subnet: "10.9.0.0/24",
          status: "ready",
        },
      ]);
    }
    if (url.includes("/clients") && init?.method === "POST") {
      return makeFetchResponse(202, {
        task_id: "t-1",
        client: { id: 1, name: "spoke", status: "pending" },
      });
    }
    if (url.includes("/clients")) return makeFetchResponse(200, []);
    if (url.includes("/tasks/")) {
      return makeFetchResponse(200, { task_id: "t-1", state: "PENDING" });
    }
    return makeFetchResponse(404, { detail: `unstubbed ${url}` });
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

/** Open the register form and fill the required fields. */
async function fillRequiredFields() {
  fireEvent.click(await screen.findByRole("button", { name: /register client/i }));
  fireEvent.change(await screen.findByLabelText(/^name$/i), {
    target: { value: "spoke" },
  });
  fireEvent.change(screen.getByLabelText(/ssh hostname/i), {
    target: { value: "spoke.example.com" },
  });
  // Wait for the async-loaded <option>s before selecting them.
  await screen.findByRole("option", { name: /#1 — lab/ });
  fireEvent.change(screen.getByLabelText(/ssh role/i), { target: { value: "1" } });
  await screen.findByRole("option", { name: /hub\.example\.com/ });
  fireEvent.change(screen.getByLabelText(/server \(hub\)/i), {
    target: { value: "7" },
  });
}

/** Parsed JSON body of the last `POST /clients` call. */
async function lastClientPostBody(
  fetchSpy: ReturnType<typeof stubApi>,
): Promise<Record<string, unknown>> {
  let body: Record<string, unknown> = {};
  await waitFor(() => {
    const posts = fetchSpy.mock.calls.filter(
      ([url, init]) =>
        String(url).endsWith("/clients") && init?.method === "POST",
    );
    expect(posts.length).toBe(1);
    body = JSON.parse(String(posts[0][1]?.body));
  });
  return body;
}

afterEach(() => {
  vi.restoreAllMocks();
  cleanup();
});

describe("Register client — bootstrap section", () => {
  it("forwards the pasted PEM and passphrase to POST /clients", async () => {
    const fetchSpy = stubApi();
    renderPage();
    await fillRequiredFields();

    fireEvent.change(screen.getByLabelText(/bootstrap ssh private key/i), {
      target: { value: PEM },
    });
    fireEvent.change(screen.getByLabelText(/key passphrase/i), {
      target: { value: "hunter2" },
    });
    fireEvent.click(screen.getByRole("button", { name: /register and provision/i }));

    const body = await lastClientPostBody(fetchSpy);
    expect(body.bootstrap_ssh_key_pem).toBe(PEM);
    expect(body.bootstrap_ssh_key_passphrase).toBe("hunter2");
    expect(body.hostname).toBe("spoke.example.com");
  });

  it("omits both bootstrap fields when the PEM is blank", async () => {
    const fetchSpy = stubApi();
    renderPage();
    await fillRequiredFields();

    // A passphrase with no PEM must not reach the API (it would 422).
    fireEvent.change(screen.getByLabelText(/key passphrase/i), {
      target: { value: "stray" },
    });
    fireEvent.click(screen.getByRole("button", { name: /register and provision/i }));

    const body = await lastClientPostBody(fetchSpy);
    expect(body).not.toHaveProperty("bootstrap_ssh_key_pem");
    expect(body).not.toHaveProperty("bootstrap_ssh_key_passphrase");
  });
});
