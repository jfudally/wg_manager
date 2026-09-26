/**
 * Layout regression test for the Actions column of the Clients, Servers
 * and SSH keys tables.
 *
 * Each Actions cell used to be `<td className="flex ...">`. A flex `<td>`
 * stops being a table cell, so it no longer stretches to the row height,
 * and its buttons can't wrap. On the Clients page that forced the table
 * wider than the page's `max-w-6xl` content area and left a horizontal
 * scrollbar.
 *
 * jsdom does no layout, so this pins the structure that prevents the
 * problem: the `<td>` stays a plain table cell, and the buttons sit in
 * an inner flex container that is allowed to wrap.
 */

import type { ComponentType } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import ClientsPage from "@/app/clients/page";
import ServersPage from "@/app/servers/page";
import SSHKeysPage from "@/app/ssh-keys/page";
import type { Client, Server, SSHKey } from "@/lib/types";

const CLIENT: Client = {
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
};

const SERVER: Server = {
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
  created_at: "2026-09-24T00:00:00Z",
};

const SSH_KEY: SSHKey = {
  id: 1,
  name: "ops",
  created_at: "2026-09-24T00:00:00Z",
  mode: "ca",
  tenant_id: 1,
};

/**
 * Stub `fetch` so each list endpoint returns one row. `/ssh-keys` is
 * matched first because the other pages may also load it for their
 * forms; anything unrecognised gets an empty list.
 */
function stubApi() {
  return vi.spyOn(global, "fetch").mockImplementation((async (
    input: string | URL,
  ) => {
    const url = typeof input === "string" ? input : input.toString();
    let body: unknown = [];
    if (url.includes("/ssh-keys")) body = [SSH_KEY];
    else if (url.includes("/clients")) body = [CLIENT];
    else if (url.includes("/servers")) body = [SERVER];
    return {
      status: 200,
      ok: true,
      statusText: "OK",
      text: async () => JSON.stringify(body),
    } as unknown as Response;
  }) as typeof fetch);
}

const PAGES: Array<{ name: string; Page: ComponentType }> = [
  { name: "Clients", Page: ClientsPage },
  { name: "Servers", Page: ServersPage },
  { name: "SSH keys", Page: SSHKeysPage },
];

describe("table actions cell", () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it.each(PAGES)(
    "$name: keeps the <td> a table cell and lets the buttons wrap",
    async ({ Page }) => {
      stubApi();
      const qc = new QueryClient({
        defaultOptions: { queries: { retry: false } },
      });
      render(
        <QueryClientProvider client={qc}>
          <Page />
        </QueryClientProvider>,
      );

      // Every one of these tables has a per-row Delete button.
      const [del] = await screen.findAllByRole("button", { name: "Delete" });
      const cell = del.closest("td");
      expect(cell).not.toBeNull();
      // A flex <td> breaks table layout; the cell itself must not be flex.
      expect(cell!.className.split(/\s+/)).not.toContain("flex");

      const group = del.parentElement!;
      expect(group.tagName).toBe("DIV");
      expect(group.className.split(/\s+/)).toEqual(
        expect.arrayContaining(["flex", "flex-wrap", "justify-end"]),
      );
    },
  );
});
