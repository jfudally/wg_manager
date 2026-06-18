"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { Client, ClientUpdate } from "@/lib/types";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { StatusBadge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { EmptyState } from "@/components/empty-state";
import { TaskPoller } from "@/components/task-poller";
import { formatDateTime } from "@/lib/utils";

/**
 * Clients page. Register and reprovision spoke nodes. The server picker
 * is filtered to ``ready`` servers since the API rejects client
 * registration against a server that isn't fully provisioned.
 */
export default function ClientsPage() {
  const qc = useQueryClient();
  const clientsQuery = useQuery({
    queryKey: ["clients"],
    queryFn: api.listClients,
  });
  const [showForm, setShowForm] = useState(false);
  const [showManualForm, setShowManualForm] = useState(false);
  // Client currently open in the inline edit form, or null when no edit
  // is in progress. Stored as the full row so the form pre-populates
  // without a re-fetch.
  const [editingClient, setEditingClient] = useState<Client | null>(null);
  // When a manual client's config panel is open, hold both the client
  // row and the rendered wg0.conf body. Set after a successful
  // POST /clients/manual — the body comes back exactly once on that
  // response (the control plane no longer persists the private key),
  // so the panel is purely a one-shot display surface driven by the
  // register flow. There is no path that re-fetches the body for an
  // existing row.
  const [configClient, setConfigClient] = useState<{
    client: Client;
    body: string;
  } | null>(null);
  const [activeTasks, setActiveTasks] = useState<
    Array<{ key: string; taskId: string; label: string }>
  >([]);
  const [showExport, setShowExport] = useState(false);

  const hasClients = (clientsQuery.data?.length ?? 0) > 0;

  return (
    <div className="flex flex-col gap-6">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Clients</h1>
          <p className="text-sm text-muted-foreground">
            Spoke nodes. Each one is auto-allocated an IP in its hub's
            subnet on registration.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            onClick={() => setShowExport((v) => !v)}
            disabled={!hasClients}
            title={
              hasClients
                ? "Generate an ~/.ssh/config block for every client"
                : "Register at least one client first"
            }
          >
            {showExport ? "Hide SSH config" : "Export SSH config"}
          </Button>
          <Button
            variant="outline"
            onClick={() => {
              setShowManualForm((v) => !v);
              setShowForm(false);
            }}
            title="Register a device wg-manager can't SSH into (phones, IoT, ...)"
          >
            {showManualForm ? "Cancel" : "+ Add manual client"}
          </Button>
          <Button
            onClick={() => {
              setShowForm((v) => !v);
              setShowManualForm(false);
            }}
          >
            {showForm ? "Cancel" : "+ Register client"}
          </Button>
        </div>
      </header>

      {showExport ? (
        <SshConfigExport onClose={() => setShowExport(false)} />
      ) : null}

      {showForm ? (
        <RegisterClientForm
          onRegistered={(taskId) => {
            setShowForm(false);
            qc.invalidateQueries({ queryKey: ["clients"] });
            setActiveTasks((t) => [
              ...t,
              {
                key: `register-${taskId}`,
                taskId,
                label: "Register client",
              },
            ]);
          }}
        />
      ) : null}

      {showManualForm ? (
        <RegisterManualClientForm
          onRegistered={(client, taskId, wgConfig) => {
            setShowManualForm(false);
            qc.invalidateQueries({ queryKey: ["clients"] });
            // Surface the rendered config immediately so the operator
            // can copy / download it before navigating away — this is
            // the only moment the body exists outside the response.
            setConfigClient({ client, body: wgConfig });
            setActiveTasks((t) => [
              ...t,
              {
                key: `reconfigure-after-manual-${taskId}`,
                taskId,
                label: `Reconfigure hub for ${client.name}`,
              },
            ]);
          }}
        />
      ) : null}

      {configClient ? (
        <ManualClientConfigPanel
          client={configClient.client}
          body={configClient.body}
          onClose={() => setConfigClient(null)}
        />
      ) : null}

      {editingClient ? (
        <EditClientForm
          client={editingClient}
          onCancel={() => setEditingClient(null)}
          onSaved={() => {
            setEditingClient(null);
            qc.invalidateQueries({ queryKey: ["clients"] });
          }}
        />
      ) : null}

      {activeTasks.map((t) => (
        <div key={t.key} className="flex flex-col gap-2">
          <TaskPoller
            taskId={t.taskId}
            label={t.label}
            onSuccess={() =>
              qc.invalidateQueries({ queryKey: ["clients"] })
            }
          />
          <div className="flex justify-end">
            <Button
              variant="ghost"
              size="sm"
              onClick={() =>
                setActiveTasks((cur) => cur.filter((x) => x.key !== t.key))
              }
            >
              Dismiss
            </Button>
          </div>
        </div>
      ))}

      {clientsQuery.isError ? (
        <Alert variant="error" title="Couldn't load clients">
          {(clientsQuery.error as Error).message}
        </Alert>
      ) : null}

      {clientsQuery.isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : clientsQuery.data && clientsQuery.data.length === 0 ? (
        <EmptyState
          title="No clients yet"
          description="Once a server is ready, register clients here and the hub auto-reconfigures to add them as peers."
        />
      ) : clientsQuery.data ? (
        <ClientTable
          clients={clientsQuery.data}
          onTaskDispatched={(taskId, label) =>
            setActiveTasks((t) => [
              ...t,
              { key: `${label}-${taskId}`, taskId, label },
            ])
          }
          onEdit={(c) => setEditingClient(c)}
          onDeleted={() =>
            qc.invalidateQueries({ queryKey: ["clients"] })
          }
        />
      ) : null}
    </div>
  );
}

function ClientTable({
  clients,
  onTaskDispatched,
  onEdit,
  onDeleted,
}: {
  clients: Client[];
  onTaskDispatched: (taskId: string, label: string) => void;
  onEdit: (client: Client) => void;
  onDeleted: () => void;
}) {
  const reprovision = useMutation({
    mutationFn: (id: number) => api.reprovisionClient(id),
    onSuccess: (data) =>
      onTaskDispatched(
        data.task_id,
        `Reprovision client #${data.client.id}`,
      ),
  });

  // Errors from a previous DELETE attempt — surfaced inline beneath the
  // table so the operator can see which row failed and why.
  const [deleteError, setDeleteError] = useState<{
    clientId: number;
    message: string;
  } | null>(null);

  const deleteMutation = useMutation({
    mutationFn: (id: number) => api.deleteClient(id),
    onSuccess: (data) => {
      setDeleteError(null);
      // The delete response is a 202 with the hub-reconfigure task id —
      // surface that as a TaskPoller via the page-level activeTasks queue.
      onTaskDispatched(
        data.task_id,
        `Reconfigure hub after deleting client #${data.client_id}`,
      );
      onDeleted();
    },
    onError: (err, variables) =>
      setDeleteError({
        clientId: variables,
        message: (err as Error).message,
      }),
  });

  function requestDelete(c: Client) {
    setDeleteError(null);
    const confirmed = window.confirm(
      `Delete client #${c.id} (${c.name})?\n\n` +
        "The row will be removed and the hub will be reconfigured so " +
        "the deleted peer's public key can no longer connect. The " +
        "client host itself is not touched — wg-quick on the box keeps " +
        "running until you stop it manually.",
    );
    if (!confirmed) return;
    deleteMutation.mutate(c.id);
  }

  return (
    <div className="flex flex-col gap-2">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>ID</TableHead>
            <TableHead>Name</TableHead>
            <TableHead>Kind</TableHead>
            <TableHead>Hostname</TableHead>
            <TableHead>Server</TableHead>
            <TableHead>Address</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Created</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {clients.map((c) => (
            <TableRow key={c.id}>
              <TableCell className="font-mono text-xs">{c.id}</TableCell>
              <TableCell className="font-medium">{c.name}</TableCell>
              <TableCell>
                {c.is_manual ? (
                  <Badge
                    variant="info"
                    title="Registered without SSH provisioning — config installed by hand"
                  >
                    manual
                  </Badge>
                ) : (
                  <Badge
                    variant="outline"
                    title="SSH-provisioned by wg-manager"
                  >
                    ssh
                  </Badge>
                )}
              </TableCell>
              <TableCell className="text-xs">
                {c.hostname ?? (
                  <span className="text-muted-foreground">—</span>
                )}
              </TableCell>
              <TableCell className="font-mono text-xs">#{c.server_id}</TableCell>
              <TableCell className="font-mono text-xs">{c.address}</TableCell>
              <TableCell>
                <StatusBadge status={c.status} />
              </TableCell>
              <TableCell className="text-xs text-muted-foreground">
                {formatDateTime(c.created_at)}
              </TableCell>
              <TableCell className="flex justify-end gap-2">
                {c.is_manual ? (
                  // Manual rows: no SSH credentials (so Reprovision
                  // can't reach the device) and the wg0.conf body is
                  // not retrievable any more — it was delivered once
                  // at registration. The only recovery action is
                  // Delete + register a fresh manual client.
                  <span
                    className="text-xs text-muted-foreground"
                    title="Manual clients receive their wg0.conf once at registration. Delete and re-register to mint a new keypair."
                  >
                    Manual
                  </span>
                ) : (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => reprovision.mutate(c.id)}
                    disabled={reprovision.isPending}
                  >
                    Reprovision
                  </Button>
                )}
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => onEdit(c)}
                >
                  Edit
                </Button>
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={() => requestDelete(c)}
                  disabled={
                    deleteMutation.isPending &&
                    deleteMutation.variables === c.id
                  }
                >
                  Delete
                </Button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {reprovision.isError ? (
        <Alert variant="error">
          {(reprovision.error as Error).message}
        </Alert>
      ) : null}
      {deleteError ? (
        <Alert
          variant="error"
          title={`Couldn't delete client #${deleteError.clientId}`}
        >
          <div className="flex flex-col gap-2">
            <p>{deleteError.message}</p>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setDeleteError(null)}
              className="self-start"
            >
              Dismiss
            </Button>
          </div>
        </Alert>
      ) : null}
    </div>
  );
}

function RegisterClientForm({
  onRegistered,
}: {
  onRegistered: (taskId: string) => void;
}) {
  const keysQuery = useQuery({ queryKey: ["ssh-keys"], queryFn: api.listSshKeys });
  const serversQuery = useQuery({
    queryKey: ["servers"],
    queryFn: api.listServers,
  });

  const readyServers =
    serversQuery.data?.filter((s) => s.status === "ready") ?? [];

  const [name, setName] = useState("");
  const [hostname, setHostname] = useState("");
  const [sshUsername, setSshUsername] = useState("ubuntu");
  const [sshPort, setSshPort] = useState(22);
  const [sshKeyId, setSshKeyId] = useState<number | "">("");
  const [serverId, setServerId] = useState<number | "">("");

  const mutation = useMutation({
    mutationFn: () => {
      if (sshKeyId === "" || serverId === "") {
        throw new Error("SSH role and server are required");
      }
      return api.registerClient({
        name: name.trim(),
        hostname: hostname.trim(),
        ssh_username: sshUsername.trim(),
        ssh_port: sshPort,
        ssh_key_id: Number(sshKeyId),
        server_id: Number(serverId),
      });
    },
    onSuccess: (data) => {
      setName("");
      setHostname("");
      onRegistered(data.task_id);
    },
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>Register a spoke client</CardTitle>
        <CardDescription>
          The client must SSH-reachable from the worker. An IP is
          auto-allocated from the chosen server's subnet.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="grid grid-cols-1 gap-4 md:grid-cols-2"
          onSubmit={(e) => {
            e.preventDefault();
            mutation.mutate();
          }}
        >
          <div className="flex flex-col gap-1">
            <Label htmlFor="cli-name">Name</Label>
            <Input
              id="cli-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="alpha"
              required
            />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="cli-host">SSH hostname</Label>
            <Input
              id="cli-host"
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              placeholder="alpha.example.com"
              required
            />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="cli-user">SSH user</Label>
            <Input
              id="cli-user"
              value={sshUsername}
              onChange={(e) => setSshUsername(e.target.value)}
              required
            />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="cli-port">SSH port</Label>
            <Input
              id="cli-port"
              type="number"
              min={1}
              max={65535}
              value={sshPort}
              onChange={(e) => setSshPort(Number(e.target.value))}
            />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="cli-key">SSH role</Label>
            <select
              id="cli-key"
              className="h-9 rounded-md border border-border bg-background px-2 text-sm"
              value={sshKeyId}
              onChange={(e) =>
                setSshKeyId(e.target.value === "" ? "" : Number(e.target.value))
              }
              required
            >
              <option value="" disabled>
                {keysQuery.data?.length ? "Pick an SSH role…" : "No SSH roles"}
              </option>
              {keysQuery.data?.map((k) => (
                <option key={k.id} value={k.id}>
                  #{k.id} — {k.name}
                </option>
              ))}
            </select>
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="cli-server">Server (hub)</Label>
            <select
              id="cli-server"
              className="h-9 rounded-md border border-border bg-background px-2 text-sm"
              value={serverId}
              onChange={(e) =>
                setServerId(e.target.value === "" ? "" : Number(e.target.value))
              }
              required
            >
              <option value="" disabled>
                {readyServers.length
                  ? "Pick a ready server…"
                  : "No ready servers — register a hub first"}
              </option>
              {readyServers.map((s) => (
                <option key={s.id} value={s.id}>
                  #{s.id} — {s.hostname} ({s.subnet})
                </option>
              ))}
            </select>
          </div>
          {mutation.isError ? (
            <div className="md:col-span-2">
              <Alert variant="error">
                {(mutation.error as ApiError | Error).message}
              </Alert>
            </div>
          ) : null}
          <CardFooter className="md:col-span-2 px-0 pb-0">
            <Button type="submit" disabled={mutation.isPending}>
              {mutation.isPending ? "Dispatching…" : "Register and provision"}
            </Button>
          </CardFooter>
        </form>
      </CardContent>
    </Card>
  );
}

/**
 * Inline panel that fetches and renders the ``~/.ssh/config`` export
 * for every registered client.
 *
 * The body is plain text returned by ``GET /clients/export/ssh-config``.
 * The operator can read it inline, copy it to the clipboard, or
 * download it as a file to drop under ``$HOME/.ssh/`` (typically
 * included from ``~/.ssh/config`` via an ``Include`` directive).
 *
 * The fetch is invalidated whenever the underlying client list changes
 * (registrations, deletes, reprovisions) so the export stays in sync
 * with what's actually managed.
 */
function SshConfigExport({ onClose }: { onClose: () => void }) {
  const exportQuery = useQuery({
    queryKey: ["clients", "ssh-config-export"],
    queryFn: api.exportSshConfig,
  });
  // "idle" | "copied" | "failed" — drives the copy-button label.
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">(
    "idle",
  );

  // Reset the copy-state hint after a couple of seconds so the button
  // doesn't get stuck on "Copied" if the operator opens it again later.
  useEffect(() => {
    if (copyState === "idle") return;
    const handle = window.setTimeout(() => setCopyState("idle"), 2000);
    return () => window.clearTimeout(handle);
  }, [copyState]);

  async function copyToClipboard(text: string) {
    try {
      if (navigator?.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        // Older browsers / non-secure contexts fall back to a hidden
        // textarea + execCommand; the dashboard is meant to be served
        // over localhost so the modern path is the common one.
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
      }
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  }

  function downloadAsFile(text: string) {
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "wg-manager.ssh-config";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  const body = exportQuery.data ?? "";
  const isEmpty = exportQuery.isSuccess && body.length === 0;

  return (
    <Card>
      <CardHeader>
        <CardTitle>SSH config export</CardTitle>
        <CardDescription>
          One <code>Host &lt;name&gt;.vpn</code> entry per registered
          client, ready to append to <code>~/.ssh/config</code> (or to
          drop into a file referenced by an <code>Include</code>{" "}
          directive there). No <code>IdentityFile</code> is emitted — key
          selection is left to your local SSH agent.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {exportQuery.isLoading ? (
          <p className="text-sm text-muted-foreground">Generating…</p>
        ) : exportQuery.isError ? (
          <Alert variant="error" title="Couldn't generate SSH config">
            {(exportQuery.error as Error).message}
          </Alert>
        ) : isEmpty ? (
          <p className="text-sm text-muted-foreground">
            No clients registered yet — nothing to export.
          </p>
        ) : (
          <pre
            data-testid="ssh-config-body"
            className="max-h-96 overflow-auto rounded-md border border-border bg-muted/40 p-3 font-mono text-xs"
          >
            {body}
          </pre>
        )}
      </CardContent>
      <CardFooter className="flex gap-2">
        <Button
          type="button"
          variant="outline"
          size="sm"
          disabled={!body}
          onClick={() => copyToClipboard(body)}
        >
          {copyState === "copied"
            ? "Copied!"
            : copyState === "failed"
              ? "Copy failed"
              : "Copy"}
        </Button>
        <Button
          type="button"
          variant="outline"
          size="sm"
          disabled={!body}
          onClick={() => downloadAsFile(body)}
        >
          Download
        </Button>
        <Button type="button" variant="ghost" size="sm" onClick={onClose}>
          Close
        </Button>
      </CardFooter>
    </Card>
  );
}

/**
 * Inline edit form for an existing client. Pre-populates from the current
 * row and PATCHes only the fields the operator changed. The parent
 * server, allocated address, public key and status are all read-only
 * here because the backend treats them as provisioning artefacts.
 */
function EditClientForm({
  client,
  onCancel,
  onSaved,
}: {
  client: Client;
  onCancel: () => void;
  onSaved: () => void;
}) {
  const keysQuery = useQuery({ queryKey: ["ssh-keys"], queryFn: api.listSshKeys });
  const [name, setName] = useState(client.name);
  // Manual clients have NULL SSH fields — coerce to empty string for the
  // form inputs, but build the PATCH payload so only fields the operator
  // typed something into actually go on the wire.
  const [hostname, setHostname] = useState(client.hostname ?? "");
  const [sshUsername, setSshUsername] = useState(client.ssh_username ?? "");
  const [sshPort, setSshPort] = useState(client.ssh_port);
  const [sshKeyId, setSshKeyId] = useState<number | "">(
    client.ssh_key_id ?? "",
  );

  // Build a partial payload containing only fields the operator actually
  // changed, so unchanged keys never go on the wire.
  function buildPayload(): ClientUpdate {
    const payload: ClientUpdate = {};
    if (name.trim() !== client.name) payload.name = name.trim();
    if (hostname.trim() !== (client.hostname ?? ""))
      payload.hostname = hostname.trim();
    if (sshUsername.trim() !== (client.ssh_username ?? ""))
      payload.ssh_username = sshUsername.trim();
    if (sshPort !== client.ssh_port) payload.ssh_port = sshPort;
    if (sshKeyId !== "" && sshKeyId !== client.ssh_key_id)
      payload.ssh_key_id = sshKeyId;
    return payload;
  }

  const mutation = useMutation({
    mutationFn: () => api.updateClient(client.id, buildPayload()),
    onSuccess: () => onSaved(),
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          Edit client #{client.id} — {client.name}
        </CardTitle>
        <CardDescription>
          Only operator-supplied connection metadata is editable. The
          parent hub, allocated address, public key and status are managed
          by provisioning — delete and re-register if you need to move
          this client to a different hub or reissue its keypair.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="grid grid-cols-1 gap-4 md:grid-cols-2"
          onSubmit={(e) => {
            e.preventDefault();
            mutation.mutate();
          }}
        >
          <div className="flex flex-col gap-1">
            <Label htmlFor="edit-cli-name">Name</Label>
            <Input
              id="edit-cli-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="edit-cli-host">SSH hostname</Label>
            <Input
              id="edit-cli-host"
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              // Manual clients legitimately have no hostname — don't force
              // the operator to invent one just to edit the display name.
              required={!client.is_manual}
              placeholder={client.is_manual ? "(none — manual client)" : ""}
            />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="edit-cli-user">SSH user</Label>
            <Input
              id="edit-cli-user"
              value={sshUsername}
              onChange={(e) => setSshUsername(e.target.value)}
              required={!client.is_manual}
              placeholder={client.is_manual ? "(none — manual client)" : ""}
            />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="edit-cli-port">SSH port</Label>
            <Input
              id="edit-cli-port"
              type="number"
              min={1}
              max={65535}
              value={sshPort}
              onChange={(e) => setSshPort(Number(e.target.value))}
            />
          </div>
          <div className="flex flex-col gap-1 md:col-span-2">
            <Label htmlFor="edit-cli-key">SSH role</Label>
            <select
              id="edit-cli-key"
              className="h-9 rounded-md border border-border bg-background px-2 text-sm"
              value={sshKeyId}
              onChange={(e) =>
                setSshKeyId(
                  e.target.value === "" ? "" : Number(e.target.value),
                )
              }
              required={!client.is_manual}
            >
              {/* Manual clients are allowed to leave this unset — keep the
                  empty option available so the operator can save other
                  edits without being forced to bind an SSH role. */}
              {client.is_manual ? (
                <option value="">
                  (none — manual client)
                </option>
              ) : null}
              {keysQuery.data?.map((k) => (
                <option key={k.id} value={k.id}>
                  #{k.id} — {k.name}
                </option>
              ))}
            </select>
          </div>
          {mutation.isError ? (
            <div className="md:col-span-2">
              <Alert variant="error">
                {(mutation.error as ApiError | Error).message}
              </Alert>
            </div>
          ) : null}
          <CardFooter className="md:col-span-2 px-0 pb-0 flex gap-2">
            <Button
              type="submit"
              disabled={
                mutation.isPending ||
                Object.keys(buildPayload()).length === 0
              }
            >
              {mutation.isPending ? "Saving…" : "Save changes"}
            </Button>
            <Button
              type="button"
              variant="ghost"
              onClick={onCancel}
              disabled={mutation.isPending}
            >
              Cancel
            </Button>
          </CardFooter>
        </form>
      </CardContent>
    </Card>
  );
}

/**
 * Register a client we won't SSH into. The only fields the operator
 * supplies are the name and the target hub — wg-manager generates the
 * WireGuard keypair, allocates an IP from the hub's subnet, and
 * reconfigures the hub so the new peer is admitted. After the response
 * comes back, the caller (the page) opens a config panel so the
 * operator can copy/download the rendered ``wg0.conf`` for hand-install
 * on the device.
 */
function RegisterManualClientForm({
  onRegistered,
}: {
  onRegistered: (client: Client, taskId: string, wgConfig: string) => void;
}) {
  const serversQuery = useQuery({
    queryKey: ["servers"],
    queryFn: api.listServers,
  });

  // Same gate as the SSH-provisioned flow: a server without a known
  // public key can't be baked into a working config.
  const readyServers =
    serversQuery.data?.filter((s) => s.status === "ready") ?? [];

  const [name, setName] = useState("");
  const [serverId, setServerId] = useState<number | "">("");

  const mutation = useMutation({
    mutationFn: () => {
      if (serverId === "") {
        throw new Error("Server is required");
      }
      return api.registerManualClient({
        name: name.trim(),
        server_id: Number(serverId),
      });
    },
    onSuccess: (data) => {
      setName("");
      onRegistered(data.client, data.task_id, data.wg_config);
    },
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>Add a manual client</CardTitle>
        <CardDescription>
          For devices wg-manager can&apos;t SSH into — phones, IoT, locked-
          down embedded boxes. The keypair is generated server-side and
          the rendered <code>wg0.conf</code> is shown <strong>once</strong>{" "}
          on the next screen so you can install it on the device by hand.
          The private key is <strong>not</strong> kept on the control
          plane afterward — if you dismiss the panel before saving the
          body, you&apos;ll need to delete the row and re-register to
          mint a new keypair.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="grid grid-cols-1 gap-4 md:grid-cols-2"
          onSubmit={(e) => {
            e.preventDefault();
            mutation.mutate();
          }}
        >
          <div className="flex flex-col gap-1">
            <Label htmlFor="manual-cli-name">Name</Label>
            <Input
              id="manual-cli-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="phone"
              required
            />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="manual-cli-server">Server (hub)</Label>
            <select
              id="manual-cli-server"
              className="h-9 rounded-md border border-border bg-background px-2 text-sm"
              value={serverId}
              onChange={(e) =>
                setServerId(
                  e.target.value === "" ? "" : Number(e.target.value),
                )
              }
              required
            >
              <option value="" disabled>
                {readyServers.length
                  ? "Pick a ready server…"
                  : "No ready servers — register a hub first"}
              </option>
              {readyServers.map((s) => (
                <option key={s.id} value={s.id}>
                  #{s.id} — {s.hostname} ({s.subnet})
                </option>
              ))}
            </select>
          </div>
          {mutation.isError ? (
            <div className="md:col-span-2">
              <Alert variant="error">
                {(mutation.error as ApiError | Error).message}
              </Alert>
            </div>
          ) : null}
          <CardFooter className="md:col-span-2 px-0 pb-0">
            <Button type="submit" disabled={mutation.isPending}>
              {mutation.isPending ? "Generating…" : "Generate config"}
            </Button>
          </CardFooter>
        </form>
      </CardContent>
    </Card>
  );
}

/**
 * One-shot inline panel that displays the rendered ``wg0.conf`` body
 * for a freshly-registered manual client. The body is supplied as a
 * prop because the control plane no longer persists the private key —
 * the body comes back exactly once on the ``POST /clients/manual``
 * response, the parent caches it in component state, and this panel
 * gives the operator copy / download affordances before the state is
 * discarded.
 *
 * There is no re-fetch path: closing the panel without saving the
 * body means delete + re-register is the only way to get it back
 * (which mints a fresh keypair).
 */
function ManualClientConfigPanel({
  client,
  body,
  onClose,
}: {
  client: Client;
  body: string;
  onClose: () => void;
}) {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">(
    "idle",
  );

  useEffect(() => {
    if (copyState === "idle") return;
    const handle = window.setTimeout(() => setCopyState("idle"), 2000);
    return () => window.clearTimeout(handle);
  }, [copyState]);

  async function copyToClipboard(text: string) {
    try {
      if (navigator?.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
      }
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  }

  function downloadAsFile(text: string, filename: string) {
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          WireGuard config — {client.name} (#{client.id})
        </CardTitle>
        <CardDescription>
          Install this body on the device as{" "}
          <code>/etc/wireguard/wg0.conf</code> (Linux) or import it into
          the WireGuard app (phones / desktops). It contains the
          device&apos;s private key. <strong>Save it now</strong> — the
          control plane doesn&apos;t keep a copy, so closing this panel
          without copying / downloading the body means delete + re-
          register is the only way to mint a new one.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <pre
          data-testid="manual-client-config-body"
          className="max-h-96 overflow-auto rounded-md border border-border bg-muted/40 p-3 font-mono text-xs"
        >
          {body}
        </pre>
      </CardContent>
      <CardFooter className="flex gap-2">
        <Button
          type="button"
          variant="outline"
          size="sm"
          disabled={!body}
          onClick={() => copyToClipboard(body)}
        >
          {copyState === "copied"
            ? "Copied!"
            : copyState === "failed"
              ? "Copy failed"
              : "Copy"}
        </Button>
        <Button
          type="button"
          variant="outline"
          size="sm"
          disabled={!body}
          onClick={() => downloadAsFile(body, `${client.name}.conf`)}
        >
          Download
        </Button>
        <Button type="button" variant="ghost" size="sm" onClick={onClose}>
          Close
        </Button>
      </CardFooter>
    </Card>
  );
}
