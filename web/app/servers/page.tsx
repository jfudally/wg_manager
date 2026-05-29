"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { Server, ServerUpdate } from "@/lib/types";
import { Alert } from "@/components/ui/alert";
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
import { cn, formatDateTime } from "@/lib/utils";

/**
 * Servers page. Each row exposes the three operations the API supports
 * (reprovision, discover, view peers). Discovery dispatches a task and a
 * `TaskPoller` watches it to terminal state — `is_managed` flags appear
 * on the discovered peers page once the task succeeds.
 */
export default function ServersPage() {
  const qc = useQueryClient();
  const serversQuery = useQuery({
    queryKey: ["servers"],
    queryFn: api.listServers,
  });
  const [showForm, setShowForm] = useState(false);
  // When set, an inline edit form is rendered for this server above the
  // table. Stored as the full row so the form can pre-populate without
  // re-fetching.
  const [editingServer, setEditingServer] = useState<Server | null>(null);
  // Track active tasks per (server-id, kind) so multiple operations can
  // be polled concurrently without losing context.
  const [activeTasks, setActiveTasks] = useState<
    Array<{ key: string; taskId: string; label: string }>
  >([]);

  const discoverAllMutation = useMutation({
    mutationFn: api.discoverAllServers,
    onSuccess: (data) => {
      setActiveTasks((t) => [
        ...t,
        {
          key: `discover-all-${data.task_id}`,
          taskId: data.task_id,
          label: `Discover all (${data.server_count} servers)`,
        },
      ]);
    },
  });

  function dropTask(key: string) {
    setActiveTasks((t) => t.filter((x) => x.key !== key));
  }

  return (
    <div className="flex flex-col gap-6">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Servers</h1>
          <p className="text-sm text-muted-foreground">
            WireGuard hub nodes. Provisioning, reprovisioning, and peer
            discovery all run as background tasks.
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            onClick={() => discoverAllMutation.mutate()}
            disabled={discoverAllMutation.isPending}
          >
            {discoverAllMutation.isPending ? "Dispatching…" : "Discover all"}
          </Button>
          <Button onClick={() => setShowForm((v) => !v)}>
            {showForm ? "Cancel" : "+ Register server"}
          </Button>
        </div>
      </header>

      {discoverAllMutation.isError ? (
        <Alert variant="error">
          {(discoverAllMutation.error as ApiError | Error).message}
        </Alert>
      ) : null}

      {showForm ? (
        <RegisterServerForm
          onRegistered={(taskId) => {
            setShowForm(false);
            qc.invalidateQueries({ queryKey: ["servers"] });
            setActiveTasks((t) => [
              ...t,
              {
                key: `register-${taskId}`,
                taskId,
                label: "Register server",
              },
            ]);
          }}
        />
      ) : null}

      {editingServer ? (
        <EditServerForm
          server={editingServer}
          onCancel={() => setEditingServer(null)}
          onSaved={() => {
            setEditingServer(null);
            qc.invalidateQueries({ queryKey: ["servers"] });
          }}
        />
      ) : null}

      {activeTasks.map((t) => (
        <div key={t.key} className="flex flex-col gap-2">
          <TaskPoller
            taskId={t.taskId}
            label={t.label}
            onSuccess={() => {
              qc.invalidateQueries({ queryKey: ["servers"] });
              qc.invalidateQueries({ queryKey: ["discovered-peers"] });
            }}
          />
          <div className="flex justify-end">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => dropTask(t.key)}
            >
              Dismiss
            </Button>
          </div>
        </div>
      ))}

      {serversQuery.isError ? (
        <Alert variant="error" title="Couldn't load servers">
          {(serversQuery.error as Error).message}
        </Alert>
      ) : null}

      {serversQuery.isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : serversQuery.data && serversQuery.data.length === 0 ? (
        <EmptyState
          title="No servers yet"
          description="Register your first hub node above to start provisioning the network."
        />
      ) : serversQuery.data ? (
        <ServerTable
          servers={serversQuery.data}
          onTaskDispatched={(taskId, label) =>
            setActiveTasks((t) => [
              ...t,
              { key: `${label}-${taskId}`, taskId, label },
            ])
          }
          onEdit={(s) => setEditingServer(s)}
          onDeleted={() =>
            qc.invalidateQueries({ queryKey: ["servers"] })
          }
        />
      ) : null}
    </div>
  );
}

function ServerTable({
  servers,
  onTaskDispatched,
  onEdit,
  onDeleted,
}: {
  servers: Server[];
  onTaskDispatched: (taskId: string, label: string) => void;
  onEdit: (server: Server) => void;
  onDeleted: () => void;
}) {
  const reprovision = useMutation({
    mutationFn: (id: number) => api.reprovisionServer(id),
    onSuccess: (data) =>
      onTaskDispatched(
        data.task_id,
        `Reprovision server #${data.server.id}`,
      ),
  });
  const discover = useMutation({
    mutationFn: (id: number) => api.discoverServer(id),
    onSuccess: (data) =>
      onTaskDispatched(data.task_id, `Discover #${data.server.id}`),
  });
  // Phase 2c CP3.4 — operator-driven host cert rotation. Dispatches
  // the same task envelope shape as the other server-side actions so
  // the existing TaskPoller surfaces progress without special-casing.
  const rotateHostCert = useMutation({
    mutationFn: (id: number) => api.rotateHostCert(id),
    onSuccess: (data) =>
      onTaskDispatched(
        data.task_id,
        `Rotate host cert #${data.server.id}`,
      ),
  });

  // When a DELETE returns 409 we surface it inline so the operator can
  // retry with ``force=true`` without losing context. Keyed by server id
  // so multiple rows can host independent errors at the same time.
  const [deleteError, setDeleteError] = useState<{
    serverId: number;
    message: string;
    conflict: boolean;
  } | null>(null);

  const deleteMutation = useMutation({
    mutationFn: ({ id, force }: { id: number; force: boolean }) =>
      api.deleteServer(id, force),
    onSuccess: () => {
      setDeleteError(null);
      onDeleted();
    },
    onError: (err: unknown, variables) => {
      const status = err instanceof ApiError ? err.status : 0;
      setDeleteError({
        serverId: variables.id,
        message: (err as Error).message,
        conflict: status === 409,
      });
    },
  });

  function requestDelete(server: Server) {
    setDeleteError(null);
    const confirmed = window.confirm(
      `Delete server #${server.id} (${server.hostname})?\n\n` +
        "This removes the row from the wg-manager database only — the " +
        "remote host keeps running wg-quick. Any attached managed " +
        "clients will block the delete unless you force-cascade on the " +
        "follow-up prompt.",
    );
    if (!confirmed) return;
    deleteMutation.mutate({ id: server.id, force: false });
  }

  return (
    <div className="flex flex-col gap-2">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>ID</TableHead>
            <TableHead>Hostname</TableHead>
            <TableHead>Endpoint</TableHead>
            <TableHead>Subnet</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Created</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {servers.map((s) => (
            <TableRow key={s.id}>
              <TableCell className="font-mono text-xs">{s.id}</TableCell>
              <TableCell className="font-medium">
                {s.hostname}
                <HostCertSummary server={s} />
              </TableCell>
              <TableCell className="text-xs">
                {s.endpoint_host}:{s.endpoint_port}
              </TableCell>
              <TableCell className="text-xs">{s.subnet}</TableCell>
              <TableCell>
                <StatusBadge status={s.status} />
              </TableCell>
              <TableCell className="text-xs text-muted-foreground">
                {formatDateTime(s.created_at)}
              </TableCell>
              <TableCell className="flex justify-end gap-2">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => discover.mutate(s.id)}
                  disabled={discover.isPending}
                >
                  Discover
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => reprovision.mutate(s.id)}
                  disabled={reprovision.isPending}
                >
                  Reprovision
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => rotateHostCert.mutate(s.id)}
                  disabled={rotateHostCert.isPending}
                  title="Re-mint and install this server's SSH host cert from the Vault SSH CA"
                >
                  Rotate cert
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => onEdit(s)}
                >
                  Edit
                </Button>
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={() => requestDelete(s)}
                  disabled={
                    deleteMutation.isPending &&
                    deleteMutation.variables?.id === s.id
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
      {discover.isError ? (
        <Alert variant="error">{(discover.error as Error).message}</Alert>
      ) : null}
      {rotateHostCert.isError ? (
        <Alert
          variant="error"
          title="Couldn't rotate host cert"
        >
          {(rotateHostCert.error as Error).message}
        </Alert>
      ) : null}
      {deleteError ? (
        <Alert
          variant="error"
          title={
            deleteError.conflict
              ? `Server #${deleteError.serverId} has attached clients`
              : `Couldn't delete server #${deleteError.serverId}`
          }
        >
          <div className="flex flex-col gap-2">
            <p>{deleteError.message}</p>
            {deleteError.conflict ? (
              <div className="flex gap-2">
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={() => {
                    if (
                      window.confirm(
                        "Force-delete will also remove every managed " +
                          "client and discovered peer attached to this " +
                          "server. Continue?",
                      )
                    ) {
                      deleteMutation.mutate({
                        id: deleteError.serverId,
                        force: true,
                      });
                    }
                  }}
                  disabled={deleteMutation.isPending}
                >
                  Force delete (cascade)
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setDeleteError(null)}
                >
                  Dismiss
                </Button>
              </div>
            ) : null}
          </div>
        </Alert>
      ) : null}
    </div>
  );
}

function RegisterServerForm({
  onRegistered,
}: {
  onRegistered: (taskId: string) => void;
}) {
  const keysQuery = useQuery({ queryKey: ["ssh-keys"], queryFn: api.listSshKeys });
  const [hostname, setHostname] = useState("");
  const [endpointHost, setEndpointHost] = useState("");
  const [sshUsername, setSshUsername] = useState("ubuntu");
  const [sshPort, setSshPort] = useState(22);
  const [endpointPort, setEndpointPort] = useState(51820);
  const [interfaceName, setInterfaceName] = useState("wg0");
  const [sshKeyId, setSshKeyId] = useState<number | "">("");
  const [subnet, setSubnet] = useState("");

  const mutation = useMutation({
    mutationFn: () => {
      if (sshKeyId === "") throw new Error("Pick an SSH role first");
      const trimmedSubnet = subnet.trim();
      return api.registerServer({
        hostname: hostname.trim(),
        endpoint_host: endpointHost.trim() || hostname.trim(),
        ssh_username: sshUsername.trim(),
        ssh_key_id: Number(sshKeyId),
        ssh_port: sshPort,
        endpoint_port: endpointPort,
        interface: interfaceName,
        // Only forward subnet when the operator filled it in — an empty
        // string would override the server-side default with a 422.
        ...(trimmedSubnet ? { subnet: trimmedSubnet } : {}),
      });
    },
    onSuccess: (data) => {
      setHostname("");
      setEndpointHost("");
      setSubnet("");
      onRegistered(data.task_id);
    },
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>Register a hub server</CardTitle>
        <CardDescription>
          Provisioning runs over SSH. The server row is persisted in
          <code className="mx-1 rounded bg-muted px-1 py-0.5 text-xs">
            pending
          </code>
          state immediately; the task drives it to{" "}
          <code className="rounded bg-muted px-1 py-0.5 text-xs">ready</code>{" "}
          when the install succeeds.
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
            <Label htmlFor="srv-host">SSH hostname</Label>
            <Input
              id="srv-host"
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              placeholder="hub.example.com"
              required
            />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="srv-endpoint">Public endpoint host</Label>
            <Input
              id="srv-endpoint"
              value={endpointHost}
              onChange={(e) => setEndpointHost(e.target.value)}
              placeholder="leave blank to reuse SSH hostname"
            />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="srv-user">SSH user</Label>
            <Input
              id="srv-user"
              value={sshUsername}
              onChange={(e) => setSshUsername(e.target.value)}
              required
            />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="srv-sshport">SSH port</Label>
            <Input
              id="srv-sshport"
              type="number"
              min={1}
              max={65535}
              value={sshPort}
              onChange={(e) => setSshPort(Number(e.target.value))}
            />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="srv-wgport">WireGuard UDP port</Label>
            <Input
              id="srv-wgport"
              type="number"
              min={1}
              max={65535}
              value={endpointPort}
              onChange={(e) => setEndpointPort(Number(e.target.value))}
            />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="srv-iface">Interface</Label>
            <Input
              id="srv-iface"
              value={interfaceName}
              onChange={(e) => setInterfaceName(e.target.value)}
            />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="srv-subnet">WireGuard subnet (CIDR)</Label>
            <Input
              id="srv-subnet"
              value={subnet}
              onChange={(e) => setSubnet(e.target.value)}
              placeholder="leave blank for the server default (e.g. 10.9.0.0/24)"
              pattern="^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$"
              title="IPv4 CIDR, e.g. 10.42.0.0/24"
            />
          </div>
          <div className="flex flex-col gap-1 md:col-span-2">
            <Label htmlFor="srv-key">SSH role</Label>
            <select
              id="srv-key"
              className="h-9 rounded-md border border-border bg-background px-2 text-sm"
              value={sshKeyId}
              onChange={(e) =>
                setSshKeyId(e.target.value === "" ? "" : Number(e.target.value))
              }
              required
            >
              <option value="" disabled>
                {keysQuery.data?.length
                  ? "Pick an SSH role…"
                  : "No SSH roles registered — add one first"}
              </option>
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
 * Inline edit form for an existing server. Pre-populates from the current
 * row and only PATCHes the fields the operator changed — `interface`,
 * subnet, address, public key and status are intentionally absent because
 * the backend treats them as provisioning-managed state.
 */
function EditServerForm({
  server,
  onCancel,
  onSaved,
}: {
  server: Server;
  onCancel: () => void;
  onSaved: () => void;
}) {
  const keysQuery = useQuery({ queryKey: ["ssh-keys"], queryFn: api.listSshKeys });
  const [hostname, setHostname] = useState(server.hostname);
  const [endpointHost, setEndpointHost] = useState(server.endpoint_host);
  const [sshUsername, setSshUsername] = useState(server.ssh_username);
  const [sshPort, setSshPort] = useState(server.ssh_port);
  const [endpointPort, setEndpointPort] = useState(server.endpoint_port);
  const [sshKeyId, setSshKeyId] = useState<number>(server.ssh_key_id);

  // Build a partial-update payload containing only fields the operator
  // actually changed, so unchanged keys are never sent on the wire.
  function buildPayload(): ServerUpdate {
    const payload: ServerUpdate = {};
    if (hostname.trim() !== server.hostname) payload.hostname = hostname.trim();
    if (endpointHost.trim() !== server.endpoint_host)
      payload.endpoint_host = endpointHost.trim();
    if (sshUsername.trim() !== server.ssh_username)
      payload.ssh_username = sshUsername.trim();
    if (sshPort !== server.ssh_port) payload.ssh_port = sshPort;
    if (endpointPort !== server.endpoint_port)
      payload.endpoint_port = endpointPort;
    if (sshKeyId !== server.ssh_key_id) payload.ssh_key_id = sshKeyId;
    return payload;
  }

  const mutation = useMutation({
    mutationFn: () => api.updateServer(server.id, buildPayload()),
    onSuccess: () => onSaved(),
  });

  const endpointChanged =
    endpointHost.trim() !== server.endpoint_host ||
    endpointPort !== server.endpoint_port;

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          Edit server #{server.id} — {server.hostname}
        </CardTitle>
        <CardDescription>
          Only operator-supplied connection metadata is editable. Subnet,
          address, public key and the wg interface name stay locked because
          they are managed by provisioning. Changing the WireGuard endpoint
          will not rewrite already-deployed client configs — re-provision
          each client to pick up the new value.
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
            <Label htmlFor="edit-host">SSH hostname</Label>
            <Input
              id="edit-host"
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              required
            />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="edit-endpoint">Public endpoint host</Label>
            <Input
              id="edit-endpoint"
              value={endpointHost}
              onChange={(e) => setEndpointHost(e.target.value)}
              required
            />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="edit-user">SSH user</Label>
            <Input
              id="edit-user"
              value={sshUsername}
              onChange={(e) => setSshUsername(e.target.value)}
              required
            />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="edit-sshport">SSH port</Label>
            <Input
              id="edit-sshport"
              type="number"
              min={1}
              max={65535}
              value={sshPort}
              onChange={(e) => setSshPort(Number(e.target.value))}
            />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="edit-wgport">WireGuard UDP port</Label>
            <Input
              id="edit-wgport"
              type="number"
              min={1}
              max={65535}
              value={endpointPort}
              onChange={(e) => setEndpointPort(Number(e.target.value))}
            />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="edit-key">SSH role</Label>
            <select
              id="edit-key"
              className="h-9 rounded-md border border-border bg-background px-2 text-sm"
              value={sshKeyId}
              onChange={(e) => setSshKeyId(Number(e.target.value))}
              required
            >
              {keysQuery.data?.map((k) => (
                <option key={k.id} value={k.id}>
                  #{k.id} — {k.name}
                </option>
              ))}
            </select>
          </div>
          {endpointChanged ? (
            <div className="md:col-span-2">
              <Alert variant="warning" title="Endpoint changed">
                Existing client configs still point at{" "}
                <code className="rounded bg-muted px-1 py-0.5 text-xs">
                  {server.endpoint_host}:{server.endpoint_port}
                </code>
                . Re-provision each managed client to pick up the new
                endpoint.
              </Alert>
            </div>
          ) : null}
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
 * Phase 2c CP3.4 — compact host-cert summary rendered under the
 * server hostname. Shows nothing when the row has no host cert minted
 * (legacy mode, or a pre-CP3 row that hasn't been re-provisioned).
 *
 * The rendered line is intentionally muted so operators reading the
 * table for routine work can skim past it; the "expires Xd" badge
 * goes amber inside 30 days and red once expired so a row about to
 * lose host-cert auth grabs attention.
 */
function HostCertSummary({ server }: { server: Server }) {
  if (!server.host_cert_serial || !server.host_cert_valid_before) {
    return null;
  }
  const expires = new Date(server.host_cert_valid_before);
  const now = Date.now();
  const daysLeft = Math.floor(
    (expires.getTime() - now) / (1000 * 60 * 60 * 24),
  );
  const expired = daysLeft < 0;
  const warning = daysLeft < 30 && !expired;
  return (
    <div className="text-xs font-normal text-muted-foreground">
      cert <span className="font-mono">#{server.host_cert_serial}</span>{" "}
      ·{" "}
      <span
        className={cn(
          expired && "font-medium text-destructive",
          warning && "font-medium text-amber-600 dark:text-amber-400",
        )}
      >
        {expired ? "expired" : `expires in ${daysLeft}d`}
      </span>
    </div>
  );
}
