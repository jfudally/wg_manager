"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { DiscoveredPeer } from "@/lib/types";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
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
import { formatBytes, relativeFromNow } from "@/lib/utils";

/**
 * Discovered peers page. Shows what `wg show <iface> dump` reported on
 * each server, filtered by server selection. The "Discover all" button
 * walks every server and is fail-soft — unreachable hosts are logged
 * rather than aborting the batch.
 */
export default function DiscoveredPeersPage() {
  const qc = useQueryClient();
  const peersQuery = useQuery({
    queryKey: ["discovered-peers", "all"],
    queryFn: api.listAllDiscoveredPeers,
  });
  const serversQuery = useQuery({
    queryKey: ["servers"],
    queryFn: api.listServers,
  });

  const [serverFilter, setServerFilter] = useState<number | "all">("all");
  const [activeTaskId, setActiveTaskId] = useState<string | null>(null);

  const discoverAll = useMutation({
    mutationFn: api.discoverAllServers,
    onSuccess: (data) => {
      // Clear the displayed results the moment a new run is dispatched so
      // the table never shows a previous pass's peers while discovery is in
      // flight. The TaskPoller's onSuccess re-fetches the authoritative list
      // once the run completes (the backend prunes vanished peers on its
      // side, so the refetch reflects exactly what is on the wire now).
      qc.setQueryData<DiscoveredPeer[]>(["discovered-peers", "all"], []);
      setActiveTaskId(data.task_id);
    },
  });

  const peers = peersQuery.data ?? [];
  const filtered = useMemo(() => {
    if (serverFilter === "all") return peers;
    return peers.filter((p) => p.server_id === serverFilter);
  }, [peers, serverFilter]);

  const serverById = useMemo(() => {
    const m = new Map<number, string>();
    for (const s of serversQuery.data ?? []) m.set(s.id, s.hostname);
    return m;
  }, [serversQuery.data]);

  return (
    <div className="flex flex-col gap-6">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">
            Discovered Peers
          </h1>
          <p className="text-sm text-muted-foreground">
            What <code>wg show</code> reported on each server. The
            <code className="mx-1 rounded bg-muted px-1 py-0.5 text-xs">
              is_managed
            </code>
            flag is true when a managed Client row matches the public key.
          </p>
        </div>
        <Button
          onClick={() => discoverAll.mutate()}
          disabled={discoverAll.isPending}
        >
          {discoverAll.isPending ? "Dispatching…" : "Discover all servers"}
        </Button>
      </header>

      {discoverAll.isError ? (
        <Alert variant="error">
          {(discoverAll.error as ApiError | Error).message}
        </Alert>
      ) : null}

      {activeTaskId ? (
        <div className="flex flex-col gap-2">
          <TaskPoller
            taskId={activeTaskId}
            label="Discover all servers"
            onSuccess={() => {
              qc.invalidateQueries({ queryKey: ["discovered-peers"] });
            }}
          />
          <div className="flex justify-end">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setActiveTaskId(null)}
            >
              Dismiss
            </Button>
          </div>
        </div>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>Filter</CardTitle>
          <CardDescription>
            Restrict the table to a single server, or view every observed
            peer at once.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <select
            className="h-9 w-full max-w-sm rounded-md border border-border bg-background px-2 text-sm"
            value={String(serverFilter)}
            onChange={(e) =>
              setServerFilter(
                e.target.value === "all" ? "all" : Number(e.target.value),
              )
            }
          >
            <option value="all">All servers</option>
            {serversQuery.data?.map((s) => (
              <option key={s.id} value={s.id}>
                #{s.id} — {s.hostname}
              </option>
            ))}
          </select>
        </CardContent>
      </Card>

      {peersQuery.isError ? (
        <Alert variant="error" title="Couldn't load peers">
          {(peersQuery.error as Error).message}
        </Alert>
      ) : null}

      {peersQuery.isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : filtered.length === 0 ? (
        <EmptyState
          title="No peers discovered yet"
          description='Click "Discover all servers" or use the Discover button on a single server in the Servers tab.'
        />
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Server</TableHead>
              <TableHead>Public key</TableHead>
              <TableHead>Allowed IPs</TableHead>
              <TableHead>Endpoint</TableHead>
              <TableHead>Handshake</TableHead>
              <TableHead>Transfer</TableHead>
              <TableHead>Managed?</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filtered.map((p) => (
              <TableRow key={p.id}>
                <TableCell className="text-xs">
                  #{p.server_id} — {serverById.get(p.server_id) ?? "?"}
                </TableCell>
                <TableCell className="font-mono text-xs">
                  <span title={p.public_key}>
                    {p.public_key.length > 24
                      ? `${p.public_key.slice(0, 12)}…${p.public_key.slice(-8)}`
                      : p.public_key}
                  </span>
                </TableCell>
                <TableCell className="font-mono text-xs">
                  {p.allowed_ips}
                </TableCell>
                <TableCell className="font-mono text-xs">
                  {p.endpoint ?? "—"}
                </TableCell>
                <TableCell className="text-xs">
                  {p.last_handshake_at
                    ? relativeFromNow(p.last_handshake_at)
                    : "never"}
                </TableCell>
                <TableCell className="text-xs">
                  ↑ {formatBytes(p.tx_bytes)} · ↓ {formatBytes(p.rx_bytes)}
                </TableCell>
                <TableCell>
                  {p.is_managed ? (
                    <Badge variant="success">managed</Badge>
                  ) : (
                    <Badge variant="warn">unmanaged</Badge>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  );
}
