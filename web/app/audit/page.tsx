"use client";

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "@/lib/api";
import type { AuditEventListParams } from "@/lib/types";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { EmptyState } from "@/components/empty-state";
import { formatDateTime } from "@/lib/utils";

/**
 * Phase 2e cycle 4 — Audit log dashboard page.
 *
 * Read-only view onto the `auditevent` table. The backend's
 * `GET /audit` endpoint (admin / auditor only) returns a filtered,
 * paginated, newest-first list; this page renders it as a single
 * filterable table.
 *
 * Layout (top to bottom):
 *
 * 1. **Filters card** — five exact-match inputs (event slug, actor CN,
 *    resource type, resource id) plus a `since` / `until` time window.
 *    Each typed value re-triggers the query via TanStack's query-key
 *    dependency, so filter changes show up without a manual refresh.
 * 2. **Result envelope** — "Showing X-Y of Z" header that reflects
 *    the backend's `total` field. Lets an auditor scope their filter
 *    until the total falls under a manageable number.
 * 3. **Audit table** — one row per event with timestamp, slug,
 *    actor (CN + role badge), resource (type / id), action, and a
 *    request-id tail for cross-correlation with the CP5 stderr stream.
 * 4. **Pagination** — Prev / Next walk by `limit`. Prev is disabled on
 *    page 1; Next is disabled when `offset + items.length >= total`.
 *
 * Hashes (`before_hash` / `after_hash`) and the payload dict are not
 * surfaced in the table by default — they would dominate the column
 * widths and an auditor reviewing the trail can drop into the CLI for
 * the full row when they need it. A future cycle can lift them into a
 * per-row drawer if the workflow demands it.
 */

const PAGE_SIZE = 100;

export default function AuditPage() {
  // Single useState object keeps the filter inputs and the page
  // offset in lockstep — every filter change resets the offset back
  // to zero so the auditor doesn't end up on page 5 of a freshly
  // filtered result they thought was empty.
  const [filters, setFilters] = useState<AuditEventListParams>({
    limit: PAGE_SIZE,
    offset: 0,
  });

  const update = (patch: Partial<AuditEventListParams>) => {
    setFilters((prev) => ({
      ...prev,
      ...patch,
      // Filter changes always reset to page 1 — except when the patch
      // itself sets offset (the Prev/Next buttons).
      offset: "offset" in patch ? (patch.offset as number) : 0,
    }));
  };

  const auditQuery = useQuery({
    queryKey: ["audit", filters],
    queryFn: () => api.listAuditEvents(filters),
    retry: false,
  });

  const total = auditQuery.data?.total ?? 0;
  const offset = filters.offset ?? 0;
  const items = auditQuery.data?.items ?? [];
  // Step Next/Prev by the page size the server echoed back, so the
  // dashboard stays aligned with the actual page boundary the backend
  // is serving. Falls back to the local default for the first render
  // (before any response has landed).
  const stepLimit = auditQuery.data?.limit ?? filters.limit ?? PAGE_SIZE;
  const displayLimit = filters.limit ?? PAGE_SIZE;

  const lastShown = Math.min(offset + items.length, total);
  const firstShown = items.length === 0 ? 0 : offset + 1;

  const hasPrev = offset > 0;
  const hasNext = offset + items.length < total;

  return (
    <div className="flex flex-col gap-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Audit log</h1>
        <p className="text-sm text-muted-foreground">
          Every mutation the control plane has recorded — who did it,
          what changed, and when. Read-only; entries are written by the
          endpoint that performed the mutation.
        </p>
      </header>

      {auditQuery.isError ? (
        <Alert variant="error" title="Could not load audit log">
          {(auditQuery.error as Error).message}
        </Alert>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>Filters</CardTitle>
          <CardDescription>
            Narrow the result set. All filters are exact-match and
            AND-combined.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <div className="flex flex-col gap-1">
              <Label htmlFor="audit-filter-event">Event slug</Label>
              <Input
                id="audit-filter-event"
                placeholder="e.g. server.create"
                value={filters.event ?? ""}
                onChange={(e) =>
                  update({ event: e.target.value || undefined })
                }
              />
            </div>
            <div className="flex flex-col gap-1">
              <Label htmlFor="audit-filter-actor">Actor CN</Label>
              <Input
                id="audit-filter-actor"
                placeholder="e.g. ops@wg.local"
                value={filters.actor_cn ?? ""}
                onChange={(e) =>
                  update({ actor_cn: e.target.value || undefined })
                }
              />
            </div>
            <div className="flex flex-col gap-1">
              <Label htmlFor="audit-filter-rtype">Resource type</Label>
              <Input
                id="audit-filter-rtype"
                placeholder="e.g. server"
                value={filters.resource_type ?? ""}
                onChange={(e) =>
                  update({ resource_type: e.target.value || undefined })
                }
              />
            </div>
            <div className="flex flex-col gap-1">
              <Label htmlFor="audit-filter-rid">Resource id</Label>
              <Input
                id="audit-filter-rid"
                type="number"
                min={1}
                placeholder="e.g. 7"
                value={
                  filters.resource_id === undefined
                    ? ""
                    : String(filters.resource_id)
                }
                onChange={(e) => {
                  const raw = e.target.value;
                  if (raw === "") {
                    update({ resource_id: undefined });
                  } else {
                    const n = Number(raw);
                    if (!Number.isNaN(n)) update({ resource_id: n });
                  }
                }}
              />
            </div>
            <div className="flex flex-col gap-1">
              <Label htmlFor="audit-filter-since">Since (ISO-8601)</Label>
              <Input
                id="audit-filter-since"
                placeholder="2026-06-01T00:00:00Z"
                value={filters.since ?? ""}
                onChange={(e) =>
                  update({ since: e.target.value || undefined })
                }
              />
            </div>
            <div className="flex flex-col gap-1">
              <Label htmlFor="audit-filter-until">Until (ISO-8601)</Label>
              <Input
                id="audit-filter-until"
                placeholder="2026-07-01T00:00:00Z"
                value={filters.until ?? ""}
                onChange={(e) =>
                  update({ until: e.target.value || undefined })
                }
              />
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Events</CardTitle>
          <CardDescription>
            {total === 0
              ? "No matching events."
              : `Showing ${firstShown}-${lastShown} of ${total}.`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {auditQuery.isLoading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : items.length === 0 ? (
            <EmptyState
              title="No audit events"
              description="Mutations recorded by the control plane will appear here. Try clearing the filters above."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Timestamp</TableHead>
                  <TableHead>Event</TableHead>
                  <TableHead>Actor</TableHead>
                  <TableHead>Resource</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Request</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((row) => (
                  <TableRow key={row.id}>
                    <TableCell className="whitespace-nowrap text-xs">
                      {formatDateTime(row.ts)}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {row.event}
                    </TableCell>
                    <TableCell className="text-xs">
                      <div className="flex flex-col gap-1">
                        <span>{row.actor_cn ?? "—"}</span>
                        {row.actor_role ? (
                          <Badge variant="info" className="w-fit">
                            {row.actor_role}
                          </Badge>
                        ) : null}
                      </div>
                    </TableCell>
                    <TableCell className="text-xs">
                      {row.resource_type}
                      {row.resource_id !== null ? `#${row.resource_id}` : ""}
                    </TableCell>
                    <TableCell className="text-xs">{row.action}</TableCell>
                    <TableCell className="font-mono text-[10px] text-muted-foreground">
                      {row.request_id ?? "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}

          <div className="mt-4 flex items-center justify-between">
            <p className="text-xs text-muted-foreground">
              Page size: {displayLimit}
            </p>
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={!hasPrev}
                onClick={() =>
                  update({ offset: Math.max(0, offset - stepLimit) })
                }
              >
                Prev
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={!hasNext}
                onClick={() => update({ offset: offset + stepLimit })}
              >
                Next
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
