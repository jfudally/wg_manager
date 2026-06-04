"use client";

import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { useState } from "react";
import { api } from "@/lib/api";
import type { OperatorRole, OperatorTenantRead, Tenant } from "@/lib/types";
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
 * Phase 3b cycle 2 — Tenants dashboard page.
 *
 * Three vertically-stacked sections:
 *
 * 1. **Tenant inventory** — every row in :class:`wg_manager.models.Tenant`,
 *    with a per-row Select button that loads the detail panel.
 * 2. **Create tenant** form — wraps `POST /tenants`. Mirrors the
 *    CLI's `wg-manager tenants create` flags.
 * 3. **Selected tenant detail** — header + a per-tenant operator
 *    table (`GET /tenants/{slug}/operators`) with an Attach form
 *    and per-row Detach buttons.
 *
 * Cycle 3 will tighten the list endpoint to return only the
 * operator's per-tenant set, at which point this page automatically
 * narrows without code changes. Cycle 5 is the polish slice that
 * adds search, per-role badging, and the IPAM panel.
 */
export default function TenantsPage() {
  const queryClient = useQueryClient();
  const tenantsQuery = useQuery({
    queryKey: ["tenants"],
    queryFn: api.listTenants,
    retry: false,
  });
  const [selectedSlug, setSelectedSlug] = useState<string | null>(null);

  const operatorsQuery = useQuery({
    queryKey: ["tenants", selectedSlug, "operators"],
    queryFn: () => api.listTenantOperators(selectedSlug as string),
    enabled: selectedSlug !== null,
    retry: false,
  });

  const createMutation = useMutation({
    mutationFn: api.createTenant,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["tenants"] });
    },
  });

  const attachMutation = useMutation({
    mutationFn: ({
      slug,
      cn,
      role,
    }: {
      slug: string;
      cn: string;
      role: OperatorRole;
    }) => api.attachOperatorToTenant(slug, { cn, role }),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["tenants", selectedSlug, "operators"],
      });
    },
  });

  const detachMutation = useMutation({
    mutationFn: ({ slug, cn }: { slug: string; cn: string }) =>
      api.detachOperatorFromTenant(slug, cn),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["tenants", selectedSlug, "operators"],
      });
    },
  });

  const [createName, setCreateName] = useState("");
  const [createSlug, setCreateSlug] = useState("");
  const [createPool, setCreatePool] = useState("");
  const [attachCn, setAttachCn] = useState("");
  const [attachRole, setAttachRole] = useState<OperatorRole>("operator");

  const tenants = tenantsQuery.data ?? [];
  const operators = operatorsQuery.data ?? [];
  const selectedTenant =
    selectedSlug !== null
      ? tenants.find((t) => t.slug === selectedSlug) ?? null
      : null;

  return (
    <div className="flex flex-col gap-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Tenants</h1>
        <p className="text-sm text-muted-foreground">
          Namespace boundary for the multi-tenant operator model
          (Phase 3b). The <code>default</code> tenant ships with the
          schema; every Phase-3b-cycle-1 row was back-filled there.
          Attach operators to a tenant to grant them access; the
          per-tenant role is independent of the operator&apos;s
          global role.
        </p>
      </header>

      {tenantsQuery.isError ? (
        <Alert variant="error" title="Could not load tenants">
          {(tenantsQuery.error as Error).message}
        </Alert>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>Tenants</CardTitle>
          <CardDescription>
            Every tenant registered with the control plane.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {tenantsQuery.isLoading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : tenants.length === 0 ? (
            <EmptyState
              title="No tenants"
              description="Create the first tenant below, or run `alembic upgrade head` if the default tenant is missing."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Slug</TableHead>
                  <TableHead>Subnet pool</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="w-32" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {tenants.map((tenant) => (
                  <TableRow key={tenant.id}>
                    <TableCell className="font-medium">
                      {tenant.name}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {tenant.slug}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {tenant.subnet_pool}
                    </TableCell>
                    <TableCell className="text-xs">
                      {formatDateTime(tenant.created_at)}
                    </TableCell>
                    <TableCell>
                      <Button
                        size="sm"
                        variant={
                          selectedSlug === tenant.slug
                            ? "default"
                            : "outline"
                        }
                        aria-label={`Select ${tenant.slug}`}
                        onClick={() => setSelectedSlug(tenant.slug)}
                      >
                        {selectedSlug === tenant.slug
                          ? "Selected"
                          : "Select"}
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Create tenant</CardTitle>
          <CardDescription>
            Add a new namespace. The slug derives from the name when
            left blank.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex flex-col gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              if (!createName.trim()) return;
              createMutation.mutate({
                name: createName.trim(),
                slug: createSlug.trim() || undefined,
                subnet_pool: createPool.trim() || undefined,
              });
              setCreateName("");
              setCreateSlug("");
              setCreatePool("");
            }}
          >
            <div className="flex flex-col gap-1">
              <Label htmlFor="tenant-create-name">Name</Label>
              <Input
                id="tenant-create-name"
                placeholder="Acme"
                value={createName}
                onChange={(e) => setCreateName(e.target.value)}
              />
            </div>
            <div className="flex flex-col gap-1">
              <Label htmlFor="tenant-create-slug">Slug (optional)</Label>
              <Input
                id="tenant-create-slug"
                placeholder="acme"
                value={createSlug}
                onChange={(e) => setCreateSlug(e.target.value)}
              />
            </div>
            <div className="flex flex-col gap-1">
              <Label htmlFor="tenant-create-pool">
                Subnet pool (optional)
              </Label>
              <Input
                id="tenant-create-pool"
                placeholder="10.42.0.0/16"
                value={createPool}
                onChange={(e) => setCreatePool(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                CIDR carving the tenant&apos;s slice of the WireGuard
                IP space. Must be disjoint from every other
                tenant&apos;s pool. Defaults to 10.0.0.0/8 when blank.
              </p>
            </div>
            {createMutation.isError ? (
              <Alert variant="error" title="Could not create tenant">
                {(createMutation.error as Error).message}
              </Alert>
            ) : null}
            <div>
              <Button
                type="submit"
                disabled={createMutation.isPending || !createName.trim()}
              >
                {createMutation.isPending ? "Creating…" : "Create"}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      {selectedTenant !== null ? (
        <Card>
          <CardHeader>
            <CardTitle>
              {selectedTenant.name}{" "}
              <span className="text-sm font-mono text-muted-foreground">
                ({selectedTenant.slug})
              </span>
            </CardTitle>
            <CardDescription>
              Subnet pool{" "}
              <code className="font-mono text-xs">
                {selectedTenant.subnet_pool}
              </code>{" "}
              — every server in this tenant must allocate its
              subnet from inside the pool. Operators below have
              per-tenant access; their per-tenant role gates which
              endpoints they can hit on this tenant&apos;s
              resources.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-6">
            {operatorsQuery.isError ? (
              <Alert variant="error" title="Could not load operators">
                {(operatorsQuery.error as Error).message}
              </Alert>
            ) : null}

            {operatorsQuery.isLoading ? (
              <p className="text-sm text-muted-foreground">Loading…</p>
            ) : operators.length === 0 ? (
              <EmptyState
                title="No operators attached"
                description="Attach an operator below to grant them access to this tenant."
              />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Operator CN</TableHead>
                    <TableHead>Role</TableHead>
                    <TableHead>Attached</TableHead>
                    <TableHead className="w-32" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {operators.map((join) => (
                    <TableRow key={join.id}>
                      <TableCell className="font-mono text-xs">
                        {join.operator_cn}
                      </TableCell>
                      <TableCell>
                        <Badge variant="info">{join.role}</Badge>
                      </TableCell>
                      <TableCell className="text-xs">
                        {formatDateTime(join.created_at)}
                      </TableCell>
                      <TableCell>
                        <Button
                          size="sm"
                          variant="outline"
                          aria-label={`Detach ${join.operator_cn}`}
                          onClick={() =>
                            detachMutation.mutate({
                              slug: selectedTenant.slug,
                              cn: join.operator_cn,
                            })
                          }
                          disabled={detachMutation.isPending}
                        >
                          Detach
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}

            <form
              className="flex flex-col gap-4 border-t border-border pt-6"
              onSubmit={(e) => {
                e.preventDefault();
                if (!attachCn.trim()) return;
                attachMutation.mutate({
                  slug: selectedTenant.slug,
                  cn: attachCn.trim(),
                  role: attachRole,
                });
                setAttachCn("");
              }}
            >
              <h3 className="text-sm font-semibold">Attach operator</h3>
              <div className="flex flex-col gap-1">
                <Label htmlFor="tenant-attach-cn">Operator CN</Label>
                <Input
                  id="tenant-attach-cn"
                  placeholder="alice@wg.local"
                  value={attachCn}
                  onChange={(e) => setAttachCn(e.target.value)}
                />
              </div>
              <div className="flex flex-col gap-1">
                <Label htmlFor="tenant-attach-role">Role</Label>
                <select
                  id="tenant-attach-role"
                  className="h-9 rounded-md border border-input bg-background px-3 text-sm"
                  value={attachRole}
                  onChange={(e) =>
                    setAttachRole(e.target.value as OperatorRole)
                  }
                >
                  <option value="operator">operator</option>
                  <option value="admin">admin</option>
                  <option value="auditor">auditor</option>
                </select>
              </div>
              {attachMutation.isError ? (
                <Alert variant="error" title="Could not attach">
                  {(attachMutation.error as Error).message}
                </Alert>
              ) : null}
              <div>
                <Button
                  type="submit"
                  disabled={
                    attachMutation.isPending || !attachCn.trim()
                  }
                >
                  {attachMutation.isPending ? "Attaching…" : "Attach"}
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}
