"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { api, ApiError } from "@/lib/api";
import type {
  EnrollmentToken,
  EnrollmentTokenCreate,
  EnrollmentTokenCreateResponse,
  EnrollmentTokenStatus,
  Server,
} from "@/lib/types";
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
import { Textarea } from "@/components/ui/textarea";
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
 * Enrollment tokens page (Phase 3f). The dashboard counterpart of
 * `wg-manager enroll-tokens`: list tokens with their derived status,
 * mint one (the plaintext is shown exactly once), and revoke.
 *
 * Everything goes through `/enrollment-tokens`, which is admin-only:
 * a non-admin sees an empty list and gets a 403 on mint / revoke,
 * which the page surfaces as-is.
 */
export default function EnrollmentTokensPage() {
  const qc = useQueryClient();
  const [activeOnly, setActiveOnly] = useState(false);
  const [showForm, setShowForm] = useState(false);
  // The freshly minted token. Held only in component state and dropped
  // on dismiss: the API can't return it again.
  const [minted, setMinted] = useState<EnrollmentTokenCreateResponse | null>(null);

  const tokensQuery = useQuery({
    queryKey: ["enrollment-tokens", { activeOnly }],
    queryFn: () => api.listEnrollmentTokens({ active: activeOnly }),
  });
  const serversQuery = useQuery({ queryKey: ["servers"], queryFn: api.listServers });
  const serversById = useMemo(
    () => new Map((serversQuery.data ?? []).map((s) => [s.id, s])),
    [serversQuery.data],
  );

  return (
    <div className="flex flex-col gap-6">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Enrollment tokens</h1>
          <p className="text-sm text-muted-foreground">
            Tokens a fresh host puts in its userdata to join a hub on its own
            (<code>scripts/enroll_node.sh</code>). Admin only.
          </p>
        </div>
        <Button onClick={() => setShowForm((v) => !v)}>
          {showForm ? "Cancel" : "+ Mint token"}
        </Button>
      </header>

      {minted ? <MintedToken minted={minted} onDismiss={() => setMinted(null)} /> : null}

      {showForm ? (
        <MintForm
          servers={serversQuery.data ?? []}
          onMinted={(resp) => {
            setShowForm(false);
            setMinted(resp);
            qc.invalidateQueries({ queryKey: ["enrollment-tokens"] });
          }}
        />
      ) : null}

      <label className="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={activeOnly}
          onChange={(e) => setActiveOnly(e.target.checked)}
        />
        Active only
      </label>

      {tokensQuery.isError ? (
        <Alert variant="error" title="Couldn't load enrollment tokens">
          {(tokensQuery.error as Error).message}
        </Alert>
      ) : null}

      {tokensQuery.isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : tokensQuery.data && tokensQuery.data.length === 0 ? (
        <EmptyState
          title="No enrollment tokens"
          description={
            activeOnly
              ? "No token is redeemable right now."
              : "Mint one to let new hosts join a hub from their userdata."
          }
        />
      ) : tokensQuery.data ? (
        <TokenTable tokens={tokensQuery.data} serversById={serversById} />
      ) : null}
    </div>
  );
}

const STATUS_VARIANT: Record<EnrollmentTokenStatus, "success" | "error" | "warn" | "default"> = {
  active: "success",
  revoked: "error",
  expired: "default",
  exhausted: "warn",
};

function TokenTable({
  tokens,
  serversById,
}: {
  tokens: EnrollmentToken[];
  serversById: Map<number, Server>;
}) {
  const qc = useQueryClient();
  const revoke = useMutation({
    mutationFn: (id: number) => api.revokeEnrollmentToken(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["enrollment-tokens"] }),
  });

  return (
    <div className="flex flex-col gap-2">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[70px]">ID</TableHead>
            <TableHead>Hub</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Uses</TableHead>
            <TableHead>Expires</TableHead>
            <TableHead>Allowed from</TableHead>
            <TableHead>Created by</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {tokens.map((t) => (
            <TableRow key={t.id}>
              <TableCell className="font-mono text-xs">{t.id}</TableCell>
              <TableCell>
                {serversById.get(t.server_id)?.hostname ?? `#${t.server_id}`}
                <div className="text-xs text-muted-foreground">
                  {t.name_prefix}-* as {t.ssh_username}
                </div>
              </TableCell>
              <TableCell>
                <Badge variant={STATUS_VARIANT[t.status]}>{t.status}</Badge>
              </TableCell>
              <TableCell>
                {t.use_count} / {t.max_uses}
              </TableCell>
              <TableCell className="text-muted-foreground">
                {formatDateTime(t.expires_at)}
              </TableCell>
              <TableCell className="font-mono text-xs">
                {t.allowed_cidrs ? (
                  t.allowed_cidrs.map((c) => <div key={c}>{c}</div>)
                ) : (
                  <span className="font-sans text-muted-foreground">anywhere</span>
                )}
              </TableCell>
              <TableCell className="text-muted-foreground">{t.created_by_cn ?? "—"}</TableCell>
              <TableCell className="flex justify-end">
                {t.status !== "revoked" ? (
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={revoke.isPending}
                    onClick={() => {
                      if (
                        window.confirm(
                          `Revoke enrollment token #${t.id}? It stops working immediately; hosts it already enrolled stay enrolled.`,
                        )
                      ) {
                        revoke.mutate(t.id);
                      }
                    }}
                  >
                    Revoke
                  </Button>
                ) : null}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {revoke.isError ? (
        <Alert variant="error">{(revoke.error as ApiError | Error).message}</Alert>
      ) : null}
    </div>
  );
}

const TTL_PRESETS: Array<[number, string]> = [
  [900, "15 minutes"],
  [3600, "1 hour"],
  [6 * 3600, "6 hours"],
  [86400, "1 day"],
  [7 * 86400, "7 days"],
];

function MintForm({
  servers,
  onMinted,
}: {
  servers: Server[];
  onMinted: (resp: EnrollmentTokenCreateResponse) => void;
}) {
  const keysQuery = useQuery({ queryKey: ["ssh-keys"], queryFn: api.listSshKeys });
  // Only ready hubs can be minted for: the API needs the hub's public key.
  const readyServers = servers.filter((s) => s.status === "ready");

  const [serverId, setServerId] = useState<number | "">("");
  const [sshKeyId, setSshKeyId] = useState<number | "">("");
  const [sshUser, setSshUser] = useState("");
  const [namePrefix, setNamePrefix] = useState("node");
  const [ttl, setTtl] = useState(3600);
  const [maxUses, setMaxUses] = useState(1);
  const [cidrs, setCidrs] = useState("");

  function buildPayload(): EnrollmentTokenCreate {
    const payload: EnrollmentTokenCreate = {
      server_id: Number(serverId),
      ssh_key_id: Number(sshKeyId),
      ssh_username: sshUser.trim(),
      name_prefix: namePrefix.trim(),
      ttl_seconds: ttl,
      max_uses: maxUses,
    };
    const lines = cidrs
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);
    // Blank means "anywhere"; the API rejects an empty list.
    if (lines.length) payload.allowed_cidrs = lines;
    return payload;
  }

  const mutation = useMutation({
    mutationFn: () => api.createEnrollmentToken(buildPayload()),
    onSuccess: onMinted,
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>Mint an enrollment token</CardTitle>
        <CardDescription>
          Hosts that redeem it join the hub as managed clients named{" "}
          <code>&lt;prefix&gt;-&lt;hostname&gt;</code>. Keep the lifetime close to a
          boot, and uses at 1 unless it&apos;s for an autoscaling group.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="grid gap-4 md:grid-cols-2"
          onSubmit={(e) => {
            e.preventDefault();
            mutation.mutate();
          }}
        >
          <div className="flex flex-col gap-1">
            <Label htmlFor="tok-server">Hub</Label>
            <select
              id="tok-server"
              className="h-9 rounded-md border border-border bg-background px-2 text-sm"
              value={serverId}
              onChange={(e) => setServerId(e.target.value === "" ? "" : Number(e.target.value))}
              required
            >
              <option value="" disabled>
                {readyServers.length ? "Pick a ready hub…" : "No ready hubs"}
              </option>
              {readyServers.map((s) => (
                <option key={s.id} value={s.id}>
                  #{s.id} — {s.hostname}
                </option>
              ))}
            </select>
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="tok-key">SSH role</Label>
            <select
              id="tok-key"
              className="h-9 rounded-md border border-border bg-background px-2 text-sm"
              value={sshKeyId}
              onChange={(e) => setSshKeyId(e.target.value === "" ? "" : Number(e.target.value))}
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
            <Label htmlFor="tok-user">SSH user</Label>
            <Input
              id="tok-user"
              value={sshUser}
              onChange={(e) => setSshUser(e.target.value)}
              placeholder="wgmgr"
              required
            />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="tok-prefix">Name prefix</Label>
            <Input
              id="tok-prefix"
              value={namePrefix}
              onChange={(e) => setNamePrefix(e.target.value)}
              required
            />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="tok-ttl">Lifetime</Label>
            <select
              id="tok-ttl"
              className="h-9 rounded-md border border-border bg-background px-2 text-sm"
              value={ttl}
              onChange={(e) => setTtl(Number(e.target.value))}
            >
              {TTL_PRESETS.map(([seconds, label]) => (
                <option key={seconds} value={seconds}>
                  {label}
                </option>
              ))}
            </select>
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="tok-uses">Max uses</Label>
            <Input
              id="tok-uses"
              type="number"
              min={1}
              max={100}
              value={maxUses}
              onChange={(e) => setMaxUses(Number(e.target.value))}
              required
            />
          </div>
          <div className="flex flex-col gap-1 md:col-span-2">
            <Label htmlFor="tok-cidrs">Allowed networks (optional)</Label>
            <Textarea
              id="tok-cidrs"
              rows={3}
              value={cidrs}
              onChange={(e) => setCidrs(e.target.value)}
              placeholder={"203.0.113.0/24\n198.51.100.7"}
            />
            <p className="text-xs text-muted-foreground">
              One network or address per line, up to 16. The token only works from
              these; leave blank to allow any source. Use the addresses the enroll
              port sees (e.g. your NAT gateway&apos;s public IP).
            </p>
          </div>
          {mutation.isError ? (
            <div className="md:col-span-2">
              <Alert variant="error">{(mutation.error as ApiError | Error).message}</Alert>
            </div>
          ) : null}
          <CardFooter className="px-0 pb-0 md:col-span-2">
            <Button type="submit" disabled={mutation.isPending}>
              {mutation.isPending ? "Minting…" : "Mint"}
            </Button>
          </CardFooter>
        </form>
      </CardContent>
    </Card>
  );
}

/**
 * One-time reveal of a freshly minted token. wg-manager stores only its
 * hash, so once this is dismissed the token is gone for good.
 */
function MintedToken({
  minted,
  onDismiss,
}: {
  minted: EnrollmentTokenCreateResponse;
  onDismiss: () => void;
}) {
  const [copied, setCopied] = useState(false);
  return (
    <Card>
      <CardHeader>
        <CardTitle>Token #{minted.id} minted</CardTitle>
        <CardDescription>
          Copy it now. It&apos;s <strong>shown exactly once</strong>: wg-manager keeps
          only its hash. Expires {formatDateTime(minted.expires_at)}, {minted.max_uses}{" "}
          use{minted.max_uses === 1 ? "" : "s"}.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <div className="flex gap-2">
          <Input
            readOnly
            aria-label="Enrollment token"
            className="font-mono text-xs"
            value={minted.token}
            onFocus={(e) => e.currentTarget.select()}
          />
          <Button
            type="button"
            onClick={async () => {
              await navigator.clipboard.writeText(minted.token);
              setCopied(true);
            }}
          >
            {copied ? "Copied" : "Copy token"}
          </Button>
        </div>
        <p className="text-xs text-muted-foreground">
          In the host&apos;s userdata, set <code>WGM_ENROLL_TOKEN</code> to this value
          and run <code>enroll_node.sh</code> (see the operator guide).
        </p>
        <div>
          <Button type="button" variant="ghost" onClick={onDismiss}>
            Dismiss
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
