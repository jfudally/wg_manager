"use client";

import { useQuery } from "@tanstack/react-query";
import { api, ApiError } from "@/lib/api";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

/**
 * Crypto status page.
 *
 * After Alembic 0008 dropped the sshkey ciphertext columns and 0009
 * dropped the manual-client private-key ciphertext column, no wg-
 * manager table holds persisted secret material at rest. The page
 * shrinks to reporting only the active backend identity and key
 * version — the two facts the operator still cares about:
 *
 * - Which backend is bootstrapped (`local-dev` or `vault-transit`)
 *   and whether Vault is healthy enough to answer.
 * - The current key version. Bumps after a Vault Transit rotation;
 *   nothing on disk needs rewrapping (no row carries ciphertext),
 *   but the bump is a useful "rotation landed" smoke signal.
 *
 * The Vault Transit binding stays because it is the canonical
 * substrate for any future encrypted-at-rest column.
 */
export default function CryptoPage() {
  const status = useQuery({
    queryKey: ["crypto-status"],
    queryFn: api.cryptoStatus,
  });

  return (
    <div className="flex flex-col gap-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Crypto Status</h1>
        <p className="text-sm text-muted-foreground">
          Encryption-at-rest backend identity and current key version.
        </p>
      </header>

      {status.isError ? (
        <Alert variant="error" title="Couldn't load crypto status">
          {(status.error as ApiError | Error).message}
        </Alert>
      ) : null}

      {status.isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : null}

      {status.data ? <CryptoStatusPanel data={status.data} /> : null}
    </div>
  );
}

function CryptoStatusPanel({
  data,
}: {
  data: {
    backend: string;
    key_version: number;
  };
}) {
  const backendVariant: "success" | "info" =
    data.backend === "vault-transit" ? "success" : "info";

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>Backend</CardTitle>
          <CardDescription>
            Which wg-manager component is wrapping persisted secrets.
            Currently no row carries ciphertext (Alembic 0008 dropped
            the SSH key columns; 0009 dropped the manual-client column);
            the backend stays bootstrapped as the substrate for any
            future encrypted-at-rest column.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex items-center gap-3">
          <Badge variant={backendVariant}>{data.backend}</Badge>
          <span className="text-sm text-muted-foreground">
            key version{" "}
            <code className="rounded bg-muted px-1 py-0.5 text-xs">
              {data.key_version}
            </code>
          </span>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Storage</CardTitle>
          <CardDescription>
            What persisted secret material the schema currently holds.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Badge variant="success">No encrypted columns</Badge>
          <p className="mt-2 text-xs text-muted-foreground">
            SSH auth mints from the CA at task time; manual-client
            wg0.conf bodies are delivered exactly once at registration
            and never persisted. Nothing on disk needs rewrapping after
            a Vault Transit rotation.
          </p>
        </CardContent>
      </Card>

      <Card className="lg:col-span-2">
        <CardHeader>
          <CardTitle>Operator runbook</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm text-muted-foreground">
          <p>
            <strong className="text-foreground">Rotate the Vault key.</strong>{" "}
            Run{" "}
            <code className="rounded bg-muted px-1 py-0.5 text-xs">
              vault write -f transit/keys/wg-manager/rotate
            </code>{" "}
            — the key version above should bump on the next page load.{" "}
            <code className="rounded bg-muted px-1 py-0.5 text-xs">
              wg-manager crypto rewrap
            </code>{" "}
            is a no-op against the current schema (no encrypted columns
            to walk) but stays available for forward-compat and as a
            backend-reachability smoke test.
          </p>
          <p>
            <strong className="text-foreground">Adding a new secret column.</strong>{" "}
            Use the CryptoBackend seam — see{" "}
            <code className="rounded bg-muted px-1 py-0.5 text-xs">
              docs/vault-cookbook.md
            </code>{" "}
            for the per-row context binding convention and the
            row-swap defence pattern the prior encrypted columns used.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
