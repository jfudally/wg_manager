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
 * Crypto status page — Phase 2b checkpoint 3.
 *
 * Surfaces the encryption-at-rest layer:
 *
 * - Which backend is wrapping secrets (`local-dev` or `vault-transit`).
 * - The active key version. Bumps after a Vault Transit rotation;
 *   operators should run `wg-manager crypto rewrap` after the bump so
 *   every row lands on the same version.
 * - Per-table counts of rows with ciphertext vs. rows that bypassed the
 *   encryption seam (the "legacy" buckets). Post-Alembic-0005 those
 *   numbers should be zero in steady state — non-zero means a row was
 *   inserted via a path that did not encrypt and needs to be rewrapped
 *   (or, on a pre-0005 schema, run `wg-manager crypto migrate` first).
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
          Encryption-at-rest state for SSH keys, passphrases, and manual
          client WireGuard keys.
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
    sshkey_encrypted: number;
    sshkey_legacy: number;
    client_encrypted: number;
    client_legacy: number;
  };
}) {
  const totalLegacy = data.sshkey_legacy + data.client_legacy;
  const backendVariant: "success" | "info" =
    data.backend === "vault-transit" ? "success" : "info";

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>Backend</CardTitle>
          <CardDescription>
            Which wg-manager component is wrapping persisted secrets.
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
          <CardTitle>Health</CardTitle>
          <CardDescription>
            Legacy rows are operator-visible flags. In steady state both
            counts should be zero.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {totalLegacy === 0 ? (
            <Badge variant="success">All rows encrypted</Badge>
          ) : (
            <Badge variant="warn">
              {totalLegacy} legacy row{totalLegacy === 1 ? "" : "s"}
            </Badge>
          )}
        </CardContent>
      </Card>

      <Card className="lg:col-span-2">
        <CardHeader>
          <CardTitle>Row counts</CardTitle>
          <CardDescription>
            Per-table breakdown of how many rows hold ciphertext.
            SSH-provisioned clients keep their key on the device and are
            excluded — only manual clients store a private key on the
            control plane.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <table className="w-full text-sm">
            <thead className="text-left text-muted-foreground">
              <tr>
                <th className="pb-2">Table</th>
                <th className="pb-2">Encrypted</th>
                <th className="pb-2">Legacy</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-t border-border">
                <td className="py-2 font-medium">SSH keys</td>
                <td className="py-2">
                  <Badge variant="success">{data.sshkey_encrypted}</Badge>
                </td>
                <td className="py-2">
                  <Badge
                    variant={data.sshkey_legacy === 0 ? "default" : "warn"}
                  >
                    {data.sshkey_legacy}
                  </Badge>
                </td>
              </tr>
              <tr className="border-t border-border">
                <td className="py-2 font-medium">Manual clients</td>
                <td className="py-2">
                  <Badge variant="success">{data.client_encrypted}</Badge>
                </td>
                <td className="py-2">
                  <Badge
                    variant={data.client_legacy === 0 ? "default" : "warn"}
                  >
                    {data.client_legacy}
                  </Badge>
                </td>
              </tr>
            </tbody>
          </table>
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
            then{" "}
            <code className="rounded bg-muted px-1 py-0.5 text-xs">
              wg-manager crypto rewrap
            </code>{" "}
            so every row lands on the new version.
          </p>
          <p>
            <strong className="text-foreground">Legacy rows.</strong> If the
            Legacy column is non-zero, inspect those rows and rewrap them.
            The cookbook documents the recovery path —{" "}
            <code className="rounded bg-muted px-1 py-0.5 text-xs">
              docs/vault-cookbook.md
            </code>{" "}
            §3.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
