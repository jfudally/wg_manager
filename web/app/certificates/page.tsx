"use client";

import {
  useMutation,
  useQuery,
  useQueryClient,
  type UseQueryResult,
} from "@tanstack/react-query";
import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import type {
  Certificate,
  CertificateIssueRequest,
  CertificateIssueResponse,
  CertificateType,
  WhoAmI,
} from "@/lib/types";
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
 * Phase 2d CP3.4 — Certificates dashboard page.
 *
 * Three vertically-stacked sections:
 *
 * 1. **Who am I?** splash — calls `GET /certs/whoami` and surfaces
 *    the cert subject the API actually saw. A 200 here is the
 *    visible proof that the operator's freshly-imported PKCS#12
 *    is accepted by the mTLS listener and matched against an active
 *    operator row. The splash also gates the rest of the page — the
 *    role chip drives whether the issue/revoke controls render.
 * 2. **Issue cert** form (admin only) — wraps `POST /certs`. Mirrors
 *    the CLI's `wg-manager certs issue` flags. For `dashboard` certs
 *    the response embeds a base64 PKCS#12 the browser saves as a
 *    single import file.
 * 3. **Certificate inventory** table — every row in
 *    :class:`wg_manager.models.Certificate`. Auditors see it read-
 *    only; admins get a per-row Revoke button.
 *
 * The page is intentionally one component file. The Certificates
 * surface is small enough that a multi-file split would be churn —
 * grow it out when a fourth section appears.
 */
export default function CertificatesPage() {
  const whoamiQuery = useQuery({
    queryKey: ["certs-whoami"],
    queryFn: api.whoami,
    retry: false,
  });
  const certsQuery = useQuery({
    queryKey: ["certs"],
    queryFn: api.listCertificates,
    // Suppress the auto-retry when the role gate denies the list —
    // the splash explains *why* without spamming the API.
    retry: false,
  });

  const isAdmin = whoamiQuery.data?.operator_role === "admin";

  return (
    <div className="flex flex-col gap-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Certificates</h1>
        <p className="text-sm text-muted-foreground">
          Identity surface: who you are to the API, every cert
          wg-manager has issued, and the controls to mint and revoke
          them.
        </p>
      </header>

      <WhoAmIPanel query={whoamiQuery} />

      {isAdmin ? <IssueCertSection /> : null}

      <CertificateInventory query={certsQuery} isAdmin={isAdmin} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Who am I splash
// ---------------------------------------------------------------------------

function WhoAmIPanel({
  query,
}: {
  query: UseQueryResult<WhoAmI, Error>;
}) {
  if (query.isError) {
    const err = query.error as ApiError | Error;
    return (
      <Alert
        variant="error"
        title="mTLS handshake didn't surface an operator"
      >
        <p>{err.message}</p>
        <p className="mt-2 text-xs">
          Confirm the BFF proxy is presenting the operator client
          cert and that the CN is registered via{" "}
          <code className="rounded bg-muted px-1 py-0.5">
            wg-manager operators add
          </code>
          .
        </p>
      </Alert>
    );
  }
  if (query.isLoading || !query.data) {
    return (
      <p className="text-sm text-muted-foreground">Resolving identity…</p>
    );
  }
  const data = query.data;
  const roleVariant: "success" | "info" | "warn" =
    data.operator_role === "admin"
      ? "success"
      : data.operator_role === "auditor"
        ? "info"
        : "warn";
  return (
    <Card>
      <CardHeader>
        <CardTitle>Who am I?</CardTitle>
        <CardDescription>
          Subject the API saw on this request, after the mTLS handshake
          and the operator-registry lookup.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid grid-cols-1 gap-3 text-sm md:grid-cols-2">
        <Field label="Operator CN">{data.operator_cn}</Field>
        <Field label="Role">
          <Badge variant={roleVariant}>{data.operator_role}</Badge>
        </Field>
        <Field label="Cert CN">{data.cn}</Field>
        <Field label="Serial">
          <code className="break-all rounded bg-muted px-1 py-0.5 text-xs">
            {data.serial}
          </code>
        </Field>
        <Field label="Subject alternative names">
          <span className="break-all">{data.sans.join(", ") || "—"}</span>
        </Field>
        <Field label="Validity">
          <span>
            {formatDateTime(data.not_before)} →{" "}
            {formatDateTime(data.not_after)}
          </span>
        </Field>
      </CardContent>
    </Card>
  );
}

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <p className="text-xs uppercase tracking-wide text-muted-foreground">
        {label}
      </p>
      <div className="mt-1">{children}</div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Issue form (admin only)
// ---------------------------------------------------------------------------

function IssueCertSection() {
  const [open, setOpen] = useState(false);
  const [lastIssued, setLastIssued] =
    useState<CertificateIssueResponse | null>(null);
  return (
    <section className="flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Issue certificate</h2>
        <Button onClick={() => setOpen((v) => !v)}>
          {open ? "Cancel" : "+ Issue new cert"}
        </Button>
      </div>
      {open ? (
        <IssueCertForm
          onIssued={(resp) => {
            setLastIssued(resp);
            setOpen(false);
          }}
        />
      ) : null}
      {lastIssued ? (
        <IssuedCertPanel
          resp={lastIssued}
          onDismiss={() => setLastIssued(null)}
        />
      ) : null}
    </section>
  );
}

const CERT_TYPES: { value: CertificateType; label: string; hint: string }[] = [
  {
    value: "api",
    label: "API (server)",
    hint: "serverAuth — FastAPI mTLS listener.",
  },
  {
    value: "cli",
    label: "CLI (client)",
    hint: "clientAuth — operator's wg-manager CLI cert.",
  },
  {
    value: "dashboard",
    label: "Dashboard (PKCS#12)",
    hint: "clientAuth — browser-importable PKCS#12 archive.",
  },
  {
    value: "mysql",
    label: "MySQL (server)",
    hint: "serverAuth — DB listener (Phase 2d CP4).",
  },
];

function IssueCertForm({
  onIssued,
}: {
  onIssued: (resp: CertificateIssueResponse) => void;
}) {
  const qc = useQueryClient();
  const [certType, setCertType] = useState<CertificateType>("api");
  const [commonName, setCommonName] = useState("");
  const [sansRaw, setSansRaw] = useState("");
  const [ttlDays, setTtlDays] = useState("");
  const [operatorCn, setOperatorCn] = useState("");
  const [pkcs12Password, setPkcs12Password] = useState("");

  const mutation = useMutation({
    mutationFn: (payload: CertificateIssueRequest) =>
      api.issueCertificate(payload),
    onSuccess: (resp) => {
      qc.invalidateQueries({ queryKey: ["certs"] });
      onIssued(resp);
    },
  });

  function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const sans = sansRaw
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    const payload: CertificateIssueRequest = {
      cert_type: certType,
      common_name: commonName.trim(),
    };
    if (sans.length > 0) payload.sans = sans;
    if (ttlDays.trim().length > 0) payload.ttl_days = Number(ttlDays);
    if (operatorCn.trim().length > 0) payload.operator_cn = operatorCn.trim();
    if (certType === "dashboard" && pkcs12Password.length > 0) {
      payload.pkcs12_password = pkcs12Password;
    }
    mutation.mutate(payload);
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Issue a new leaf cert</CardTitle>
        <CardDescription>
          Mints a fresh leaf from the configured PKI backend and
          records the audit row. The private key is surfaced once on
          the next screen — wg-manager keeps no copy.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={onSubmit} className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <div className="md:col-span-2">
            <Label htmlFor="cert-type">Cert type</Label>
            <select
              id="cert-type"
              aria-label="Cert type"
              value={certType}
              onChange={(e) =>
                setCertType(e.currentTarget.value as CertificateType)
              }
              className="mt-1 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
            >
              {CERT_TYPES.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
            <p className="mt-1 text-xs text-muted-foreground">
              {CERT_TYPES.find((c) => c.value === certType)?.hint}
            </p>
          </div>

          <div>
            <Label htmlFor="cert-cn">Common Name</Label>
            <Input
              id="cert-cn"
              required
              value={commonName}
              onChange={(e) => setCommonName(e.currentTarget.value)}
              placeholder={
                certType === "api"
                  ? "127.0.0.1"
                  : certType === "mysql"
                    ? "mysql"
                    : "ops@wg.local"
              }
            />
          </div>

          <div>
            <Label htmlFor="cert-ttl">TTL (days, optional)</Label>
            <Input
              id="cert-ttl"
              type="number"
              min="1"
              value={ttlDays}
              onChange={(e) => setTtlDays(e.currentTarget.value)}
              placeholder={
                certType === "api" || certType === "mysql" ? "30" : "365"
              }
            />
          </div>

          <div className="md:col-span-2">
            <Label htmlFor="cert-sans">SANs (comma-separated, optional)</Label>
            <Input
              id="cert-sans"
              value={sansRaw}
              onChange={(e) => setSansRaw(e.currentTarget.value)}
              placeholder={
                certType === "api"
                  ? "127.0.0.1, localhost"
                  : certType === "mysql"
                    ? "mysql, 127.0.0.1, localhost"
                    : "(defaults to the CN)"
              }
            />
          </div>

          {certType === "cli" || certType === "dashboard" ? (
            <div className="md:col-span-2">
              <Label htmlFor="cert-operator-cn">
                Operator CN (defaults to CN)
              </Label>
              <Input
                id="cert-operator-cn"
                value={operatorCn}
                onChange={(e) => setOperatorCn(e.currentTarget.value)}
                placeholder="ops@wg.local"
              />
              <p className="mt-1 text-xs text-muted-foreground">
                Must match a registered operator row. Use{" "}
                <code className="rounded bg-muted px-1 py-0.5">
                  wg-manager operators add
                </code>{" "}
                to seed one.
              </p>
            </div>
          ) : null}

          {certType === "dashboard" ? (
            <div className="md:col-span-2">
              <Label htmlFor="cert-p12-pw">PKCS#12 password (optional)</Label>
              <Input
                id="cert-p12-pw"
                type="password"
                value={pkcs12Password}
                onChange={(e) => setPkcs12Password(e.currentTarget.value)}
              />
            </div>
          ) : null}

          <div className="md:col-span-2 flex items-center gap-3">
            <Button type="submit" disabled={mutation.isPending}>
              {mutation.isPending ? "Issuing…" : "Issue cert"}
            </Button>
            {mutation.isError ? (
              <Alert variant="error" title="Issuance failed">
                {(mutation.error as Error).message}
              </Alert>
            ) : null}
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

function IssuedCertPanel({
  resp,
  onDismiss,
}: {
  resp: CertificateIssueResponse;
  onDismiss: () => void;
}) {
  function download(name: string, body: string, mime = "application/x-pem-file") {
    const blob = new Blob([body], { type: mime });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = name;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  function downloadPkcs12() {
    if (!resp.pkcs12_b64) return;
    const binary = atob(resp.pkcs12_b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    const blob = new Blob([bytes], { type: "application/x-pkcs12" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${resp.certificate.common_name}.p12`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Cert issued — serial {resp.certificate.serial}</CardTitle>
        <CardDescription>
          Save the artefacts now. The private key is{" "}
          <strong>shown exactly once</strong> — wg-manager keeps no
          server-side copy.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-wrap items-center gap-3">
        <Button
          type="button"
          onClick={() =>
            download(`${resp.certificate.common_name}.crt`, resp.cert_pem)
          }
        >
          Download cert
        </Button>
        <Button
          type="button"
          variant="secondary"
          onClick={() =>
            download(`${resp.certificate.common_name}.key`, resp.private_pem)
          }
        >
          Download key
        </Button>
        <Button
          type="button"
          variant="secondary"
          onClick={() =>
            download(`${resp.certificate.common_name}.chain.crt`, resp.chain_pem)
          }
        >
          Download chain
        </Button>
        {resp.pkcs12_b64 ? (
          <Button type="button" onClick={downloadPkcs12}>
            Download PKCS#12
          </Button>
        ) : null}
        <Button type="button" variant="ghost" onClick={onDismiss}>
          Dismiss
        </Button>
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Inventory table
// ---------------------------------------------------------------------------

function CertificateInventory({
  query,
  isAdmin,
}: {
  query: UseQueryResult<Certificate[], Error>;
  isAdmin: boolean;
}) {
  if (query.isError) {
    const err = query.error as ApiError | Error;
    const status =
      err instanceof ApiError ? (err as ApiError).status : undefined;
    if (status === 403) {
      return (
        <Alert
          variant="info"
          title="Inventory hidden"
        >
          Your role doesn't permit reading the cert inventory. Ask an
          admin to grant the auditor or admin role to your operator
          row.
        </Alert>
      );
    }
    return (
      <Alert variant="error" title="Couldn't load certificates">
        {err.message}
      </Alert>
    );
  }
  if (query.isLoading) {
    return <p className="text-sm text-muted-foreground">Loading…</p>;
  }
  const certs = query.data ?? [];
  if (certs.length === 0) {
    return (
      <EmptyState
        title="No certificates issued yet"
        description="Issue your first cert above or via wg-manager certs issue."
      />
    );
  }
  return <CertificateTable certs={certs} isAdmin={isAdmin} />;
}

function CertificateTable({
  certs,
  isAdmin,
}: {
  certs: Certificate[];
  isAdmin: boolean;
}) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Type</TableHead>
          <TableHead>Common Name</TableHead>
          <TableHead>SANs</TableHead>
          <TableHead>Serial</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Valid until</TableHead>
          {isAdmin ? <TableHead className="w-32 text-right">Actions</TableHead> : null}
        </TableRow>
      </TableHeader>
      <TableBody>
        {certs.map((cert) => (
          <CertificateRow key={cert.id} cert={cert} isAdmin={isAdmin} />
        ))}
      </TableBody>
    </Table>
  );
}

function CertificateRow({
  cert,
  isAdmin,
}: {
  cert: Certificate;
  isAdmin: boolean;
}) {
  const qc = useQueryClient();
  const revokeMutation = useMutation({
    mutationFn: () => api.revokeCertificate(cert.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["certs"] });
    },
  });

  const sans = cert.sans.split(",").filter((s) => s.length > 0);
  return (
    <TableRow>
      <TableCell>
        <Badge variant="info">{cert.cert_type}</Badge>
      </TableCell>
      <TableCell className="font-medium">{cert.common_name}</TableCell>
      <TableCell className="text-xs text-muted-foreground">
        {sans.length > 0 ? sans.join(", ") : "—"}
      </TableCell>
      <TableCell>
        <code className="break-all text-xs">{cert.serial}</code>
      </TableCell>
      <TableCell>
        {cert.revoked ? (
          <Badge variant="error">revoked</Badge>
        ) : (
          <Badge variant="success">live</Badge>
        )}
        {cert.revoked && cert.revoked_at ? (
          <p className="mt-1 text-xs text-muted-foreground">
            {formatDateTime(cert.revoked_at)}
          </p>
        ) : null}
      </TableCell>
      <TableCell className="text-xs">
        {formatDateTime(cert.not_after)}
      </TableCell>
      {isAdmin ? (
        <TableCell className="text-right">
          {cert.revoked ? (
            <span className="text-xs text-muted-foreground">—</span>
          ) : (
            <Button
              size="sm"
              variant="destructive"
              disabled={revokeMutation.isPending}
              onClick={() => {
                if (
                  window.confirm(
                    `Revoke cert serial ${cert.serial} (${cert.common_name})? ` +
                      `The CRL flips immediately; presenting peers will be rejected on the next handshake.`,
                  )
                ) {
                  revokeMutation.mutate();
                }
              }}
            >
              {revokeMutation.isPending ? "Revoking…" : "Revoke"}
            </Button>
          )}
        </TableCell>
      ) : null}
    </TableRow>
  );
}
