/**
 * Compact SSH host-cert summary shared by the Servers and Clients tables.
 *
 * Renders "cert #<serial> · expires in <n>d|<n>h" under a row's hostname,
 * or nothing when the row has no host cert recorded (manual clients,
 * rows that pre-date host-cert tracking, never-provisioned rows).
 *
 * The line is muted so it doesn't compete with routine table reading.
 * The expiry turns amber inside 30 days and red once expired. Anything
 * under a day is shown in hours because the default host-cert TTL is
 * 24h (`SSH_HOST_CERT_TTL_SECONDS`), where "0d" would say nothing.
 */
import { cn } from "@/lib/utils";

const HOUR_MS = 1000 * 60 * 60;

export interface HostCertFields {
  host_cert_serial?: number | null;
  host_cert_valid_before?: string | null;
}

/**
 * @param node - Any row carrying the `host_cert_*` fields (a `Server` or
 *   a `Client`). Only `host_cert_serial` and `host_cert_valid_before`
 *   are read.
 * @returns The summary line, or `null` when no cert is recorded.
 */
export function HostCertSummary({ node }: { node: HostCertFields }) {
  if (!node.host_cert_serial || !node.host_cert_valid_before) {
    return null;
  }
  const msLeft = new Date(node.host_cert_valid_before).getTime() - Date.now();
  const expired = msLeft < 0;
  const daysLeft = Math.floor(msLeft / (24 * HOUR_MS));
  const warning = daysLeft < 30 && !expired;
  const remaining =
    daysLeft >= 1 ? `${daysLeft}d` : `${Math.floor(msLeft / HOUR_MS)}h`;
  return (
    <div className="text-xs font-normal text-muted-foreground">
      cert <span className="font-mono">#{node.host_cert_serial}</span> ·{" "}
      <span
        className={cn(
          expired && "font-medium text-destructive",
          warning && "font-medium text-amber-600 dark:text-amber-400",
        )}
      >
        {expired ? "expired" : `expires in ${remaining}`}
      </span>
    </div>
  );
}
