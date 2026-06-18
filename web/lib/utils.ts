import clsx, { type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/**
 * Tailwind-aware `classnames`. Use everywhere two or more conditional
 * class strings need to be combined — `twMerge` resolves conflicting
 * utilities (e.g. `p-2 p-4` → `p-4`) so component variants compose
 * predictably.
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

/**
 * Parse an ISO timestamp string from the API into a `Date`.
 *
 * The backend stores aware-UTC instants but serializes them through
 * timezone-naive DB columns, so the JSON often lacks an offset
 * designator (e.g. "2026-06-18T18:00:00"). The browser would otherwise
 * interpret a naive string as *local* time, shifting timestamps into the
 * future for users behind UTC (showing negative "ago" durations). We
 * append "Z" when no timezone is present so naive values are read as UTC.
 */
function parseApiDate(value: string): Date {
  const hasTimezone = /([zZ]|[+-]\d{2}:?\d{2})$/.test(value.trim());
  return new Date(hasTimezone ? value : `${value}Z`);
}

/**
 * Format an ISO timestamp from the API into a short locale string. Falls
 * back to the raw value if parsing fails (e.g. when the backend returns
 * an unexpected shape during development).
 */
export function formatDateTime(value: string | null | undefined): string {
  if (!value) return "—";
  const date = parseApiDate(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

/** Human-friendly relative duration, e.g. "5m ago". */
export function relativeFromNow(value: string | null | undefined): string {
  if (!value) return "—";
  const date = parseApiDate(value);
  if (Number.isNaN(date.getTime())) return value;
  const diffMs = Date.now() - date.getTime();
  const diffSec = Math.round(diffMs / 1000);
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.round(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.round(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.round(diffHr / 24);
  return `${diffDay}d ago`;
}

/** Format a byte count as a SI-suffixed string ("1.2 MB"). */
export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const idx = Math.min(units.length - 1, Math.floor(Math.log10(bytes) / 3));
  const value = bytes / Math.pow(1000, idx);
  return `${value.toFixed(value >= 10 || idx === 0 ? 0 : 1)} ${units[idx]}`;
}
