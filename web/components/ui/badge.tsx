import type { HTMLAttributes } from "react";
import { cn } from "@/lib/utils";
import type { NodeStatus } from "@/lib/types";

type BadgeVariant = "default" | "outline" | "success" | "warn" | "error" | "info";

const VARIANT_STYLES: Record<BadgeVariant, string> = {
  default: "bg-muted text-foreground",
  outline: "border border-border text-foreground",
  success: "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300",
  warn: "bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300",
  error: "bg-rose-100 text-rose-700 dark:bg-rose-900/40 dark:text-rose-300",
  info: "bg-sky-100 text-sky-700 dark:bg-sky-900/40 dark:text-sky-300",
};

interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  variant?: BadgeVariant;
}

export function Badge({
  className,
  variant = "default",
  ...props
}: BadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium",
        VARIANT_STYLES[variant],
        className,
      )}
      {...props}
    />
  );
}

/** Convenience badge for the `NodeStatus` enum exposed by the API. */
export function StatusBadge({ status }: { status: NodeStatus }) {
  const variant: BadgeVariant =
    status === "ready" ? "success" : status === "error" ? "error" : "warn";
  return <Badge variant={variant}>{status}</Badge>;
}
