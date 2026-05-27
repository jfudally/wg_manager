import type { ReactNode } from "react";

interface EmptyStateProps {
  title: string;
  description?: string;
  action?: ReactNode;
}

/**
 * Reusable placeholder for "no data yet" states. Use everywhere a list
 * page or detail panel has zero rows — keeps the dashboard from feeling
 * broken on first load.
 */
export function EmptyState({ title, description, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-border bg-muted/30 px-6 py-12 text-center">
      <p className="text-sm font-medium">{title}</p>
      {description ? (
        <p className="max-w-md text-xs text-muted-foreground">{description}</p>
      ) : null}
      {action ? <div className="mt-2">{action}</div> : null}
    </div>
  );
}
