"use client";

import { useQuery } from "@tanstack/react-query";
import { useEffect } from "react";
import { api } from "@/lib/api";
import type { TaskState } from "@/lib/types";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";

const TERMINAL_STATES: ReadonlySet<TaskState> = new Set<TaskState>([
  "SUCCESS",
  "FAILURE",
  "REVOKED",
]);

interface TaskPollerProps {
  taskId: string;
  label?: string;
  /** Invoked once the task reaches SUCCESS so callers can refresh data. */
  onSuccess?: () => void;
  /** Invoked on FAILURE/REVOKED so callers can show targeted error UI. */
  onFailure?: (message: string) => void;
}

/**
 * Polls `/tasks/{id}` on a short interval until the task reaches a
 * terminal state, then surfaces the result inline. Drop one of these
 * into any page that just dispatched a Celery task — it handles the
 * polling, terminal-state detection, and result rendering.
 */
export function TaskPoller({
  taskId,
  label = "Task",
  onSuccess,
  onFailure,
}: TaskPollerProps) {
  const query = useQuery({
    queryKey: ["task", taskId],
    queryFn: ({ signal }) => api.taskStatus(taskId),
    refetchInterval: (q) => {
      const state = q.state.data?.state;
      return state && TERMINAL_STATES.has(state) ? false : 1000;
    },
  });

  const state = query.data?.state;
  const result = query.data?.result;
  const errorMessage = query.data?.error ?? (query.error as Error | null)?.message;

  useEffect(() => {
    if (state === "SUCCESS") onSuccess?.();
    if (state && (state === "FAILURE" || state === "REVOKED")) {
      onFailure?.(errorMessage ?? "task failed");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state]);

  const variant: "info" | "success" | "error" =
    state === "SUCCESS" ? "success" : state === "FAILURE" || state === "REVOKED" ? "error" : "info";

  return (
    <Alert
      variant={variant}
      title={`${label} — ${state ?? "PENDING"}`}
      className="mt-2"
    >
      <div className="flex flex-col gap-1 text-xs">
        <div className="flex items-center gap-2">
          <span className="text-muted-foreground">task_id:</span>
          <code className="rounded bg-background/60 px-1 py-0.5">{taskId}</code>
          {state ? <Badge variant="outline">{state}</Badge> : null}
        </div>
        {errorMessage ? (
          <p className="break-words text-rose-700 dark:text-rose-300">
            {errorMessage}
          </p>
        ) : null}
        {result ? (
          <pre className="mt-1 max-h-48 overflow-auto rounded bg-background/60 p-2 text-[11px]">
            {JSON.stringify(result, null, 2)}
          </pre>
        ) : null}
      </div>
    </Alert>
  );
}
