import { cn } from "@/lib/utils";
import type { HTMLAttributes } from "react";

type Variant = "info" | "error" | "success" | "warning";

const VARIANT_STYLES: Record<Variant, string> = {
  info: "border-sky-200 bg-sky-50 text-sky-900 dark:border-sky-900 dark:bg-sky-950 dark:text-sky-100",
  error:
    "border-rose-200 bg-rose-50 text-rose-900 dark:border-rose-900 dark:bg-rose-950 dark:text-rose-100",
  success:
    "border-emerald-200 bg-emerald-50 text-emerald-900 dark:border-emerald-900 dark:bg-emerald-950 dark:text-emerald-100",
  warning:
    "border-amber-200 bg-amber-50 text-amber-900 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-100",
};

interface AlertProps extends HTMLAttributes<HTMLDivElement> {
  variant?: Variant;
  title?: string;
}

export function Alert({
  className,
  variant = "info",
  title,
  children,
  ...props
}: AlertProps) {
  return (
    <div
      className={cn(
        "rounded-md border px-4 py-3 text-sm",
        VARIANT_STYLES[variant],
        className,
      )}
      {...props}
    >
      {title ? <p className="font-semibold">{title}</p> : null}
      <div className={cn(title && "mt-1")}>{children}</div>
    </div>
  );
}
