import { forwardRef, type InputHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

/** Plain text input styled to match the dashboard's neutral palette. */
export const Input = forwardRef<
  HTMLInputElement,
  InputHTMLAttributes<HTMLInputElement>
>(function Input({ className, type = "text", ...props }, ref) {
  return (
    <input
      ref={ref}
      type={type}
      className={cn(
        "flex h-9 w-full rounded-md border border-border bg-background px-3 py-1 text-sm shadow-sm",
        "placeholder:text-muted-foreground",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40",
        "disabled:cursor-not-allowed disabled:opacity-50",
        className,
      )}
      {...props}
    />
  );
});
