import { forwardRef, type ButtonHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

type Variant = "default" | "outline" | "ghost" | "destructive" | "secondary";
type Size = "default" | "sm" | "lg";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
}

const VARIANT_STYLES: Record<Variant, string> = {
  default:
    "bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50",
  outline:
    "border border-border bg-transparent hover:bg-accent hover:text-accent-foreground",
  ghost: "hover:bg-accent hover:text-accent-foreground",
  destructive:
    "bg-destructive text-destructive-foreground hover:bg-destructive/90",
  secondary: "bg-muted text-foreground hover:bg-muted/80",
};

const SIZE_STYLES: Record<Size, string> = {
  default: "h-9 px-4 py-2 text-sm",
  sm: "h-8 px-3 text-xs",
  lg: "h-10 px-6 text-sm",
};

/**
 * Shadcn-inspired button. Uses CSS variables from `globals.css` so the
 * dashboard's palette is centralised — swap variants by class name, not
 * inline styles.
 */
export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  function Button(
    { className, variant = "default", size = "default", ...props },
    ref,
  ) {
    return (
      <button
        ref={ref}
        className={cn(
          "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md font-medium transition-colors",
          "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40",
          "disabled:pointer-events-none disabled:opacity-50",
          VARIANT_STYLES[variant],
          SIZE_STYLES[size],
          className,
        )}
        {...props}
      />
    );
  },
);
