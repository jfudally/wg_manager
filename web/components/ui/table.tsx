import { forwardRef, type HTMLAttributes, type TdHTMLAttributes, type ThHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

/**
 * Minimal table primitives. Keep these as thin styled wrappers — the
 * dashboard's tables stay manageable without virtualisation at the
 * scales the API targets (tens of servers, hundreds of peers).
 */
export const Table = forwardRef<
  HTMLTableElement,
  HTMLAttributes<HTMLTableElement>
>(function Table({ className, ...props }, ref) {
  return (
    <div className="w-full overflow-auto rounded-md border border-border">
      <table
        ref={ref}
        className={cn("w-full caption-bottom text-sm", className)}
        {...props}
      />
    </div>
  );
});

export const TableHeader = forwardRef<
  HTMLTableSectionElement,
  HTMLAttributes<HTMLTableSectionElement>
>(function TableHeader({ className, ...props }, ref) {
  return (
    <thead
      ref={ref}
      className={cn("bg-muted/60 text-xs uppercase tracking-wide", className)}
      {...props}
    />
  );
});

export const TableBody = forwardRef<
  HTMLTableSectionElement,
  HTMLAttributes<HTMLTableSectionElement>
>(function TableBody({ className, ...props }, ref) {
  return (
    <tbody
      ref={ref}
      className={cn("[&_tr:last-child]:border-0", className)}
      {...props}
    />
  );
});

export const TableRow = forwardRef<
  HTMLTableRowElement,
  HTMLAttributes<HTMLTableRowElement>
>(function TableRow({ className, ...props }, ref) {
  return (
    <tr
      ref={ref}
      className={cn(
        "border-b border-border transition-colors hover:bg-muted/40",
        className,
      )}
      {...props}
    />
  );
});

export const TableHead = forwardRef<
  HTMLTableCellElement,
  ThHTMLAttributes<HTMLTableCellElement>
>(function TableHead({ className, ...props }, ref) {
  return (
    <th
      ref={ref}
      className={cn(
        "h-10 px-4 text-left align-middle font-medium text-muted-foreground",
        className,
      )}
      {...props}
    />
  );
});

export const TableCell = forwardRef<
  HTMLTableCellElement,
  TdHTMLAttributes<HTMLTableCellElement>
>(function TableCell({ className, ...props }, ref) {
  return (
    <td
      ref={ref}
      className={cn("px-4 py-3 align-middle", className)}
      {...props}
    />
  );
});
