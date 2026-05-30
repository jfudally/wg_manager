"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";

interface NavItem {
  href: string;
  label: string;
}

const NAV_ITEMS: NavItem[] = [
  { href: "/", label: "Overview" },
  { href: "/ssh-keys", label: "SSH Roles" },
  { href: "/servers", label: "Servers" },
  { href: "/clients", label: "Clients" },
  { href: "/discovered-peers", label: "Discovered Peers" },
  { href: "/crypto", label: "Crypto" },
  { href: "/certificates", label: "Certificates" },
];

/**
 * Persistent left nav. Highlights the active section based on the current
 * pathname. Sticks to the viewport so the dashboard feels app-shell-like
 * even when individual pages scroll.
 */
export function NavSidebar() {
  const pathname = usePathname();
  return (
    <aside className="sticky top-0 flex h-screen w-60 flex-col border-r border-border bg-muted/30 px-4 py-6">
      <div className="mb-8">
        <Link href="/" className="text-lg font-semibold tracking-tight">
          wg-manager
        </Link>
        <p className="mt-1 text-xs text-muted-foreground">control plane</p>
      </div>
      <nav className="flex flex-col gap-1">
        {NAV_ITEMS.map((item) => {
          const active =
            item.href === "/"
              ? pathname === "/"
              : pathname.startsWith(item.href);
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "rounded-md px-3 py-2 text-sm transition-colors",
                active
                  ? "bg-primary text-primary-foreground"
                  : "text-foreground hover:bg-accent hover:text-accent-foreground",
              )}
            >
              {item.label}
            </Link>
          );
        })}
      </nav>
      <div className="mt-auto pt-6 text-xs text-muted-foreground">
        <p>
          API:{" "}
          <code className="rounded bg-muted px-1 py-0.5 text-[10px]">
            {process.env.NEXT_PUBLIC_WG_MANAGER_API ?? "/api/proxy (BFF → mTLS)"}
          </code>
        </p>
      </div>
    </aside>
  );
}
