import type { Metadata } from "next";
import "./globals.css";
import { Providers } from "./providers";
import { NavSidebar } from "@/components/nav-sidebar";

export const metadata: Metadata = {
  title: "wg-manager",
  description: "Control-plane dashboard for the wg-manager WireGuard fleet.",
};

/**
 * Root layout. Holds the global providers (React Query) and the
 * persistent navigation chrome. Page-specific layouts can be added
 * under `app/<section>/layout.tsx` later if a section needs its own.
 */
export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-background text-foreground antialiased">
        <Providers>
          <div className="flex min-h-screen">
            <NavSidebar />
            <main className="flex-1 overflow-x-auto">
              <div className="mx-auto max-w-6xl px-6 py-8">{children}</div>
            </main>
          </div>
        </Providers>
      </body>
    </html>
  );
}
