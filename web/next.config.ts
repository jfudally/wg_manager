import type { NextConfig } from "next";

/**
 * Next.js configuration for the wg-manager dashboard.
 *
 * Keep this minimal — feature flags, redirects, and rewrites belong here
 * but the dashboard talks to the FastAPI control plane directly via the
 * client-side `fetch()` wrapper in `lib/api.ts`. The API base URL is
 * sourced from `NEXT_PUBLIC_WG_MANAGER_API` at build/runtime.
 */
const nextConfig: NextConfig = {
  reactStrictMode: true,
};

export default nextConfig;
