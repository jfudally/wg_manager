import type { NextConfig } from "next";

/**
 * Next.js configuration for the wg-manager dashboard.
 *
 * Keep this minimal — feature flags, redirects, and rewrites belong here
 * but the dashboard talks to the FastAPI control plane directly via the
 * client-side `fetch()` wrapper in `lib/api.ts`. The API base URL is
 * sourced from `NEXT_PUBLIC_WG_MANAGER_API` at build/runtime.
 *
 * ``output: "standalone"`` (Phase 2f cycle 1) emits a self-contained
 * ``.next/standalone`` bundle that the Docker image's runtime stage
 * copies in. The bundle includes only the runtime-needed
 * node_modules, dropping next/build deps + tooling — the difference
 * between a multi-hundred-MB image and a sub-200MB one.
 */
const nextConfig: NextConfig = {
  reactStrictMode: true,
  output: "standalone",
};

export default nextConfig;
