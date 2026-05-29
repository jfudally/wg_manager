/**
 * BFF (Backend-For-Frontend) catch-all proxy route.
 *
 * The browser hits ``/api/proxy/<path>`` on the Next.js dev/prod server
 * (plain HTTP, same-origin), this Route Handler runs in the Node
 * runtime, presents the wg-manager client certificate to the FastAPI
 * control plane over mTLS, and surfaces the upstream response
 * verbatim. The browser therefore never participates in the mTLS
 * handshake, which lets the Phase 2d CP2 contract ("plain-HTTP
 * listener is removed") hold without breaking
 * :ref:`feedback_ui_parity` dashboard access.
 *
 * Configuration is environment-driven (see :file:`web/.env.example`):
 *
 * - ``WG_MANAGER_API_UPSTREAM`` — base URL of the FastAPI listener,
 *   e.g. ``https://127.0.0.1:8000``. No trailing slash.
 * - ``WG_MANAGER_API_CLIENT_CERT`` — path to the client certificate
 *   (PEM) the proxy presents to the API.
 * - ``WG_MANAGER_API_CLIENT_KEY`` — path to the matching private key.
 * - ``WG_MANAGER_API_CA_BUNDLE`` — path to the CA bundle that signs
 *   the API's server certificate.
 *
 * Missing config produces a 500 with a JSON ``detail`` that names the
 * exact env vars to set — same shape as :class:`ApiError` so the
 * dashboard's existing error UI keeps working.
 */

import { readFileSync } from "node:fs";
import {
  forwardToUpstream,
  makeMTlsFetcher,
  type UpstreamFetcher,
} from "@/lib/proxy";

// The Node runtime is required: we use ``node:https`` + ``node:fs``
// for the mTLS handshake and cert loading. Edge runtime has neither.
export const runtime = "nodejs";
// Forwarding is per-request — caching here would mask real upstream
// errors and serve stale rows that the dashboard expects to be live.
export const dynamic = "force-dynamic";

interface RouteContext {
  // Next.js 15 made ``params`` a Promise — see
  // https://nextjs.org/docs/app/building-your-application/upgrading/version-15
  params: Promise<{ path: string[] }>;
}

interface ProxyConfig {
  upstream: string;
  fetcher: UpstreamFetcher;
}

/**
 * Read + validate the BFF env. Throws a typed error when any var is
 * missing so the handler can return a structured 500 to the browser
 * instead of crashing the Next.js request pipeline.
 */
function loadProxyConfig(): ProxyConfig {
  const upstream = process.env.WG_MANAGER_API_UPSTREAM;
  const certPath = process.env.WG_MANAGER_API_CLIENT_CERT;
  const keyPath = process.env.WG_MANAGER_API_CLIENT_KEY;
  const caPath = process.env.WG_MANAGER_API_CA_BUNDLE;

  const missing: string[] = [];
  if (!upstream) missing.push("WG_MANAGER_API_UPSTREAM");
  if (!certPath) missing.push("WG_MANAGER_API_CLIENT_CERT");
  if (!keyPath) missing.push("WG_MANAGER_API_CLIENT_KEY");
  if (!caPath) missing.push("WG_MANAGER_API_CA_BUNDLE");
  if (missing.length > 0) {
    throw new Error(
      `BFF proxy is not configured: missing ${missing.join(", ")}. ` +
        "Set them in web/.env.local — see web/.env.example for the " +
        "throwaway-dev values produced by `make tls-issue-dev`.",
    );
  }

  return {
    upstream: upstream!,
    fetcher: makeMTlsFetcher({
      clientCert: readFileSync(certPath!),
      clientKey: readFileSync(keyPath!),
      ca: readFileSync(caPath!),
    }),
  };
}

// Cache the loaded config + the keep-alive https.Agent for the
// process's lifetime. The Next.js dev server reloads this module on
// edits, which is exactly when we want to re-read the cert files.
let cachedConfig: ProxyConfig | undefined;

function getProxyConfig(): ProxyConfig {
  if (!cachedConfig) cachedConfig = loadProxyConfig();
  return cachedConfig;
}

async function handle(
  request: Request,
  { params }: RouteContext,
): Promise<Response> {
  try {
    const { path } = await params;
    const { upstream, fetcher } = getProxyConfig();
    return await forwardToUpstream(request, path ?? [], upstream, fetcher);
  } catch (err) {
    const detail = err instanceof Error ? err.message : "BFF proxy error";
    return new Response(JSON.stringify({ detail }), {
      status: 500,
      headers: { "content-type": "application/json" },
    });
  }
}

export const GET = handle;
export const POST = handle;
export const PUT = handle;
export const PATCH = handle;
export const DELETE = handle;
export const OPTIONS = handle;
export const HEAD = handle;
