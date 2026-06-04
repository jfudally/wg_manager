/**
 * BFF (Backend-For-Frontend) proxy core.
 *
 * The Next.js Route Handler at ``app/api/proxy/[...path]/route.ts``
 * delegates every verb to :func:`forwardToUpstream`, which copies the
 * inbound web :class:`Request` onto the mTLS-protected FastAPI control
 * plane. The browser only ever sees same-origin plain HTTP to the
 * Next.js server; the client certificate (Phase 2d CP2 contract) lives
 * exclusively on the Node side.
 *
 * The transport layer is abstracted behind :type:`UpstreamFetcher` so
 * tests can pin the wire-format contract without standing up real
 * sockets. :func:`makeMTlsFetcher` is the production implementation
 * (Node ``https.request`` + a long-lived keep-alive ``Agent``).
 *
 * Hop-by-hop headers (``Host``, ``Connection``, ``Content-Length``,
 * ``Transfer-Encoding``) are intentionally stripped on both directions
 * — the upstream must compute its own framing, and the inbound
 * ``Host`` would otherwise tell the API it's being addressed as
 * ``localhost:3000``.
 */

import { Agent, request as httpsRequest } from "node:https";

export interface UpstreamRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: Uint8Array;
}

export interface UpstreamResponse {
  status: number;
  headers: Headers;
  body: Uint8Array;
}

/**
 * Pluggable transport. The production impl is
 * :func:`makeMTlsFetcher`; tests pass a fake to assert on the
 * forwarded request without doing real I/O.
 */
export type UpstreamFetcher = (
  request: UpstreamRequest,
) => Promise<UpstreamResponse>;

/**
 * Inbound hop-by-hop headers that must not be forwarded. ``host`` is
 * here because the inbound value (``localhost:3000``) is irrelevant to
 * the upstream and would defeat any virtual-host routing on its side.
 * ``content-length`` is recomputed by the transport.
 */
const STRIP_REQUEST_HEADERS = new Set([
  "host",
  "connection",
  "content-length",
  "transfer-encoding",
  "keep-alive",
  "proxy-authorization",
  "proxy-authenticate",
  "te",
  "trailer",
  "upgrade",
]);

/**
 * Outbound hop-by-hop headers that Next.js's web ``Response`` is
 * unhappy to receive (``content-encoding`` survives because we never
 * decompress; the upstream-returned bytes are surfaced verbatim).
 */
const STRIP_RESPONSE_HEADERS = new Set([
  "connection",
  "content-length",
  "transfer-encoding",
  "keep-alive",
]);

/**
 * Forward an inbound :class:`Request` to ``upstreamBaseUrl`` and
 * convert the upstream's response back into a web :class:`Response`.
 *
 * @param request The Route Handler's inbound web ``Request``.
 * @param pathSegments Path segments captured by the ``[...path]``
 *   catch-all, in the order they appear in the URL.
 * @param upstreamBaseUrl Base URL of the FastAPI listener, e.g.
 *   ``"https://127.0.0.1:8000"``. No trailing slash.
 * @param fetcher Transport implementation; in production this is the
 *   mTLS fetcher returned by :func:`makeMTlsFetcher`.
 */
export async function forwardToUpstream(
  request: Request,
  pathSegments: string[],
  upstreamBaseUrl: string,
  fetcher: UpstreamFetcher,
): Promise<Response> {
  // Phase 3c — every BFF call lands on /v1/* upstream. The dashboard
  // sends `/api/proxy/<resource>`; the proxy rewrites to
  // `<upstream>/v1/<resource>`. Operators who set
  // `WG_MANAGER_API_UPSTREAM` to include `/v1` (or callers that
  // already pre-pended `/v1/` in pathSegments) don't get a double
  // prefix because we strip an existing `/v1` first.
  const joined = pathSegments.join("/");
  const withoutV1 = joined.startsWith("v1/")
    ? joined.slice(3)
    : joined === "v1"
      ? ""
      : joined;
  const targetPath = "/v1/" + withoutV1;
  const { search } = new URL(request.url);
  const url = `${upstreamBaseUrl}${targetPath}${search}`;

  const headers: Record<string, string> = {};
  request.headers.forEach((value, key) => {
    if (STRIP_REQUEST_HEADERS.has(key.toLowerCase())) return;
    headers[key] = value;
  });

  const hasBody = !["GET", "HEAD"].includes(request.method.toUpperCase());
  const body = hasBody
    ? new Uint8Array(await request.arrayBuffer())
    : undefined;

  const upstream = await fetcher({
    url,
    method: request.method,
    headers,
    body,
  });

  const respHeaders = new Headers();
  upstream.headers.forEach((value, key) => {
    if (STRIP_RESPONSE_HEADERS.has(key.toLowerCase())) return;
    respHeaders.set(key, value);
  });

  // ``upstream.body`` is ``Uint8Array<ArrayBufferLike>`` (typescript
  // 6's narrower lib types) but ``Response``'s ``BodyInit`` expects
  // ``ArrayBufferView<ArrayBuffer>`` — runtime-equivalent, but the
  // assignment is no longer structurally compatible. The cast is the
  // documented workaround until lib-dom catches up; the underlying
  // bytes are passed through verbatim. Phase 2f cycle 1 fix — the
  // docker image build's ``next build`` is what surfaced this latent
  // breakage (vitest doesn't run tsc).
  return new Response(upstream.body as unknown as BodyInit, {
    status: upstream.status,
    headers: respHeaders,
  });
}

export interface MTlsCredentials {
  clientCert: Buffer;
  clientKey: Buffer;
  ca: Buffer;
}

/**
 * Build the production :type:`UpstreamFetcher`. Uses a single
 * keep-alive ``https.Agent`` so the TLS handshake amortises across
 * requests — the dashboard fires several calls per page load and
 * re-handshaking each time would be needlessly slow.
 */
export function makeMTlsFetcher(creds: MTlsCredentials): UpstreamFetcher {
  const agent = new Agent({
    cert: creds.clientCert,
    key: creds.clientKey,
    ca: creds.ca,
    keepAlive: true,
  });

  return (req) =>
    new Promise<UpstreamResponse>((resolve, reject) => {
      const parsed = new URL(req.url);
      const r = httpsRequest(
        {
          method: req.method,
          protocol: parsed.protocol,
          hostname: parsed.hostname,
          port: parsed.port || 443,
          path: parsed.pathname + parsed.search,
          headers: req.headers,
          agent,
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (chunk: Buffer) => chunks.push(chunk));
          res.on("end", () => {
            const headers = new Headers();
            for (const [k, v] of Object.entries(res.headers)) {
              if (v === undefined) continue;
              if (Array.isArray(v)) {
                for (const item of v) headers.append(k, item);
              } else {
                headers.set(k, String(v));
              }
            }
            resolve({
              status: res.statusCode ?? 502,
              headers,
              body: new Uint8Array(Buffer.concat(chunks)),
            });
          });
          res.on("error", reject);
        },
      );
      r.on("error", reject);
      if (req.body && req.body.length > 0) r.write(req.body);
      r.end();
    });
}
