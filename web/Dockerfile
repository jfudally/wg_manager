# wg-manager dashboard image (Phase 2f cycle 1).
#
# Multi-stage build using Next.js standalone output:
#  * ``builder`` — node:22-slim, runs ``npm ci`` against the lockfile
#    + ``npm run build``. Next emits a self-contained app under
#    ``.next/standalone`` that includes only the runtime-needed
#    node_modules.
#  * ``runtime`` — node:22-slim with the standalone bundle + static
#    assets + public/. Runs as the non-root ``nextjs`` user.
#
# The dashboard's BFF proxy talks to the FastAPI control plane on a
# separate hostname (see web/.env.example + the dashboard README's
# "BFF proxy" section). The image needs no mTLS material — the
# operator's mTLS client cert + key + CA bundle are mounted in at
# runtime.

ARG NODE_VERSION=22

# ---------------------------------------------------------------------------
# Stage 1 — builder: install deps + run next build
# ---------------------------------------------------------------------------
FROM node:${NODE_VERSION}-slim AS builder

WORKDIR /app

# Copy lockfile + manifest first so npm ci's layer cache stays hot when
# only source files change. ``npm ci`` requires the lockfile match
# (this matches the cycle 3 lockfile parity gate's invariant).
COPY package.json package-lock.json ./
RUN npm ci

# Now bring in the rest of the source.
COPY . .

# Next emits .next/standalone when output: 'standalone' is set in
# next.config.ts (Phase 2f cycle 1 turns this on).
RUN npm run build

# ---------------------------------------------------------------------------
# Stage 2 — runtime: minimal node + standalone bundle + non-root user
# ---------------------------------------------------------------------------
FROM node:${NODE_VERSION}-slim AS runtime

# Non-root user — same fixed-UID pattern as the API image so the two
# stay parallel.
RUN groupadd --system --gid 1001 nextjs \
    && useradd --system --uid 1001 --gid nextjs --create-home nextjs

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3100
ENV HOSTNAME=0.0.0.0

# Copy the standalone bundle (server.js + the trimmed node_modules) +
# static assets. Next's standalone output expects this layout. The
# canonical pattern also copies ``public/`` but the wg-manager
# dashboard ships no static assets there yet — when one lands, add the
# COPY line back (see Next.js standalone-output docs).
COPY --from=builder --chown=nextjs:nextjs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nextjs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3100

CMD ["node", "server.js"]
