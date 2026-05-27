# wg-manager dashboard

Next.js 15 + TypeScript + Tailwind dashboard for the wg-manager FastAPI
control plane. Lives in this monorepo so backend schema changes can be
mirrored in `lib/types.ts` in the same commit.

## Quickstart

```bash
# from the repo root
make ui-install            # npm install inside web/
make run                   # the API on 127.0.0.1:8000 (in another terminal)
make worker                # the Celery worker (in another terminal)

cp web/.env.example web/.env.local   # optional — defaults to localhost:8000
make ui-dev                # next dev on 127.0.0.1:3000
```

Open <http://127.0.0.1:3000>. The sidebar covers every resource the
control plane exposes; each page provides inline forms plus the
mutating actions (register, reprovision, discover).

## Layout

```
web/
├── app/              # App-Router pages — one folder per route
├── components/       # Reusable UI (forms, tables, sidebar, task poller)
│   └── ui/           # shadcn-style primitives (Button, Card, Input, …)
├── lib/
│   ├── api.ts        # Typed fetch wrapper. Single source of truth for HTTP.
│   ├── types.ts      # TS shapes mirroring backend pydantic schemas.
│   └── utils.ts      # cn() + small formatters.
└── __tests__/        # Vitest unit tests
```

## Stack

- **Next.js 15** App Router, React 19, TypeScript strict
- **Tailwind v3** + a small set of hand-authored shadcn-style components
  (no Radix dependency yet, swap-in compatible if needed later)
- **TanStack Query v5** for API state, mutations, and the async task
  polling loop in `<TaskPoller />`
- **Vitest** + Testing Library for unit tests

## Test

```bash
make ui-test                  # vitest run
# or, from web/:
npm run test
npm run test:watch
```

## Build

```bash
make ui-build                 # next build
```

## How task polling works

Mutating endpoints return a `task_id`. The page drops a `<TaskPoller
taskId={id} />` into the layout — it queries `/tasks/{id}` once a second
until the state is `SUCCESS`, `FAILURE`, or `REVOKED`, then displays the
result inline. Successful tasks invalidate the relevant React Query keys
so the affected table refreshes automatically.

See `web/ROADMAP.md` for what's next.
