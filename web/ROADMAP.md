# Dashboard roadmap

Phased per the global development standards (Phase 0 spike → Phase 1 MVP
→ Phase 2 hardening → Phase 3 polish). Update this file before
introducing new feature work.

## Phase 0 — Validation ✅

Confirmed that the FastAPI API can be reached cross-origin from a
Next.js dev server once CORS is configured, and that TanStack Query
handles the async task-polling pattern cleanly without server-sent
events.

## Phase 1 — MVP ✅

Read + write for every resource:

- [x] SSH keys: list, add, delete
- [x] Servers: list, register, discover, reprovision
- [x] Clients: list, register, reprovision
- [x] Discovered peers: list (all + filter by server), batch discover
- [x] Inline task polling for every mutation that dispatches a Celery task
- [x] CORS middleware on the FastAPI app
- [x] Tailwind theme + reusable shadcn-style primitives
- [x] Vitest smoke test for the API client

## Phase 2 — Hardening (next)

- [ ] Replace `window.confirm` with a proper confirmation dialog
- [ ] Error boundary at the app shell so a broken page doesn't blank the
      whole dashboard
- [ ] Toast notifications for mutation success/failure (instead of an
      inline `<Alert />` per form)
- [ ] Discovered peer "adopt" flow — promote an `is_managed=false` peer
      into a managed Client row (requires a backend endpoint first)
- [ ] CSV / JSON export buttons on every table
- [ ] Component tests for the task poller and at least one form
- [ ] Dark-mode toggle (palette is already CSS-variable based)

## Phase 3 — Polish

- [ ] Per-server detail page with peer transfer charts (rx/tx over time
      — requires a metrics-snapshot endpoint)
- [ ] Real-time updates via SSE or WebSocket instead of polling
- [ ] Auth (the backend ships without it; aligns with the README TODO)
- [ ] Multi-tenant scoping (if a team starts sharing one control plane)
- [ ] Settings page for `NEXT_PUBLIC_WG_MANAGER_API`, theme, polling
      cadence
