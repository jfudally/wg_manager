# API versioning + deprecation policy

Phase 3c — public API versioning. Every wg-manager HTTP endpoint is
dual-mounted at two paths:

| Surface           | Path shape          | Status     | Sunset                  |
|-------------------|---------------------|------------|-------------------------|
| Legacy (Phase 1+) | `/<resource>`       | deprecated | configurable; see below |
| v1                | `/v1/<resource>`    | active     | none                    |

Both surfaces share the **same handler code**. Identical request →
identical response body + status. The only difference is the
deprecation envelope on the legacy surface.

## Deprecation envelope

Every response from a legacy path carries three headers (RFC 9745):

```
Deprecation: true
Sunset: 2027-01-01
Link: <https://github.com/jfudally/wg_manager/blob/main/docs/api-versioning.md>; rel="deprecation"; type="text/html"
```

The `Sunset` date is operator-tunable via the `API_LEGACY_SUNSET_DATE`
setting; the `Link` URL via `API_DEPRECATION_DOC_URL`. Defaults ship
in `.env.example`.

In addition, every legacy hit emits one structured `api.deprecation`
audit line on the `wg_manager.audit` logger:

```json
{"ts":"...","event":"api.deprecation","path":"/servers","method":"GET","sunset":"2027-01-01"}
```

so operators can run a SIEM query to enumerate legacy callers.

## OpenAPI surface

* `GET /openapi.json` — full spec, both surfaces (legacy + v1).
* `GET /v1/openapi.json` — filtered to `/v1/*` paths only, with
  `info.version = "1.0"` pinned. Use this when generating a typed
  OpenAPI client so future deprecations of the legacy surface
  don't churn your generated code.

## Semver contract

`/v1` follows semver:

* **Patch** (1.0.x) — bug fixes, no behaviour change a well-behaved
  client could observe.
* **Minor** (1.x.0) — additive only. New endpoints, new fields on
  responses (default-omitted on requests), new enum variants where
  the schema explicitly allows them. Clients that ignore unknown
  fields keep working.
* **Major** (`/v2`) — removals, renames, changes to existing field
  semantics. Lives at a separate path prefix. Phase 3c does not ship
  v2; the door is open for the next phase that needs it.

`/v1` and any future `/v2` coexist; we don't break v1 to ship v2.

## Cutover guidance

Both the wg-manager CLI and the dashboard BFF were cut over to
`/v1` in Phase 3c. **Third-party integrations** (Terraform
providers, ad-hoc curl scripts, monitoring probes) should:

1. Change their base URL to include `/v1`:
   ```
   - https://api.example.com/servers
   + https://api.example.com/v1/servers
   ```
2. Inspect their integration's response headers in CI for any
   remaining `Deprecation: true` hits.
3. Watch the SIEM for `api.deprecation` audit lines tagged with
   their cert's CN.

## Removal timeline

The legacy unprefixed surface remains available until the configured
`API_LEGACY_SUNSET_DATE`. The default shipped in `.env.example`
gives operators **a full release cycle** to migrate; production
deployments are expected to set their own date matching their
integration partners' schedules.

Once an operator's `Sunset` date passes, the recommended action is
to remove the legacy dual mount via a follow-up PR that drops the
unprefixed `application.include_router` loop in `wg_manager.main`.
That removal is one diff line; the audit log + `Sunset` header give
operators advance warning so the change is undramatic.

## Why a dual mount (not a redirect)?

A 301/307 redirect would force every legacy caller to issue two
round trips per request. For an mTLS API every additional handshake
is real cost (CPU + latency) and would worsen the migration
experience. The dual mount lands legacy and v1 at the same handler
in the same process, so callers see a pure header difference and
zero performance penalty during the migration window.
