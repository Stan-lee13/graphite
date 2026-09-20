# Graphite Console

Read-only operational console for Graphite Core (Phase 2, Feature 7).

Polling web UI (React + TypeScript + Vite) that visualizes live Core state
through the Core server's read-only `/api/*` endpoints. The console never
mutates any server state (Constitution P4) — it is observability, not control
plane.

## Design

The console is built in the idiom of a developer-platform dashboard (the
Supabase console is the reference), in Graphite's own material:

- **One neutral ramp, sampled from the logo.** The mark's facets sit between
  `#101018` and `#282830` — a cool near-black — so the page, the cards and the
  borders are steps on that ramp. Depth is a hairline ring and one background
  step; nothing floats.
- **One accent, and it is the logo's.** The violet at the mark's core reads at
  hue 259°; `--brand: #9b7bff` is that hue lifted to 5.7:1 on the surface. It
  marks selection, focus and the brand, never decoration.
- **Colour otherwise means state.** Green passed, red blocked, amber degraded
  or refused-by-policy. A console that decorates with colour has no colour
  left to warn with.
- **Data is monospace, every numeral tabular.** Program IDs, hashes and
  confidence values are compared column-to-column far more than they are read
  as prose.
- **Nothing loads from a CDN.** Inter and JetBrains Mono ship with the build
  via `@fontsource`; icons are Lucide, bundled. A security console should not
  phone out for its typeface.

The design tokens live at the top of `src/styles.css`. The sidebar, the top
bar and every primitive read from them; there are no raw colours in
components.

Program names come from Graphite's **own manifests** (`/api/graph` carries
`name`). No third-party label service is consulted — a verification console
should not learn what a program is called from a source it does not verify.

## Views

| View | Source endpoint | Content |
| --- | --- | --- |
| Overview | `/api/graph`, `/api/protocols/top`, `/api/confidence-history`, `/api/policy-violations` | Landing page: programs, approval rate, blocked count, quarantine, recent confidence with outcome strip, the six most recent refusals (risk block vs policy floor drawn differently), the six most exercised programs |
| Protocol Overview | `/api/protocols/top`, `/api/graph` | Programs with trust tiers, instruction counts, baseline samples, battle-tested volume, quarantine status |
| Semantic Graph | `/api/graph` | Nodes (merged manifest + earned behavior + baseline) and directed CPI edges; click a node for evidence |
| Confidence History | `/api/confidence-history` | Audit-log time series with per-point approved/blocked outcome |
| Policy Violations | `/api/policy-violations` | Blocked verifications + rejected error-path requests |
| Manifest Registry | `/api/registry` | Accepted submissions with version lineage + registered reviewers |

## Running

```bash
npm ci
npm run dev        # dev server on :5173, proxies /api and /health to Core :7331
npm run build      # typecheck + production build → dist/
npm run typecheck  # tsc --noEmit only
```

- The dev proxy target is `http://localhost:7331` by default; override with
  `VITE_GRAPHITE_PROXY=http://host:port npm run dev`.
- For a production deployment, serve `dist/` from any static host and set
  `VITE_GRAPHITE_API` at build time (default: same-origin `/api`).
- Core requires `GRAPHITE_API_KEY` by default: enter the key in the header's
  **API key** field (stored in localStorage, sent as `Authorization: Bearer` on
  every `/api/*` request). `/health` stays open for load balancers, so the
  header health indicator works without a key. A `GRAPHITE_DEV_MODE=1` Core
  (keyless, loopback only) needs no key.
- Confidence history, policy violations and protocol totals cover the whole
  audit trail — rotated archives plus the active file — not only what was
  written since the last rotation (fixed 2026-09-12).
- Direct cross-origin browser access needs `GRAPHITE_CORS_ORIGINS` on Core;
  the dev proxy and same-origin production setups do not.

## Security & operational notes

- Read-only by construction: the UI only issues GETs against `/api/*`.
- All dashboard endpoints sit behind Core's existing Bearer auth, per-IP rate
  limiter, request timeout, and body limit; `/health` stays open for load
  balancers.
- Polling interval is 5s per source; real-time push is deferred to Phase 3 by
  design (see `docs/phase2-plan.md` Feature 7).
- Errors are surfaced in the UI, never silently swallowed; the last good
  payload survives transient fetch failures.
