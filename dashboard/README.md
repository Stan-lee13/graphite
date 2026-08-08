# Graphite Dashboard

Read-only operational dashboard for Graphite Core (Phase 2, Feature 7).

Polling web UI (React + TypeScript + Vite) that visualizes live Core state
through the Core server's read-only `/api/*` endpoints. The dashboard never
mutates any server state (Constitution P4) — it is observability, not control
plane.

## Views

| View | Source endpoint | Content |
| --- | --- | --- |
| Protocol Overview | `/api/protocols/top`, `/api/graph` | Programs with trust tiers, instruction counts, baseline samples, battle-tested volume, quarantine status |
| Semantic Graph | `/api/graph` | Nodes (merged manifest + earned behavior + baseline) and directed CPI edges; click a node for evidence |
| Confidence History | `/api/confidence-history` | Audit-log time series with per-point approved/blocked outcome |
| Policy Violations | `/api/policy-violations` | Blocked verifications + rejected error-path requests |
| Manifest Registry | `/api/registry` | Accepted submissions with version lineage + registered reviewers |

## Running

```bash
npm install
npm run dev        # dev server on :5173, proxies /api and /health to Core :7331
npm run build      # typecheck + production build → dist/
npm run typecheck  # tsc --noEmit only
```

- The dev proxy target is `http://localhost:7331` by default; override with
  `VITE_GRAPHITE_PROXY=http://host:port npm run dev`.
- For a production deployment, serve `dist/` from any static host and set
  `VITE_GRAPHITE_API` at build time (default: same-origin `/api`).
- If Core runs with `GRAPHITE_API_KEY`, configure the dashboard to send the
  Bearer token (e.g. via a reverse proxy or a fetch wrapper) — all `/api/*`
  routes require it by default.

## Security & operational notes

- Read-only by construction: the UI only issues GETs against `/api/*`.
- All dashboard endpoints sit behind Core's existing Bearer auth, per-IP rate
  limiter, request timeout, and body limit; `/health` stays open for load
  balancers.
- Polling interval is 5s per source; real-time push is deferred to Phase 3 by
  design (see `docs/phase2-plan.md` Feature 7).
- Errors are surfaced in the UI, never silently swallowed; the last good
  payload survives transient fetch failures.
