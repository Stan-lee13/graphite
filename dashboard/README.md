# Graphite Console

Read-only operational console for Graphite Core (Phase 2, Feature 7).

A polling web UI (React + TypeScript + Vite) over the Core's read-only routes.
The console never mutates server state (Constitution P4): it is
observability, not a control plane.

## Design

The console is built in the idiom of a developer-platform dashboard (the
Supabase console is the reference) in Graphite's own material, and it has two
anatomies rather than one layout at two widths.

- **Desktop (≥ 1100px):** a sidebar, a content column, a detail drawer that
  slides in from the right. **Tablet (768–1099px):** the sidebar collapses to
  an icon rail. **Phone (< 768px):** a top bar, the content, a bottom tab bar
  under the thumb (Overview, Programs, Trail, Blocked, More) and bottom sheets
  for detail. Tables become row lists on a phone; they are a different
  component, not a squeezed table.
- **One neutral ramp, sampled from the logo.** The mark's facets sit between
  `#101018` and `#282830`, a cool near-black; the canvas, surfaces and
  hairlines are steps on that ramp. The mark itself sits on a lit tile so its
  facets read on a dark page.
- **One accent, and it is the logo's.** The violet at the mark's core, lifted
  to `#9b7bff` for contrast. It marks selection, focus and the brand, never
  decoration.
- **Colour otherwise means a verdict.** Green approved, red refused on risk,
  amber refused on policy or degraded. The one thing on the page that moves
  is the verdict tape on Overview, and it moves only when the gate decides.
- **Type:** Instrument Sans (all interface text) and Commit Mono
  (identifiers, hashes, numeric columns), both OFL, both shipped with the
  build via `@fontsource`. Icons are Lucide, bundled. Nothing loads from a
  CDN: a security console should not phone out for its typeface.
- **URL is state.** `#/programs/<id>` opens that program's manifest;
  `#/graph/<id>` isolates its edges. ⌘K / Ctrl+K searches views and programs.

Tokens live at the top of `src/styles.css`; components carry no raw colours.
Program names come from Graphite's own manifests, never from a third-party
label service.

## Views

| View | Routes read | Content |
| --- | --- | --- |
| Overview | `/api/graph`, `/api/protocols/top`, `/api/confidence-history`, `/api/policy-violations`, `/metrics` | The verdict tape, approval and refusal figures, the six most recent refusals (risk vs policy drawn differently), the most exercised programs, and a red band the moment any bypass counter is non-zero |
| Programs | `/api/graph`, `/api/protocols/top`, `/manifests` | Every program with a manifest, ranked by traffic; a detail pane with the manifest's instructions, discriminators, account roles, expected state changes, risk rules and declared CPI targets. The trust tier shown is the one the Core **applied**, which since Round 18 is lowered from a declared `BattleTested` when the mainnet measurement in `battle_tested_evidence.json` does not support it |
| Call graph | `/api/graph` | Declared CPI edges in call order; on a phone, the same roles as lists |
| Verifications | `/api/confidence-history` | Every verdict in trail order, confidence drawn against the Gaming, Trading and Treasury floors |
| Blocked | `/api/policy-violations` | Refused transactions and requests the Core could not parse |
| Registry | `/api/registry` | Accepted submissions with version lineage, and registered reviewers |
| System | `/health`, `/metrics` | The Core's own report on its durability, and every counter it exports, bypass signals first |
| Connection | `/health`, `/api/protocols/top` | Where the Core is and the key the console presents, with a two-step test that proves the key works before anything depends on it |

## Running

```bash
npm ci
npm run dev        # dev server on :5173, proxies the Core's routes to :7331
npm run build      # typecheck + production build → dist/
npm run typecheck  # tsc --noEmit only
npm test           # node --test (Node 22+): transport and router
```

- The dev proxy target is `http://localhost:7331` by default; override with
  `VITE_GRAPHITE_PROXY=http://host:port npm run dev`.
- For a production deployment, serve `dist/` from any static host. The Core
  address is set at runtime on the Connection screen (or pre-set at build
  time with `VITE_GRAPHITE_API`); direct cross-origin access needs the
  console's origin in `GRAPHITE_CORS_ORIGINS` on the Core.
- The console refuses to send its key to a plain `http://` Core that is not
  on loopback (localhost, 127.0.0.0/8, [::1]); use `https://` for anything
  else (Round 19, `src/transport.ts`). A malformed `%` escape in the URL hash
  is treated as an unknown route rather than crashing the router.

## The API key

A Core has one verify key, `GRAPHITE_API_KEY`, chosen by whoever starts it.
(A second, optional operator key, `GRAPHITE_ADMIN_API_KEY`, guards
`/admin/*`; the console never calls those routes and never needs it.) There
is no sign-up and no key service:

1. The operator generates a secret of at least 32 characters
   (`openssl rand -hex 32`).
2. The Core starts with it. It refuses to start without one unless
   `GRAPHITE_DEV_MODE=1` is set, and then only on a loopback address.
3. Every caller — this console, the agent kit, the CLI — sends the same key
   as `Authorization: Bearer`. Every route except `/health` requires it.

The console receives its copy on the Connection screen, which tests it in
two steps: `/health` proves the address is a Core that this origin may talk
to, and a key-guarded route proves the key. The key is kept in this
browser's localStorage only, is never written to a URL, and can be forgotten
with one click. A rejected key is reported as such — distinct from a Core
that is down — in the sidebar, in a banner, and on every panel.

## Security & operational notes

- Read-only by construction: the UI only issues GETs.
- Every route the console reads sits behind the Core's Bearer auth, per-IP
  rate limiter, request timeout and body limit; `/health` stays open for load
  balancers.
- Polling interval is 5s per source (slower while the tab is hidden);
  real-time push is deferred to Phase 3 by design (see `docs/phase2-plan.md`
  Feature 7).
- Errors are surfaced in the UI, never silently swallowed; the last good
  payload survives transient fetch failures.
- Confidence history, policy violations and protocol totals cover the whole
  audit trail, rotated archives included.
