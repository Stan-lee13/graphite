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
- **Colour otherwise means a verdict.** Green executable (the Core's
  `executable_approved`, bound to bytes — Round 30); amber approved but not
  executable (analysis only, not reported, or descriptive), inconclusive,
  refused on policy, or degraded; red refused on risk. The one thing on the page that moves
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
| Overview | `/api/graph`, `/api/protocols/top`, `/api/confidence-history`, `/api/policy-violations`, `/metrics` | The verdict tape, whole-trail approval and refusal totals, executable vs not-executable approvals over the returned window (labelled "last N"), the six most recent refusals (risk vs policy drawn differently), the most exercised programs, a red band the moment any bypass counter is non-zero, and an "unknown — /metrics unavailable" band whenever those counters cannot be read |
| Programs | `/api/graph`, `/api/protocols/top`, `/manifests` | Every program with a manifest, the most verified here first (every program's count, from `/api/protocols/top?limit=500`), then by mainnet census; a detail pane with the manifest's instructions, discriminators, account roles, expected state changes, risk rules and declared CPI targets. The trust tier shown is the one the Core **applied**, which since Round 18 is lowered from a declared `BattleTested` when the mainnet measurement in `battle_tested_evidence.json` does not support it |
| Call graph | `/api/graph` | Declared CPI edges in call order; on a phone, the same roles as lists |
| Verifications | `/api/confidence-history` | The trail's total, and its newest 500 verdicts in trail order — bound, descriptive and refused counted apart — with confidence drawn against the Gaming, Trading and Treasury floors |
| Blocked | `/api/policy-violations` | Whole-trail refusal total, and the newest 200 refused transactions and 200 requests the Core could not parse |
| Registry | `/api/registry` | Accepted submissions with version lineage, and registered reviewers |
| System | `/health`, `/metrics` | The Core's own report on its durability, and every counter it exports, bypass signals first |
| Connection | `/health`, `/api/protocols/top` | Where the Core is and the key the console presents, with a two-step test: `/health` proves the address, and one key-guarded route (`/api/protocols/top`) proves the key |

## Running

```bash
npm ci
npm run dev        # dev server on :5173, proxies the Core's routes to :7331
npm run build      # typecheck + production build → dist/ (no source maps)
npm run typecheck  # tsc --noEmit only
npm test           # tsx --test (Node 22+): transport, router, connection storage, figures, CSP
```

- The dev proxy target is `http://localhost:7331` by default; override with
  `VITE_GRAPHITE_PROXY=http://host:port npm run dev`.
- For a production deployment, serve `dist/` over http(s) from any static
  host, at its root or under a subpath. Opening `dist/index.html` from
  `file://` does not work: browsers refuse module scripts there. The Core
  address is set at runtime on the Connection screen (or pre-set at build
  time with `VITE_GRAPHITE_API`); direct cross-origin access needs the
  console's origin in `GRAPHITE_CORS_ORIGINS` on the Core.
- The console refuses to send its key to a plain `http://` Core that is not
  on loopback (localhost, 127.0.0.0/8, [::1]); use `https://` for anything
  else (Round 19, `src/transport.ts`). A malformed `%` escape in the URL hash
  is treated as an unknown route rather than crashing the router.
- The built `index.html` carries a Content-Security-Policy (`src/csp.ts`,
  Round 29): scripts, styles, fonts and images from the console's own origin
  only, no inline script and no `eval`; `connect-src` allows any `https://`
  origin and plain `http://` on `localhost` and `127.0.0.1` — the same rule
  `src/transport.ts` applies. A CSP host source cannot be an IPv6 literal or
  a range, so a plain-http Core at `[::1]` or `127.0.0.2+` is refused before
  sending, with that reason (Round 30; it used to fail as "No response").
  It is added at build time only; the dev server needs inline scripts.
  Production builds ship no source maps (`GRAPHITE_DASHBOARD_SOURCEMAP=1`
  for a local debugging build).
- **Serving it (Round 30).** A `<meta>` CSP cannot carry `frame-ancestors`,
  so the host serving `dist/` must send headers: `src/csp.ts`
  `securityHeaders()` is the set — the CSP plus `frame-ancestors 'none'`,
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`
  and a `Permissions-Policy` that denies camera, microphone, geolocation,
  payment and USB. `npm run preview` serves exactly these; configure your
  static host (nginx `add_header`, a CDN's header rules) with the same.

## Browser smoke test (Round 30)

`e2e/smoke.mjs` walks every view of the built console in Chromium, at
desktop and phone width, against a running Core, and fails on a CSP
violation, a page error or a view's error boundary, a page wider than the
viewport, any axe-core violation (when `AXE_CORE_PATH` names `axe.min.js`),
or a verdict drawn "executable" that the Core's `/api/confidence-history`
did not report as `executable_approved`:

```bash
npm run build && npm run preview -- --port 4173 &   # serves dist/ with the security headers
# a Core on loopback with GRAPHITE_CORS_ORIGINS=http://127.0.0.1:4173
node e2e/smoke.mjs http://127.0.0.1:4173/ http://127.0.0.1:7331 "$GRAPHITE_API_KEY"
```

Playwright is not a dependency of the console; the script finds it in this
package or under `PLAYWRIGHT_NODE_PATH`. Breaking the colour rule (drawing an
unreported bound approval green) makes it fail on every such row.

## What a verdict's colour means (Round 30)

Green is spent on one thing: an approval the Core reports as
`decision: "executable_approved"` with `executable: true`, bound to
transaction bytes — the only verdict a signer may act on. Every other
approval is amber and says which kind it is: **analysis only** (the Core
judged it without a simulation, or with an unobserved residual),
**executability not reported** (a Core older than the decision contract),
or **descriptive** (no bytes at all). An unknown `decision`, or a `decision`
and `executable` that disagree, is drawn as not executable. Refusals are
red; **inconclusive** (evidence could not be obtained) is amber. The
Overview tape writes its counts beside it, so the colours are never the
only signal. Before Round 30 every bound approval was green, including the
ones a Core with no RPC made.

System shows **Simulation RPC** from `/health`'s `rpc_attached` — "None"
means no approval from that Core is executable — and "Not reported" when
the Core does not say. It also surfaces frozen baselines and detected
program upgrades from `/health`.

Every response is checked for the fields the views read (`src/shape.ts`).
A Core of another version or a proxy's page is reported as "the Core's
answer could not be read", naming the field, instead of crashing the view
or showing "NaN" — and is no longer misreported as "No response". Changing
the Core or key clears the previous Core's numbers at once rather than
showing them under the new Core's name while it loads.

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
to, and a key-guarded route (`/api/protocols/top`) proves the key. By
default the key is kept for this tab only (sessionStorage) and is gone when
the tab closes; ticking "Remember the key on this device" keeps it in this
browser's localStorage instead, and un-ticking it removes that copy. Either
way it is never written to a URL, and "Forget key" drops it (and nothing
else) with one click. Web Storage is readable by any script running on the
console's origin, which is why the build carries a strict CSP. A rejected key is reported as such — distinct from a Core
that is down — in the sidebar, in a banner, and on every panel.

## Security & operational notes

- Read-only by construction: the UI only issues GETs.
- Every route the console reads sits behind the Core's Bearer auth, per-IP
  rate limiter, request timeout and body limit; `/health` stays open for load
  balancers.
- Polling intervals, per view: `/health` 10 s (the shell) and 5 s (System);
  `/metrics` 10 s on Overview and 5 s on System; `/api/graph` 5 s where it is
  the view's subject and 30 s where it only supplies names (Verifications,
  Registry, search); `/api/protocols/top` 5 s (Overview, Programs) and 10 s
  (Call graph); `/api/confidence-history`, `/api/policy-violations` and
  `/api/registry` 5 s; `/manifests` 5 min (Round 30: it is every manifest in
  full, about 4.6 MB, and was fetched every 30 s). `/api/protocols/top` is
  asked for every row (`?limit=500`), so every program has its count. Every interval is six times longer
  while the tab is hidden. Real-time push is deferred to Phase 3 by design
  (see `docs/phase2-plan.md` Feature 7).
- Every request has a 15 s deadline (headers and body), so a Core that
  accepts a request and never answers cannot stall a view's polling.
- Errors are surfaced in the UI, never silently swallowed: a source that
  has delivered keeps its last good payload on screen under a banner naming
  the failure and the data's age; every view shows when its data was last
  updated; a render failure is caught by an error boundary per view.
- Totals (verifications on record, refusals, the Blocked badge) are the
  Core's whole-trail counts, rotated archives included. The lists are
  windows — the newest 500 verdicts and the newest 200 refusals and 200
  rejected requests — and every figure computed from a window says so
  ("last 500").
