# Round 39 — dashboard (brief Phase E, campaign 15)

Internal engineering evidence, not an independent audit. Target: `c087bfb` (Round 38 merge).
Work commits: `cb8a741` (console fixes and unit tests, CI floor 36 → 48), `1df84a4` (e2e harness).
File:line references to pre-fix code are at `c087bfb`.

Everything here was run against a real Core: `/home/user/bin/graphite-c087bfb server` on loopback
with a scratch `GRAPHITE_DATA_DIR`, keyed, seeded by `dashboard/e2e/seed.mjs`, the console built
(`npm run build`) and served by `vite preview` with its production headers — the same way
`.github/scripts/dashboard-e2e.sh` does it, which was also run unchanged.

## 1. Scope read

| File | Read | Disposition |
| --- | --- | --- |
| `.github/scripts/dashboard-e2e.sh` | fully | run 4× (baseline + 3 after); header updated for the new sizes/states |
| `dashboard/README.md` | fully | updated (views, test list, sizes, Round 39 states and storage rules) |
| `dashboard/index.html` | fully | no defect |
| `dashboard/package.json` | fully | no defect |
| `dashboard/package-lock.json` | machine-validated only (`npm ci --ignore-scripts`, `npm audit`: 0 vulnerabilities) | no defect |
| `dashboard/tsconfig.json` | fully (JSONC; validated by `tsc -p`) | no defect |
| `dashboard/vite.config.ts` | fully | no defect; note: `vite preview` also proxies `/health`, `/api`, `/metrics`, `/manifests` to `localhost:7331` (see campaign "fresh") |
| `dashboard/public/*.png`, `favicon.ico` (6 binaries) | machine-validated only (`file`: PNG 16/32/48/180/256 px, ICO 3 icons) | no defect |
| `dashboard/src/main.tsx` | fully | no defect |
| `dashboard/src/App.tsx` | fully | fixed (R39-DASH-6, -7, fresh-start redirect kept, phone tab count, dev-mode claim) |
| `dashboard/src/CommandPalette.tsx` | fully | no change needed (R39-DASH-2 fixed in the shared modal hook) |
| `dashboard/src/ErrorBoundary.tsx` | fully | no defect |
| `dashboard/src/api.ts` | fully | `baseProblem`, `optional` account field |
| `dashboard/src/connection.ts` | fully | no defect (storage wrappers re-verified with storage that throws) |
| `dashboard/src/csp.ts` | fully | no defect; `connect-src https:` is by design (runtime Core address) |
| `dashboard/src/figures.ts` | fully | no defect |
| `dashboard/src/poll-state.ts` | fully | no defect |
| `dashboard/src/router.ts` | fully | no defect |
| `dashboard/src/shape.ts` | fully | fixed (R39-DASH-12) |
| `dashboard/src/transport.ts` | fully | fixed (R39-DASH-7) |
| `dashboard/src/ui.tsx` | fully | fixed (R39-DASH-2, -8, -9) |
| `dashboard/src/usePolling.ts` | fully | fixed (R39-DASH-9) |
| `dashboard/src/styles.css` | read in part (2,223 lines: tokens, base, focus, shell, sections, tables, copy, seg, connect, motion read; the rest checked through axe contrast and the screenshots) | fixed (R39-DASH-10) |
| `dashboard/src/views/OverviewView.tsx` | fully | fixed (R39-DASH-3) |
| `dashboard/src/views/ProgramsView.tsx` | fully | fixed (R39-DASH-1, optional accounts, no-manifest wording, NaN) |
| `dashboard/src/views/GraphView.tsx` | fully | fixed (R39-DASH-1, stub detection) |
| `dashboard/src/views/VerificationsView.tsx` | fully | fixed (R39-DASH-11) |
| `dashboard/src/views/BlockedView.tsx` | fully | no defect (see notes) |
| `dashboard/src/views/RegistryView.tsx` | fully | no defect |
| `dashboard/src/views/SystemView.tsx` | fully | fixed (R39-DASH-4, -5) |
| `dashboard/src/views/ConnectView.tsx` | fully | fixed (R39-DASH-6, -7, live region, dev-mode claim) |
| `dashboard/src/*.test.ts` (9 before, 11 after) | fully | one re-pinned (see §2, R39-DASH-7); 12 tests added |
| `dashboard/e2e/package.json`, `package-lock.json` | fully / machine-validated (`npm audit`: 0) | no defect |
| `dashboard/e2e/seed.mjs` | fully | no defect |
| `dashboard/e2e/smoke.mjs` | fully | fixed (R39-DASH-13), five widths |
| `dashboard/e2e/states.mjs` | fully | 10 new state walks (§4) |
| new: `dashboard/src/status.ts`, `modal-stack.ts`, `status.test.ts`, `modal-stack.test.ts` | — | added |

Server code read only where the console's truth depends on it: `graphite-core/src/server.rs`
`health_handler` (2823), `policy_violations_handler` counts (4646–4700), and
`verification.rs` `graph_snapshot` (3447) — behaviour-only nodes have `manifest_version: null`.

## 2. Findings

All are P2/P3 presentation or harness defects: the console is read-only, nothing it shows feeds a
signer, and no finding changes a verdict. All are reproduced against the real Core; each has a
browser check in `dashboard/e2e/states.mjs` or `smoke.mjs` that fails on the `c087bfb` console and
passes on this one, and the pure parts have unit tests. Confidence: high for all.

| Id | Sev | Where (c087bfb) | Finding | Test | Status |
| --- | --- | --- | --- | --- | --- |
| R39-DASH-1 | P3 | `ProgramsView.tsx:162`, `GraphView.tsx:323` | A deep link (`#/programs/<id>`, `#/graph/<id>`) opened before `/api/graph` answered said "Unknown program — Not in the graph. No manifest describes this program ID": a claim about a program nobody had looked up | states.mjs §11 `deeplink-loading/*` | fixed with test |
| R39-DASH-2 | P3 | `ui.tsx:462` `useModal` | Every modal put its own keydown listener on `window`; with the palette (Ctrl+K) open over a detail pane one Escape closed both, and both focus traps ran on Tab | `modal-stack.test.ts` (2); states.mjs §12 | fixed with test |
| R39-DASH-3 | P3 | `OverviewView.tsx:381` | The verdict tape's right edge was labelled "now" whatever the newest verdict's age ("2d ago … now"): the gate looked as if it had just decided something | states.mjs §18 `tape-old` | fixed with test |
| R39-DASH-4 | P3 | `SystemView.tsx:66` | `pollFault(health, metrics)`: a `/metrics` that failed before its first answer (a proxy that does not route it, 404) replaced every `/health` figure with its fault — partial data drawn as none | states.mjs §13 `metrics-404/system` | fixed with test |
| R39-DASH-5 | P2 | `SystemView.tsx:99–104` | A `/health` without `audit` or `graph_persistence` was drawn "Off — verdicts are not being recorded" / "Off" (unread drawn as a definite negative); a trail whose appends fail (`audit.writes_failed > 0`) was drawn green "Writing". Same class as R36-D1 (P2) | `status.test.ts` (3); states.mjs §14 | fixed with test |
| R39-DASH-6 | P3 | `ConnectView.tsx:232`, `App.tsx:114` | The connection test answered a `/health` that came back 500 or 429 with "No answer … add this origin to GRAPHITE_CORS_ORIGINS"; the sidebar called such a Core "Core unreachable" | `status.test.ts` (2); states.mjs §1 `500/sidebar`, §15 `connect/health-500` | fixed with test |
| R39-DASH-7 | P3 | `transport.ts:52`, `ConnectView.tsx:61`, `App.tsx:384` | A value typed into the address field — most plausibly the key, pasted one field too high — was saved to localStorage (on disk, whatever "Remember the key" says), echoed in every view's fault text (`"<value>" is not a URL`) and drawn in the sidebar; an address with user-info (`https://u:<key>@host`) was stored and drawn the same way. Now refused and not saved; no refusal repeats the value; the sidebar shows host and path only (`displayBase`) | `transport.test.ts` (3, one re-pinned); states.mjs §15 `connect/key-as-address` | fixed with test |
| R39-DASH-8 | P3 | `ui.tsx:105` `CopyId` | A copy the browser refused (no clipboard on an insecure origin, denied permission) did nothing visible; now "Copy failed", the value selected for a manual copy, and a status announcement | states.mjs §16 `copy-refused` | fixed with test |
| R39-DASH-9 | P3 | `ui.tsx:282` `Freshness`, `usePolling.ts:50` | "Updated Ns ago" was computed only when a poll landed, so it stood still between polls ("Updated 0s ago" 12 s later), and a tab brought back kept its six-fold hidden-tab wait | states.mjs §19 `freshness` | fixed with test |
| R39-DASH-10 | P3 | `styles.css:169` `.sr-only`, `:1041`, `:1946`, `:1058` | Horizontal page overflow: Connection +48/78/118 px at 390/360/320 (the `1fr` column's minimum was the `<pre>` line), Verifications +35 at 320 (filter in the head row), Verifications +58/+6 and Blocked +35 at 768/820 (absolutely positioned `.sr-only` in scrolled tables resolved against the page) | smoke.mjs (5 widths, 12 failures on c087bfb) | fixed with test |
| R39-DASH-11 | P3 | `VerificationsView.tsx:125` | The filter was `role="radiogroup"`/`role="radio"` with no arrow keys and a tab stop per option; now toggle buttons (`aria-pressed`) in a group | states.mjs §19 `filter` | fixed with test |
| R39-DASH-12 | P3 | `shape.ts:161` `checkManifests` | Only `instructions` was checked to be a list; a manifest instruction without `accounts` (or the other lists) crashed the Programs view into its error boundary when a program was opened. Also unchecked: graph `community_verified_count` (drawn "NaN"), `cpi_targets[]` text, `manifest_version`, health `degraded_reasons[]` text | `shape.test.ts` (2); states.mjs §17 | fixed with test |
| R39-DASH-13 | P3 (test gap) | `e2e/smoke.mjs:84` | The smoke's overflow check was `scrollWidth - innerWidth`; under Playwright mobile emulation `innerWidth` widens to the content (390 px phone, 438 px page → `innerWidth` 438), so it was 0 on every phone and tablet walk. This is what hid R39-DASH-10 from CI. Now `clientWidth`, and 768 and 320 px walks added | smoke.mjs | fixed |

Smaller corrections made in the same commits (no separate id): the key field's placeholder said
"Not needed: this Core runs in dev mode" whenever `/health` answered, before any key-guarded route
had (now only after a key-guarded answer to an empty key); the phone's Blocked tab showed its
refusal count only as an `aria-hidden` dot (now also screen-reader text); the connection report
mounted its own `aria-live` region with its content (often not announced; now one persistent
region with "Testing…"); optional manifest accounts were drawn as required; a behaviour-only graph
node (`manifest_version: null`, `verification.rs:3487`) was described as "reached only as a CPI
target" (stubs are now told apart by membership); Programs' description said "every program with a
manifest" although behaviour-only nodes are listed.

Kept the first-run redirect working: with R39-DASH-6 a static host answering `/health` with its own
502 is "erroring", not "down", so the redirect condition now covers both (states.mjs §20).

Noted, not changed (accepted, informational):
- `connect-src` allows any `https:` origin: the Core address is chosen at run time; documented in
  `csp.ts` and README since Round 29.
- Blocked view draws a refused row's `policy_verdict: "Approved"` / `risk_status: "Clear"` cells in
  the pass tone. They are true component results inside a red refused row; no approval is implied.
- `risk-class ${ix.risk_class}` puts a manifest string in a class name: class injection only
  (React escapes the attribute; hostile-string walk clean).
- `parseMetrics` takes the last space-separated field as the value; the Core's exposition has no
  labels or timestamps (30 lines, 2 fields each, checked live).

Break results: the new unit tests were copied onto the `c087bfb` source in `/home/user/brk-dashboard-1`
(8 of 43 fail: the 3 R39-DASH-7 tests and the re-pinned one, the 2 R39-DASH-12 tests, and the two new
suites, whose modules do not exist there). The new `smoke.mjs` against the `c087bfb` build: 12
failures (all overflow, including at the existing 820 and 390 sizes). The new `states.mjs` against
the `c087bfb` build: 19 failures (every new check except §20 fresh and the §6 restart addition,
which are regression guards and pass on both). Against this build: 0 and 0.

## 3. Prior findings re-verified (in scope)

| Id | Current status (re-checked in code and in the browser) |
| --- | --- |
| F-19-C6 (Round 19) | holds: `insecureBaseReason` checked before every `fetch` (`api.ts` `request`); malformed `%` escape → no program (`router.ts parseHash`, `router.test.ts`) |
| A5-04 | holds: `redirect: "error"` (`transport.ts fetchFromCore`); `transport.test.ts` "a redirect from the Core is a failed request" |
| R29 D1 (window vs whole-trail totals) | holds: `trailTotals`/`refusalTotals` use `count`/`violation_count`/`error_count`; live Core sends all three |
| R29 D2 (/metrics error band) | holds; extended by R39-DASH-4 to System |
| R29 D3 (deadline, stale banner) | holds: 15 s deadline; banner live-checked (states §6) and recovery after the Core returns now checked |
| R29 D4 (descriptive approvals) | holds (`verdictKind`, figures.test.ts) |
| R29 D5 (blocked storage, error boundary) | holds: live-checked with both storages throwing on access — Connect renders, a saved connection works for the page |
| R29 D6 (key per tab, CSP, no source maps) | holds: build has no `.map`, meta CSP present, headers from `vite preview` read back (curl) |
| R29 D7 (empty base / file://) | holds |
| R29 D9 (Forget key) | holds (states §8) |
| R29 D10 (unknown count not zero) | holds (`observedText`, "—" with title) |
| Round 30 (green only for executable, shape checks, clear on Core switch, frame-ancestors, CSP IPv6) | holds: smoke checks every green row against `/api/confidence-history`; states §9 switch; headers read back |
| R32 browser smoke in CI | holds, but its overflow check was blind on phones/tablets: R39-DASH-13 |
| R36-D1 (unread drawn 0 / clear / Operational) | holds for the bypass counters and Status; the same class remained for the audit and snapshot figures: R39-DASH-5 |
| G2-6 (Round 38, 32 MiB bound) | holds (`readBounded`, test) |
| W22 (descriptive verdicts) | holds |
| F-010 (witness is not proof) | holds: System's L8 figure says "an RPC provider's word, not proof of inclusion" |

## 4. Attack campaign 15 and Phase E items

Fixture for all: the real Core (`graphite-c087bfb`, keyed, no RPC, seeded with 4 verdicts: a
descriptive approval, a bound analysis-only approval, two refusals), the built console, and the
`states.mjs` fault proxy (or the scratch probe `explore.mjs`, same proxy design) between them.

| Case | Pre-fix (c087bfb) | Expected | Observed now | Test |
| --- | --- | --- | --- | --- |
| Wrong key (401 on /api, /metrics, /manifests) | every view keeps its h1, fault shown, axe clean | same | same | states §1 |
| Down / 500 / not JSON | as above; sidebar "unreachable" for 500 | 500 says "answering with errors" | yes | states §1 |
| Degraded `/health` | Status "Degraded", banner lists reasons | same | same | states §7 (hostile health is degraded) |
| Partial: /metrics 404 | whole System view replaced by the fault | /health figures kept, counters faulted, bypass "unknown" | yes | states §13 |
| Partial: /health without audit/persistence | "Off — verdicts are not being recorded" | "Not reported" | yes | states §14 |
| Fake-zero / unknown residual | bypass unknown not clear (R36); unknown decision drawn not executable | same | same | unit + states §2–3 |
| Malformed: manifest without accounts | Programs view crashed ("failed to draw") | refused as unreadable | yes | states §17 |
| Server restart mid-session | stale banner, not "Operational" | and recovers when the Core returns | yes | states §6 |
| Polling errors / stale | banner with age; age frozen between polls | age keeps counting; tab return polls | yes | states §19 |
| Empty trail | "No verifications yet", no mean of nothing | same | same | states §5 |
| Large: 2,137 programs, 500 verdicts, count 1,234,567 | renders in < 3 s, no overflow, no boundary | same | same | `explore.mjs large` (scratch) |
| Fresh / no config | redirect to Connection, or "requires a key, and none is stored" | same | same | states §20 |
| XSS: markup in every drawn string, `javascript:` website | inert | same | same | states §7 |
| Unsafe URL schemes in rendered links | only `httpUrl` hrefs (http/https) | same | same | states §7 |
| CSP | no violation on any view at five widths | same | same | smoke |
| Key persistence | session by default; remember is explicit | and never via the address field | yes | connection.test.ts, states §8, §15 |
| Key in URL / logs / DOM / error text | not in URL or logs; echoed via address field and sidebar | never | yes | transport.test.ts, states §15 |
| Mobile overflow | +35 to +118 px at 320–820 (hidden from CI by R39-DASH-13) | none | none at 320, 360, 390, 768, 820, 1024, 1280, 1440, 1920, and 640 @2× (200 % zoom) | smoke (5 widths) |
| Keyboard / modal focus trap | trap holds; Escape closed both modals when stacked | top modal only | yes | states §10, §12 |
| Reduced motion | no infinite animation with `prefers-reduced-motion: reduce` | same | same | `explore.mjs reduced` |
| Copy controls | refused copy silent | says so | yes | states §16 |
| Browser storage failure | both storages throwing: console works for the page | same | same | `explore.mjs storage`, connection.test.ts |

Keyboard pass (scratch probe, every view): every stop has a visible focus ring (the graph nodes'
ring is on their hit rectangle, checked by screenshot); skip link present. Charts' text
equivalents: the tape writes its counts beside it; the Verifications chart is `role="img"` with a
label, and the figures and the table above/below carry the numbers; the call graph's nodes are
named buttons with in/out counts, and the phone layout is lists.

Responsive screenshots (not committed): 82 PNGs — 320, 360, 390, 768, 820, 1024, 1280, 1440 and
1920 px for all eight views plus an open program pane, and the large-dataset Verifications — in
`/tmp/claude-0/-home-user-graphite/f2822178-bc53-556e-99d2-3fd4bf6ff8ab/scratchpad/dash/shots/`.

## 5. Invariant evidence (dashboard's share)

| Invariant | Implementation | Tests | Gap |
| --- | --- | --- | --- |
| Executable is stricter than approved (as displayed) | `figures.ts verdictKind/verdictTone`: green only for `executable_approved` + `executable: true` + bytes | figures.test.ts; smoke checks every green row against the Core | none found |
| Fail closed / unknown is not zero | `readBypass`, `auditReading`, `persistenceReading`, `observedText`, shape checks | unknown-not-zero.test.ts, status.test.ts, shape.test.ts, states §2–5, §13–14 | none known after R39-DASH-5 |
| Operational integrity: secrets never exposed | key only in an `Authorization` header; session storage by default; address validated, never echoed; sidebar `displayBase` | connection.test.ts, transport.test.ts, states §8, §15 | Web Storage is readable by any script on the origin; mitigated by the CSP (documented) |
| No redirect-based trust bypass | `redirect: "error"`, loopback-only plain http | transport.test.ts | none |
| Cross-language parity (rendering) | unknown decision strings drawn not executable | figures.test.ts | none |

## 6. Commands run

| Command | Result |
| --- | --- |
| `npm ci --ignore-scripts` (dashboard, dashboard/e2e) | ok; `npm audit` 0 vulnerabilities in both |
| `npm run typecheck` | clean |
| `npm test` (before) | 36 passed, 0 failed |
| `npm test` (after) | 48 passed, 0 failed (CI floor raised 36 → 48 in `ci.yml`) |
| `npm run build` | ok; no `.map`; meta CSP present |
| `CHROMIUM_PATH=… bash .github/scripts/dashboard-e2e.sh /home/user/bin/graphite-c087bfb` (before) | seed 4 verdicts; smoke "8 views x 3 sizes clean, axe included"; states clean |
| same (after) | seed 4 verdicts; smoke "8 views x 5 sizes clean, axe included"; states "… clean, axe included" |
| new `smoke.mjs` / `states.mjs` against the `c087bfb` build | 12 / 19 failures (break evidence above) |
| new unit tests on the `c087bfb` source | 8 of 43 fail |

Environment deviation: `dashboard/e2e`'s lockfile installs Playwright 1.64.1, whose Chromium build
is not on this machine and must not be downloaded here; the harness was run with its own
`CHROMIUM_PATH` hook pointing at the preinstalled Chromium (`/opt/pw-browsers/chromium-1194`).
CI uses Playwright's own Chromium; the CI run of `1df84a4` is still to be read.

Not run: Rust (out of scope, not built). Nothing BLOCKED.

Deleted afterwards: `/home/user/brk-dashboard-1` (break copy), the worktree's `dashboard/node_modules`,
`dashboard/e2e/node_modules` and `dashboard/dist`, the scratch Core's data directory.
