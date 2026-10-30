// Browser smoke test for the built console against a running Core.
//
// Round 30: the console's unit tests run under Node and never draw a page,
// so nothing checked that the production build renders, obeys its own CSP,
// fits a phone, or is usable with assistive technology. This walks every
// view at desktop and phone width in Chromium and fails on:
//   - a Content-Security-Policy violation (including an invalid source),
//   - an uncaught page error or a view's error boundary ("failed to draw"),
//   - the page wider than the viewport (Round 39: measured against the
//     layout width, clientWidth — under mobile emulation innerWidth grows
//     to fit the overflow, so the old measure never saw it on a phone),
//   - any axe-core violation, when AXE_CORE_PATH names axe.min.js,
//   - a green "executable" verdict the Core did not report as
//     `executable_approved` (checked against /api/confidence-history).
//
// Usage (the console served by `npm run preview`, a Core on loopback whose
// GRAPHITE_CORS_ORIGINS names the preview origin):
//   node e2e/smoke.mjs http://127.0.0.1:4173/ http://127.0.0.1:7331 "$GRAPHITE_API_KEY"
// Playwright is resolved from this package or PLAYWRIGHT_NODE_PATH (a
// node_modules directory that contains it); it is not a dependency of the
// console, so CI installs it for this job only.
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";

const [consoleUrl, coreBase, key = ""] = process.argv.slice(2);
if (!consoleUrl || !coreBase) {
  console.error("usage: node e2e/smoke.mjs <console-url> <core-base> [api-key]");
  process.exit(2);
}

async function loadPlaywright() {
  try {
    return await import("playwright");
  } catch {
    const base = process.env.PLAYWRIGHT_NODE_PATH;
    if (!base) throw new Error("playwright not found: install it, or set PLAYWRIGHT_NODE_PATH");
    return createRequire(`${base.replace(/\/$/, "")}/`)("playwright");
  }
}

const { chromium } = await loadPlaywright();
const axe = process.env.AXE_CORE_PATH ? readFileSync(process.env.AXE_CORE_PATH, "utf8") : null;
const VIEWS = ["overview", "programs", "graph", "verifications", "blocked", "registry", "system", "connect"];
// Round 36: tablet too. At 768–1099px the sidebar is an icon rail, its own
// anatomy, and its Search button had no accessible name — never drawn here.
// Round 39: the narrowest phone too (320 CSS px: an iPhone SE in a split
// view, or a 1280 window at 400% zoom), and the tablet's narrow edge (768),
// where both Verifications and Blocked scrolled sideways.
const SIZES = {
  desktop: { viewport: { width: 1440, height: 900 } },
  tablet: { viewport: { width: 820, height: 1180 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true },
  "tablet-narrow": { viewport: { width: 768, height: 1024 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true },
  phone: { viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true },
  "phone-small": { viewport: { width: 320, height: 640 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true },
};
const failures = [];
const fail = (where, what) => failures.push(`${where}: ${what}`);

// What the Core says about each verdict, to check the colours against.
const headers = key ? { Authorization: `Bearer ${key}` } : {};
const history = await fetch(`${coreBase}/api/confidence-history`, { headers }).then((r) => r.json());
const executableIds = new Set(
  history.series.filter((p) => p.decision === "executable_approved" && p.executable === true && p.transaction_sha256).map((p) => p.audit_trail_id),
);

// CHROMIUM_PATH names a Chromium to use instead of Playwright's own.
const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
try {
  for (const [size, opts] of Object.entries(SIZES)) {
    // CSP enforced except for the axe pass, which injects a script.
    for (const bypassCSP of axe ? [false, true] : [false]) {
      const ctx = await browser.newContext({ ...opts, bypassCSP });
      await ctx.addInitScript(
        ([b, k]) => {
          localStorage.setItem("graphite.core", b);
          sessionStorage.setItem("graphite.key", k);
          sessionStorage.setItem("graphite.sawConnect", "1");
        },
        [coreBase, key],
      );
      const page = await ctx.newPage();
      page.on("console", (m) => {
        if (!bypassCSP && /Content Security Policy/.test(m.text())) fail(size, `CSP: ${m.text()}`);
      });
      page.on("pageerror", (e) => fail(size, `page error: ${e.message}`));
      for (const view of VIEWS) {
        const where = `${size}/${view}${bypassCSP ? " (axe)" : ""}`;
        await page.goto(`${consoleUrl}#/${view}`);
        await page.waitForTimeout(1500);
        if (await page.getByText(/failed to draw/).count()) fail(where, "the view's error boundary caught a render failure");
        // Round 39 (R39-DASH-13): clientWidth, the layout viewport. Under
        // isMobile, innerWidth widens to the content (a 390 px phone with a
        // 438 px page reports innerWidth 438), so `scrollWidth - innerWidth`
        // was 0 on every phone and tablet walk however wide the page was.
        const over = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
        if (over > 1) fail(where, `the page is ${over}px wider than the viewport`);
        if (bypassCSP) {
          await page.addScriptTag({ content: axe });
          const violations = await page.evaluate(async () => (await window.axe.run(document)).violations.map((v) => `${v.id} x${v.nodes.length}`));
          for (const v of violations) fail(where, `axe: ${v}`);
        }
        if (view === "verifications" && !bypassCSP && size === "desktop") {
          // Every row drawn "executable" must be one the Core reported so.
          const rows = await page.$$eval("table.data tbody tr", (trs) =>
            trs.map((tr) => ({ verdict: tr.querySelector(".state")?.textContent ?? "", id: tr.querySelector(".id .copy")?.getAttribute("title") ?? "" })),
          );
          for (const r of rows) {
            const id = r.id.replace(/^Copy /, "");
            if (r.verdict === "executable" && !executableIds.has(id)) fail(where, `${id} is drawn executable; the Core did not report it so`);
          }
        }
      }
      await ctx.close();
    }
  }
} finally {
  await browser.close();
}

if (failures.length) {
  console.error(`console smoke: ${failures.length} failure(s)`);
  for (const f of failures) console.error(`  ${f}`);
  process.exit(1);
}
console.log(`console smoke: ${VIEWS.length} views x ${Object.keys(SIZES).length} sizes clean${axe ? ", axe included" : ""}`);
