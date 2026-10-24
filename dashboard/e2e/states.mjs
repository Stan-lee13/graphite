// Browser test of the console's failure, stale, hostile and switching states
// against a running Core (Round 36 audit).
//
// smoke.mjs walks every view while the Core answers well. Most of what an
// operator console can get wrong happens when it does not: a 401, a 500, an
// answer that is not JSON, a Core that stops mid-session, a /metrics that a
// proxy answers with its login page, a field that carries markup, a change
// of Core while the old one is still answering. This puts a small fault
// proxy (in this process, no dependencies) between the console and the
// real Core and walks those states. It fails on:
//   - a view that drops its heading when it shows a fault (it is the only
//     <h1>; axe page-has-heading-one), or any other axe violation;
//   - a bypass signal reported "clear" (or not reported at all) when the
//     counters behind it were not read — unread is not zero;
//   - a window label that claims a window ("all 0") before anything loaded,
//     or a mean confidence of 0.00 over no verdicts;
//   - System calling a Core "Operational" when it has stopped answering;
//   - a string from the API that runs as markup (XSS), or a javascript: link;
//   - the connection test's verdict shown beside an address it did not test;
//   - a "rejected the key stored in this browser" banner after the key was
//     forgotten;
//   - one Core's verdicts shown after switching to another;
//   - a transaction-bound verdict whose digest is not on screen;
//   - a call-graph label drawn outside its canvas;
//   - focus escaping an open detail pane, or not returning when it closes.
//
// Usage (the console served by `npm run preview`, a Core on loopback whose
// GRAPHITE_CORS_ORIGINS names the preview origin; seeded by seed.mjs):
//   AXE_CORE_PATH=e2e/node_modules/axe-core/axe.min.js \
//   node e2e/states.mjs http://127.0.0.1:4173/ http://127.0.0.1:7331 "$GRAPHITE_API_KEY"
// CHROMIUM_PATH names a Chromium to use instead of Playwright's own.
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import http from "node:http";

const [consoleUrl, coreBase, key = ""] = process.argv.slice(2);
if (!consoleUrl || !coreBase || !process.env.AXE_CORE_PATH) {
  console.error("usage: AXE_CORE_PATH=… node e2e/states.mjs <console-url> <core-base> [api-key]");
  process.exit(2);
}
const consoleOrigin = new URL(consoleUrl).origin;

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
const axe = readFileSync(process.env.AXE_CORE_PATH, "utf8");

// ---------------------------------------------------------------------------
// The fault proxy. `rules` maps a path prefix to a fault; the first match
// wins, no match passes the request to the Core untouched.

const MARKUP = `<img src=x onerror="window.__xss=1"><script>window.__xss=2</script>"'><svg onload="window.__xss=3">`;

function hostile(path, body) {
  const j = JSON.parse(body);
  const h = (s) => `${MARKUP}${s}`;
  if (path.startsWith("/api/graph")) for (const n of j.nodes) Object.assign(n, { name: h(n.name), quarantine_reason: MARKUP });
  if (path.startsWith("/api/policy-violations")) {
    for (const v of j.violations) Object.assign(v, { protocol_name: h(v.protocol_name), instruction_name: MARKUP, policy_verdict: MARKUP });
    j.error_violations.push({ timestamp: new Date().toISOString(), program_id: MARKUP, instruction_name: MARKUP, error: MARKUP, error_type: MARKUP, status: 400 });
  }
  if (path.startsWith("/api/confidence-history")) for (const p of j.series) p.audit_trail_id = h(p.audit_trail_id);
  if (path.startsWith("/api/protocols/top")) for (const t of j.top) t.name = h(t.name);
  if (path.startsWith("/api/registry")) {
    j.records.push({ program_id: "11111111111111111111111111111111", version_label: MARKUP, previous_version_ref: MARKUP, content_hash: MARKUP, trust_tier: MARKUP, source: MARKUP });
    j.reviewers.push({ pubkey: MARKUP, reputation_score: 1 });
    j.record_count = j.records.length;
  }
  if (path.startsWith("/manifests")) {
    for (const m of j) {
      m.protocol.website = "javascript:window.__xss=4";
      m.protocol.category = MARKUP;
      for (const ix of m.instructions) Object.assign(ix, { name: h(ix.name), risk_rules: [MARKUP], expected_state_changes: [MARKUP] });
    }
  }
  if (path.startsWith("/health")) Object.assign(j, { version: MARKUP, degraded: true, degraded_reasons: [MARKUP] });
  return JSON.stringify(j);
}

/** An empty trail: a Core that has decided nothing yet. */
function empty(path, body) {
  const j = JSON.parse(body);
  if (path.startsWith("/api/confidence-history")) return JSON.stringify({ series: [], count: 0 });
  if (path.startsWith("/api/policy-violations")) return JSON.stringify({ violations: [], error_violations: [], count: 0, violation_count: 0, error_count: 0 });
  return JSON.stringify(j);
}

function startProxy() {
  const state = { rules: [] };
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://proxy");
    const path = url.pathname + url.search;
    if (req.headers.origin === consoleOrigin) {
      res.setHeader("Access-Control-Allow-Origin", consoleOrigin);
      res.setHeader("Vary", "Origin");
      res.setHeader("Access-Control-Allow-Headers", "authorization, accept");
      res.setHeader("Access-Control-Allow-Methods", "GET");
    }
    if (req.method === "OPTIONS") {
      res.statusCode = 204;
      res.end();
      return;
    }
    const fault = state.rules.find((r) => path.startsWith(r.path))?.fault ?? "pass";
    const send = (status, body, type = "application/json") => {
      res.statusCode = status;
      res.setHeader("content-type", type);
      res.end(body);
    };
    if (fault === "401") return send(401, '{"error":"unauthorized"}');
    if (fault === "500") return send(500, '{"error":"internal"}');
    if (fault === "notjson") return send(200, "{not json");
    if (fault === "html") return send(200, "<!doctype html><title>Sign in</title><p>Sign in to continue", "text/html");
    if (fault === "down") return req.socket.destroy();
    if (fault === "hang") return; // answers nothing; the console's deadline must end it
    if (fault === "slow") await new Promise((r) => setTimeout(r, 4000));
    let upstream;
    try {
      upstream = await fetch(`${coreBase}${path}`, { headers: key ? { Authorization: `Bearer ${key}` } : {} });
    } catch {
      return req.socket.destroy();
    }
    let body = await upstream.text();
    const json = (upstream.headers.get("content-type") ?? "").includes("json");
    if (upstream.ok && json && fault === "hostile") body = hostile(url.pathname, body);
    if (upstream.ok && json && fault === "empty") body = empty(url.pathname, body);
    send(upstream.status, body, upstream.headers.get("content-type") ?? "application/json");
  });
  return new Promise((resolve) =>
    server.listen(0, "127.0.0.1", () => {
      state.base = `http://127.0.0.1:${server.address().port}`;
      state.set = (...rules) => (state.rules = rules.map(([path, fault]) => ({ path, fault })));
      state.close = () => new Promise((r) => (server.closeAllConnections(), server.close(r)));
      resolve(state);
    }),
  );
}

// ---------------------------------------------------------------------------

const failures = [];
const fail = (where, what) => failures.push(`${where}: ${what}`);
const DESKTOP = { viewport: { width: 1440, height: 900 } };
const PHONE = { viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true };
const TITLES = { overview: "Overview", programs: "Programs", graph: "Call graph", verifications: "Verifications", blocked: "Blocked", registry: "Registry", system: "System" };

const proxy = await startProxy();
const coreB = await startProxy(); // a second "Core": the same one, its trail empty
coreB.set(["/api/", "empty"]);
const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});

/** A page whose console points at `base` with the run's key (set once). */
async function open(base, opts = DESKTOP, withKey = key) {
  // bypassCSP so axe can be injected; smoke.mjs checks the CSP itself.
  const ctx = await browser.newContext({ ...opts, bypassCSP: true });
  await ctx.addInitScript(
    ([b, k]) => {
      if (sessionStorage.getItem("e2e.init")) return;
      localStorage.setItem("graphite.core", b);
      if (k) sessionStorage.setItem("graphite.key", k);
      sessionStorage.setItem("graphite.sawConnect", "1");
      sessionStorage.setItem("e2e.init", "1");
    },
    [base, withKey],
  );
  const page = await ctx.newPage();
  page.on("pageerror", (e) => fail("page", `page error: ${e.message}`));
  page.on("dialog", (d) => {
    fail("page", `a dialog opened: ${d.message()}`);
    void d.dismiss();
  });
  return { ctx, page };
}
const go = async (page, route, wait = 1800) => {
  await page.goto(`${consoleUrl}#/${route}`);
  await page.waitForTimeout(wait);
};
const mainText = async (page) => (await page.locator("#main").innerText()).replace(/\s+/g, " ");
async function runAxe(page, where) {
  await page.addScriptTag({ content: axe });
  const violations = await page.evaluate(async () => (await window.axe.run(document)).violations.map((v) => `${v.id} x${v.nodes.length} (${v.nodes[0].target})`));
  for (const v of violations) fail(where, `axe: ${v}`);
}
async function noMarkup(page, where) {
  const ran = await page.evaluate(() => [window.__xss ?? null, document.querySelectorAll("#root script, #root img[src='x'], #root svg[onload], #root [onerror]").length]);
  if (ran[0] !== null || ran[1] > 0) fail(where, `API text ran as markup: ${JSON.stringify(ran)}`);
  const js = await page.$$eval("a[href]", (as) => as.map((a) => a.getAttribute("href")).filter((h) => /^\s*javascript:/i.test(h)));
  if (js.length) fail(where, `javascript: link rendered: ${js[0]}`);
}

try {
  // 1. Every view, in every way the Core can fail before it ever answered:
  //    the view keeps its heading and the fault is accessible.
  for (const [fault, rules] of [
    ["401", [["/api/", "401"], ["/metrics", "401"], ["/manifests", "401"]]],
    ["500", [["/", "500"]]],
    ["not JSON", [["/", "notjson"]]],
    ["down", [["/", "down"]]],
  ]) {
    proxy.set(...rules);
    for (const opts of [DESKTOP, PHONE]) {
      const { ctx, page } = await open(proxy.base, opts);
      for (const [view, title] of Object.entries(TITLES)) {
        const where = `${fault}/${opts === PHONE ? "phone" : "desktop"}/${view}`;
        await go(page, view);
        const h1 = await page.locator("main h1").allInnerTexts();
        if (h1.length !== 1 || h1[0].trim() !== title) fail(where, `the view's heading is ${JSON.stringify(h1)}, not "${title}"`);
        if (!(await page.locator("main .fault").count())) fail(where, "no fault is shown");
        if (await page.getByText(/failed to draw/).count()) fail(where, "the error boundary caught a render failure");
        await runAxe(page, where);
      }
      await ctx.close();
    }
  }

  // 2. /metrics answered by something that is not the Core's exposition (a
  //    proxy's sign-in page): the bypass counters were not read.
  proxy.set(["/metrics", "html"]);
  {
    const { ctx, page } = await open(proxy.base);
    await go(page, "overview", 2500);
    if (!/Bypass signals: unknown/.test(await mainText(page))) fail("metrics-html/overview", "the bypass band does not say the counters are unknown");
    await go(page, "system", 2500);
    const meta = await page.locator("section", { has: page.locator("h2", { hasText: "Bypass signals" }) }).locator(".section-meta").innerText().catch(() => "");
    if (/clear/i.test(meta)) fail("metrics-html/system", `bypass signals drawn "${meta.trim()}" with every counter unread`);
    await runAxe(page, "metrics-html/system");
    await ctx.close();
  }

  // 3. /metrics that has not answered yet: "not read yet", not silence
  //    (silence is what "all clear" looks like).
  proxy.set(["/metrics", "hang"]);
  {
    const { ctx, page } = await open(proxy.base);
    await go(page, "overview", 2500);
    if (!/Bypass signals: not read yet/.test(await mainText(page))) fail("metrics-pending/overview", "nothing says the bypass counters have not been read");
    await runAxe(page, "metrics-pending/overview");
    await ctx.close();
  }

  // 4. Nothing has answered yet: no figure claims a window it has not seen.
  proxy.set(["/", "hang"]);
  {
    const { ctx, page } = await open(proxy.base);
    for (const view of ["overview", "verifications"]) {
      await go(page, view, 1500);
      const text = await mainText(page);
      if (/\ball 0\b|\blast 0\b/.test(text)) fail(`loading/${view}`, `a figure claims a window before anything loaded: "${text.match(/[^.]{0,30}\ball 0\b/)?.[0]}"`);
    }
    await ctx.close();
  }

  // 5. An empty trail: no mean of nothing.
  proxy.set(["/api/", "empty"]);
  {
    const { ctx, page } = await open(proxy.base);
    await go(page, "verifications", 2500);
    const mean = await page.locator(".figure", { hasText: "Mean confidence" }).innerText().catch(() => "");
    if (/0\.00/.test(mean)) fail("empty/verifications", `mean confidence over no verdicts drawn as "${mean.replace(/\s+/g, " ")}"`);
    await ctx.close();
  }

  // 6. The Core stops mid-session: the last good data stays, under a banner,
  //    and nothing calls the silent Core "Operational".
  proxy.set();
  {
    const { ctx, page } = await open(proxy.base);
    await go(page, "system", 2500);
    proxy.set(["/", "down"]);
    await page.waitForTimeout(7000);
    if (!(await page.getByText(/Showing the last good data/).count())) fail("stopped/system", "no stale-data banner");
    const status = await page.locator(".figure", { hasText: "Status" }).first().innerText();
    if (/Operational/.test(status)) fail("stopped/system", `a Core that stopped answering is drawn "${status.replace(/\s+/g, " ")}"`);
    await runAxe(page, "stopped/system");
    await ctx.close();
  }

  // 7. Hostile strings in every field the console draws: inert text.
  proxy.set(["/", "hostile"]);
  {
    const { ctx, page } = await open(proxy.base);
    for (const view of [...Object.keys(TITLES), "programs/11111111111111111111111111111111", "graph/11111111111111111111111111111111"]) {
      await go(page, view, 2500);
      if (view.startsWith("programs/")) await page.locator("details.ix summary").first().click();
      await noMarkup(page, `hostile/${view}`);
    }
    await page.keyboard.press("Control+k");
    await page.keyboard.type("Sys");
    await page.waitForTimeout(400);
    await noMarkup(page, "hostile/palette");
    await ctx.close();
  }
  proxy.set();

  // 8. The connection test reports on the address it tested, not on
  //    whatever is in the field afterwards.
  {
    const { ctx, page } = await open(coreBase);
    await go(page, "connect", 800);
    await page.getByRole("button", { name: "Test connection" }).click();
    await page.locator(".report").waitFor();
    await page.fill("#core-base", "http://127.0.0.1:9");
    await page.waitForTimeout(300);
    if (/Core reached/.test((await page.locator(".report").allInnerTexts()).join(" "))) fail("connect/edited", "a report for the previous address is shown beside the new one");
    // A slow test that is overtaken by an edit is dropped when it lands.
    proxy.set(["/health", "slow"]);
    await page.fill("#core-base", proxy.base);
    await page.getByRole("button", { name: "Test connection" }).click();
    await page.waitForTimeout(300);
    await page.fill("#core-base", coreBase);
    await page.waitForTimeout(5000);
    if (await page.locator(".report").count()) fail("connect/overtaken", `a test of ${proxy.base} reported beside ${coreBase}: ${(await page.locator(".report").innerText()).replace(/\s+/g, " ")}`);
    proxy.set();
    // Forget key: the key is gone from both storages, and the banner does
    // not claim a stored key was rejected.
    await page.fill("#core-base", coreBase);
    await page.getByRole("button", { name: "Forget key" }).click();
    const stored = await page.evaluate(() => [localStorage.getItem("graphite.key"), sessionStorage.getItem("graphite.key")]);
    if (stored.some((s) => s !== null)) fail("connect/forget", `a key is still stored: ${JSON.stringify(stored)}`);
    await go(page, "verifications", 2500);
    if (/rejected the key stored in this browser/.test(await mainText(page))) fail("connect/forget", "the banner blames a stored key after the key was forgotten");
    await runAxe(page, "connect/forget");
    await ctx.close();
  }

  // 9. Switching Core while the old one is still answering: none of its
  //    verdicts survive the switch, not even one that lands after it.
  {
    const history = await fetch(`${coreBase}/api/confidence-history`, { headers: key ? { Authorization: `Bearer ${key}` } : {} }).then((r) => r.json());
    const ids = history.series.map((p) => p.audit_trail_id);
    const { ctx, page } = await open(proxy.base);
    await go(page, "verifications", 2500);
    proxy.set(["/api/confidence-history", "slow"]);
    await page.waitForTimeout(5500); // a poll to the old Core is now in flight
    await go(page, "connect", 500);
    await page.fill("#core-base", coreB.base);
    await page.getByRole("button", { name: "Save and use" }).click();
    await go(page, "verifications", 6000);
    const text = await mainText(page);
    const leaked = ids.filter((id) => text.includes(id.slice(0, 6)) && text.includes(id.slice(-4)));
    if (leaked.length) fail("switch", `the previous Core's verdicts are on screen: ${leaked.join(", ")}`);
    if (!/No verifications yet/.test(text)) fail("switch", "the new Core's empty trail is not what is shown");
    proxy.set();
    await ctx.close();
  }

  // 10. Verifications on the real Core: a bound verdict shows its digest;
  //     the call graph's labels stay on the canvas; a detail pane holds
  //     focus and gives it back.
  {
    const history = await fetch(`${coreBase}/api/confidence-history`, { headers: key ? { Authorization: `Bearer ${key}` } : {} }).then((r) => r.json());
    const bound = history.series.filter((p) => p.transaction_sha256);
    for (const opts of [DESKTOP, PHONE]) {
      const size = opts === PHONE ? "phone" : "desktop";
      const { ctx, page } = await open(coreBase, opts);
      await go(page, "verifications", 2500);
      const text = await mainText(page);
      for (const p of bound) {
        if (!text.includes(p.transaction_sha256.slice(0, 6))) fail(`${size}/verifications`, `${p.audit_trail_id} is bound to bytes; its digest is not on screen`);
      }
      await runAxe(page, `${size}/verifications`);
      if (opts === DESKTOP) {
        await go(page, "graph", 2500);
        const outside = await page.$$eval(".graph-canvas", (svgs) => {
          const svg = svgs[0];
          if (!svg) return ["no canvas"];
          const box = svg.getBoundingClientRect();
          return [...svg.querySelectorAll(".node-label")]
            .filter((t) => {
              const r = t.getBoundingClientRect();
              return r.left < box.left - 0.5 || r.right > box.right + 0.5;
            })
            .map((t) => t.textContent);
        });
        if (outside.length) fail("desktop/graph", `${outside.length} label(s) drawn outside the canvas, e.g. "${outside[0]}"`);

        await go(page, "programs", 2500);
        const link = page.locator("table.data a.cell-link").first();
        await link.focus();
        await page.keyboard.press("Enter");
        await page.waitForTimeout(800);
        for (let i = 0; i < 40; i++) await page.keyboard.press("Tab");
        if (!(await page.evaluate(() => !!document.activeElement?.closest(".detail")))) fail("desktop/programs", "Tab left the open detail pane");
        await runAxe(page, "desktop/programs (detail open)");
        await page.keyboard.press("Escape");
        await page.waitForTimeout(400);
        if (await page.locator(".detail").count()) fail("desktop/programs", "Escape did not close the detail pane");
        const back = await page.evaluate(() => document.activeElement?.classList.contains("cell-link") ?? false);
        if (!back) fail("desktop/programs", "focus did not return to the row that opened the pane");
      }
      await ctx.close();
    }
  }
} finally {
  await browser.close();
  await proxy.close();
  await coreB.close();
}

if (failures.length) {
  console.error(`console states: ${failures.length} failure(s)`);
  for (const f of failures) console.error(`  ${f}`);
  process.exit(1);
}
console.log("console states: faults, stale, hostile, switching and focus clean, axe included");
