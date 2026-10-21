// Tests for the npm advisory gate (gate.mjs). Run: node --test .github/npm-audit/
//
// The gate is the only thing between a new advisory and a green CI, so its own
// failure modes are pinned here: an unlisted advisory, a stale entry, an
// unusable report and an allowlist entry past (or missing) its review date
// must each fail it; a report whose every advisory is listed and current
// passes.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const GATE = join(dirname(fileURLToPath(import.meta.url)), "gate.mjs");
const TODAY = "2026-10-21";

function advisory(id, name, severity = "moderate") {
  return { source: 1, name, title: `${name} issue`, url: `https://github.com/advisories/${id}`, severity, range: "<9" };
}

function report(advisories) {
  const vulnerabilities = {};
  for (const a of advisories) {
    vulnerabilities[a.name] = { name: a.name, severity: a.severity, via: [a] };
  }
  return {
    auditReportVersion: 2,
    vulnerabilities,
    metadata: { vulnerabilities: { info: 0, low: 0, moderate: advisories.length, high: 0, critical: 0, total: advisories.length } },
  };
}

function run(reportJson, allowText, today = TODAY) {
  const dir = mkdtempSync(join(tmpdir(), "gate-"));
  const r = join(dir, "audit.json");
  const a = join(dir, "pkg.allow");
  writeFileSync(r, typeof reportJson === "string" ? reportJson : JSON.stringify(reportJson));
  writeFileSync(a, allowText);
  const out = spawnSync(process.execPath, [GATE, r, a], { env: { ...process.env, GATE_TODAY: today }, encoding: "utf8" });
  return { status: out.status, out: out.stdout + out.stderr };
}

const ID = "GHSA-528h-pc64-c93x";

test("a clean report with an empty allowlist passes", () => {
  const r = run(report([]), "# nothing\n");
  assert.equal(r.status, 0, r.out);
});

test("an unlisted advisory fails", () => {
  const r = run(report([advisory(ID, "stream-json")]), "# nothing\n");
  assert.notEqual(r.status, 0);
  assert.match(r.out, /NEW moderate advisory/);
});

test("a listed advisory with a current review date passes", () => {
  const r = run(report([advisory(ID, "stream-json")]), `${ID}@stream-json  review-by:2027-01-20  # why\n`);
  assert.equal(r.status, 0, r.out);
});

test("an entry past its review date fails", () => {
  const r = run(report([advisory(ID, "stream-json")]), `${ID}@stream-json  review-by:2026-10-20  # why\n`);
  assert.notEqual(r.status, 0);
  assert.match(r.out, /due for review on 2026-10-20/);
});

test("an entry with no review date fails", () => {
  const r = run(report([advisory(ID, "stream-json")]), `${ID}@stream-json  # why\n`);
  assert.notEqual(r.status, 0);
  assert.match(r.out, /needs exactly one review-by/);
});

test("a review date more than 120 days ahead fails", () => {
  const r = run(report([advisory(ID, "stream-json")]), `${ID}@stream-json  review-by:2027-06-01  # why\n`);
  assert.notEqual(r.status, 0);
  assert.match(r.out, /more than 120 days ahead/);
});

test("a bare GHSA id (any package) is refused", () => {
  const r = run(report([advisory(ID, "stream-json")]), `${ID}  review-by:2027-01-20\n`);
  assert.notEqual(r.status, 0);
  assert.match(r.out, /one named package only/);
});

test("a listed advisory that is no longer reported fails (prune it)", () => {
  const r = run(report([]), `${ID}@stream-json  review-by:2027-01-20\n`);
  assert.notEqual(r.status, 0);
  assert.match(r.out, /no longer reported/);
});

test("an npm error instead of a report fails closed", () => {
  const r = run({ error: { code: "ENOTFOUND", summary: "registry unreachable" } }, "");
  assert.notEqual(r.status, 0);
  assert.match(r.out, /no usable report/);
});

test("output that is not JSON fails closed", () => {
  const r = run("npm ERR! something", "");
  assert.notEqual(r.status, 0);
});
