// npm advisory gate (A6-05).
//
//   npm audit --json > audit.json      # exit status deliberately not used
//   node gate.mjs audit.json <package>.allow
//
// Fails when the lockfile carries a HIGH or CRITICAL advisory that is not
// listed in the package's allowlist, when a listed advisory is no longer
// reported (the list must be pruned in the same change that fixes it), and
// when the report is missing or is an npm error instead of an audit.
//
// Why a list and not `npm audit --audit-level=high`: the SAK bridge's tree
// carries dozens of known high/critical advisories with no non-breaking fix, so a
// plain level gate would be red on every commit, and a red gate that everyone
// ignores is no gate. The list names each known advisory; a NEW one fails the
// build the day it is published. The list can only be shortened by fixing
// something, and lengthened only in a reviewed diff.
import { readFileSync } from "node:fs";

const [reportPath, allowPath] = process.argv.slice(2);
if (!reportPath || !allowPath) {
  console.error("usage: node gate.mjs <npm-audit.json> <allowlist>");
  process.exit(2);
}

function fail(msg) {
  console.log(`::error::${msg}`);
  process.exitCode = 1;
}

let report;
try {
  report = JSON.parse(readFileSync(reportPath, "utf8"));
} catch (e) {
  fail(`npm audit did not produce a JSON report (${e.message})`);
  process.exit(1);
}
// A registry or network failure yields {"error": ...} with no report. That is
// "not scanned", not "clean": fail closed.
if (report.error || report.auditReportVersion !== 2 || !report.metadata?.vulnerabilities) {
  fail(`npm audit returned no usable report: ${JSON.stringify(report.error ?? report).slice(0, 500)}`);
  process.exit(1);
}

const GATED = new Set(["high", "critical"]);
const found = new Map(); // GHSA id -> {severity, name, range, title}
for (const vuln of Object.values(report.vulnerabilities)) {
  for (const via of vuln.via) {
    // String entries point at another package's entry; the advisory itself is
    // an object and is recorded where it is defined.
    if (typeof via !== "object" || !GATED.has(via.severity)) continue;
    const id = String(via.url ?? "").split("/").pop();
    if (!id) {
      fail(`advisory without an id on ${via.name}: ${via.title}`);
      continue;
    }
    found.set(id, { severity: via.severity, name: via.name, range: via.range, title: via.title });
  }
}

const allowed = new Set(
  readFileSync(allowPath, "utf8")
    .split(/\r?\n/)
    .map((l) => l.replace(/#.*/, "").trim())
    .filter(Boolean)
    .map((l) => l.split(/\s+/)[0]),
);

for (const [id, a] of found) {
  if (!allowed.has(id)) {
    fail(`NEW ${a.severity} advisory ${id} in ${a.name} ${a.range}: ${a.title}`);
  }
}
for (const id of allowed) {
  if (!found.has(id)) {
    fail(`${id} is allowlisted but no longer reported at high/critical; remove it from ${allowPath}`);
  }
}

const counts = report.metadata.vulnerabilities;
console.log(
  `npm audit: ${counts.critical} critical, ${counts.high} high, ${counts.moderate} moderate, ` +
    `${counts.low} low (by package); ${found.size} distinct high/critical advisories, ` +
    `${allowed.size} allowlisted`,
);
if (process.exitCode) {
  console.log("advisory gate FAILED");
} else {
  console.log("advisory gate passed: every high/critical advisory is a known, listed one");
}
