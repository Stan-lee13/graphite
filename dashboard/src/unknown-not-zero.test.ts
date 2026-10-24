// Round 36 (console audit against a live Core): a figure the console has
// not read is drawn as unknown, never as zero or as "clear". Run: npm test.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { BYPASS_COUNTERS, meanConfidence, readBypass, windowed, windowLabel } from "./figures.ts";
import { MANIFESTS_POLL_MS } from "./poll-state.ts";

const allZero = () => new Map(BYPASS_COUNTERS.map((m) => [m, 0]));

test("bypass counters missing from /metrics are unknown, not clear", () => {
  // A /metrics answered by a proxy's sign-in page parses to nothing.
  const empty = readBypass(new Map());
  assert.equal(empty.state, "unknown");
  assert.deepEqual(empty.missing, [...BYPASS_COUNTERS]);
  // A Core that exports some of them: still not clear.
  const partial = allZero();
  partial.delete("graphite_execution_discrepancies_total");
  assert.equal(readBypass(partial).state, "unknown");
  assert.deepEqual(readBypass(partial).missing, ["graphite_execution_discrepancies_total"]);
  // Every counter read and zero: clear.
  assert.deepEqual(readBypass(allZero()), { state: "clear", hits: [], missing: [] });
});

test("bypass counters not read yet are unread; a non-zero one is an alarm even with others missing", () => {
  assert.equal(readBypass(null).state, "unread");
  const m = new Map([["graphite_lifecycle_events_on_blocked_total", 2]]);
  const r = readBypass(m);
  assert.equal(r.state, "alarm");
  assert.deepEqual(r.hits, [{ metric: "graphite_lifecycle_events_on_blocked_total", n: 2 }]);
  assert.equal(r.missing.length, BYPASS_COUNTERS.length - 1);
});

test("no window is claimed before one was read, and nothing is averaged over no verdicts", () => {
  assert.equal(windowed("Executable", null), "Executable");
  assert.equal(windowed("Executable", windowLabel(4, 4)), "Executable, all 4");
  assert.equal(meanConfidence([]), null);
  assert.equal(meanConfidence([{ confidence: 0.4 }, { confidence: 0.6 }]), 0.5);
});

test("every view polls /manifests (4.6 MB) at the one slow interval", () => {
  const dir = new URL("./views/", import.meta.url);
  let polls = 0;
  for (const f of readdirSync(dir).filter((f) => f.endsWith(".tsx"))) {
    const src = readFileSync(new URL(f, dir), "utf8");
    for (const m of src.matchAll(/usePolling\(\s*\(\)\s*=>\s*api\.manifests\(\),\s*([^)]+)\)/g)) {
      polls++;
      assert.equal(m[1].trim(), "MANIFESTS_POLL_MS", `${f} polls /manifests every ${m[1].trim()}`);
    }
  }
  assert.ok(polls >= 2, "the Programs and Call graph views both poll /manifests");
  assert.ok(MANIFESTS_POLL_MS >= 300_000);
});
