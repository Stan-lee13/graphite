// Round 39 (dashboard audit against a live Core): what the console says
// about the Core's own state. Run: npm test.
import { test } from "node:test";
import assert from "node:assert/strict";
import { anchorsFailing, auditReading, chainHead, coreLabel, coreState, persistenceReading, reachProblem } from "./status.ts";

// The /health a Core sends (server.rs health_handler), trimmed. Since audit
// A018 it carries no counter and no size: those stepped with every verdict,
// and /health answers anyone. They are read from /metrics.
const AUDIT = { enabled: true, integrity: "corruption_evident" as const };
const METRICS = new Map([
  ["graphite_audit_writes_ok_total", 4],
  ["graphite_audit_writes_failed_total", 0],
  ["graphite_audit_active_bytes", 3277],
  ["graphite_audit_archive_count", 0],
  ["graphite_graph_snapshots_ok_total", 7],
  ["graphite_graph_snapshots_failed_total", 0],
]);

test("R39-DASH-5: an audit trail /health does not report is not reported, never Off", () => {
  for (const audit of [undefined, null, "yes", {}, { enabled: "true" }]) {
    const r = auditReading({ audit: audit as never }, METRICS);
    assert.equal(r.value, "Not reported", JSON.stringify(audit));
    assert.doesNotMatch(r.sub ?? "", /not being recorded/);
  }
  // Benign control: a reported, disabled trail is Off, and says what that means.
  assert.deepEqual(auditReading({ audit: { enabled: false } }, METRICS), { value: "Off", tone: "warn", sub: "verdicts are not being recorded" });
});

test("R39-DASH-5: a trail whose appends fail is not drawn green Writing", () => {
  // The count, from /metrics.
  const r = auditReading({ audit: AUDIT }, new Map([...METRICS, ["graphite_audit_writes_failed_total", 3]]));
  assert.equal(r.value, "Failing");
  assert.equal(r.tone, "block");
  assert.match(r.sub ?? "", /3 append\(s\) failed/);
  // The degraded reason alone, before /metrics answers (or where it is not
  // routed), is Failing too: never green on a reason the Core gave.
  for (const m of [null, undefined, new Map<string, number>()]) {
    const f = auditReading({ audit: AUDIT, degraded_reasons: ["audit_writes_failed"] }, m);
    assert.equal(f.value, "Failing");
    assert.equal(f.tone, "block");
  }
  // Benign control: a healthy trail is Writing, with its size from /metrics.
  assert.deepEqual(auditReading({ audit: AUDIT }, METRICS), { value: "Writing", tone: "pass", sub: "3.2 KB active, 0 archived" });
  // A size /metrics does not give is not drawn as 0 B.
  assert.equal(auditReading({ audit: AUDIT }, null).sub, "size not reported");
  assert.equal(auditReading({ audit: AUDIT }, new Map()).sub, "size not reported");
});

test("Audit A018: the readings take nothing from /health's former counters", () => {
  // A Core from before A018 still sends them; they are not what is drawn.
  const old = { ...AUDIT, writes_failed: 0, active_bytes: 99, archive_count: 9 } as never;
  assert.equal(auditReading({ audit: old }, METRICS).sub, "3.2 KB active, 0 archived");
  const snap = { enabled: true, snapshots_ok: 99, snapshots_failed: 0 } as never;
  assert.equal(persistenceReading({ graph_persistence: snap }, METRICS).value, "7");
});

test("Audit A018: anchor failures and the chain head come from /metrics, a failure also from /health's reason", () => {
  assert.equal(anchorsFailing({}, METRICS), null);
  assert.equal(anchorsFailing({}, new Map([["graphite_audit_anchor_writes_failed_total", 2]])), 2);
  assert.equal(anchorsFailing({ degraded_reasons: ["audit_anchor_failed"] }, null), true);
  assert.equal(chainHead(new Map([["graphite_audit_chain_head_seq", 41]])), 41);
  assert.equal(chainHead(METRICS), null);
  assert.equal(chainHead(null), null);
});

test("R39-DASH-5: graph persistence /health does not report is not reported; a failing one is not green", () => {
  assert.equal(persistenceReading({ graph_persistence: undefined }, METRICS).value, "Not reported");
  assert.equal(persistenceReading({ graph_persistence: { enabled: false } }, METRICS).value, "Off");
  const failing = persistenceReading(
    { graph_persistence: { enabled: true, last_error: "snapshot failed; the error is in the server log" } },
    new Map([...METRICS, ["graphite_graph_snapshots_failed_total", 1]]),
  );
  assert.equal(failing.tone, "block");
  assert.equal(failing.sub, "snapshot failed; the error is in the server log");
  // The degraded reason alone is Failing too.
  const byReason = persistenceReading({ graph_persistence: { enabled: true }, degraded_reasons: ["graph_snapshot_failed"] }, null);
  assert.equal(byReason.value, "Failing");
  assert.equal(byReason.tone, "block");
  assert.deepEqual(persistenceReading({ graph_persistence: { enabled: true } }, METRICS), { value: "7", tone: "pass", sub: "snapshots written" });
  assert.deepEqual(persistenceReading({ graph_persistence: { enabled: true } }, null), { value: "On", tone: "pass", sub: "count not reported" });
});

test("R39-DASH-6: only no answer at all gets the CORS advice; an answer says what it was", () => {
  assert.equal(reachProblem("network", "No response from the Core.").corsHint, true);
  for (const kind of ["server", "ratelimited", "unavailable", "unauthorized", "malformed", "insecure"] as const) {
    const r = reachProblem(kind, `the ${kind} message`);
    assert.equal(r.corsHint, false, kind);
    assert.equal(r.text, `the ${kind} message`);
    assert.doesNotMatch(r.text, /CORS/);
  }
});

test("R39-DASH-6: a /health that answered an error is not an unreachable Core", () => {
  const base = { health: null, keyedError: null };
  assert.equal(coreState({ ...base, healthError: "network" }), "down");
  assert.equal(coreState({ ...base, healthError: "insecure" }), "down");
  for (const k of ["server", "ratelimited", "unavailable", "malformed"] as const) {
    assert.equal(coreState({ ...base, healthError: k }), "erroring", k);
  }
  assert.equal(coreLabel("erroring"), "Core answering with errors");
  // The rest of the ladder is unchanged.
  assert.equal(coreState({ healthError: null, health: null, keyedError: null }), "connecting");
  assert.equal(coreState({ healthError: null, health: { degraded: false }, keyedError: "unauthorized" }), "unauthorized");
  assert.equal(coreState({ healthError: null, health: { degraded: true }, keyedError: null }), "degraded");
  assert.equal(coreState({ healthError: null, health: { degraded: false }, keyedError: "server" }), "ok");
});

test("Audit A062: a /health figure is never green while /health is not answering", async () => {
  const { whileSilent } = await import("./status.ts");
  const writing = { value: "Writing", tone: "pass" as const, sub: "12 appends" };
  assert.deepEqual(whileSilent(writing, false), writing);
  const silent = whileSilent(writing, true);
  assert.equal(silent.tone, "warn");
  assert.equal(silent.value, "Writing");
  assert.match(silent.sub ?? "", /as of the last answer/);
  const failing = { value: "Failing", tone: "block" as const };
  assert.deepEqual(whileSilent(failing, true), failing);
});
