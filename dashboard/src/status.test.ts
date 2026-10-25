// Round 39 (dashboard audit against a live Core): what the console says
// about the Core's own state. Run: npm test.
import { test } from "node:test";
import assert from "node:assert/strict";
import { auditReading, coreLabel, coreState, persistenceReading, reachProblem } from "./status.ts";

// The /health a Round 38 Core sends (server.rs health_handler), trimmed.
const AUDIT = { enabled: true, writes_ok: 4, writes_failed: 0, active_bytes: 3277, archive_count: 0 };

test("R39-DASH-5: an audit trail /health does not report is not reported, never Off", () => {
  for (const audit of [undefined, null, "yes", {}, { enabled: "true" }]) {
    const r = auditReading({ audit: audit as never });
    assert.equal(r.value, "Not reported", JSON.stringify(audit));
    assert.doesNotMatch(r.sub ?? "", /not being recorded/);
  }
  // Benign control: a reported, disabled trail is Off, and says what that means.
  assert.deepEqual(auditReading({ audit: { enabled: false } }), { value: "Off", tone: "warn", sub: "verdicts are not being recorded" });
});

test("R39-DASH-5: a trail whose appends fail is not drawn green Writing", () => {
  const r = auditReading({ audit: { ...AUDIT, writes_failed: 3 } });
  assert.equal(r.value, "Failing");
  assert.equal(r.tone, "block");
  // Benign control: a healthy trail is Writing, with its size.
  assert.deepEqual(auditReading({ audit: AUDIT }), { value: "Writing", tone: "pass", sub: "3.2 KB active, 0 archived" });
  // A size the Core does not send is not drawn as 0 B.
  assert.equal(auditReading({ audit: { enabled: true } }).sub, "size not reported");
});

test("R39-DASH-5: graph persistence /health does not report is not reported; a failing one is not green", () => {
  assert.equal(persistenceReading({ graph_persistence: undefined }).value, "Not reported");
  assert.equal(persistenceReading({ graph_persistence: { enabled: false } }).value, "Off");
  const failing = persistenceReading({ graph_persistence: { enabled: true, snapshots_ok: 2, snapshots_failed: 1, last_error: "snapshot failed; the error is in the server log" } });
  assert.equal(failing.tone, "block");
  assert.equal(failing.sub, "snapshot failed; the error is in the server log");
  assert.deepEqual(persistenceReading({ graph_persistence: { enabled: true, snapshots_ok: 7, snapshots_failed: 0 } }), { value: "7", tone: "pass", sub: "snapshots written" });
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
