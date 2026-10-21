// Round 29 (audit 2026-10-20, D1/D4): totals come from the server's totals,
// window figures say which window, and descriptive approvals are their own
// kind. Run: npm test.
import { test } from "node:test";
import assert from "node:assert/strict";
import { countWindow, refusalTotals, trailTotals, verdictKind, verdictTone, windowLabel } from "./figures.ts";
import type { ConfidencePoint, PolicyViolation, ErrorViolation } from "./api";

const point = (i: number, approved: boolean, bound: boolean): ConfidencePoint => ({
  timestamp: `2026-10-20T00:00:${String(i % 60).padStart(2, "0")}Z`,
  confidence: 0.9,
  approved,
  program_id: "11111111111111111111111111111111",
  audit_trail_id: `id${i}`,
  transaction_sha256: bound ? "ab".repeat(32) : null,
});

const violation = (i: number): PolicyViolation => ({
  timestamp: "2026-10-20T00:00:00Z",
  program_id: "p",
  protocol_name: "P",
  instruction_name: "i",
  confidence: 0.1,
  policy_verdict: "Rejected",
  risk_status: "Blocked",
  audit_trail_id: `v${i}`,
});

const rejection = (): ErrorViolation => ({
  timestamp: "2026-10-20T00:00:00Z",
  program_id: "",
  instruction_name: "",
  error: "bad",
  error_type: "BadRequest",
  status: 400,
});

test("a descriptive approval is not a green approval", () => {
  assert.equal(verdictKind(point(0, true, true)), "bound");
  assert.equal(verdictKind(point(1, true, false)), "descriptive");
  assert.equal(verdictKind({ approved: true }), "descriptive", "an older server omits the digest");
  assert.equal(verdictKind(point(2, false, false)), "refused");
  assert.notEqual(verdictTone("descriptive"), "pass");
  const series = [point(0, true, true), point(1, true, false), point(2, true, false), point(3, false, true)];
  assert.deepEqual(countWindow(series), { n: 4, bound: 1, descriptive: 2, refused: 1 });
});

test("whole-trail totals use the server's counts, not the capped windows", () => {
  // The Core returned its newest 500 verdicts of 12,000 and its newest 200
  // refusals of 3,000, plus 7 rejected requests; `count` = 3,000 + 7.
  const series = Array.from({ length: 500 }, (_, i) => point(i, i % 2 === 0, true));
  const violations = {
    violations: Array.from({ length: 200 }, (_, i) => violation(i)),
    error_violations: Array.from({ length: 7 }, rejection),
    count: 3_007,
  };
  const t = trailTotals({ series, count: 12_000 }, violations);
  assert.deepEqual(t, { verifications: 12_000, refused: 3_000, approved: 9_000 });
  assert.deepEqual(refusalTotals(violations), { refused: 3_000, rejected: 7, rejectedAtLeast: false });
  assert.equal(windowLabel(series.length, 12_000), "last 500");
  assert.equal(windowLabel(37, 37), "all 37");
});

test("rejections at the server's cap are a lower bound; explicit totals win", () => {
  const atCap = { violations: [], error_violations: Array.from({ length: 200 }, rejection), count: 200 };
  assert.deepEqual(refusalTotals(atCap), { refused: 0, rejected: 200, rejectedAtLeast: true });
  const explicit = { ...atCap, violation_count: 4, error_count: 950, count: 204 };
  assert.deepEqual(refusalTotals(explicit), { refused: 4, rejected: 950, rejectedAtLeast: false });
  // Polls landing a verdict apart never produce a negative approval total.
  assert.equal(trailTotals({ series: [], count: 3 }, { violations: [], error_violations: [], count: 4 }).approved, 0);
});
