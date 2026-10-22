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
  assert.equal(verdictKind(point(1, true, false)), "descriptive");
  assert.equal(verdictKind({ approved: true }), "descriptive", "an older server omits the digest");
  assert.equal(verdictKind(point(2, false, false)), "refused");
  assert.notEqual(verdictTone("descriptive"), "pass");
});

// Round 30 (shared execution contract): green means executable, and only
// the Core's own "executable_approved" + `executable: true` earns it.
const decided = (decision: string | undefined, executable: boolean | undefined, bound = true, approved = true): ConfidencePoint => ({
  ...point(9, approved, bound),
  decision,
  executable,
});

test("only an executable decision is drawn as executable", () => {
  assert.equal(verdictKind(decided("executable_approved", true)), "executable");
  assert.equal(verdictTone(verdictKind(decided("executable_approved", true))), "pass");
  // A bound approval the Core judged without a simulation (no RPC):
  assert.equal(verdictKind(decided("analysis_only", false)), "analysis");
  // A bound approval from a Core that predates the contract: not green.
  assert.equal(verdictKind(point(0, true, true)), "unreported");
  for (const k of ["analysis", "unreported", "descriptive", "inconclusive"] as const) {
    assert.notEqual(verdictTone(k), "pass", k);
  }
});

test("a disagreeing or unknown decision fails closed", () => {
  assert.equal(verdictKind(decided("executable_approved", false)), "analysis", "decision and flag disagree");
  assert.equal(verdictKind(decided("executable_approved", undefined)), "analysis", "flag missing");
  assert.equal(verdictKind(decided("EXECUTABLE_APPROVED", true)), "analysis", "case variant");
  assert.equal(verdictKind(decided("approved", true)), "analysis", "unknown value");
  // executable with no bytes is still descriptive: nothing constrains the signature.
  assert.equal(verdictKind(decided("executable_approved", true, false)), "descriptive");
  assert.equal(verdictKind(decided("inconclusive", false, true, false)), "inconclusive");
  assert.equal(verdictKind(decided("blocked", false, true, false)), "refused");
});

test("window counts keep executable apart from every other approval", () => {
  const series = [
    decided("executable_approved", true),
    decided("analysis_only", false),
    point(0, true, true),
    point(1, true, false),
    point(2, true, false),
    point(3, false, true),
    decided("inconclusive", false, true, false),
  ];
  assert.deepEqual(countWindow(series), {
    n: 7,
    executable: 1,
    notExecutable: 4,
    descriptive: 2,
    refused: 1,
    inconclusive: 1,
  });
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
