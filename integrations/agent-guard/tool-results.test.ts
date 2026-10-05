/**
 * What a framework tool reports to the model (W22, external review): the
 * verdict's scope, its transaction digest and residuals, and who refused.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { toolRefusalOf, toolResultOf } from "./tool-results.js";
import { ResidualPolicyRefusal } from "./residual-policy.js";
import { SpendPolicyRefusal } from "./spend-policy.js";
import { BLOCKED_VERDICT } from "./loopback-mocks.js";
import type { ExecutionOutcome } from "./guard.js";

const DIGEST = "ab".repeat(32);

function outcome(scope: unknown, executed = false): ExecutionOutcome {
  return {
    executed,
    verifiedExecution: executed,
    verification: { ...BLOCKED_VERDICT, scope } as unknown as ExecutionOutcome["verification"],
    ...(executed
      ? {
          signature: "sig",
          lifecycle: { confirmed: true, acceptedUnobserved: ["simulation"] } as unknown as ExecutionOutcome["lifecycle"],
        }
      : {}),
  } as ExecutionOutcome;
}

test("a tool result carries the verdict's scope, digest, residuals and manifest version", () => {
  const scope = {
    kind: "artifact_bound",
    transaction_sha256: DIGEST,
    unobserved: ["the program's own semantics"],
    unobserved_codes: ["program_semantics"],
  };
  const r = toolResultOf(outcome(scope, true));
  assert.equal(r.executed, true);
  assert.equal(r.verdict?.scope, "artifact_bound");
  assert.equal(r.verdict?.transactionSha256, DIGEST);
  assert.deepEqual(r.verdict?.unobservedCodes, ["program_semantics"]);
  assert.equal(r.verdict?.manifestVersion, "1.0.0");
  assert.deepEqual(r.acceptedUnobserved, ["simulation"]);
});

test("a descriptive or unscoped verdict says so and carries no digest", () => {
  const d = toolResultOf(outcome({ kind: "descriptive", unobserved: ["x"], unobserved_codes: ["no_artifact"] }));
  assert.equal(d.refusedBy, "graphite");
  assert.equal(d.verdict?.scope, "descriptive");
  assert.equal(d.verdict?.transactionSha256, undefined);
  assert.equal(toolResultOf(outcome(undefined)).verdict?.scope, "unscoped");
});

test("each refusal names who refused", () => {
  assert.equal(toolRefusalOf(new ResidualPolicyRefusal("no")).refusedBy, "residual-policy");
  assert.equal(toolRefusalOf(new SpendPolicyRefusal("no")).refusedBy, "spend-policy");
  assert.equal(toolRefusalOf(new Error("boom")).refusedBy, "error");
});
