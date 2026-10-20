/**
 * What a framework tool reports to the model (W22, external review): the
 * verdict's scope, its transaction digest and residuals, and who refused.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { MAX_REASON_CHARS, redactReason, toolRefusalOf, toolResultOf } from "./tool-results.js";
import { ConfirmationDeclined, SubmissionOutcomeUnknown } from "./execution-lifecycle.js";
import { SwapRouteRefusal } from "./swap-instructions.js";
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

// Round 29 (audit 2026-10-20).
test("Round 29: new refusals map to who refused; an unknown submission carries its signature", () => {
  assert.equal(toolRefusalOf(new SwapRouteRefusal("dust")).refusedBy, "swap-route");
  assert.equal(toolRefusalOf(new ConfirmationDeclined("transfer", "declined")).refusedBy, "person");
  const unknown = toolRefusalOf(new SubmissionOutcomeUnknown("transfer", "SIG123", 9, "timeout", true));
  assert.equal(unknown.refusedBy, "submission-unknown");
  assert.equal(unknown.signature, "SIG123");
});

test("Info: a refusal's text reaches the model without secrets, and bounded", () => {
  const r = toolRefusalOf(
    new Error(
      "fetch https://user:pw@rpc.example.com/v1/?api-key=K3Y failed; Authorization: Bearer abc.def; token=t0k; " +
        "x".repeat(2000),
    ),
  );
  assert.equal(r.refusedBy, "error");
  for (const secret of ["K3Y", "pw@", "abc.def", "t0k", "/v1/"]) assert.ok(!r.reason!.includes(secret), secret);
  assert.match(r.reason!, /https:\/\/rpc\.example\.com/);
  assert.ok(r.reason!.length <= MAX_REASON_CHARS + 1);
  // The guard's own guidance survives: which form is accepted.
  const g = toolRefusalOf(new SpendPolicyRefusal("1 lamports exceeds the per-transfer cap of 0"));
  assert.match(g.reason!, /exceeds the per-transfer cap/);
  assert.equal(redactReason('A transfer is only built from "send <amount> SOL to <address>"'), 'A transfer is only built from "send <amount> SOL to <address>"');
});
