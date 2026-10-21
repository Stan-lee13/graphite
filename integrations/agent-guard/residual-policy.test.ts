/**
 * Round 9: the residual policy is the gate that "surfaced, not gated" was not.
 *
 * Every case here is a verdict that is APPROVED and ARTIFACT-BOUND — the two
 * things the bridge used to gate on — and differs only in what it did not
 * observe. Before this policy, all of them executed.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { ACCEPT_UNOBSERVED_ENV, ResidualPolicy, ResidualPolicyRefusal } from "./residual-policy.js";
import {
  INHERENT_UNOBSERVED,
  UNOBSERVED_CODES,
  type ArtifactBoundScope,
  type UnobservedCode,
  type VerificationScope,
} from "../../sdk/typescript/src/types.js";

const DIGEST = "e32950f70a7f63c5d34695964ac376fc53b6727806c26269639ee27b2bc3a886";

function bound(codes: UnobservedCode[], prose?: string[]): ArtifactBoundScope {
  return {
    kind: "artifact_bound",
    transaction_sha256: DIGEST,
    transaction_bytes: 215,
    simulated: true,
    unobserved: prose ?? codes.map((c) => `prose for ${c}`),
    unobserved_codes: codes,
  };
}

const INHERENT: UnobservedCode[] = ["program_semantics", "inner_instructions"];

test("the inherent residuals are exactly the two the core marks inherent", () => {
  assert.deepEqual([...INHERENT_UNOBSERVED].sort(), [...INHERENT].sort());
  // And they are in the code list, as is everything else the core emits.
  for (const c of INHERENT) assert.ok(UNOBSERVED_CODES.includes(c));
  assert.equal(UNOBSERVED_CODES.length, 15);
});

test("a fully observed artifact-bound verdict passes the default policy", () => {
  const policy = new ResidualPolicy();
  const d = policy.assertExecutable(bound(INHERENT), "t");
  assert.deepEqual(d.accepted, []);
  assert.deepEqual(d.inherent, INHERENT);
});

test("every non-inherent residual refuses under the default policy, naming the code and the prose", () => {
  const policy = new ResidualPolicy();
  for (const code of UNOBSERVED_CODES) {
    if (INHERENT_UNOBSERVED.has(code)) continue;
    const scope = bound([...INHERENT, code], [...INHERENT.map((c) => c), `WHY ${code} WAS NOT OBSERVED`]);
    assert.throws(
      () => policy.assertExecutable(scope, "t"),
      (e: Error) =>
        e.message.includes(code) &&
        e.message.includes(`WHY ${code} WAS NOT OBSERVED`) &&
        e.message.includes(ACCEPT_UNOBSERVED_ENV) &&
        e.message.includes("ABORTING"),
      `${code} must refuse by default`,
    );
  }
});

test("an accepted residual executes and is reported as accepted", () => {
  const policy = new ResidualPolicy(["no_state_diff"]);
  const d = policy.assertExecutable(bound([...INHERENT, "no_state_diff"]), "t");
  assert.deepEqual(d.accepted, ["no_state_diff"]);
  assert.deepEqual(policy.accepts(), ["no_state_diff"]);
  // Accepting one does not accept another.
  assert.throws(() => policy.assertExecutable(bound([...INHERENT, "not_simulated"]), "t"), /not_simulated/);
  // Two residuals, one accepted: still refused, naming the other one.
  assert.throws(
    () => policy.assertExecutable(bound([...INHERENT, "no_state_diff", "lookup_tables_unresolved"]), "t"),
    (e: Error) => e.message.includes("lookup_tables_unresolved") && !e.message.includes("- no_state_diff"),
  );
});

test("the accepted list is validated at construction — a typo is an error, not a silent no-op", () => {
  assert.throws(() => new ResidualPolicy(["no_state_dif"]), /not an unobserved code/);
  assert.throws(() => new ResidualPolicy(["NO_STATE_DIFF"]), /not an unobserved code/);
  // Whitespace and empty entries from a comma-separated env are tolerated.
  const p = new ResidualPolicy([" no_state_diff ", "", "program_semantics"]);
  assert.deepEqual(p.accepts(), ["no_state_diff"]);
});

test("fromEnv reads GRAPHITE_ACCEPT_UNOBSERVED and defaults to inherent-only", () => {
  assert.deepEqual(ResidualPolicy.fromEnv({}).accepts(), []);
  assert.deepEqual(
    ResidualPolicy.fromEnv({ [ACCEPT_UNOBSERVED_ENV]: "privileges_from_caller,no_state_diff" }).accepts(),
    ["no_state_diff", "privileges_from_caller"],
  );
  assert.throws(() => ResidualPolicy.fromEnv({ [ACCEPT_UNOBSERVED_ENV]: "everything" }), /not an unobserved code/);
});

test("a descriptive or absent scope refuses regardless of policy", () => {
  const policy = new ResidualPolicy([...UNOBSERVED_CODES]);
  const descriptive: VerificationScope = {
    kind: "descriptive",
    unobserved: ["no artifact"],
    unobserved_codes: ["no_artifact"],
  };
  assert.throws(() => policy.assertExecutable(descriptive, "t"), /descriptive, not artifact_bound/);
  assert.throws(() => policy.assertExecutable(undefined, "t"), /unscoped, not artifact_bound/);
});

test("a server that reports no codes is refused: prose is not a decision", () => {
  const policy = new ResidualPolicy();
  const scope: ArtifactBoundScope = { ...bound(INHERENT), unobserved_codes: undefined };
  assert.throws(() => policy.assertExecutable(scope, "t"), /prose only/);
});

test("codes and prose must pair by position", () => {
  const policy = new ResidualPolicy();
  const scope = bound(INHERENT, ["only one line"]);
  assert.throws(() => policy.assertExecutable(scope, "t"), /malformed verdict/);
});

test("a code this bridge does not know is refused, even under a permissive policy", () => {
  const policy = new ResidualPolicy([...UNOBSERVED_CODES]);
  const scope = bound([...INHERENT, "something_new" as UnobservedCode]);
  assert.throws(() => policy.assertExecutable(scope, "t"), /unknown to this bridge/);
});

// Round 30 (G-01): the guard's own recomputation of the Core's decision. End
// to end, the SDK's validator refuses these responses first; this is the
// second layer, held on its own.
test("G-01: the guard refuses a decision its own recomputation contradicts, whatever the SDK let through", () => {
  const inherent = { approved: true, scope: bound(INHERENT) };
  const residual = { approved: true, scope: bound(["not_simulated", "program_semantics"]) };
  const cases: { name: string; policy: ResidualPolicy; verdict: Parameters<ResidualPolicy["assertExecutableVerdict"]>[0]; why: RegExp }[] = [
    { name: "unknown decision", policy: new ResidualPolicy(), verdict: { ...inherent, decision: "executable" }, why: /not one this guard knows/ },
    { name: "analysis_only over inherent residuals", policy: new ResidualPolicy(), verdict: { ...inherent, decision: "analysis_only" }, why: /its own scope makes this verdict "executable_approved"/ },
    { name: "blocked on an approval", policy: new ResidualPolicy(), verdict: { ...inherent, decision: "blocked" }, why: /its decision is "blocked"/ },
    { name: "executable not a boolean", policy: new ResidualPolicy(), verdict: { ...inherent, decision: "executable_approved", executable: "yes" }, why: /is not a boolean/ },
    { name: "executable false on executable_approved", policy: new ResidualPolicy(), verdict: { ...inherent, decision: "executable_approved", executable: false }, why: /contradicts/ },
    {
      name: "executable_approved over an operator-accepted residual",
      policy: new ResidualPolicy(["not_simulated"]),
      verdict: { ...residual, decision: "executable_approved", executable: true },
      why: /its own scope makes this verdict "analysis_only"/,
    },
  ];
  for (const c of cases) {
    assert.throws(() => c.policy.assertExecutableVerdict(c.verdict, "test"), (e: unknown) => {
      assert.ok(e instanceof ResidualPolicyRefusal, c.name);
      assert.match((e as Error).message, c.why, c.name);
      return true;
    });
  }
  // The control: an agreeing executable verdict passes, and an operator-
  // accepted residual yields analysis_only, never executable_approved.
  assert.equal(new ResidualPolicy().assertExecutableVerdict({ ...inherent, decision: "executable_approved", executable: true }, "t").decision, "executable_approved");
  assert.equal(new ResidualPolicy(["not_simulated"]).assertExecutableVerdict({ ...residual, decision: "analysis_only", executable: false }, "t").decision, "analysis_only");
});
