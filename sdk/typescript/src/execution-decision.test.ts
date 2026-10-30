/**
 * Round 30 (G-01): sign only on `isExecutable`, and the SDK's copy of the
 * rule gives the Core's answer.
 *
 * `examples/decisions/<decision>.json` are real verdicts the Core produced
 * (`graphite-core/tests/round30_decision_fixtures.rs`): an executable
 * approval from a clean simulation, an analysis-only approval with no RPC,
 * an inconclusive refusal and a blocked one. The Go SDK reads the same
 * files. Also K-03: the client's body reads are bounded.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import {
  GraphiteClient,
  MAX_RESPONSE_BYTES,
  ResponseTooLargeError,
  readJsonBounded,
  validateVerificationResult,
} from "./client.js";
import {
  computeExecutionDecision,
  EXECUTION_DECISIONS,
  instructionBindKey,
  isExecutable,
  type ExecutionDecision,
  type VerificationInput,
  type VerificationResult,
} from "./types.js";

function fixture(name: string): VerificationResult {
  return JSON.parse(
    readFileSync(new URL(`../../../examples/decisions/${name}.json`, import.meta.url), "utf8"),
  ) as VerificationResult;
}

const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

test("each committed verdict: the SDK recomputes the Core's decision", () => {
  for (const decision of EXECUTION_DECISIONS) {
    const r = fixture(decision);
    assert.equal(r.decision, decision, "the fixture is the one it is named for");
    assert.equal(validateVerificationResult(r), null, `${decision} validates`);
    assert.equal(computeExecutionDecision(r), decision, `${decision}: the SDK's rule agrees`);
    assert.equal(isExecutable(r), decision === "executable_approved", decision);
    assert.equal(r.executable, decision === "executable_approved");
    assert.equal(instructionBindKey(r), r.content_hash);
  }
});

test("an approval nothing simulated is not executable, whatever it claims", () => {
  const r = fixture("analysis_only");
  assert.equal(r.approved, true, "control: the pipeline approved it");
  assert.ok(r.scope?.unobserved_codes?.includes("not_simulated"));
  assert.equal(isExecutable(r), false);

  // Edited into a claim of permission: the local rule disagrees.
  const forged = { ...clone(r), decision: "executable_approved" as const, executable: true };
  assert.equal(isExecutable(forged), false);
  assert.match(validateVerificationResult(forged) ?? "", /do not permit execution/);
});

test("the rule takes permission away field by field", () => {
  const base = fixture("executable_approved");
  assert.equal(isExecutable(base), true, "control");
  const variants: Array<[string, (r: VerificationResult) => void]> = [
    ["not simulated", (r) => {
      if (r.scope?.kind === "artifact_bound") r.scope.simulated = false;
    }],
    ["a non-inherent residual", (r) => {
      r.scope!.unobserved.push("lookup tables");
      r.scope!.unobserved_codes!.push("lookup_tables_unresolved");
    }],
    ["prose without a code", (r) => {
      r.scope!.unobserved.push("something");
    }],
    ["no codes at all", (r) => {
      delete r.scope!.unobserved_codes;
    }],
    ["a failed layer", (r) => {
      r.layers![0].status = "failed";
    }],
    ["no layers", (r) => {
      delete r.layers;
    }],
    ["risk Blocked", (r) => {
      r.risk_verdict.status = "Blocked";
    }],
    ["policy Rejected", (r) => {
      r.policy_verdict = "Rejected";
    }],
    ["descriptive", (r) => {
      r.scope = { kind: "descriptive", unobserved: ["no artifact"], unobserved_codes: ["no_artifact"] };
    }],
    ["a digest that is not one", (r) => {
      if (r.scope?.kind === "artifact_bound") r.scope.transaction_sha256 = "zz";
    }],
    ["no scope", (r) => {
      delete r.scope;
    }],
    ["an unknown decision", (r) => {
      (r as { decision?: string }).decision = "approved";
    }],
    ["executable: false", (r) => {
      r.executable = false;
    }],
    ["decision without executable", (r) => {
      delete r.executable;
    }],
    ["the server says analysis_only", (r) => {
      r.decision = "analysis_only";
      r.executable = false;
    }],
  ];
  for (const [what, edit] of variants) {
    const r = clone(base);
    edit(r);
    assert.equal(isExecutable(r), false, `${what} must take executable away`);
  }
});

// Re-pinned in Round 39 (R39-CLIENTS-1). This test said "a server older than
// Round 30 is judged by the recomputation alone" and asserted the verdict
// below EXECUTABLE. The Core's own `is_executable` reads an absent decision
// as `blocked` (serde default), the agent guard refuses it (Round 34), and a
// server that old predates every rule added since — so the SDK was looser
// than the Core. It is still readable; it is never executable.
test("a server older than Round 30 is readable, and never executable", () => {
  const old = clone(fixture("executable_approved"));
  delete old.decision;
  delete old.executable;
  delete old.instruction_bind_key;
  assert.equal(validateVerificationResult(old), null, "an older server still validates");
  assert.equal(computeExecutionDecision(old), "executable_approved", "control: its own fields would permit it");
  assert.equal(isExecutable(old), false, "but no decision was made: not executable");
  const oldUnsimulated = clone(fixture("analysis_only"));
  delete oldUnsimulated.decision;
  delete oldUnsimulated.executable;
  assert.equal(isExecutable(oldUnsimulated), false, "recomputed: not executable");
  assert.equal(instructionBindKey(old), old.content_hash);
});

test("refusals: inconclusive only when every finding is missing evidence", () => {
  const base = fixture("blocked");
  const refusal = (patterns: string[]): ExecutionDecision =>
    computeExecutionDecision({
      ...base,
      risk_verdict: { status: "Blocked", findings: patterns.map((pattern) => ({ pattern, reason: "t" })) },
    });
  assert.equal(refusal(["VerificationIncomplete"]), "inconclusive");
  assert.equal(refusal(["VerificationIncomplete", "DrainerPattern"]), "blocked");
  assert.equal(refusal(["SimulationFailed"]), "blocked");
  assert.equal(refusal([]), "blocked");
});

test("the validator refuses a decision that contradicts the verdict", () => {
  const blocked = fixture("blocked");
  const cases: Array<[string, Record<string, unknown>, RegExp]> = [
    ["unknown decision", { ...blocked, decision: "approved" }, /`decision` must be one of/],
    ["executable on a refusal", { ...blocked, executable: true }, /`executable` must be true exactly when/],
    ["a refusal named an approval", { ...blocked, decision: "analysis_only" }, /contradicts `approved`/],
    ["decision without executable", { ...blocked, executable: undefined }, /`executable` must be a boolean/],
    ["bind key differs", { ...blocked, instruction_bind_key: "0000000000000000" }, /instruction_bind_key/],
  ];
  for (const [what, value, why] of cases) {
    assert.match(validateVerificationResult(value) ?? "", why, what);
  }
});

const INPUT = { program_id: "11111111111111111111111111111111" } as unknown as VerificationInput;

async function serve(handler: Parameters<typeof createServer>[1]): Promise<{ server: Server; url: string }> {
  const server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
}

test("K-03: a body over the bound is refused, not read into memory", async () => {
  // Declared too large: refused before reading.
  let { server, url } = await serve((_req, res) => {
    res.writeHead(200, { "content-type": "application/json", "content-length": String(MAX_RESPONSE_BYTES + 1) });
    res.end();
  });
  try {
    await assert.rejects(new GraphiteClient({ baseUrl: url }).verify(INPUT), ResponseTooLargeError);
  } finally {
    server.close();
  }
  // Chunked with no length, and endless: the read is cancelled at the bound.
  let written = 0;
  ({ server, url } = await serve((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    const chunk = Buffer.alloc(1024 * 1024, 0x20);
    const pump = (): void => {
      while (written <= 4 * MAX_RESPONSE_BYTES) {
        written += chunk.length;
        if (!res.write(chunk)) {
          res.once("drain", pump);
          return;
        }
      }
      res.end();
    };
    res.on("close", () => {
      written = Number.POSITIVE_INFINITY;
    });
    pump();
  }));
  try {
    await assert.rejects(new GraphiteClient({ baseUrl: url }).verify(INPUT), ResponseTooLargeError);
  } finally {
    server.closeAllConnections();
    server.close();
  }
});

test("K-03: readJsonBounded reads a body within the bound, and nothing past it", async () => {
  assert.deepEqual(await readJsonBounded(new Response('{"a":1}'), 7), { a: 1 });
  await assert.rejects(readJsonBounded(new Response('{"a":1}'), 6), ResponseTooLargeError);
  await assert.rejects(readJsonBounded(new Response("not json"), 100), SyntaxError);
});
