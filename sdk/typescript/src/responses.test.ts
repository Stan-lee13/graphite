/**
 * Audit 2026-10-20 (T1, T2, T3 and the validator/schema drift): every method
 * checks what it is answered, the timeout cannot be switched off by
 * accident, bytes are bytes, and the API key is not a property of the client.
 * Loopback servers only.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import {
  GraphiteClient,
  MAX_TIMEOUT_MS,
  assertSecureBaseUrl,
  isLoopbackHost,
  resolveTimeoutMs,
  validateExecutionCheckResult,
  validateLifecycleEventReceipt,
  validateVerificationResult,
} from "./client.js";
import { AuditBindError, checkedBytes, computeContentHash, projectionFromInstruction } from "./auditbind.js";
import { transactionDigest, verifyTransactionDigest } from "./transaction-digest.js";
import { isArtifactBound, type LifecycleEventInput, type VerificationInput } from "./types.js";

const SAMPLE = JSON.parse(
  readFileSync(new URL("../../../examples/sample-verification-result.json", import.meta.url), "utf8"),
) as Record<string, unknown>;

/** The committed (blocked, descriptive) sample turned into an artifact-bound approval. */
const APPROVED: Record<string, unknown> = {
  ...SAMPLE,
  approved: true,
  policy_verdict: "Approved",
  risk_verdict: { status: "Clear", findings: [] },
  scope: {
    kind: "artifact_bound",
    transaction_sha256: "ab".repeat(32),
    transaction_bytes: 215,
    simulated: true,
    unobserved: ["program semantics", "inner instructions"],
    unobserved_codes: ["program_semantics", "inner_instructions"],
  },
};

const RECEIPT = {
  recorded: true,
  event_type: "signing",
  content_hash: "48c65c638aceb5de",
  verdict_on_record: "approved",
  verdict_on_record_key: "audit_trail_id",
  sequence_anomalies: [],
  prior_events_on_record: 0,
};
const EVENT: LifecycleEventInput = { event_type: "signing", content_hash: "48c65c638aceb5de", audit_trail_id: "gr-x" };

const SIGNATURE = "5".repeat(88);
const EXECUTION = {
  signature: SIGNATURE,
  chain_status: { Confirmed: { signature: SIGNATURE, slot: 1, success: true, error: null, commitment: "finalized" } },
  recorded_approved: true,
  recorded_audit_trail_id: "gr-x",
  recorded_transaction_sha256: "ab".repeat(32),
  reconciliation: "ApprovedAndExecuted",
  discrepancy: false,
  attribution: "chain",
  chain_transaction_sha256: "ab".repeat(32),
  caller_keys_disagree: [],
  chain_bytes_rejected: null,
  chain_bytes_unavailable: null,
  chain_inconsistent: null,
  inclusion_witness: null,
  recorded_verdicts: { approved: 1, refused: 0 },
  audit_recorded: true,
};

const HEALTH = { status: "ok", degraded: false, degraded_reasons: [], service: "graphite-core", version: "0.3.0-beta" };

const MANIFEST = {
  graphite_manifest_version: "1.0",
  protocol: { name: "System Program", program_id: "11111111111111111111111111111111" },
  version: { label: "1.0.0", effective_from_slot: 0 },
  instructions: [
    {
      name: "Transfer",
      discriminator: "02000000",
      accounts: [{ name: "from", role: "signer", is_writable: true, is_signer: true }],
      expected_state_changes: [],
      allowed_cpis: [],
      risk_rules: [],
    },
  ],
  trust_tier: "OfficialManifest",
};

type Answer = { status: number; body: string };

/** A loopback Core answering each route with what the test sets. */
async function core(answers: Record<string, Answer>): Promise<{ url: string; close: () => Promise<void> }> {
  const server: Server = createServer((req, res) => {
    req.resume();
    const a = answers[`${req.method} ${req.url}`] ?? { status: 404, body: "{}" };
    res.writeHead(a.status, { "content-type": "application/json" });
    res.end(a.body);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    close: async () => {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

function ok(value: unknown): Answer {
  return { status: 200, body: JSON.stringify(value) };
}

const INPUT = { program_id: "11111111111111111111111111111111" } as VerificationInput;
const CALLS: [string, (c: GraphiteClient) => Promise<unknown>][] = [
  ["POST /verify", (c) => c.verify(INPUT)],
  ["POST /audit/event", (c) => c.recordLifecycleEvent(EVENT)],
  ["POST /verify/execution", (c) => c.verifyExecution({ signature: SIGNATURE })],
  ["GET /health", (c) => c.health()],
  ["GET /manifests", (c) => c.listManifests()],
];
const GOOD: Record<string, unknown> = {
  "POST /verify": APPROVED,
  "POST /audit/event": RECEIPT,
  "POST /verify/execution": EXECUTION,
  "GET /health": HEALTH,
  "GET /manifests": [MANIFEST],
};

test("T1: every method accepts the well-formed answer its route gives", async () => {
  const c = await core(Object.fromEntries(Object.entries(GOOD).map(([k, v]) => [k, ok(v)])));
  try {
    const client = new GraphiteClient({ baseUrl: c.url });
    for (const [route, call] of CALLS) {
      assert.deepEqual(await call(client), GOOD[route], route);
    }
  } finally {
    await c.close();
  }
});

test("T1: a 200 whose body is not JSON is thrown by every method, never returned", async () => {
  const c = await core(Object.fromEntries(CALLS.map(([r]) => [r, { status: 200, body: "<html>ok</html>" }])));
  try {
    const client = new GraphiteClient({ baseUrl: c.url });
    for (const [route, call] of CALLS) {
      await assert.rejects(call(client), /not JSON/, route);
    }
  } finally {
    await c.close();
  }
});

test("T1: a 200 of the wrong shape is thrown by every method", async () => {
  const wrong: Record<string, unknown[]> = {
    "POST /verify": [{}, [], { ...APPROVED, approved: "yes" }],
    "POST /audit/event": [{}, { ...RECEIPT, recorded: false }, { ...RECEIPT, verdict_on_record: "maybe" }],
    "POST /verify/execution": [{}, { ...EXECUTION, discrepancy: undefined }, { ...EXECUTION, reconciliation: "Fine" }],
    "GET /health": [{}, { ...HEALTH, status: 1 }, []],
    "GET /manifests": [{}, [{}], [{ ...MANIFEST, instructions: [{ name: "x" }] }]],
  };
  for (const [route, call] of CALLS) {
    for (const body of wrong[route]) {
      const c = await core({ [route]: ok(body) });
      try {
        await assert.rejects(call(new GraphiteClient({ baseUrl: c.url })), /structurally invalid/, `${route} ${JSON.stringify(body)}`);
      } finally {
        await c.close();
      }
    }
  }
});

test("verify: a non-2xx is thrown with its status and the server's error, never returned", async () => {
  for (const status of [400, 401, 413, 429, 500, 503]) {
    const c = await core({ "POST /verify": { status, body: JSON.stringify({ error: `refused ${status}` }) } });
    try {
      await assert.rejects(
        new GraphiteClient({ baseUrl: c.url }).verify(INPUT),
        (e: Error) => e.message.includes(String(status)) && e.message.includes(`refused ${status}`),
      );
    } finally {
      await c.close();
    }
  }
  // A non-2xx whose body is not JSON still fails, with the status.
  const c = await core({ "POST /verify": { status: 502, body: "bad gateway" } });
  try {
    await assert.rejects(new GraphiteClient({ baseUrl: c.url }).verify(INPUT), /502/);
  } finally {
    await c.close();
  }
});

test("T1: a receipt or an L8 answer about something else is refused", () => {
  assert.equal(validateLifecycleEventReceipt(RECEIPT, EVENT), null);
  assert.match(validateLifecycleEventReceipt({ ...RECEIPT, event_type: "submission" }, EVENT) ?? "", /not the signing/);
  assert.match(validateLifecycleEventReceipt({ ...RECEIPT, content_hash: "0".repeat(16) }, EVENT) ?? "", /content_hash/);
  assert.equal(validateExecutionCheckResult(EXECUTION, { signature: SIGNATURE }), null);
  assert.match(validateExecutionCheckResult(EXECUTION, { signature: "4".repeat(88) }) ?? "", /different signature/);
  // The alarm cannot be dropped while the outcome is kept.
  assert.match(
    validateExecutionCheckResult({ ...EXECUTION, reconciliation: "BlockedButExecuted", discrepancy: false }) ?? "",
    /discrepancy/,
  );
  assert.equal(validateExecutionCheckResult({ ...EXECUTION, reconciliation: "BlockedButExecuted", discrepancy: true }), null);
  const refusedElsewhere = {
    RecordedForDifferentBytes: { recorded_approved: false, recorded_transaction_sha256: null, chain_transaction_sha256: "cd".repeat(32) },
  };
  // A cited verdict about other bytes is never an alarm (audit 2026-10-20,
  // F5): only BlockedButExecuted is a discrepancy, so a body raising one on
  // any other outcome is refused too.
  assert.equal(validateExecutionCheckResult({ ...EXECUTION, reconciliation: refusedElsewhere }), null);
  assert.match(
    validateExecutionCheckResult({ ...EXECUTION, reconciliation: refusedElsewhere, discrepancy: true }) ?? "",
    /discrepancy/,
  );
});

test("the validator requires what the Core always emits and refuses what it never does", () => {
  assert.equal(validateVerificationResult(SAMPLE), null, "the committed sample");
  assert.equal(validateVerificationResult(APPROVED), null, "an artifact-bound approval");
  const without = (k: string) => Object.fromEntries(Object.entries(APPROVED).filter(([key]) => key !== k));
  for (const k of ["scope", "layers", "breakdown", "transaction", "resolved_accounts", "policy_verdict", "trust_tier", "summary", "manifest_version", "simulation_flagged", "simulation_divergence"]) {
    assert.notEqual(validateVerificationResult(without(k)), null, `without ${k}`);
  }
  const scope = APPROVED.scope as Record<string, unknown>;
  const accounts = APPROVED.resolved_accounts as Record<string, unknown>[];
  const layers = APPROVED.layers as Record<string, unknown>[];
  const refused: [string, Record<string, unknown>, RegExp][] = [
    ["approved beside Rejected", { policy_verdict: "Rejected" }, /policy_verdict/],
    ["an unknown policy verdict", { policy_verdict: "Blocked" }, /policy_verdict/],
    ["codes missing", { scope: { ...scope, unobserved_codes: undefined } }, /unobserved_codes/],
    [
      "a descriptive scope with a digest",
      { scope: { kind: "descriptive", unobserved: ["x"], unobserved_codes: ["no_artifact"], transaction_sha256: "ab".repeat(32) } },
      /descriptive/,
    ],
    ["an account without identity", { resolved_accounts: [{ ...accounts[0], identity: undefined }] }, /identity/],
    ["an account without its mismatch flag", { resolved_accounts: [{ ...accounts[0], pda_mismatch: undefined }] }, /pda_mismatch/],
    ["passed beside failed", { layers: [{ ...layers[0], passed: true, status: "failed" }] }, /passed/],
    ["a layer without status", { layers: [{ ...layers[0], status: undefined }] }, /status/],
    ["an empty breakdown", { breakdown: [] }, /breakdown/],
    ["a bad compute budget", { scope: { ...scope, compute_budget: { source: "guess" } } }, /compute_budget/],
  ];
  for (const [what, change, reason] of refused) {
    const violation = validateVerificationResult({ ...APPROVED, ...change });
    assert.ok(violation !== null && reason.test(violation), `${what}: ${violation}`);
  }
  // A blocked verdict that says "Approved" contradicts itself too.
  assert.match(validateVerificationResult({ ...SAMPLE, policy_verdict: "Approved" }) ?? "", /policy_verdict/);
});

test("isArtifactBound needs the digest of what was bound", () => {
  const scope = APPROVED.scope as Record<string, unknown>;
  assert.equal(isArtifactBound(APPROVED as never), true);
  for (const sha of [undefined, "", "AB".repeat(32), "ab".repeat(31)]) {
    assert.equal(isArtifactBound({ scope: { ...scope, transaction_sha256: sha } } as never), false, String(sha));
  }
});

test("T2: only 0 disables the timeout; any other non-timeout is refused at construction", () => {
  assert.equal(resolveTimeoutMs(undefined), 30_000);
  assert.equal(resolveTimeoutMs(0), 0);
  assert.equal(resolveTimeoutMs(1), 1);
  assert.equal(resolveTimeoutMs(MAX_TIMEOUT_MS), MAX_TIMEOUT_MS);
  for (const bad of [-1, -0.5, NaN, Infinity, -Infinity, 1.5, MAX_TIMEOUT_MS + 1, "30000" as unknown as number]) {
    assert.throws(() => new GraphiteClient({ baseUrl: "https://graphite.internal", timeoutMs: bad }), /timeoutMs/, String(bad));
  }
});

test("T2: a hung Core times out instead of hanging the call", async () => {
  const hung = createServer(() => {
    /* never answers */
  });
  await new Promise<void>((resolve) => hung.listen(0, "127.0.0.1", resolve));
  try {
    const client = new GraphiteClient({ baseUrl: `http://127.0.0.1:${(hung.address() as AddressInfo).port}`, timeoutMs: 150 });
    const started = Date.now();
    await assert.rejects(client.verify(INPUT), (e: Error) => e.name === "TimeoutError" || /timeout|abort/i.test(e.message));
    assert.ok(Date.now() - started < 5_000, "bounded by the configured timeout");
  } finally {
    hung.closeAllConnections();
    await new Promise<void>((resolve) => hung.close(() => resolve()));
  }
});

test("T3: an element that is not a byte is refused, not wrapped modulo 256", () => {
  const base = { programId: "11111111111111111111111111111111", instructionDiscriminator: "02000000", accountAddresses: ["a"] };
  assert.equal(computeContentHash({ ...base, instructionData: [0, 255] }).length, 16);
  for (const bad of [[256], [-1], [1.5], [NaN], ["1" as unknown as number]]) {
    assert.throws(() => computeContentHash({ ...base, instructionData: bad }), AuditBindError, JSON.stringify(bad));
    assert.throws(() => checkedBytes(bad, "x"), /not a byte/);
  }
  // [256] used to hash as [0] — the two must not be confused.
  assert.throws(() => computeContentHash({ ...base, instructionData: [256] }));
  assert.throws(
    () => projectionFromInstruction({ programId: "p", accounts: [], data: [2, 0, 0, 300] as unknown as Uint8Array }),
    /not a byte/,
  );
  const tx = [1, ...new Array(64).fill(0), 1, 2, 3];
  assert.equal(transactionDigest(tx), transactionDigest(Uint8Array.from(tx)));
  const wrapped = [...tx];
  wrapped[66] = 258; // would have been 2 after Uint8Array.from
  assert.throws(() => transactionDigest(wrapped), /not a byte/);
  const result = { approved: true, scope: { kind: "artifact_bound", transaction_sha256: transactionDigest(tx) } };
  verifyTransactionDigest(tx, result);
  assert.throws(() => verifyTransactionDigest(wrapped, result), /not a byte/);
});

test("the API key is not a readable property of the client", () => {
  const key = "k".repeat(32);
  const client = new GraphiteClient({ baseUrl: "https://graphite.internal", apiKey: key });
  assert.equal((client as unknown as Record<string, unknown>)["apiKey"], undefined);
  assert.ok(!JSON.stringify(client).includes(key));
  assert.ok(!Object.values(client).some((v) => v === key));
});

test("IPv4-mapped loopback is loopback in this SDK, as in Go's", () => {
  for (const base of ["http://[::ffff:127.0.0.1]:7331", "http://[::ffff:7f00:1]", "http://[0:0:0:0:0:ffff:127.1.2.3]"]) {
    assert.doesNotThrow(() => assertSecureBaseUrl(base), base);
  }
  for (const base of ["http://[::ffff:10.0.0.1]", "http://[::ffff:128.0.0.1]", "http://[::127.0.0.1]", "http://[::ffff:7f:1]"]) {
    assert.throws(() => assertSecureBaseUrl(base), /non-loopback/, base);
  }
  assert.equal(isLoopbackHost("[::ffff:7f00:1]"), true);
});
