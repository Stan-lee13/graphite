/**
 * Round 9: the execution path, step by step, against fakes that record every
 * call in order.
 *
 * The invariants under test are ordering invariants: the policy decides
 * before anything is signed; the signing is on the trail before anything is
 * submitted, and a trail that will not take it means nothing is submitted;
 * after submission, every failure is reported and none is hidden; L8 runs
 * at the end whether or not confirmation completed. Nothing here contacts a
 * network.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { Keypair, SystemProgram, Transaction, TransactionInstruction } from "@solana/web3.js";
import { BoundTransaction } from "./artifact.js";
import { ResidualPolicy } from "./residual-policy.js";
import {
  executeBoundTransaction,
  type LifecycleReporter,
  type SubmitConnection,
} from "./execution-lifecycle.js";
import type {
  ExecutionCheckResult,
  LifecycleEventInput,
  LifecycleEventReceipt,
  UnobservedCode,
  VerdictOnRecord,
  VerificationResult,
} from "../../sdk/typescript/src/types.js";

const payer = Keypair.generate();
const destination = Keypair.generate().publicKey;
const BLOCKHASH = "11111111111111111111111111111111";
const INHERENT: UnobservedCode[] = ["program_semantics", "inner_instructions"];

function transfer(lamports = 2_000_000): TransactionInstruction {
  return SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: destination, lamports });
}

function build() {
  return BoundTransaction.build({
    instructions: [transfer()],
    feePayer: payer.publicKey,
    recentBlockhash: BLOCKHASH,
    lastValidBlockHeight: 42,
  });
}

function verdict(bound: BoundTransaction, codes: UnobservedCode[] = INHERENT, approved = true): VerificationResult {
  return {
    approved,
    confidence: 0.64,
    breakdown: [],
    trust_tier: "OfficialManifest",
    risk_verdict: { status: "Clear", findings: [] },
    policy_verdict: "Approved",
    audit_trail_id: "gr-test",
    content_hash: "afb61d8865b4cb68",
    transaction: { instructions: [], signers: [], recent_blockhash: BLOCKHASH } as unknown as VerificationResult["transaction"],
    resolved_accounts: [],
    protocol_name: "System Program",
    instruction_name: "Transfer",
    manifest_found: true,
    unknown_protocol: false,
    summary: "APPROVED",
    scope: {
      kind: "artifact_bound",
      transaction_sha256: createHash("sha256").update(bound.artifactBytes).digest("hex"),
      transaction_bytes: bound.artifactBytes.length,
      simulated: true,
      unobserved: codes.map((c) => `prose ${c}`),
      unobserved_codes: codes,
    },
  };
}

/** Records every call, in order, and can be told to fail at any step. */
class Fakes implements SubmitConnection, LifecycleReporter {
  calls: string[] = [];
  events: LifecycleEventInput[] = [];
  submitted: Uint8Array[] = [];
  verdictOnRecord: VerdictOnRecord = "approved";
  failSigningRecord = false;
  failSubmissionRecord = false;
  failConfirm = false;
  failReconcile = false;
  discrepancy = false;

  async sendRawTransaction(raw: Uint8Array): Promise<string> {
    this.calls.push("send");
    this.submitted.push(raw);
    return "5xSignature";
  }
  async confirmTransaction(s: { signature: string; blockhash: string; lastValidBlockHeight: number }): Promise<unknown> {
    this.calls.push(`confirm:${s.blockhash}:${s.lastValidBlockHeight}`);
    if (this.failConfirm) throw new Error("block height exceeded");
    return { value: { err: null } };
  }
  async recordLifecycleEvent(event: LifecycleEventInput): Promise<LifecycleEventReceipt> {
    this.calls.push(`record:${event.event_type}`);
    if (event.event_type === "signing" && this.failSigningRecord) throw new Error("503 NOT recorded");
    if (event.event_type === "submission" && this.failSubmissionRecord) throw new Error("503 NOT recorded");
    this.events.push(event);
    return {
      recorded: true,
      event_type: event.event_type,
      content_hash: event.content_hash,
      verdict_on_record: this.verdictOnRecord,
    };
  }
  async verifyExecution(input: { signature: string; content_hash?: string }): Promise<ExecutionCheckResult> {
    this.calls.push(`l8:${input.signature}`);
    if (this.failReconcile) throw new Error("rpc unavailable");
    return {
      signature: input.signature,
      chain_status: { Confirmed: { slot: 1, success: true } },
      recorded_approved: true,
      recorded_audit_trail_id: "gr-test",
      reconciliation: this.discrepancy ? "BlockedButExecuted" : "ApprovedAndExecuted",
      discrepancy: this.discrepancy,
      audit_recorded: true,
    };
  }
}

function run(fakes: Fakes, bound: BoundTransaction, v: VerificationResult, policy = new ResidualPolicy()) {
  return executeBoundTransaction({
    bound,
    verification: v,
    signers: [payer],
    connection: fakes,
    graphite: fakes,
    policy,
    reportedBy: "test-bridge",
    label: "t",
    log: () => {},
  });
}

test("the honest path: policy, sign, record signing, send, record submission, confirm, L8 — in that order", async () => {
  const fakes = new Fakes();
  const bound = build();
  const lc = await run(fakes, bound, verdict(bound));
  assert.deepEqual(fakes.calls, [
    "record:signing",
    "send",
    "record:submission",
    `confirm:${BLOCKHASH}:42`,
    "l8:5xSignature",
  ]);
  assert.equal(lc.signature, "5xSignature");
  assert.equal(lc.signingRecorded, true);
  assert.equal(lc.verdictOnRecordAtSigning, "approved");
  assert.equal(lc.submissionRecorded, true);
  assert.equal(lc.confirmed, true);
  assert.deepEqual(lc.acceptedUnobserved, []);
  assert.equal(lc.reconciliation?.discrepancy, false);
  // The events carry the join keys and the reporter.
  assert.equal(fakes.events[0].content_hash, "afb61d8865b4cb68");
  assert.equal(fakes.events[0].audit_trail_id, "gr-test");
  assert.equal(fakes.events[0].reported_by, "test-bridge");
  assert.equal(fakes.events[1].transaction_signature, "5xSignature");
  // And what went out is the signed bound transaction — one submission.
  assert.equal(fakes.submitted.length, 1);
  const tx = Transaction.from(fakes.submitted[0]);
  assert.equal(tx.signatures.length, 1);
  assert.ok(tx.verifySignatures());
});

test("a non-inherent residual refuses BEFORE anything is signed or recorded", async () => {
  const fakes = new Fakes();
  const bound = build();
  await assert.rejects(run(fakes, bound, verdict(bound, [...INHERENT, "no_state_diff"])), /no_state_diff/);
  assert.deepEqual(fakes.calls, [], "nothing touched the network or the trail");
});

test("an accepted residual executes and is named on the lifecycle", async () => {
  const fakes = new Fakes();
  const bound = build();
  const lc = await run(fakes, bound, verdict(bound, [...INHERENT, "no_state_diff"]), new ResidualPolicy(["no_state_diff"]));
  assert.deepEqual(lc.acceptedUnobserved, ["no_state_diff"]);
  assert.equal(fakes.submitted.length, 1);
});

test("a verdict that is not an approval never reaches the policy", async () => {
  const fakes = new Fakes();
  const bound = build();
  await assert.rejects(run(fakes, bound, verdict(bound, INHERENT, false)), /not an approval/);
  assert.deepEqual(fakes.calls, []);
});

test("a digest mismatch refuses after the policy and before the trail", async () => {
  const fakes = new Fakes();
  const bound = build();
  const v = verdict(bound);
  (v.scope as { transaction_sha256: string }).transaction_sha256 = "0".repeat(64);
  await assert.rejects(run(fakes, bound, v), /ABORTING/);
  assert.deepEqual(fakes.calls, [], "a mismatch is not a signing and is not recorded as one");
});

test("if the signing cannot be recorded, nothing is submitted", async () => {
  const fakes = new Fakes();
  fakes.failSigningRecord = true;
  const bound = build();
  await assert.rejects(run(fakes, bound, verdict(bound)), /NOT submitting/);
  assert.deepEqual(fakes.calls, ["record:signing"]);
  assert.equal(fakes.submitted.length, 0);
});

test("if the trail's verdict on record is not an approval, nothing is submitted", async () => {
  for (const on of ["blocked", "not_found"] as VerdictOnRecord[]) {
    const fakes = new Fakes();
    fakes.verdictOnRecord = on;
    const bound = build();
    await assert.rejects(run(fakes, bound, verdict(bound)), new RegExp(`"${on}", not the approval`));
    assert.deepEqual(fakes.calls, ["record:signing"]);
    assert.equal(fakes.submitted.length, 0);
  }
});

test("after submission, a failed submission record is reported, not hidden, and the path continues", async () => {
  const fakes = new Fakes();
  fakes.failSubmissionRecord = true;
  const bound = build();
  const lc = await run(fakes, bound, verdict(bound));
  assert.equal(lc.submissionRecorded, false);
  assert.match(lc.submissionRecordError ?? "", /NOT recorded/);
  assert.equal(lc.confirmed, true);
  assert.ok(lc.reconciliation);
  assert.deepEqual(fakes.calls.slice(0, 3), ["record:signing", "send", "record:submission"]);
});

test("a confirmation that does not complete still runs L8, and says so", async () => {
  const fakes = new Fakes();
  fakes.failConfirm = true;
  const bound = build();
  const lc = await run(fakes, bound, verdict(bound));
  assert.equal(lc.confirmed, false);
  assert.match(lc.confirmationError ?? "", /block height exceeded/);
  assert.equal(fakes.calls.at(-1), "l8:5xSignature");
  assert.ok(lc.reconciliation);
});

test("an L8 failure is reported on the lifecycle", async () => {
  const fakes = new Fakes();
  fakes.failReconcile = true;
  const bound = build();
  const lc = await run(fakes, bound, verdict(bound));
  assert.equal(lc.reconciliation, undefined);
  assert.match(lc.reconciliationError ?? "", /rpc unavailable/);
  assert.equal(lc.submissionRecorded, true);
});

test("an L8 discrepancy is carried through verbatim", async () => {
  const fakes = new Fakes();
  fakes.discrepancy = true;
  const bound = build();
  const lc = await run(fakes, bound, verdict(bound));
  assert.equal(lc.reconciliation?.discrepancy, true);
  assert.equal(lc.reconciliation?.reconciliation, "BlockedButExecuted");
});

test("a server without residual codes is refused before signing", async () => {
  const fakes = new Fakes();
  const bound = build();
  const v = verdict(bound);
  delete (v.scope as { unobserved_codes?: unknown }).unobserved_codes;
  await assert.rejects(run(fakes, bound, v), /prose only/);
  assert.deepEqual(fakes.calls, []);
});
