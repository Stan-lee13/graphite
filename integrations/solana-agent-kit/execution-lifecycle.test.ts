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
  VerificationKeyKind,
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
    content_hash: "48c65c638aceb5de",
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
  verdictKey: VerificationKeyKind = "audit_trail_id";
  failSigningRecord = false;
  failSubmissionRecord = false;
  failSubmissionRecordTimes = 0;
  failConfirm = false;
  failReconcile = false;
  discrepancy = false;
  chainBytesRejected: string | null = null;

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
    if (event.event_type === "submission" && this.failSubmissionRecordTimes > 0) {
      this.failSubmissionRecordTimes -= 1;
      throw new Error("503 NOT recorded");
    }
    const duplicate = this.events.some(
      (e) => e.event_type === event.event_type && e.transaction_signature === event.transaction_signature,
    );
    this.events.push(event);
    return {
      recorded: true,
      event_type: event.event_type,
      content_hash: event.content_hash,
      verdict_on_record: this.verdictOnRecord,
      verdict_on_record_key: this.verdictKey,
      sequence_anomalies: duplicate ? [`duplicate: ${event.event_type} was already reported`] : [],
      prior_events_on_record: this.events.length - 1,
    };
  }
  l8Inputs: Array<{ signature: string; content_hash?: string; transaction_sha256?: string; audit_trail_id?: string }> = [];
  async verifyExecution(input: { signature: string; content_hash?: string; transaction_sha256?: string; audit_trail_id?: string }): Promise<ExecutionCheckResult> {
    this.calls.push(`l8:${input.signature}`);
    this.l8Inputs.push(input);
    if (this.failReconcile) throw new Error("rpc unavailable");
    if (this.chainBytesRejected) {
      // What the server returns when the RPC's bytes are not the
      // signature's: nothing attributed, nothing resolved, and why.
      return {
        signature: input.signature,
        chain_status: { Confirmed: { slot: 1, success: true } },
        recorded_approved: null,
        recorded_audit_trail_id: null,
        recorded_transaction_sha256: null,
        reconciliation: { Unavailable: { reason: this.chainBytesRejected } },
        discrepancy: false,
        attribution: "none",
        chain_transaction_sha256: null,
        caller_keys_disagree: [],
        chain_bytes_rejected: this.chainBytesRejected,
        audit_recorded: true,
      };
    }
    return {
      signature: input.signature,
      chain_status: { Confirmed: { slot: 1, success: true } },
      recorded_approved: true,
      recorded_audit_trail_id: "gr-test",
      recorded_transaction_sha256: input.transaction_sha256 ?? null,
      reconciliation: this.discrepancy ? "BlockedButExecuted" : "ApprovedAndExecuted",
      discrepancy: this.discrepancy,
      attribution: "chain",
      chain_transaction_sha256: input.transaction_sha256 ?? null,
      caller_keys_disagree: [],
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
    // Tests do not wait on the retry backoff.
    submissionRecordBackoffMs: 0,
  });
}

test("the honest path: policy, sign, record signing, send, record submission, confirm, L8 — in that order", async () => {
  const fakes = new Fakes();
  const bound = build();
  const v = verdict(bound);
  const lc = await run(fakes, bound, v);
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
  // The events carry every join key — the exact ones, not only the
  // instruction-level content_hash — and the reporter.
  assert.equal(fakes.events[0].content_hash, "48c65c638aceb5de");
  assert.equal(fakes.events[0].audit_trail_id, "gr-test");
  const digest = (v.scope as { transaction_sha256: string }).transaction_sha256;
  assert.equal(fakes.events[0].transaction_sha256, digest);
  assert.equal(fakes.events[1].transaction_sha256, digest);
  assert.equal(fakes.l8Inputs[0].audit_trail_id, "gr-test");
  assert.equal(fakes.l8Inputs[0].transaction_sha256, digest);
  assert.equal(fakes.events[0].reported_by, "test-bridge");
  assert.equal(fakes.events[1].transaction_signature, "5xSignature");
  // And what went out is the signed bound transaction — one submission.
  assert.equal(fakes.submitted.length, 1);
  const tx = Transaction.from(fakes.submitted[0]);
  assert.equal(tx.signatures.length, 1);
  assert.ok(tx.verifySignatures());
  // What the chain will hold, with its signature slot zeroed, IS the artifact
  // Graphite verified — the join L8 performs (Round 10, `unsigned_artifact`).
  const zeroed = Uint8Array.from(fakes.submitted[0]);
  zeroed.fill(0, 1, 65);
  assert.deepEqual(Array.from(zeroed), Array.from(bound.artifactBytes));
  assert.equal(createHash("sha256").update(zeroed).digest("hex"), digest);
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

test("a signing resolved by a coarser key than the exact id is not submitted", async () => {
  // A content_hash-resolved "approved" may be about a different transaction
  // carrying the same instruction (Round 10).
  for (const key of ["content_hash", "transaction_sha256"] as VerificationKeyKind[]) {
    const fakes = new Fakes();
    fakes.verdictKey = key;
    const bound = build();
    await assert.rejects(run(fakes, bound, verdict(bound)), new RegExp(`resolved the signing by "${key}"`));
    assert.deepEqual(fakes.calls, ["record:signing"]);
    assert.equal(fakes.submitted.length, 0);
  }
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
  // Three attempts by default (Round 12), then the path continues.
  assert.equal(lc.submissionRecordAttempts, 3);
  assert.equal(lc.confirmed, true);
  assert.ok(lc.reconciliation);
  assert.deepEqual(fakes.calls.slice(0, 5), [
    "record:signing",
    "send",
    "record:submission",
    "record:submission",
    "record:submission",
  ]);
});

test("a submission record that fails once is retried and lands (Round 12)", async () => {
  const fakes = new Fakes();
  fakes.failSubmissionRecordTimes = 1;
  const bound = build();
  const lc = await run(fakes, bound, verdict(bound));
  assert.equal(lc.submissionRecorded, true);
  assert.equal(lc.submissionRecordError, undefined);
  assert.equal(lc.submissionRecordAttempts, 2);
  assert.equal(fakes.events.filter((e) => e.event_type === "submission").length, 1);
  // The signature the trail holds is the one that went out.
  assert.equal(fakes.events.find((e) => e.event_type === "submission")?.transaction_signature, lc.signature);
});

test("a retry after a lost answer is a duplicate on the trail, and counts as recorded", async () => {
  // The first report reached the trail but its answer was lost: the fake
  // records the event and then throws, as a dropped connection would.
  const fakes = new Fakes();
  const original = fakes.recordLifecycleEvent.bind(fakes);
  let lost = true;
  fakes.recordLifecycleEvent = async (event) => {
    const receipt = await original(event);
    if (event.event_type === "submission" && lost) {
      lost = false;
      throw new Error("socket hang up");
    }
    return receipt;
  };
  const bound = build();
  const lc = await run(fakes, bound, verdict(bound));
  assert.equal(lc.submissionRecorded, true);
  assert.equal(lc.submissionRecordAttempts, 2);
  // Two rows on the (fake) trail, the second named a duplicate — never a
  // second submission.
  assert.equal(fakes.events.filter((e) => e.event_type === "submission").length, 2);
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

test("an L8 refusal of the RPC's bytes is carried through and named, never read as a pass", async () => {
  const fakes = new Fakes();
  fakes.chainBytesRejected =
    "the RPC returned bytes for 5xSignature that are not bound to it: the first signature slot holds a different signature";
  const bound = build();
  const logs: string[] = [];
  const lc = await executeBoundTransaction({
    bound,
    verification: verdict(bound),
    signers: [payer],
    connection: fakes,
    graphite: fakes,
    policy: new ResidualPolicy(),
    reportedBy: "test-bridge",
    label: "t",
    log: (m) => logs.push(m),
  });
  assert.equal(lc.reconciliation?.attribution, "none");
  assert.equal(lc.reconciliation?.discrepancy, false);
  assert.equal(lc.reconciliation?.recorded_approved, null);
  assert.deepEqual(lc.reconciliation?.reconciliation, {
    Unavailable: { reason: fakes.chainBytesRejected },
  });
  assert.ok(logs.some((l) => l.includes("L8 REFUSED") && l.includes("not bound to it")), logs.join(" / "));
});

test("a server without residual codes is refused before signing", async () => {
  const fakes = new Fakes();
  const bound = build();
  const v = verdict(bound);
  delete (v.scope as { unobserved_codes?: unknown }).unobserved_codes;
  await assert.rejects(run(fakes, bound, v), /prose only/);
  assert.deepEqual(fakes.calls, []);
});
