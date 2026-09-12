/**
 * The execution path, in one place, in order.
 *
 * Everything that happens to an approved transaction after the verdict lives
 * here: the residual-policy decision, the one signing call, the two
 * caller-reported lifecycle events, the submission, the confirmation, and the
 * L8 reconciliation. Until Round 9 (2026-09-12) the bridge signed and
 * submitted without telling Graphite it had done either: the reference
 * integration — the component that actually performs signing and submission —
 * never called `POST /audit/event`, and never called `POST /verify/execution`,
 * so the trail held verifications and nothing after them, and L8 ran only
 * when an operator ran it by hand. Constitution P9 asks for the whole
 * lifecycle on the trail; the party that performs a stage is the only one
 * that can put it there.
 *
 * The ordering rule: no irreversible step proceeds unless the step before it
 * is on the trail. The signing event is recorded BEFORE submission and a
 * failure to record it aborts — the bytes are signed but nothing has left the
 * process, so refusing is free. After submission nothing can be undone;
 * failures to record are reported on the outcome, never swallowed and never
 * treated as reasons to pretend the transaction did not go out.
 *
 * Nothing here decides anything: the policy is configuration, the digest
 * check is `signApproved`'s, and the reconciliation is the server's.
 */

import type { Keypair } from "@solana/web3.js";
import type {
  ExecutionCheckResult,
  LifecycleEventInput,
  LifecycleEventReceipt,
  UnobservedCode,
  VerdictOnRecord,
  VerificationResult,
} from "../../sdk/typescript/src/types.js";
import type { BoundTransaction } from "./artifact.js";
import type { ResidualPolicy } from "./residual-policy.js";

/** The two Connection calls this path makes, so a test can stand in a fake. */
export interface SubmitConnection {
  sendRawTransaction(raw: Uint8Array): Promise<string>;
  confirmTransaction(strategy: {
    signature: string;
    blockhash: string;
    lastValidBlockHeight: number;
  }): Promise<unknown>;
}

/** The two GraphiteClient calls this path makes. */
export interface LifecycleReporter {
  recordLifecycleEvent(event: LifecycleEventInput): Promise<LifecycleEventReceipt>;
  verifyExecution(input: {
    signature: string;
    content_hash?: string;
    reported_by?: string;
  }): Promise<ExecutionCheckResult>;
}

/** What happened, stage by stage. Every field is a fact about this execution. */
export interface ExecutionLifecycle {
  signature: string;
  /** Non-inherent residuals the policy accepted for this execution (P14). */
  acceptedUnobserved: UnobservedCode[];
  /** The `signing` event reached the trail before submission (always true on a returned lifecycle). */
  signingRecorded: true;
  /** What the trail said about the content_hash when signing was reported. */
  verdictOnRecordAtSigning: VerdictOnRecord;
  /** Whether the `submission` event reached the trail; the error when it did not. */
  submissionRecorded: boolean;
  submissionRecordError?: string;
  /** Whether the RPC confirmed the signature inside its blockhash window. */
  confirmed: boolean;
  confirmationError?: string;
  /** L8's answer, when the reconciliation call succeeded. */
  reconciliation?: ExecutionCheckResult;
  reconciliationError?: string;
}

export interface ExecuteParams {
  bound: BoundTransaction;
  verification: VerificationResult;
  signers: Keypair[];
  connection: SubmitConnection;
  graphite: LifecycleReporter;
  policy: ResidualPolicy;
  /** Recorded on every lifecycle row as `reported_by`. */
  reportedBy: string;
  label: string;
  log?: (line: string) => void;
}

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/**
 * Sign, record, submit, record, confirm, reconcile — in that order, and only
 * that order.
 */
export async function executeBoundTransaction(p: ExecuteParams): Promise<ExecutionLifecycle> {
  const log = p.log ?? ((line: string) => console.log(line));
  const { verification, label } = p;
  if (!verification.approved) {
    throw new Error(`[Graphite] ${label}: the verdict is not an approval. ABORTING.`);
  }

  // 1. Policy: what the verdict did not observe, against what this deployment
  //    accepts. Refuses on anything else, including a server that reports no
  //    codes.
  const decision = p.policy.assertExecutable(verification.scope, label);
  const scope = verification.scope;
  if (scope?.kind !== "artifact_bound") {
    // Unreachable after assertExecutable; kept so the type narrows.
    throw new Error(`[Graphite] ${label}: not artifact_bound. ABORTING.`);
  }
  if (decision.accepted.length > 0) {
    log(
      `[Graphite] ${label}: executing under ${decision.accepted.length} accepted residual(s): ` +
        decision.accepted.join(", "),
    );
  }

  // 2. The one signing path: digest and signer set re-derived over this
  //    object, compared against what Graphite hashed.
  const raw = p.bound.signApproved(scope.transaction_sha256, p.signers);
  log(
    `[Graphite] ${label}: transaction matches the approved digest ` +
      `${scope.transaction_sha256.slice(0, 16)}… — signed those exact bytes.`,
  );

  // 3. Signing goes on the trail BEFORE anything leaves the process. If it
  //    cannot be recorded, nothing is submitted: the bytes exist only here.
  let signing: LifecycleEventReceipt;
  try {
    signing = await p.graphite.recordLifecycleEvent({
      event_type: "signing",
      content_hash: verification.content_hash,
      audit_trail_id: verification.audit_trail_id,
      reported_by: p.reportedBy,
      detail: `digest ${scope.transaction_sha256}`,
    });
  } catch (e) {
    throw new Error(
      `[Graphite] ${label}: signed, but the signing could not be recorded on the audit trail ` +
        `(${message(e)}). NOT submitting: a transaction whose signing is not on the trail cannot ` +
        "be reconciled by L8. Retry once the audit path is healthy.",
    );
  }
  if (signing.verdict_on_record !== "approved") {
    // The server that verified this transaction is not the server whose
    // trail was just consulted, or the trail changed under us. Either way
    // the approval in hand is not the approval on record.
    throw new Error(
      `[Graphite] ${label}: the audit trail's most recent verdict for ${verification.content_hash} ` +
        `is "${signing.verdict_on_record}", not the approval this process holds. NOT submitting.`,
    );
  }

  // 4. Submission. From here nothing can be undone; every failure below is
  //    reported, none is a reason to pretend this did not happen.
  const signature = await p.connection.sendRawTransaction(raw);
  log(`[Graphite] ${label}: submitted ${signature}`);

  const lifecycle: ExecutionLifecycle = {
    signature,
    acceptedUnobserved: decision.accepted,
    signingRecorded: true,
    verdictOnRecordAtSigning: signing.verdict_on_record,
    submissionRecorded: false,
    confirmed: false,
  };

  // 5. Submission on the trail, with the signature.
  try {
    await p.graphite.recordLifecycleEvent({
      event_type: "submission",
      content_hash: verification.content_hash,
      audit_trail_id: verification.audit_trail_id,
      transaction_signature: signature,
      reported_by: p.reportedBy,
    });
    lifecycle.submissionRecorded = true;
  } catch (e) {
    lifecycle.submissionRecordError = message(e);
    log(`[Graphite] ${label}: WARNING — submission of ${signature} was NOT recorded: ${message(e)}`);
  }

  // 6. Confirmation, bounded by the blockhash the transaction was built on.
  try {
    await p.connection.confirmTransaction({
      signature,
      blockhash: p.bound.recentBlockhash,
      lastValidBlockHeight: p.bound.lastValidBlockHeight,
    });
    lifecycle.confirmed = true;
  } catch (e) {
    lifecycle.confirmationError = message(e);
    log(`[Graphite] ${label}: confirmation of ${signature} did not complete: ${message(e)}`);
  }

  // 7. L8: the chain's account of the signature, reconciled against the
  //    verdict on record. Run whether or not confirmation completed — an
  //    expired blockhash is exactly the case where the chain's answer matters.
  try {
    lifecycle.reconciliation = await p.graphite.verifyExecution({
      signature,
      content_hash: verification.content_hash,
      reported_by: p.reportedBy,
    });
    const r = lifecycle.reconciliation;
    log(
      `[Graphite] ${label}: L8 reconciliation ${JSON.stringify(r.reconciliation)}` +
        (r.audit_recorded ? "" : " (NOT recorded on the trail)"),
    );
    if (r.discrepancy) {
      log(`[Graphite] ${label}: L8 DISCREPANCY on ${signature} — Graphite's decision did not govern`);
    }
  } catch (e) {
    lifecycle.reconciliationError = message(e);
    log(`[Graphite] ${label}: L8 reconciliation of ${signature} failed: ${message(e)}`);
  }

  return lifecycle;
}
