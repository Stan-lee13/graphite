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

import type {
  ExecutionCheckResult,
  LifecycleEventInput,
  LifecycleEventReceipt,
  UnobservedCode,
  VerdictOnRecord,
  VerificationResult,
} from "../../sdk/typescript/src/types.js";
import { instructionBindKey } from "../../sdk/typescript/src/types.js";
import { firstSignatureOf, type BoundTransaction, type TransactionSigner } from "./artifact.js";
import type { ExecutionDecision, ResidualPolicy } from "./residual-policy.js";

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
    instruction_bind_key?: string;
    content_hash?: string;
    transaction_sha256?: string;
    audit_trail_id?: string;
    reported_by?: string;
  }): Promise<ExecutionCheckResult>;
}

/**
 * The verification's instruction-level key under both its names (Round 32,
 * R-M10): `instruction_bind_key`, its name since Round 30, and
 * `content_hash`, which every Core before Round 32 requires. The same value
 * under both, so every Core reads one key.
 */
function bindKeyOf(verification: VerificationResult): { instruction_bind_key: string; content_hash: string } {
  const key = instructionBindKey(verification);
  return { instruction_bind_key: key, content_hash: key };
}

/** What happened, stage by stage. Every field is a fact about this execution. */
export interface ExecutionLifecycle {
  /** The transaction id: the fee payer's signature, read from the signed bytes. */
  signature: string;
  /**
   * Present only when the RPC's `sendTransaction` answer named a different
   * id than the signed bytes carry. The RPC's answer is not used for
   * anything; it is kept here as the evidence that the RPC misreported.
   */
  rpcReportedSignature?: string;
  /** Non-inherent residuals the policy accepted for this execution (P14). */
  acceptedUnobserved: UnobservedCode[];
  /**
   * The execution decision this process acted on (Round 30, G-01):
   * `executable_approved`, or `analysis_only` under residuals the operator
   * accepted by name. Recomputed from the verdict's scope and, when the Core
   * reported one, equal to its `decision`.
   */
  decision: "executable_approved" | "analysis_only";
  /** The Core's own `decision`, or null from a server that predates it. */
  reportedDecision: ExecutionDecision | null;
  /** The `signing` event reached the trail before submission (always true on a returned lifecycle). */
  signingRecorded: true;
  /** What the trail said about the content_hash when signing was reported. */
  verdictOnRecordAtSigning: VerdictOnRecord;
  /**
   * Whether the `submission` event reached the trail; the error when it did
   * not, after every attempt. A retry the server had already recorded comes
   * back as a `duplicate` anomaly and counts as recorded.
   */
  submissionRecorded: boolean;
  submissionRecordError?: string;
  /** How many times the submission report was attempted. */
  submissionRecordAttempts: number;
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
  /**
   * Exactly the signers the message requires: web3.js `Keypair`s, or
   * `{ publicKey, keyPair }` with a non-extractable WebCrypto key pair (what
   * the guard holds since Round 30).
   */
  signers: TransactionSigner[];
  connection: SubmitConnection;
  graphite: LifecycleReporter;
  policy: ResidualPolicy;
  /** Recorded on every lifecycle row as `reported_by`. */
  reportedBy: string;
  label: string;
  log?: (line: string) => void;
  /**
   * How many times to try recording the submission before giving up
   * (default 3), and the pause between tries in milliseconds (default 500,
   * doubling). The signature is already on the network by then, so the
   * retries cost nothing but the wait; the server names a repeat of a
   * report it already took as `duplicate`, so retrying is safe.
   */
  submissionRecordAttempts?: number;
  submissionRecordBackoffMs?: number;
  /**
   * A last say, after the verdict and the residual policy and immediately
   * before anything is signed (Round 29, audit 2026-10-20, M7). Anything but
   * `true` — false, a throw — aborts with `ConfirmationDeclined` and nothing
   * signed. The guard passes a summary of the resolved transaction to the
   * caller's hook through this.
   */
  confirm?: (decided: { acceptedUnobserved: UnobservedCode[] }) => Promise<boolean>;
  /**
   * How long `confirm` may take, in milliseconds (default
   * `DEFAULT_CONFIRM_TIMEOUT_MS`). A confirmation that has not answered by
   * then is a decline (Round 30): a hook that never returns must not hold a
   * signing decision open, and an answer that arrives minutes later is an
   * answer about a transaction the person saw minutes ago.
   */
  confirmTimeoutMs?: number;
  /**
   * Called after the confirmation and immediately before the one signing
   * call (Round 34). The guard refuses here once it is closed or has lost
   * its wallet's lock. A throw aborts: nothing is signed.
   */
  beforeSign?: () => void;
  /**
   * Called with the transaction's signature after the signing is on the
   * trail and immediately before the bytes are handed to the RPC (Round 30).
   * The guard records the submission as unresolved here, durably, so a crash
   * during the send cannot lose it. A throw aborts: nothing is sent.
   */
  beforeSubmit?: (signature: string) => void;
  /**
   * The verdict's age bound (Round 35, F-017). `requestedAt` is a reading of
   * `now` (default `performance.now`, a monotonic clock a wall-clock change
   * cannot move) taken BEFORE the verification was asked for, so the age is
   * never under-counted. Immediately before signing, a verdict older than
   * `maxMs` is refused with `StaleVerdict` and nothing is signed.
   */
  verdictAge?: { requestedAt: number; maxMs: number; now?: () => number };
}

/** How long a confirmation hook may take before it counts as declined (Round 30). */
export const DEFAULT_CONFIRM_TIMEOUT_MS = 120_000;

/**
 * The oldest verdict the guard signs by default (Round 35, F-017): the
 * default confirmation window (`DEFAULT_CONFIRM_TIMEOUT_MS`) plus 30 s for
 * the verification's own round trip and the steps around it.
 *
 * Every transaction the guard builds is bounded by its blockhash as well
 * (about 60–90 s of blocks); the guard refuses durable-nonce transactions at
 * build, and the Core refuses them unless GRAPHITE_ALLOW_DURABLE_NONCE=1.
 * This bound is the guard's own, on the verdict rather than the transaction,
 * so it holds whatever the transaction's lifetime.
 */
export const DEFAULT_MAX_VERDICT_AGE_MS = 150_000;
/** The largest bound an operator may set (ten minutes). */
export const MAX_MAX_VERDICT_AGE_MS = 600_000;

/**
 * The verdict is older than the deployment signs (Round 35, F-017): the chain
 * it was judged against has moved on. Nothing was signed or sent; ask again.
 */
export class StaleVerdict extends Error {
  readonly ageMs: number;
  readonly maxMs: number;
  constructor(label: string, ageMs: number, maxMs: number) {
    super(
      `[Graphite] ${label}: the verdict is ${Math.round(ageMs)} ms old, over the ${maxMs} ms bound ` +
        "(GRAPHITE_MAX_VERDICT_AGE_MS). Nothing was signed or sent; repeat the request for a fresh verdict.",
    );
    this.name = "StaleVerdict";
    this.ageMs = ageMs;
    this.maxMs = maxMs;
  }
}

/** The person (or the caller's hook) did not confirm: nothing was signed or sent. */
export class ConfirmationDeclined extends Error {
  constructor(label: string, why: string) {
    super(`[Graphite] ${label}: not confirmed (${why}). Nothing was signed or sent.`);
    this.name = "ConfirmationDeclined";
  }
}

/**
 * `sendRawTransaction` failed in a way that does not say whether the bytes
 * reached the network (Round 29, audit 2026-10-20, L2). The bytes were signed
 * and handed to the RPC; a timeout or a dropped connection can come after the
 * RPC forwarded them. The signature is known — it is in the signed bytes — and
 * is carried here, and was recorded on the trail as a submission attempt.
 * A caller MUST check this signature's status (or wait until
 * `lastValidBlockHeight` has passed) before building the same request again:
 * a rebuild is a new transaction, and both can land. The guard enforces this
 * for a repeat of the same request (`GraphiteGuard`).
 */
export class SubmissionOutcomeUnknown extends Error {
  readonly signature: string;
  readonly lastValidBlockHeight: number;
  readonly attemptRecorded: boolean;
  constructor(label: string, signature: string, lastValidBlockHeight: number, cause: string, attemptRecorded: boolean) {
    super(
      `[Graphite] ${label}: submitting ${signature} failed (${cause}), and the failure does not say whether ` +
        `the transaction reached the network. It may still land until block height ${lastValidBlockHeight}. ` +
        "Check this signature's status before retrying: a rebuilt transaction is a second transaction." +
        (attemptRecorded ? "" : " (The attempt could not be recorded on the audit trail either.)"),
    );
    this.name = "SubmissionOutcomeUnknown";
    this.signature = signature;
    this.lastValidBlockHeight = lastValidBlockHeight;
    this.attemptRecorded = attemptRecorded;
  }
}

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function pause(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
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
  //    accepts, and the Core's execution decision recomputed and compared
  //    (Round 30, G-01). Refuses on anything else, including a server that
  //    reports no codes and a decision that disagrees with its own scope.
  const decision = p.policy.assertExecutableVerdict(verification, label);
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

  // 1b. The caller's last say (Round 29, M7): after everything that can
  //     refuse has run, before the one irreversible local step.
  if (p.confirm) {
    const timeoutMs = p.confirmTimeoutMs ?? DEFAULT_CONFIRM_TIMEOUT_MS;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
      throw new ConfirmationDeclined(label, `the confirmation timeout ${String(timeoutMs)} is not a positive integer of milliseconds`);
    }
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timedOut = new Promise<"timeout">((resolve) => {
      timer = setTimeout(() => resolve("timeout"), timeoutMs);
    });
    let answer: unknown;
    try {
      answer = await Promise.race([p.confirm({ acceptedUnobserved: [...decision.accepted] }), timedOut]);
    } catch (e) {
      throw new ConfirmationDeclined(label, `the confirmation failed: ${message(e)}`);
    } finally {
      clearTimeout(timer);
    }
    if (answer === "timeout") throw new ConfirmationDeclined(label, `no answer within ${timeoutMs} ms`);
    // Exactly `true`: "yes", 1 or an object is not a confirmation.
    if (answer !== true) throw new ConfirmationDeclined(label, "declined");
  }

  // 2. The one signing path: digest and signer set re-derived over this
  //    object, compared against what Graphite hashed.
  p.beforeSign?.();
  // Round 35 (F-017): the verdict's age, with nothing awaited between this
  // check and the digest recomputation inside `signApproved`.
  if (p.verdictAge) {
    const { requestedAt, maxMs } = p.verdictAge;
    const age = (p.verdictAge.now ?? (() => performance.now()))() - requestedAt;
    if (!Number.isFinite(age) || !Number.isSafeInteger(maxMs) || maxMs < 1 || age > maxMs) {
      throw new StaleVerdict(label, Number.isFinite(age) ? age : Number.POSITIVE_INFINITY, maxMs);
    }
  }
  const raw = await p.bound.signApproved(scope.transaction_sha256, p.signers);
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
      ...bindKeyOf(verification),
      audit_trail_id: verification.audit_trail_id,
      transaction_sha256: scope.transaction_sha256,
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
  if (signing.verdict_on_record_key !== "audit_trail_id") {
    // The bridge sent the exact verification id; a server that answered by
    // a coarser key (or none) is not the server this bridge is written for,
    // and a content_hash-resolved "approved" may be about a different
    // transaction carrying the same instruction (Round 10).
    throw new Error(
      `[Graphite] ${label}: the audit trail resolved the signing by "${signing.verdict_on_record_key}", ` +
        "not by the exact audit_trail_id this bridge supplied. NOT submitting.",
    );
  }
  if (signing.verdict_on_record !== "approved") {
    // The server that verified this transaction is not the server whose
    // trail was just consulted, or the trail changed under us. Either way
    // the approval in hand is not the approval on record.
    throw new Error(
      `[Graphite] ${label}: the audit trail's verdict for ${verification.audit_trail_id} ` +
        `is "${signing.verdict_on_record}", not the approval this process holds. NOT submitting.`,
    );
  }

  // 4. Submission. From here nothing can be undone; every failure below is
  //    reported, none is a reason to pretend this did not happen.
  //
  //    The transaction's id is its fee payer's signature, which this process
  //    just made: it is read from the signed bytes (after the count for
  //    legacy and v0, first of the trailing array for v1), not taken from the
  //    RPC. An RPC that answered with some other id would otherwise steer the
  //    audit trail and L8 to a transaction of its choosing; its answer is
  //    compared and a disagreement is recorded, but the id used is ours.
  //
  //    Round 29 (L2): the id is computed BEFORE sending, so a send that fails
  //    ambiguously still leaves the caller holding it. It used to be thrown
  //    away with the error, and a retry built and signed a second transfer.
  const signature = firstSignatureOf(raw);
  if (p.beforeSubmit) {
    try {
      p.beforeSubmit(signature);
    } catch (e) {
      throw new Error(
        `[Graphite] ${label}: signed, but the submission of ${signature} could not be recorded before sending ` +
          `(${message(e)}). NOT submitting.`,
      );
    }
  }
  let reported: string;
  try {
    reported = await p.connection.sendRawTransaction(raw);
  } catch (e) {
    let attemptRecorded = false;
    try {
      await p.graphite.recordLifecycleEvent({
        event_type: "submission",
        ...bindKeyOf(verification),
        audit_trail_id: verification.audit_trail_id,
        transaction_sha256: scope.transaction_sha256,
        transaction_signature: signature,
        reported_by: p.reportedBy,
        detail: `submission ATTEMPT, outcome unknown: sendRawTransaction failed: ${message(e)}`.slice(0, 1024),
      });
      attemptRecorded = true;
    } catch (recordError) {
      log(`[Graphite] ${label}: the submission attempt of ${signature} could not be recorded: ${message(recordError)}`);
    }
    throw new SubmissionOutcomeUnknown(label, signature, p.bound.lastValidBlockHeight, message(e), attemptRecorded);
  }
  log(`[Graphite] ${label}: submitted ${signature}`);
  if (reported !== signature) {
    log(
      `[Graphite] ${label}: WARNING — the RPC reported the submission as ${reported}, but the signed ` +
        `bytes carry ${signature}. Using the signed bytes' id; the RPC's answer is not the transaction submitted.`,
    );
  }

  const lifecycle: ExecutionLifecycle = {
    signature,
    ...(reported !== signature ? { rpcReportedSignature: reported } : {}),
    acceptedUnobserved: decision.accepted,
    decision: decision.decision,
    reportedDecision: decision.reportedDecision,
    signingRecorded: true,
    verdictOnRecordAtSigning: signing.verdict_on_record,
    submissionRecorded: false,
    submissionRecordAttempts: 0,
    confirmed: false,
  };

  // 5. Submission on the trail, with the signature. Retried (Round 12): a
  //    submission the trail never hears of is a signature L8 cannot join
  //    until the reconciliation row itself lands, and one lost answer used
  //    to be the end of it. The server treats a repeat as a duplicate, so a
  //    retry after a lost answer is harmless.
  const attempts = Math.max(1, p.submissionRecordAttempts ?? 3);
  let backoff = Math.max(0, p.submissionRecordBackoffMs ?? 500);
  for (let attempt = 1; attempt <= attempts; attempt++) {
    lifecycle.submissionRecordAttempts = attempt;
    try {
      const receipt = await p.graphite.recordLifecycleEvent({
        event_type: "submission",
        ...bindKeyOf(verification),
        audit_trail_id: verification.audit_trail_id,
        transaction_sha256: scope.transaction_sha256,
        transaction_signature: signature,
        reported_by: p.reportedBy,
        // Round 30: an RPC that answered with another id is an anomaly the
        // trail keeps, not only a log line in this process.
        ...(reported !== signature
          ? { detail: `RPC ANOMALY: sendTransaction answered ${String(reported).slice(0, 100)}; the signed bytes carry ${signature}` }
          : {}),
      });
      lifecycle.submissionRecorded = true;
      lifecycle.submissionRecordError = undefined;
      const anomalies = receipt.sequence_anomalies ?? [];
      const serious = anomalies.filter((a) => !a.startsWith("duplicate"));
      if (serious.length > 0) {
        log(`[Graphite] ${label}: the trail flagged this submission report: ${serious.join(" | ")}`);
      }
      break;
    } catch (e) {
      lifecycle.submissionRecordError = message(e);
      if (attempt < attempts) {
        log(
          `[Graphite] ${label}: submission of ${signature} not yet recorded (attempt ${attempt}/${attempts}): ${message(e)} — retrying`,
        );
        await pause(backoff);
        backoff *= 2;
      } else {
        log(
          `[Graphite] ${label}: WARNING — submission of ${signature} was NOT recorded after ${attempts} attempt(s): ${message(e)}. ` +
            "The L8 reconciliation below carries the signature and is the recovery path.",
        );
      }
    }
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
      ...bindKeyOf(verification),
      transaction_sha256: scope.transaction_sha256,
      audit_trail_id: verification.audit_trail_id,
      reported_by: p.reportedBy,
    });
    const r = lifecycle.reconciliation;
    log(
      `[Graphite] ${label}: L8 reconciliation ${JSON.stringify(r.reconciliation)} (attribution: ${r.attribution})` +
        (r.audit_recorded ? "" : " (NOT recorded on the trail)"),
    );
    if (r.caller_keys_disagree.length > 0) {
      log(
        `[Graphite] ${label}: L8 resolved a different verification than this process holds: ` +
          r.caller_keys_disagree.join(" | "),
      );
    }
    if (r.chain_bytes_rejected) {
      log(
        `[Graphite] ${label}: L8 REFUSED — the RPC returned bytes for ${signature} that are not bound to it: ` +
          r.chain_bytes_rejected,
      );
    }
    if (r.chain_bytes_unavailable) {
      log(`[Graphite] ${label}: L8 attributed by this process's keys, not the chain's bytes: ${r.chain_bytes_unavailable}`);
    }
    if (r.chain_inconsistent) {
      log(`[Graphite] ${label}: L8 — the RPC contradicts itself about ${signature}: ${r.chain_inconsistent}`);
    }
    if (r.inclusion_witness && !r.inclusion_witness.agrees) {
      log(`[Graphite] ${label}: L8 — the inclusion witness disagrees: ${r.inclusion_witness.detail}`);
    }
    if (r.discrepancy) {
      log(`[Graphite] ${label}: L8 DISCREPANCY on ${signature} — Graphite's decision did not govern`);
    }
  } catch (e) {
    lifecycle.reconciliationError = message(e);
    log(`[Graphite] ${label}: L8 reconciliation of ${signature} failed: ${message(e)}`);
  }

  return lifecycle;
}
