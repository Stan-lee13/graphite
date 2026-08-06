/**
 * AuditBind — TOCTOU prevention middleware.
 *
 * After Graphite approves, re-hashes the actual transaction's key fields and
 * compares against Graphite's deterministic `content_hash`. Blocks execution if
 * the transaction was mutated between verification and submission.
 *
 * This module is intentionally dependency-free (Node `crypto` only) so the
 * cross-language pinned-vector tests in `auditbind.test.ts` can run without the
 * rest of the SAK dependency tree.
 */
import * as crypto from "crypto";

export interface AuditBindTransactionParams {
  programId: string;
  instructionDiscriminator: string;
  accountAddresses: string[];
  instructionData?: number[];
  cpiTargets?: string[];
}

export class AuditBind {
  /**
   * Computes the SAME deterministic content_hash the Rust Core produces
   * (graphite-core/src/verification.rs::generate_audit_id): SHA-256 over the
   * concatenated UTF-8 bytes of
   *   programId || instructionDiscriminator || each account address
   *   || raw instruction-data bytes (if any) || each CPI target,
   * truncated to the first 16 hex characters. The previous "|"-joined / comma
   * string encoding NEVER matched the Rust byte stream, so the TOCTOU check
   * could never succeed (it always aborted). The two sides must agree on the
   * exact byte sequence or AuditBind is worthless — see auditbind.test.ts for
   * the cross-language pinned vectors.
   */
  static computeHash(params: AuditBindTransactionParams): string {
    const hasher = crypto.createHash("sha256");
    hasher.update(params.programId, "utf8");
    hasher.update(params.instructionDiscriminator, "utf8");
    for (const addr of params.accountAddresses) {
      hasher.update(addr, "utf8");
    }
    if (params.instructionData && params.instructionData.length > 0) {
      hasher.update(Buffer.from(params.instructionData));
    }
    for (const target of params.cpiTargets ?? []) {
      hasher.update(target, "utf8");
    }
    return hasher.digest("hex").slice(0, 16);
  }

  static verify(params: {
    transaction: AuditBindTransactionParams;
    contentHash: string;
  }): void {
    // SECURITY FIX: If contentHash starts with "gr-", it means we received
    // audit_trail_id instead of content_hash — fail-closed (throw, not skip).
    if (params.contentHash.startsWith("gr-")) {
      throw new Error(
        `[AuditBind] content_hash not available from API (got audit_trail_id). ` +
          `TOCTOU check cannot be performed — ABORTING.`
      );
    }
    const computed = AuditBind.computeHash(params.transaction);
    if (computed !== params.contentHash) {
      throw new Error(
        `AuditBind FAILED: hash mismatch (computed: ${computed}, expected: ${params.contentHash}). ` +
          `Transaction may have been mutated. ABORTING.`
      );
    }
    console.log(`[AuditBind] Hash verified: ${computed}`);
  }
}
