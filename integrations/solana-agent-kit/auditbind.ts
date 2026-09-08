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

  /**
   * Build the AuditBind projection from a REAL instruction payload (the same
   * projection the Rust Core hashes): programId + discriminator (first 8
   * bytes of the instruction data, hex) + account keys + raw data bytes.
   *
   * Accepts an already-stringified web3 instruction shape so this module
   * stays dependency-free (the bridge adapts TransactionInstruction objects
   * into this shape with `.programId.toBase58()` etc.).
   */
  static projectionFromInstruction(input: {
    programId: string; // base58
    data: Uint8Array; // raw instruction data bytes
    accounts: string[]; // base58 account keys, in instruction order
    /**
     * The instruction discriminator, hex, EXACTLY as it was sent to Graphite.
     *
     * Required for any program that does not use Anchor's 8-byte convention,
     * which is every native program. Omitting it falls back to the first 8
     * bytes of the data, and for a System transfer that yields
     * `0200000040420f00` — the 4-byte discriminator plus four bytes of the
     * lamport amount — instead of `02000000`. The resulting hash cannot match
     * the one Graphite computed, so the check aborts every time.
     *
     * That mismatch is why the SAK bridge reconstructed its projection from
     * local string constants instead of calling this, which is how the TOCTOU
     * window opened: the reconstruction is a snapshot taken before the window
     * it was supposed to cover, so it could not see the instruction being
     * rewritten (found 2026-09-08, `toctou-signing-boundary.test.ts`).
     */
    discriminator?: string;
  }): AuditBindTransactionParams {
    const dataBytes = input.data ?? new Uint8Array(0);
    const discriminator =
      input.discriminator ??
      Buffer.from(dataBytes.subarray(0, 8)).toString("hex");
    return {
      programId: input.programId,
      instructionDiscriminator: discriminator,
      accountAddresses: input.accounts,
      instructionData: dataBytes.length > 0 ? Array.from(dataBytes) : undefined,
    };
  }

  /**
   * A deterministic binding over EVERY instruction in a transaction.
   *
   * `content_hash` covers the instruction Graphite verified. It cannot cover
   * one that did not exist at verification time, so an attacker who leaves the
   * approved instruction untouched and APPENDS a second one passes a
   * per-instruction check unchanged — the same shape as the attack L4 exists to
   * catch, moved to the signing boundary.
   *
   * Compare this before signing against the value taken at approval time. Any
   * addition, removal or reordering changes it.
   */
  static transactionBinding(
    instructions: {
      programId: string;
      data: Uint8Array;
      accounts: string[];
      discriminator?: string;
    }[],
  ): string {
    const hasher = crypto.createHash("sha256");
    hasher.update(String(instructions.length), "utf8");
    for (const ix of instructions) {
      // Length-prefixed per instruction so that concatenation is unambiguous:
      // without it, moving a byte from one instruction to the next would leave
      // the digest unchanged.
      const h = AuditBind.computeHash(AuditBind.projectionFromInstruction(ix));
      hasher.update(String(h.length), "utf8");
      hasher.update(h, "utf8");
    }
    return hasher.digest("hex").slice(0, 32);
  }

  /**
   * Assert a transaction still holds exactly the instructions it held when the
   * binding was taken. Throws on any change.
   */
  static verifyTransactionUnchanged(
    instructions: {
      programId: string;
      data: Uint8Array;
      accounts: string[];
      discriminator?: string;
    }[],
    expectedBinding: string,
  ): void {
    const actual = AuditBind.transactionBinding(instructions);
    if (actual !== expectedBinding) {
      throw new Error(
        `AuditBind FAILED: the transaction's instruction set changed after approval ` +
          `(binding ${actual}, expected ${expectedBinding}). ABORTING.`,
      );
    }
  }

  /**
   * Verify an actual instruction payload against the approved content_hash.
   * This closes the swap-path TOCTOU gap (audit finding C2): instead of
   * binding a reduced `programId + discriminator + wallet` projection, the
   * caller binds the EXACT instruction (full account list + raw data) that
   * will be submitted. Any mutation of the instruction between verification
   * and submission changes the hash and ABORTS.
   */
  static verifyInstruction(
    ix: {
      programId: string;
      data: Uint8Array;
      accounts: string[];
      discriminator?: string;
    },
    contentHash: string,
  ): void {
    AuditBind.verify({
      transaction: AuditBind.projectionFromInstruction(ix),
      contentHash,
    });
  }
}
