/**
 * AuditBind — TOCTOU binding between what Graphite verified and what you submit.
 *
 * Graphite verifies a transaction BEFORE it is signed. Between that approval
 * and the moment the transaction actually reaches the chain there is a window
 * in which the instruction can still be mutated — by a compromised RPC proxy,
 * a malicious wallet adapter, or simply a race inside the agent's own
 * pipeline. Verification that is not bound to the submitted bytes protects
 * nothing against that window.
 *
 * `content_hash` on a `VerificationResult` is the binding key: a deterministic
 * hash over exactly the transaction inputs (never the verification outcome, so
 * a client can reproduce it before submitting). Re-compute it from the
 * instruction you are about to send and compare. Any mutation changes the hash
 * and `verifyContentHash` throws.
 *
 * This module has NO dependencies beyond Node's `crypto`, deliberately: it
 * must be usable from any integration without dragging in a wallet or agent
 * framework, and its cross-language parity tests must run standalone.
 *
 * WHY THIS LIVES HERE (2026-09-05 SDK audit): this logic previously existed
 * only inside `integrations/solana-agent-kit/auditbind.ts`, so every developer
 * NOT using SolanaAgentKit either shipped an open TOCTOU window or reinvented
 * the hash themselves. That reinvention is exactly where it went wrong before:
 * an earlier `"|"`-joined encoding never matched the Rust byte stream, so the
 * check could never pass and always aborted. The byte layout below is pinned
 * against the Rust core by the vectors in `auditbind.test.ts`.
 */
import * as crypto from "crypto";

/**
 * The exact projection the Rust core hashes. Field ORDER is part of the
 * contract — the hash is over concatenated bytes, not a keyed structure.
 */
export interface AuditBindTransactionParams {
  /** base58 program id */
  programId: string;
  /** hex instruction discriminator */
  instructionDiscriminator: string;
  /** base58 account addresses, in instruction order */
  accountAddresses: string[];
  /** raw instruction data bytes (omit or empty when there are none) */
  instructionData?: number[];
  /** base58 CPI target program ids */
  cpiTargets?: string[];
}

/**
 * Reproduce the Rust core's deterministic `content_hash`
 * (graphite-core/src/verification.rs::generate_audit_id).
 *
 * SHA-256 over the concatenated UTF-8 bytes of
 *   programId || instructionDiscriminator || each account address
 *   || raw instruction-data bytes (if any) || each CPI target
 * truncated to the first 16 hex characters (the first 8 bytes of the digest).
 *
 * Both sides must agree on the exact byte sequence or this check is worthless
 * — see `auditbind.test.ts` for the pinned cross-language vectors.
 */
export function computeContentHash(params: AuditBindTransactionParams): string {
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

/** Thrown when the transaction about to be submitted is not the one Graphite verified. */
export class AuditBindError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuditBindError";
  }
}

/**
 * Verify a transaction projection against the approved `content_hash`.
 *
 * Throws `AuditBindError` on any mismatch — never returns a boolean, so a
 * caller cannot accidentally ignore the result the way `if (check(...))` with
 * a forgotten `!` would allow. Call it after `approved === true` and
 * immediately before signing/submitting.
 */
export function verifyContentHash(
  transaction: AuditBindTransactionParams,
  contentHash: string,
): void {
  // Fail closed on the wrong field: `audit_trail_id` is prefixed "gr-" and is
  // NOT reproducible by a client (it mixes in the verification outcome and a
  // sequence number). Silently "checking" it would mean never detecting a
  // mutation at all, so this is an error, not a skip.
  if (contentHash.startsWith("gr-")) {
    throw new AuditBindError(
      "received audit_trail_id instead of content_hash — the TOCTOU check " +
        "cannot be performed. Pass result.content_hash. ABORTING.",
    );
  }
  if (!contentHash) {
    throw new AuditBindError(
      "empty content_hash — the TOCTOU check cannot be performed. ABORTING.",
    );
  }
  const computed = computeContentHash(transaction);
  if (computed !== contentHash) {
    throw new AuditBindError(
      `hash mismatch (computed ${computed}, approved ${contentHash}). The ` +
        "transaction changed between verification and submission. ABORTING.",
    );
  }
}

/**
 * Build the hash projection from a real instruction's raw bytes.
 *
 * The discriminator is the first 8 bytes of the instruction data, hex-encoded
 * — matching how the core derives it. Takes already-stringified fields so this
 * module stays dependency-free; adapt a `@solana/web3.js` TransactionInstruction
 * with `ix.programId.toBase58()` and `ix.keys.map(k => k.pubkey.toBase58())`.
 */
export function projectionFromInstruction(input: {
  programId: string;
  data: Uint8Array;
  accounts: string[];
}): AuditBindTransactionParams {
  const dataBytes = input.data ?? new Uint8Array(0);
  const discriminator = Buffer.from(dataBytes.subarray(0, 8)).toString("hex");
  return {
    programId: input.programId,
    instructionDiscriminator: discriminator,
    accountAddresses: input.accounts,
    instructionData: dataBytes.length > 0 ? Array.from(dataBytes) : undefined,
  };
}

/**
 * Verify a real instruction payload against the approved `content_hash`.
 * Convenience wrapper over `projectionFromInstruction` + `verifyContentHash`.
 */
export function verifyInstruction(
  instruction: { programId: string; data: Uint8Array; accounts: string[] },
  contentHash: string,
): void {
  verifyContentHash(projectionFromInstruction(instruction), contentHash);
}
