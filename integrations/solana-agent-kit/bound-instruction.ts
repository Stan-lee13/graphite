/**
 * BoundInstructionPayload / buildInstructionFromPayload — the TOCTOU
 * closure `executeSwap` (graphite-sak-bridge.ts) depends on for the
 * payload-provided swap path (P1 fix, 2026-09-05 audit: "SolanaAgentKit
 * swap-path TOCTOU residual").
 *
 * Deliberately depends on `@solana/web3.js` ONLY — not `solana-agent-kit`
 * or its plugins — for the same reason `auditbind.ts` stays dependency-free
 * of the SAK tree: a broken transitive export in an SAK plugin (observed
 * 2026-09-05: `@pump-fun/pump-sdk` failing to provide `PumpSdk`) must not
 * be able to prevent this module, or its tests, from loading. If this logic
 * lived inside graphite-sak-bridge.ts directly, importing it for a unit
 * test would drag in the entire SAK plugin tree and hit exactly that class
 * of unrelated breakage.
 */
import { PublicKey, TransactionInstruction } from "@solana/web3.js";

export interface BoundInstructionPayload {
  programId: string;
  discriminator: string;
  accounts: { pubkey: string; isSigner: boolean; isWritable: boolean }[];
  instructionData?: number[];
}

/**
 * Build a real `TransactionInstruction` from a `BoundInstructionPayload`,
 * using exactly the fields AuditBind hashes (programId, account pubkeys in
 * order, raw instruction data) plus the caller-supplied signer/writable
 * flags. Pure and independently testable: the whole point is that what gets
 * submitted is deterministically derived from what was verified, not a
 * second, separately-maintained code path that merely happens to agree.
 *
 * isSigner/isWritable are trusted from the caller for EXECUTION — the same
 * trust boundary `executeTransfer`'s raw `SystemProgram.transfer(...)`
 * construction and every other caller of `TransactionInstruction` already
 * rests on. For VERIFICATION, `executeSwap` now forwards these same
 * per-account flags to Graphite as `VerificationInput.real_account_metas`
 * before building this instruction, closing the P1 "signer/writable
 * metadata is not grounded in actual transaction AccountMeta data" gap for
 * the payload-bound path (2026-09-05): the Core cross-checks them against
 * the manifest's declared signer/writable expectations and hard-blocks a
 * security-relevant mismatch (a required signer not actually signed, or a
 * readonly slot marked writable) before this function is ever called.
 */
export function buildInstructionFromPayload(payload: BoundInstructionPayload): TransactionInstruction {
  return new TransactionInstruction({
    programId: new PublicKey(payload.programId),
    keys: payload.accounts.map((a) => ({
      pubkey: new PublicKey(a.pubkey),
      isSigner: a.isSigner,
      isWritable: a.isWritable,
    })),
    data: Buffer.from(payload.instructionData ?? []),
  });
}
