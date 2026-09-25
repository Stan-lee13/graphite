/**
 * Whole-transaction binding: is THIS the transaction Graphite approved?
 *
 * Round 19 (F-19-C3). `content_hash` (auditbind.ts) binds one instruction —
 * program, discriminator, accounts, data, CPI targets. It cannot see the fee
 * payer, the blockhash, the signer set, the header, or any other instruction
 * in the transaction, so an appended drain passes it untouched. An
 * artifact-bound verdict carries something stronger: `scope.transaction_sha256`,
 * the SHA-256 of the exact bytes Graphite was shown. Until now neither SDK
 * gave a caller a way to check it, so every integration either skipped the
 * check or wrote its own parser for Solana's wire format.
 *
 * `verifyTransactionDigest(bytes, result)` is that check. It accepts the
 * unsigned artifact you sent, or the signed bytes you are about to submit:
 * every signature slot is zeroed before hashing, exactly as the Core's
 * `unsigned_artifact` does, so signing — which changes only the slots — does
 * not change the digest, and anything else does. Checking the SIGNED bytes is
 * the stronger use: it covers the window between the check and the signature.
 *
 * It fails closed on everything it cannot establish: a verdict that is not
 * `approved === true`, a scope that is absent or `descriptive`, a digest that
 * is missing or not 64 lowercase hex characters, and a frame whose signature
 * count is malformed. Like `verifyContentHash`, it throws and never returns a
 * boolean, so a forgotten `!` cannot turn it into a pass.
 */
import * as crypto from "crypto";
import { AuditBindError } from "./auditbind.js";

/**
 * The largest serialized transaction the network accepts: PACKET_DATA_SIZE =
 * 1280 − 40 − 8. Mirrors `MAX_TRANSACTION_BYTES` in
 * graphite-core/src/tx_artifact.rs.
 */
export const MAX_TRANSACTION_BYTES = 1232;

/**
 * The first byte of a v1 frame (SIMD-0385) and its size bound. Mirrors
 * `V1_PREFIX` / `MAX_V1_TRANSACTION_BYTES` in graphite-core/src/tx_artifact.rs.
 * A v1 frame is `0x81`, the message, then `num_required_signatures` × 64
 * signature bytes LAST, with no count in front of them.
 */
export const V1_PREFIX = 0x81;
export const MAX_V1_TRANSACTION_BYTES = 4096;
/** `v1::MAX_SIGNATURES` in the runtime. */
const V1_MAX_SIGNATURES = 12;

/**
 * Read the compact-u16 signature count at the front of a serialized
 * transaction. Strict, and deliberately the Core's rules (tx_artifact.rs
 * `compact_u16`): at most three bytes, the third must terminate, minimally
 * encoded (a multi-byte form whose last group is zero is a second spelling of
 * a shorter number), and no larger than a u16. Two parsers of one wire format
 * that accept different languages would let one frame mean two things.
 */
export function readSignatureCount(bytes: Uint8Array): { count: number; offset: number } {
  let count = 0;
  let offset = 0;
  for (let group = 0; group < 3; group++) {
    const byte = bytes[offset++];
    if (byte === undefined) {
      throw new AuditBindError("truncated signature count. ABORTING.");
    }
    const bits = byte & 0x7f;
    count |= bits << (group * 7);
    if ((byte & 0x80) === 0) {
      if (group > 0 && bits === 0) {
        throw new AuditBindError(
          "signature count is not minimally encoded — two spellings of one length. ABORTING.",
        );
      }
      if (count > 0xffff) {
        throw new AuditBindError(`signature count ${count} does not fit a u16. ABORTING.`);
      }
      return { count, offset };
    }
  }
  throw new AuditBindError("signature count continues past its third byte. ABORTING.");
}

/**
 * Lowercase-hex SHA-256 of a serialized transaction with every signature slot
 * zeroed — the value the Core reports as `scope.transaction_sha256` for the
 * unsigned artifact it was shown.
 */
export function transactionDigest(bytes: Uint8Array): string {
  if (bytes[0] === V1_PREFIX) return v1Digest(bytes);
  if (bytes.length > MAX_TRANSACTION_BYTES) {
    throw new AuditBindError(
      `transaction is ${bytes.length} bytes; a Solana transaction is at most ` +
        `${MAX_TRANSACTION_BYTES}. ABORTING.`,
    );
  }
  const { count, offset } = readSignatureCount(bytes);
  if (count === 0) {
    throw new AuditBindError(
      "the transaction declares no signatures; every Solana transaction has a fee payer. ABORTING.",
    );
  }
  const end = offset + count * 64;
  if (end >= bytes.length) {
    throw new AuditBindError(
      `${count} signature slot(s) run past (or up to the end of) a ${bytes.length}-byte ` +
        "transaction; there is no message to bind. ABORTING.",
    );
  }
  const unsigned = Uint8Array.from(bytes);
  unsigned.fill(0, offset, end);
  return crypto.createHash("sha256").update(unsigned).digest("hex");
}

/**
 * The digest of a v1 frame: its trailing `num_required_signatures` × 64
 * bytes zeroed (Round 19). This does not parse the message; it does not
 * need to. The Core refuses a v1 frame whose message does not end exactly
 * where those slots begin, so it never approved one — and a digest that
 * matches an approval can only be of bytes identical to the approved
 * frame outside the slots. Everything that can be checked cheaply is still
 * checked, so a malformed frame fails here rather than as a mismatch.
 */
function v1Digest(bytes: Uint8Array): string {
  if (bytes.length > MAX_V1_TRANSACTION_BYTES) {
    throw new AuditBindError(
      `v1 transaction is ${bytes.length} bytes; a v1 transaction is at most ` +
        `${MAX_V1_TRANSACTION_BYTES}. ABORTING.`,
    );
  }
  const count = bytes[1];
  if (count === undefined || count === 0 || count > V1_MAX_SIGNATURES) {
    throw new AuditBindError(
      `v1 header declares ${count ?? "no"} required signature(s); the runtime requires ` +
        `1 to ${V1_MAX_SIGNATURES}. ABORTING.`,
    );
  }
  const start = bytes.length - count * 64;
  // 0x81, the 3-byte header, the 4-byte config mask and the 32-byte
  // lifetime come before any signature.
  if (start < 40) {
    throw new AuditBindError(
      `${count} trailing signature slot(s) do not fit a ${bytes.length}-byte v1 frame. ABORTING.`,
    );
  }
  const unsigned = Uint8Array.from(bytes);
  unsigned.fill(0, start);
  return crypto.createHash("sha256").update(unsigned).digest("hex");
}

/** The fields of a verification result this check reads. */
export interface DigestBindableResult {
  approved?: unknown;
  scope?: { kind?: unknown; transaction_sha256?: unknown } | null;
}

/**
 * Throw unless `transactionBytes` is the transaction an APPROVED,
 * ARTIFACT-BOUND verdict was issued for. Call it immediately before signing
 * (on the unsigned bytes) or before submitting (on the signed bytes).
 */
export function verifyTransactionDigest(
  transactionBytes: Uint8Array | number[],
  result: DigestBindableResult | null | undefined,
): void {
  if (result === null || typeof result !== "object") {
    throw new AuditBindError("no verification result. ABORTING.");
  }
  if (result.approved !== true) {
    throw new AuditBindError(
      "the verdict is not an approval — a blocked or malformed result binds nothing. ABORTING.",
    );
  }
  const scope = result.scope;
  if (scope === null || scope === undefined || typeof scope !== "object") {
    throw new AuditBindError(
      "the verdict carries no scope, so whether it was bound to transaction bytes is unknown " +
        "(servers before 2026-09-08). ABORTING.",
    );
  }
  if (scope.kind !== "artifact_bound") {
    throw new AuditBindError(
      `the verdict's scope is ${JSON.stringify(scope.kind)}, not artifact_bound: Graphite was ` +
        "not shown a transaction, so no transaction can be bound to it. ABORTING.",
    );
  }
  const approved = scope.transaction_sha256;
  if (typeof approved !== "string" || !/^[0-9a-f]{64}$/.test(approved)) {
    throw new AuditBindError(
      "scope.transaction_sha256 is missing or is not 64 lowercase hex characters. ABORTING.",
    );
  }
  const computed = transactionDigest(Uint8Array.from(transactionBytes));
  if (computed !== approved) {
    throw new AuditBindError(
      `transaction digest mismatch (computed ${computed}, approved ${approved}). These are not ` +
        "the bytes Graphite verified. ABORTING.",
    );
  }
}
