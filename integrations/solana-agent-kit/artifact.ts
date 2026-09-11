/**
 * Give the Core the bytes, not just a description of them.
 *
 * The bridge builds the exact instructions it intends to execute, simulates
 * them, and then sent Graphite only a description: program id, discriminator,
 * account list. That put every verification through this integration into the
 * Core's Descriptive mode — the weaker of the two — while the artifact that
 * settles the questions Descriptive mode cannot answer was sitting in a local
 * variable.
 *
 * Artifact-bound verification is where the Core reads the message itself: the
 * signer and writable flags out of the header rather than out of the request,
 * the instruction's account list position by position, every other instruction
 * in the transaction, and the lookup tables. None of that is reachable without
 * the bytes.
 *
 * What is serialized here is UNSIGNED, with placeholder signature bytes, which
 * is exactly the shape Graphite is built for: it is a pre-signature gate and
 * never verifies a signature. Nothing in this module signs, sends, or touches
 * an account.
 *
 * The blockhash is a real recent one, and as of `BoundTransaction` below it IS
 * part of what gets bound: the same transaction object is verified, signed and
 * submitted, so a refreshed blockhash is a different transaction and has to be
 * re-verified. This paragraph previously said the opposite — that the executed
 * transaction would carry a fresher blockhash and only the instructions had to
 * match. That was true of the code and it was the gap.
 */

import { createHash } from "node:crypto";
import {
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";

/** One entry of the Core's `transaction_instructions`. */
export interface DeclaredInstruction {
  program_id: string;
  instruction_discriminator: string;
  account_addresses: string[];
  cpi_targets: string[];
}

function keyToBase58(key: PublicKey | string): string {
  return typeof key === "string" ? key : key.toBase58();
}

function dataHex(ix: TransactionInstruction): string {
  return Buffer.from(ix.data ?? new Uint8Array(0)).toString("hex");
}

function accountsOf(ix: TransactionInstruction): string[] {
  return ix.keys.map((k) => keyToBase58(k.pubkey));
}

/**
 * The unsigned wire-format transaction, as a byte array for `signed_transaction`.
 *
 * Throws rather than returning something partial: an artifact that does not
 * serialize is not an artifact, and sending a truncated one would make the Core
 * fall back to its weaker presence check while the request looked artifact-bound.
 */
export function serializeUnsignedArtifact(params: {
  instructions: TransactionInstruction[];
  feePayer: PublicKey;
  recentBlockhash: string;
}): number[] {
  const tx = new Transaction({
    feePayer: params.feePayer,
    recentBlockhash: params.recentBlockhash,
  });
  tx.add(...params.instructions);
  const bytes = tx.serialize({
    requireAllSignatures: false,
    verifySignatures: false,
  });
  return Array.from(bytes);
}

/**
 * Which instruction in the list is the one being verified.
 *
 * Same three things the Core matches on: program, the discriminator as a prefix
 * of the data, and the account list in order. Returns -1 when none matches,
 * which is worth surfacing rather than papering over — it means the request
 * describes an instruction the transaction does not contain, and the Core will
 * say so.
 */
export function findPrimaryIndex(
  instructions: TransactionInstruction[],
  primary: {
    programId: string;
    instructionDiscriminator: string;
    accountAddresses: string[];
  },
): number {
  const wanted = primary.accountAddresses.join(",");
  return instructions.findIndex(
    (ix) =>
      keyToBase58(ix.programId) === primary.programId &&
      dataHex(ix).startsWith(primary.instructionDiscriminator.toLowerCase()) &&
      accountsOf(ix).join(",") === wanted,
  );
}

/**
 * Every instruction except the primary, described so the Core can check the
 * description against the bytes.
 *
 * The discriminator is the instruction's FULL data, hex-encoded. That is a
 * prefix of itself, so the Core's correspondence check matches it; and a
 * manifest selector is a prefix of it, so manifest lookup for the sibling still
 * resolves. Guessing a shorter selector would mean encoding per-program
 * knowledge here, in the one place that should not need any.
 *
 * Every declared sibling is risk-assessed by the Core as a secondary
 * instruction, so declaring them buys scrutiny — it is not a way to wave them
 * through.
 */
export function declareSiblings(
  instructions: TransactionInstruction[],
  primaryIndex: number,
): DeclaredInstruction[] {
  return instructions
    .map((ix, i) => ({ ix, i }))
    .filter(({ i }) => i !== primaryIndex)
    .map(({ ix }) => ({
      program_id: keyToBase58(ix.programId),
      instruction_discriminator: dataHex(ix),
      account_addresses: accountsOf(ix),
      // CPI targets are not in a message and cannot be read from one. Declaring
      // none here says nothing false: the Core's scope already reports that
      // inner instructions are visible only through simulation effects.
      cpi_targets: [],
    }));
}

/**
 * The real per-account signer/writable bits of one instruction, in its own
 * account order.
 *
 * The Core derives these from the artifact's header now and uses a caller's
 * only when it cannot. Supplying them anyway is still worth doing: where the
 * two disagree the Core says the caller's description of these bytes is
 * unreliable, and that is a signal about the integration worth having rather
 * than one worth hiding.
 */
export function realAccountMetas(
  ix: TransactionInstruction,
): { is_signer: boolean; is_writable: boolean }[] {
  return ix.keys.map((k) => ({
    is_signer: k.isSigner,
    is_writable: k.isWritable,
  }));
}

/**
 * One transaction, carried from verification through to submission.
 *
 * The gap this closes: the bridge serialized an artifact for Graphite and then
 * built a SEPARATE `Transaction` to execute, letting `sendAndConfirmTransaction`
 * prepare it. Graphite's strongest statement is "these exact bytes were
 * verified", and the bytes it verified were not the bytes that got signed. What
 * stood in between was AuditBind, which proves the instructions still match —
 * strong, and a different invariant. It cannot see the fee payer, the
 * blockhash, the message version, the header, or the lookup structure, because
 * none of those are instruction-level facts.
 *
 * What is provable here and what is not, stated precisely rather than rounded up:
 *
 *   - The verified artifact carries EMPTY signature slots; the submitted one
 *     carries a real signature. Whole-transaction byte equality is therefore
 *     impossible by construction, and any claim of it would be false.
 *   - The stable invariant is the MESSAGE — everything after the signature
 *     array. That is the part Solana executes and the part a signature commits
 *     to, and it is byte-identical across the two.
 *
 * So the guarantee is: the message inside the bytes submitted to the network is
 * byte-identical to the message inside the bytes Graphite approved. The digest
 * comparison before signing proves nothing mutated the object in between; the
 * message slice after signing proves signing itself changed nothing but the
 * signatures.
 */
export class BoundTransaction {
  private constructor(
    /**
     * The single object that is verified, signed and submitted.
     *
     * Private, and built from COPIES of the caller's instructions. Both matter
     * and they close different holes. `readonly` on a public field prevented
     * reassignment and nothing else: a caller who kept its own reference to an
     * instruction, an AccountMeta array, or a data Buffer could mutate the
     * transaction through that alias, because JavaScript shares those by
     * reference. The digest check caught every such mutation — but catching a
     * mutation is detection, and this is structure: there is no longer a
     * reference outside this object through which the transaction can be
     * reached at all.
     *
     * TypeScript `private` is compile-time only. Code that reaches in with
     * `as any` is a hostile in-process actor, and the digest check remains for
     * exactly that case. The two together are the design.
     */
    private readonly tx: Transaction,
    /** The unsigned serialization handed to Graphite. */
    readonly artifactBytes: Uint8Array,
    /** The message, captured before verification. */
    readonly messageBytes: Uint8Array,
    /** Needed to confirm the submission against the blockhash it was built on. */
    readonly lastValidBlockHeight: number,
  ) {}

  /**
   * Deep-copy an instruction so nothing the caller holds reaches the bound
   * transaction.
   *
   * Every field is copied by value: the program id and each pubkey through
   * their bytes, the data through a fresh Buffer, the meta flags as primitives.
   * `data` in particular is a Buffer the caller may still hold — a shared
   * buffer is a shared transaction.
   */
  private static isolate(ix: TransactionInstruction): TransactionInstruction {
    return new TransactionInstruction({
      programId: new PublicKey(ix.programId.toBytes()),
      keys: ix.keys.map((k) => ({
        pubkey: new PublicKey(k.pubkey.toBytes()),
        isSigner: k.isSigner,
        isWritable: k.isWritable,
      })),
      data: Buffer.from(ix.data),
    });
  }

  static build(params: {
    instructions: TransactionInstruction[];
    feePayer: PublicKey;
    recentBlockhash: string;
    lastValidBlockHeight: number;
  }): BoundTransaction {
    const tx = new Transaction({
      feePayer: new PublicKey(params.feePayer.toBytes()),
      recentBlockhash: params.recentBlockhash,
    });
    tx.add(...params.instructions.map(BoundTransaction.isolate));
    const artifactBytes = Uint8Array.from(
      tx.serialize({ requireAllSignatures: false, verifySignatures: false }),
    );
    return new BoundTransaction(
      tx,
      artifactBytes,
      Uint8Array.from(tx.serializeMessage()),
      params.lastValidBlockHeight,
    );
  }

  /** The bytes to send as `signed_transaction`. */
  artifact(): number[] {
    return Array.from(this.artifactBytes);
  }

  /**
   * The instructions, as fresh copies.
   *
   * A caller that needs to project them (AuditBind does) gets objects it can do
   * anything to without touching the transaction. Returning the internal ones
   * would hand back the alias `isolate` exists to remove.
   */
  instructions(): TransactionInstruction[] {
    return this.tx.instructions.map(BoundTransaction.isolate);
  }

  /** The blockhash this transaction was built on. */
  get recentBlockhash(): string {
    // Set in `build`; a Transaction constructed with one always has one.
    return this.tx.recentBlockhash as string;
  }

  /**
   * Check the digest and sign, as one indivisible step.
   *
   * The two used to be separate calls, adjacent in the bridge. That is safe in
   * JavaScript — nothing can run between two synchronous statements with no
   * await between them — but it was safe by arrangement rather than by
   * construction, and an arrangement is one refactor away from a window. There
   * is now no API through which this object can be signed without its digest
   * being checked first, because signing is not separately reachable.
   *
   * Returns the exact bytes to submit. Nothing else may be submitted: they are
   * the only thing here that has been checked end to end.
   */
  signApproved(approvedSha256: string, signers: Keypair[]): Uint8Array {
    this.assertApproved(approvedSha256);
    this.assertSignersMatchTheMessage(signers);
    return this.signAndFreeze(signers);
  }

  /**
   * The signers must be exactly the ones this message requires.
   *
   * Graphite is a pre-signature gate and does not verify signatures, so nothing
   * downstream of it would notice a transaction signed by the wrong key, or one
   * short of a required signature — the network would reject it, which is a
   * failed transaction rather than a wrong one, but it is also the shape in
   * which an extra unexpected signer would slip through unremarked.
   *
   * The requirement is read out of the message rather than taken from the
   * caller: `numRequiredSignatures` over the compiled account keys is what
   * Solana itself will demand.
   */
  private assertSignersMatchTheMessage(signers: Keypair[]): void {
    const message = this.tx.compileMessage();
    const required = message.accountKeys
      .slice(0, message.header.numRequiredSignatures)
      .map((k) => k.toBase58())
      .sort();
    const supplied = signers.map((s) => s.publicKey.toBase58()).sort();
    const same =
      required.length === supplied.length &&
      required.every((k, i) => k === supplied[i]);
    if (!same) {
      throw new Error(
        `[Graphite] The signer set does not match the transaction. This message requires ` +
          `[${required.join(", ")}] and was given [${supplied.join(", ")}]. Signing with the ` +
          `wrong set, or one short of it, produces a transaction that is not the one that was ` +
          `approved. ABORTING.`,
      );
    }
  }

  /**
   * Re-serialize now and require the digest Graphite approved.
   *
   * Private: reachable only through `signApproved`, so it cannot be called and
   * then forgotten. Recomputing rather than comparing a stored value is the
   * point — a stored digest would still match after the object moved on.
   */
  private assertApproved(approvedSha256: string): void {
    const now = Uint8Array.from(
      this.tx.serialize({ requireAllSignatures: false, verifySignatures: false }),
    );
    const digest = createHash("sha256").update(now).digest("hex");
    if (digest !== approvedSha256) {
      throw new Error(
        `[Graphite] The transaction changed between approval and signing. ` +
          `Graphite approved ${approvedSha256}; this transaction now serializes to ${digest}. ` +
          `ABORTING rather than signing something that was not verified. If the blockhash ` +
          `needed refreshing, rebuild and re-verify — a new blockhash is a new transaction.`,
      );
    }
  }

  /**
   * Sign, then prove the submitted bytes carry the message that was approved.
   *
   * The message is read back out of the signed bytes by slicing off the
   * signature array rather than by re-compiling the transaction object: a
   * recompile would be asking the same code that built it whether it built it,
   * and would hide exactly the mutation this is looking for.
   */
  private signAndFreeze(signers: Keypair[]): Uint8Array {
    this.tx.sign(...signers);
    const raw = Uint8Array.from(this.tx.serialize());
    const submitted = messageOf(raw);
    if (!equalBytes(submitted, this.messageBytes)) {
      throw new Error(
        "[Graphite] The message inside the signed transaction is not the message that was " +
          "verified. Signing must change only the signatures. ABORTING.",
      );
    }
    return raw;
  }
}

/**
 * The message half of a serialized transaction: everything after the signatures.
 *
 * This is a second implementation of Solana's compact-u16 in a second language,
 * and two parsers of one wire format must accept the same language or the
 * format has effectively forked. The Rust core learned this the hard way: its
 * ShortU16 reader accepted values up to 2,097,151 until a review caught it. The
 * rules below are that reader's, deliberately:
 *
 *   - at most three groups, and the third must terminate;
 *   - minimally encoded — a multi-byte form whose final group is zero is a
 *     second spelling of a shorter number, and two spellings of one length are
 *     what a binding exists to prevent;
 *   - no larger than a u16, which is what the field is.
 *
 * A malformed count must never yield a plausible slice. Getting this wrong
 * would not read out of bounds — the bounds check below catches that — it would
 * silently compare the WRONG range of one transaction against the right range
 * of another, which is worse.
 */
export function messageOf(raw: Uint8Array): Uint8Array {
  let offset = 0;
  let count = 0;
  let terminated = false;
  for (let group = 0; group < 3; group++) {
    const byte = raw[offset++];
    if (byte === undefined) {
      throw new Error("[Graphite] truncated signature count");
    }
    const bits = byte & 0x7f;
    count |= bits << (group * 7);
    if ((byte & 0x80) === 0) {
      if (group > 0 && bits === 0) {
        throw new Error(
          "[Graphite] signature count is not minimally encoded — two spellings of one length",
        );
      }
      terminated = true;
      break;
    }
  }
  if (!terminated) {
    throw new Error("[Graphite] signature count continues past its third byte");
  }
  if (count > 0xffff) {
    throw new Error(
      `[Graphite] signature count ${count} does not fit the u16 this field is`,
    );
  }
  offset += count * 64;
  if (offset > raw.length) {
    throw new Error("[Graphite] signature array runs past the transaction");
  }
  return raw.subarray(offset);
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let same = 0;
  for (let i = 0; i < a.length; i++) same |= a[i] ^ b[i];
  return same === 0;
}
