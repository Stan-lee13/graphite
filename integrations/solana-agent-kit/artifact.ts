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
 * The blockhash is a real recent one because a transaction is not well-formed
 * without it, and it is not part of what Graphite binds — the executed
 * transaction will carry a fresher one. What must match between the artifact
 * and the executed transaction is the instructions, and those are the same
 * objects.
 */

import {
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
