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
  createKeyPairFromBytes,
  getTransactionEncoder,
  signTransaction,
  type Transaction as KitTransaction,
} from "@solana/kit";
import {
  AddressLookupTableAccount,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
import bs58 from "bs58";
import { compileWithKit } from "./kit-artifact.js";

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
 * comparison before signing proves the transaction is the approved one; the
 * message slice after signing proves signing itself changed nothing but the
 * signatures.
 *
 * Compiled and signed by `@solana/kit` (roadmap gap R-P8, phase 1). The
 * transaction lives in an ES private field: unlike TypeScript `private`, which
 * any code holding this object could read and mutate at runtime (the old
 * design relied on the digest check to catch exactly that), nothing outside
 * the class can reach it. The digest is still re-checked before signing. The
 * bytes exposed on the object are copies, so changing them changes nothing
 * that is signed. Legacy messages compile to the bytes web3.js produced; v0
 * messages to the same transaction with accounts sorted within each privilege
 * class (`kit-artifact.test.ts`).
 */
export class BoundTransaction {
  /** The single compiled transaction that is verified, signed and submitted. */
  #tx: KitTransaction;
  /** Copies of the caller's instructions, isolated from anything it holds. */
  #source: TransactionInstruction[];
  /** The unsigned serialization handed to Graphite. */
  #artifact: Uint8Array;
  /** The message, captured at build. */
  #message: Uint8Array;
  #blockhash: string;
  /** Set, synchronously, by the first signApproved that passes its checks. */
  #consumed = false;

  private constructor(
    tx: KitTransaction,
    source: TransactionInstruction[],
    /** `"legacy"`, or `0` for a v0 message (Round 22). */
    readonly version: "legacy" | 0,
    /** How many address lookup tables the v0 message reads; 0 for legacy. */
    readonly lookupTableCount: number,
    artifact: Uint8Array,
    blockhash: string,
    /** Needed to confirm the submission against the blockhash it was built on. */
    readonly lastValidBlockHeight: number,
  ) {
    this.#tx = tx;
    this.#source = source;
    this.#artifact = artifact;
    this.#message = Uint8Array.from(tx.messageBytes);
    this.#blockhash = blockhash;
  }

  /** The unsigned serialization handed to Graphite (a copy). */
  get artifactBytes(): Uint8Array {
    return Uint8Array.from(this.#artifact);
  }

  /** The message, captured at build (a copy). */
  get messageBytes(): Uint8Array {
    return Uint8Array.from(this.#message);
  }

  /**
   * Deep-copy an instruction so nothing the caller holds reaches the bound
   * transaction. Every field is copied by value; `data` in particular is a
   * Buffer the caller may still hold — a shared buffer is a shared transaction.
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

  /**
   * The runtime's rule for a durable-nonce transaction: instruction 0 is a
   * System `AdvanceNonceAccount` (bincode u32 LE discriminator 4). The bridge
   * refuses to build one — `lastValidBlockHeight`, which is the bridge's
   * only bound on how long a signed transaction stays valid, does not apply
   * to a nonce transaction, so the "verified, then signed, then sent" window
   * the whole boundary assumes would have no end. Graphite refuses them at L2
   * as well; this is the earlier, cheaper refusal.
   */
  private static isDurableNonce(instructions: TransactionInstruction[]): boolean {
    const first = instructions[0];
    if (!first) return false;
    if (!first.programId.equals(SystemProgram.programId)) return false;
    const d = first.data;
    return d.length >= 4 && d[0] === 4 && d[1] === 0 && d[2] === 0 && d[3] === 0;
  }

  /**
   * Build the one transaction that is verified, signed and submitted.
   *
   * `version: 0` compiles a v0 message, reading accounts through
   * `addressLookupTables` where they hold them (Round 22). Lookup tables are
   * given as ACCOUNTS, already fetched: a table that could not be read is the
   * caller's refusal, never a quietly smaller message. Version 1 is not built
   * here yet (R-P8, phase 2).
   */
  static build(params: {
    instructions: TransactionInstruction[];
    feePayer: PublicKey;
    recentBlockhash: string;
    lastValidBlockHeight: number;
    version?: "legacy" | 0;
    addressLookupTables?: AddressLookupTableAccount[];
  }): BoundTransaction {
    if (BoundTransaction.isDurableNonce(params.instructions)) {
      throw new Error(
        "BoundTransaction: instruction 0 is SystemProgram.nonceAdvance, so this would be a durable-nonce transaction. " +
          "It does not expire and lastValidBlockHeight does not bound it; the bridge does not build them.",
      );
    }
    const version = params.version ?? "legacy";
    if (version !== "legacy" && version !== 0) {
      throw new Error(`BoundTransaction: unsupported message version ${String(version)}`);
    }
    const tables = params.addressLookupTables ?? [];
    if (version === "legacy" && tables.length > 0) {
      throw new Error(
        "BoundTransaction: address lookup tables were given for a legacy message, which cannot read them. " +
          "Build with version: 0, or without the tables.",
      );
    }
    const source = params.instructions.map(BoundTransaction.isolate);
    const tx = compileWithKit({
      instructions: source.map(BoundTransaction.isolate),
      feePayer: new PublicKey(params.feePayer.toBytes()),
      recentBlockhash: params.recentBlockhash,
      lastValidBlockHeight: params.lastValidBlockHeight,
      version,
      addressLookupTables: tables,
    });
    const artifact = Uint8Array.from(getTransactionEncoder().encode(tx));
    if (artifact.length > MAX_TRANSACTION_BYTES) {
      throw new Error(
        `BoundTransaction: the ${version === "legacy" ? "legacy" : "v0"} transaction is ${artifact.length} bytes; the network accepts at most ${MAX_TRANSACTION_BYTES}`,
      );
    }
    return new BoundTransaction(
      tx,
      source,
      version,
      version === 0 ? lookupTableCountOf(Uint8Array.from(tx.messageBytes)) : 0,
      artifact,
      params.recentBlockhash,
      params.lastValidBlockHeight,
    );
  }

  /** The bytes to send as `signed_transaction`. */
  artifact(): number[] {
    return Array.from(this.#artifact);
  }

  /**
   * The instructions, as fresh copies. A caller that needs to project them
   * (AuditBind does) gets objects it can do anything to without touching the
   * transaction.
   */
  instructions(): TransactionInstruction[] {
    return this.#source.map(BoundTransaction.isolate);
  }

  /** The blockhash this transaction was built on. */
  get recentBlockhash(): string {
    return this.#blockhash;
  }

  /**
   * Check the digest and sign, as one indivisible step: there is no API
   * through which this object can be signed without its digest being checked
   * first, because signing is not separately reachable. Asynchronous because
   * kit signs through WebCrypto; the digest and signer checks run before any
   * await, so nothing can interleave between them and the decision to sign.
   *
   * Returns the exact bytes to submit. Nothing else may be submitted: they are
   * the only thing here that has been checked end to end.
   */
  async signApproved(approvedSha256: string, signers: Keypair[]): Promise<Uint8Array> {
    this.assertApproved(approvedSha256);
    this.assertSignersMatchTheMessage(signers);
    // Kit signs asynchronously, so two calls could both pass the checks above
    // before either has signed. The first to get here claims the transaction
    // before its first await; any other is refused.
    if (this.#consumed) {
      throw new Error(
        "[Graphite] This bound transaction is already being signed. One verified transaction is " +
          "signed once. ABORTING.",
      );
    }
    this.#consumed = true;
    return this.signAndFreeze(signers);
  }

  /**
   * The signers must be exactly the ones this message requires, read out of
   * the message itself: `numRequiredSignatures` over the static account keys
   * is what Solana will demand. Graphite does not verify signatures, so
   * nothing downstream would notice a transaction signed by the wrong key or
   * one short of a required signature.
   */
  private assertSignersMatchTheMessage(signers: Keypair[]): void {
    const required = requiredSigners(this.#message).sort();
    const supplied = signers.map((s) => s.publicKey.toBase58()).sort();
    const same =
      required.length === supplied.length && required.every((k, i) => k === supplied[i]);
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
   * Re-serialize now and require the digest Graphite approved. Recomputing
   * rather than comparing a stored value is the point — a stored digest would
   * still match after the object moved on.
   */
  private assertApproved(approvedSha256: string): void {
    const now = Uint8Array.from(getTransactionEncoder().encode(this.#tx));
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
   * The message is read back out of the signed bytes by slicing off the
   * signature array rather than by re-compiling: a recompile would be asking
   * the same code that built it whether it built it.
   */
  private async signAndFreeze(signers: Keypair[]): Promise<Uint8Array> {
    const keyPairs = await Promise.all(signers.map((s) => createKeyPairFromBytes(s.secretKey)));
    const signed = await signTransaction(keyPairs, this.#tx);
    // The object moves on to the signed transaction, as the web3.js one did:
    // a second signApproved re-encodes it, finds signatures where the approved
    // artifact had empty slots, and is refused by the digest check. One bound
    // transaction is signed once.
    this.#tx = signed;
    const raw = Uint8Array.from(getTransactionEncoder().encode(signed));
    const submitted = messageOf(raw);
    if (!equalBytes(submitted, this.#message)) {
      throw new Error(
        "[Graphite] The message inside the signed transaction is not the message that was " +
          "verified. Signing must change only the signatures. ABORTING.",
      );
    }
    return raw;
  }
}

/** Version byte, header and static keys of a legacy or v0 message. */
function messageKeys(message: Uint8Array): { v0: boolean; header: number[]; keys: string[]; after: number } {
  let i = 0;
  const v0 = (message[0] & 0x80) !== 0;
  if (v0) i++;
  const header = [message[i], message[i + 1], message[i + 2]];
  i += 3;
  const { value: count, next } = readShortU16At(message, i);
  i = next;
  const keys: string[] = [];
  for (let k = 0; k < count; k++, i += 32) {
    keys.push(bs58.encode(message.subarray(i, i + 32)));
  }
  return { v0, header, keys, after: i };
}

/** The addresses whose signatures this message requires. */
function requiredSigners(message: Uint8Array): string[] {
  const { header, keys } = messageKeys(message);
  return keys.slice(0, header[0]);
}

/** How many lookup tables a v0 message reads. */
function lookupTableCountOf(message: Uint8Array): number {
  let { after: i } = messageKeys(message);
  i += 32; // blockhash
  let r = readShortU16At(message, i);
  i = r.next;
  for (let x = 0; x < r.value; x++) {
    i += 1; // program index
    const accounts = readShortU16At(message, i);
    i = accounts.next + accounts.value;
    const data = readShortU16At(message, i);
    i = data.next + data.value;
  }
  r = readShortU16At(message, i);
  return r.value;
}

function readShortU16At(b: Uint8Array, at: number): { value: number; next: number } {
  let value = 0;
  let i = at;
  for (let g = 0; g < 3; g++) {
    const x = b[i++];
    if (x === undefined) throw new Error("[Graphite] truncated message");
    value |= (x & 0x7f) << (7 * g);
    if ((x & 0x80) === 0) break;
  }
  return { value, next: i };
}

/**
 * The largest serialized transaction the network accepts: `PACKET_DATA_SIZE`
 * = 1280 − 40 − 8 = 1232 bytes. Mirrors `MAX_TRANSACTION_BYTES` in
 * `graphite-core/src/tx_artifact.rs`; the corpus pins both sides to it.
 */
export const MAX_TRANSACTION_BYTES = 1232;

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
  if (raw.length > MAX_TRANSACTION_BYTES) {
    throw new Error(
      `[Graphite] transaction is ${raw.length} bytes; a Solana transaction is at most ` +
        `${MAX_TRANSACTION_BYTES} (PACKET_DATA_SIZE) and the network refuses anything larger`,
    );
  }
  const { offset } = readSignatureCount(raw);
  if (offset > raw.length) {
    throw new Error("[Graphite] signature array runs past the transaction");
  }
  return raw.subarray(offset);
}

/**
 * The compact-u16 signature count at the front of a serialized transaction,
 * and the offset of the first message byte behind it. The acceptance rules
 * are `messageOf`'s, documented there; this is the reader on its own so the
 * rules can be exercised at counts no packet could hold — 128 signatures is
 * 8 KB, seven times the packet size, and `messageOf` refuses that on size
 * before it reads a byte.
 */
export function readSignatureCount(raw: Uint8Array): { count: number; offset: number } {
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
  return { count, offset: offset + count * 64 };
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let same = 0;
  for (let i = 0; i < a.length; i++) same |= a[i] ^ b[i];
  return same === 0;
}
