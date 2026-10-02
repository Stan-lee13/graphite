/**
 * A cross-language serialization corpus, not a single fixture.
 *
 * `emit-artifact-fixture.ts` pins one shape: a ComputeBudget pair in front of a
 * transfer. One shape proves the mechanism exists. It does not prove the two
 * sides agree about signer sets, empty data, shared accounts, or a v0 message
 * with a real lookup table — and any of those disagreeing would not be a
 * bypass but an outage: every honest transaction refused at the signing
 * boundary, comparing a digest against the digest of something else.
 *
 * Every entry records what the TypeScript side believes about its own bytes —
 * the digest, the message slice, the required signers, the instruction count,
 * the version, and the lookups for v0 — and `tests/sak_bridge_corpus.rs`
 * requires the Rust parser to reach the same conclusions from the bytes alone.
 *
 * The v0 entry uses a REAL mainnet lookup table, decoded by `@solana/web3.js`
 * from the bytes captured read-only in `mainnet_v0_alt.json`. The v1 entries
 * (R-P8 phase 2) are built by the bridge through `@solana/kit`, and what they
 * record is what kit's own decoders read from them. Nothing here signs, sends,
 * or contacts a network.
 *
 * Run: npm run emit:corpus   (regenerates the committed corpus; CI diffs it)
 */

import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import {
  AddressLookupTableAccount,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import { getCompiledTransactionMessageDecoder, getTransactionDecoder } from "@solana/kit";
import { BoundTransaction, MAX_TRANSACTION_BYTES, MAX_V1_TRANSACTION_BYTES, messageOf } from "./artifact.js";

const SYSTEM = SystemProgram.programId;
const COMPUTE_BUDGET = new PublicKey("ComputeBudget111111111111111111111111111111");
const MEMO = new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
const BLOCKHASH = "11111111111111111111111111111111";
const OTHER_BLOCKHASH = "So11111111111111111111111111111111111111112";

const seeded = (n: number) =>
  Keypair.fromSeed(Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + n) & 0xff));
const payer = seeded(1);
const cosigner = seeded(2);
const destination = seeded(3).publicKey;
const other = seeded(4).publicKey;
const nonceAccount = seeded(5);
/** A nonce value: any 32 bytes, base58. Deliberately not a plausible blockhash. */
const NONCE_VALUE = seeded(6).publicKey.toBase58();

function transfer(from: PublicKey, to: PublicKey, lamports: bigint): TransactionInstruction {
  const data = Buffer.alloc(12);
  data.writeUInt32LE(2, 0);
  data.writeBigUInt64LE(lamports, 4);
  return new TransactionInstruction({
    programId: SYSTEM,
    keys: [
      { pubkey: from, isSigner: true, isWritable: true },
      { pubkey: to, isSigner: false, isWritable: true },
    ],
    data,
  });
}

function computeLimit(): TransactionInstruction {
  const data = Buffer.alloc(5);
  data.writeUInt8(2, 0);
  data.writeUInt32LE(200_000, 1);
  return new TransactionInstruction({ programId: COMPUTE_BUDGET, keys: [], data });
}

interface Entry {
  name: string;
  what: string;
  version: number | null;
  raw: number[];
  transaction_sha256: string;
  message: number[];
  required_signers: string[];
  instruction_count: number;
  static_keys: string[];
  lookups?: { table: string; writable: number[]; readonly: number[] }[];
  /** For a v1 entry: the config values the message carries, null when unset. */
  v1_config?: V1ConfigEntry;
}

interface V1ConfigEntry {
  priority_fee: number | null;
  compute_unit_limit: number | null;
  loaded_accounts_data_size_limit: number | null;
  heap_size: number | null;
}

function legacy(name: string, what: string, ixs: TransactionInstruction[], blockhash = BLOCKHASH): Entry {
  const tx = new Transaction({ feePayer: payer.publicKey, recentBlockhash: blockhash });
  tx.add(...ixs);
  const raw = Uint8Array.from(tx.serialize({ requireAllSignatures: false, verifySignatures: false }));
  const compiled = tx.compileMessage();
  return {
    name,
    what,
    version: null,
    raw: Array.from(raw),
    transaction_sha256: createHash("sha256").update(raw).digest("hex"),
    message: Array.from(messageOf(raw)),
    required_signers: compiled.accountKeys
      .slice(0, compiled.header.numRequiredSignatures)
      .map((k) => k.toBase58()),
    instruction_count: ixs.length,
    static_keys: compiled.accountKeys.map((k) => k.toBase58()),
  };
}

/** A v0 transaction whose instruction reaches accounts only through a real table. */
function v0WithRealTable(): Entry {
  const alt = JSON.parse(
    readFileSync(new URL("../../graphite-core/fixtures/artifacts/mainnet_v0_alt.json", import.meta.url), "utf8"),
  );
  const [tableAddress, table] = Object.entries(alt.lookup_tables)[0] as [string, { data_base64: string }];
  const lookup = new AddressLookupTableAccount({
    key: new PublicKey(tableAddress),
    state: AddressLookupTableAccount.deserialize(Buffer.from(table.data_base64, "base64")),
  });
  // Two addresses from the real table: one written, one read.
  const viaWritable = lookup.state.addresses[5];
  const viaReadonly = lookup.state.addresses[9];
  const ix = new TransactionInstruction({
    programId: MEMO,
    keys: [
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: viaWritable, isSigner: false, isWritable: true },
      { pubkey: viaReadonly, isSigner: false, isWritable: false },
    ],
    data: Buffer.from("graphite corpus v0", "utf8"),
  });
  const message = new TransactionMessage({
    payerKey: payer.publicKey,
    recentBlockhash: BLOCKHASH,
    instructions: [computeLimit(), ix],
  }).compileToV0Message([lookup]);
  const vtx = new VersionedTransaction(message);
  const raw = vtx.serialize();
  return {
    name: "v0_real_lookup_table",
    what: "a v0 message reaching two accounts only through a real mainnet lookup table",
    version: 0,
    raw: Array.from(raw),
    transaction_sha256: createHash("sha256").update(raw).digest("hex"),
    message: Array.from(messageOf(raw)),
    required_signers: message.staticAccountKeys
      .slice(0, message.header.numRequiredSignatures)
      .map((k) => k.toBase58()),
    instruction_count: 2,
    static_keys: message.staticAccountKeys.map((k) => k.toBase58()),
    lookups: message.addressTableLookups.map((l) => ({
      table: l.accountKey.toBase58(),
      writable: Array.from(l.writableIndexes),
      readonly: Array.from(l.readonlyIndexes),
    })),
  };
}

/**
 * A v0 transaction compiled by the BRIDGE (`BoundTransaction.build`, which
 * compiles through @solana/kit since R-P8 phase 1), with two read-only
 * accounts given in the reverse of their sorted order. web3.js's v0 compiler
 * keeps first-appearance order and kit sorts, so these bytes are what the
 * bridge produces and NOT what web3.js would: the Rust Core is held to the
 * bytes the bridge actually signs.
 */
function v0BridgeKitOrder(): Entry {
  const alt = JSON.parse(
    readFileSync(new URL("../../graphite-core/fixtures/artifacts/mainnet_v0_alt.json", import.meta.url), "utf8"),
  );
  const [tableAddress, table] = Object.entries(alt.lookup_tables)[0] as [string, { data_base64: string }];
  const lookup = new AddressLookupTableAccount({
    key: new PublicKey(tableAddress),
    state: AddressLookupTableAccount.deserialize(Buffer.from(table.data_base64, "base64")),
  });
  // Two fixed read-only accounts, given in DESCENDING base58 order.
  const pair = [Keypair.fromSeed(new Uint8Array(32).fill(41)).publicKey, Keypair.fromSeed(new Uint8Array(32).fill(42)).publicKey]
    .sort((a, b) => b.toBase58().localeCompare(a.toBase58()));
  const ix = new TransactionInstruction({
    programId: MEMO,
    keys: [
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: lookup.state.addresses[5], isSigner: false, isWritable: true },
      { pubkey: pair[0], isSigner: false, isWritable: false },
      { pubkey: pair[1], isSigner: false, isWritable: false },
      { pubkey: lookup.state.addresses[9], isSigner: false, isWritable: false },
    ],
    data: Buffer.from("graphite corpus v0, kit order", "utf8"),
  });
  const bound = BoundTransaction.build({
    instructions: [computeLimit(), ix],
    feePayer: payer.publicKey,
    recentBlockhash: BLOCKHASH,
    lastValidBlockHeight: 1,
    version: 0,
    addressLookupTables: [lookup],
  });
  const raw = bound.artifactBytes;
  const message = VersionedTransaction.deserialize(raw).message;
  const web3Order = new TransactionMessage({
    payerKey: payer.publicKey,
    recentBlockhash: BLOCKHASH,
    instructions: [computeLimit(), ix],
  }).compileToV0Message([lookup]).serialize();
  if (Buffer.from(web3Order).equals(Buffer.from(messageOf(raw)))) {
    throw new Error("v0_bridge_kit_order: kit and web3.js produced the same bytes; the entry would not test the bridge's order");
  }
  return {
    name: "v0_bridge_kit_order",
    what: "a v0 message compiled by the bridge itself (kit), whose account order differs from web3.js's",
    version: 0,
    raw: Array.from(raw),
    transaction_sha256: createHash("sha256").update(raw).digest("hex"),
    message: Array.from(messageOf(raw)),
    required_signers: message.staticAccountKeys
      .slice(0, message.header.numRequiredSignatures)
      .map((k) => k.toBase58()),
    instruction_count: 2,
    static_keys: message.staticAccountKeys.map((k) => k.toBase58()),
    lookups: message.addressTableLookups.map((l) => ({
      table: l.accountKey.toBase58(),
      writable: Array.from(l.writableIndexes),
      readonly: Array.from(l.readonlyIndexes),
    })),
  };
}

/**
 * What @solana/kit's own decoders read out of a v1 frame: the second SDK, not
 * the bridge's `messageOf`, so the recorded beliefs are not the bridge
 * agreeing with itself. Returns null when kit refuses the bytes.
 */
function kitReadsV1(raw: Uint8Array):
  | { signers: string[]; staticKeys: string[]; instructionCount: number; config: V1ConfigEntry; messageBytes: Uint8Array }
  | null {
  try {
    const tx = getTransactionDecoder().decode(raw);
    const m = getCompiledTransactionMessageDecoder().decode(tx.messageBytes);
    if (m.version !== 1) return null;
    // Config values arrive in mask-bit order: fee (bits 0-1), compute limit
    // (bit 2), loaded-data limit (bit 3), heap (bit 4).
    const values = [...m.configValues];
    const config: V1ConfigEntry = {
      priority_fee: null,
      compute_unit_limit: null,
      loaded_accounts_data_size_limit: null,
      heap_size: null,
    };
    if ((m.configMask & 0b11) === 0b11) config.priority_fee = Number(values.shift()!.value);
    if (m.configMask & 0b100) config.compute_unit_limit = Number(values.shift()!.value);
    if (m.configMask & 0b1000) config.loaded_accounts_data_size_limit = Number(values.shift()!.value);
    if (m.configMask & 0b1_0000) config.heap_size = Number(values.shift()!.value);
    return {
      signers: Object.keys(tx.signatures),
      staticKeys: m.staticAccounts.map(String),
      instructionCount: m.numInstructions,
      config,
      messageBytes: Uint8Array.from(tx.messageBytes),
    };
  } catch {
    return null;
  }
}

/**
 * A version-1 transaction (SIMD-0385) compiled by the bridge itself
 * (`BoundTransaction.build({ version: 1 })`). The budget is in the message
 * config, not in ComputeBudget instructions, and the signatures trail the
 * message. The beliefs recorded are kit's decoders', and the Rust Core must
 * reach each from the bytes alone.
 */
function v1Bridge(
  name: string,
  what: string,
  ixs: TransactionInstruction[],
  v1Limits: Parameters<typeof BoundTransaction.build>[0]["v1Limits"],
): Entry {
  const bound = BoundTransaction.build({
    instructions: ixs,
    feePayer: payer.publicKey,
    recentBlockhash: BLOCKHASH,
    lastValidBlockHeight: 1,
    version: 1,
    v1Limits,
  });
  const raw = bound.artifactBytes;
  const read = kitReadsV1(raw);
  if (!read) throw new Error(`${name}: kit refuses the bridge's own v1 bytes`);
  if (!Buffer.from(read.messageBytes).equals(Buffer.from(messageOf(raw)))) {
    throw new Error(`${name}: kit and messageOf disagree about where the v1 message ends`);
  }
  return {
    name,
    what,
    version: 1,
    raw: Array.from(raw),
    transaction_sha256: createHash("sha256").update(raw).digest("hex"),
    message: Array.from(messageOf(raw)),
    required_signers: read.signers,
    instruction_count: read.instructionCount,
    static_keys: read.staticKeys,
    v1_config: read.config,
  };
}

const corpus: Entry[] = [
  legacy("legacy_single_transfer", "one System transfer", [transfer(payer.publicKey, destination, 2_000_000n)]),
  legacy(
    "legacy_two_signers",
    "a transfer whose second account is also a signer, so the header requires two signatures",
    [
      new TransactionInstruction({
        programId: SYSTEM,
        keys: [
          { pubkey: payer.publicKey, isSigner: true, isWritable: true },
          { pubkey: cosigner.publicKey, isSigner: true, isWritable: false },
          { pubkey: destination, isSigner: false, isWritable: true },
        ],
        data: Buffer.from([2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]),
      }),
    ],
  ),
  legacy("legacy_empty_data", "an instruction carrying zero bytes of data", [
    new TransactionInstruction({ programId: MEMO, keys: [], data: Buffer.alloc(0) }),
    transfer(payer.publicKey, destination, 1n),
  ]),
  legacy(
    "legacy_shared_account_privilege_union",
    "the same account read-only in one instruction and writable in another; the compiled header unions them",
    [
      new TransactionInstruction({
        programId: MEMO,
        keys: [{ pubkey: destination, isSigner: false, isWritable: false }],
        data: Buffer.from("read", "utf8"),
      }),
      transfer(payer.publicKey, destination, 5n),
    ],
  ),
  legacy("legacy_large_data", "an instruction with 900 bytes of data", [
    new TransactionInstruction({ programId: MEMO, keys: [], data: Buffer.alloc(900, 0x5a) }),
  ]),
  legacy("legacy_many_accounts", "twenty distinct writable accounts in one instruction", [
    new TransactionInstruction({
      programId: MEMO,
      keys: [
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        ...Array.from({ length: 19 }, (_, i) => ({
          pubkey: seeded(10 + i).publicKey,
          isSigner: false,
          isWritable: true,
        })),
      ],
      data: Buffer.from([1]),
    }),
  ]),
  legacy("legacy_other_blockhash", "the single transfer under a different blockhash — a different digest", [
    transfer(payer.publicKey, destination, 2_000_000n),
  ], OTHER_BLOCKHASH),
  legacy("legacy_other_destination", "the single transfer to a different account — a different digest", [
    transfer(payer.publicKey, other, 2_000_000n),
  ]),
  legacy("legacy_reordered", "compute limit AFTER the transfer instead of before", [
    transfer(payer.publicKey, destination, 2_000_000n),
    computeLimit(),
  ]),
  // A durable-nonce transaction, built the way web3.js builds one: the nonce
  // advance is instruction 0 and the `recentBlockhash` slot carries the nonce
  // value. The Rust side must recognise it from the bytes alone.
  legacy(
    "legacy_durable_nonce",
    "instruction 0 is SystemProgram.nonceAdvance; recentBlockhash is the nonce value, so the transaction never expires",
    [
      SystemProgram.nonceAdvance({ noncePubkey: nonceAccount.publicKey, authorizedPubkey: payer.publicKey }),
      transfer(payer.publicKey, destination, 2_000_000n),
    ],
    NONCE_VALUE,
  ),
  // The same instructions with the advance SECOND. The runtime does not treat
  // this as nonce-based (only instruction 0 counts), so neither may Graphite.
  legacy(
    "legacy_nonce_advance_not_first",
    "a nonce advance in position 1 is an ordinary instruction; the runtime only honours position 0",
    [
      transfer(payer.publicKey, destination, 2_000_000n),
      SystemProgram.nonceAdvance({ noncePubkey: nonceAccount.publicKey, authorizedPubkey: payer.publicKey }),
    ],
  ),
  v0WithRealTable(),
  v0BridgeKitOrder(),
  v1Bridge(
    "v1_bridge_transfer_full_config",
    "a v1 transfer built by the bridge, every config field set: priority fee, compute limit, loaded-data limit, heap",
    [transfer(payer.publicKey, destination, 3_000_000n)],
    { computeUnitLimit: 450, loadedAccountsDataSizeLimit: 32 * 1024, priorityFeeLamports: 5_000n, heapSize: 64 * 1024 },
  ),
  v1Bridge(
    "v1_bridge_two_signers_limits_only",
    "a v1 message with two signers (signatures trailing, no count) and only the two limits v1 requires",
    [transfer(payer.publicKey, destination, 1_000n), transfer(cosigner.publicKey, other, 2_000n)],
    { computeUnitLimit: 900, loadedAccountsDataSizeLimit: 64 * 1024 },
  ),
];

// ─── Byte-level mutations ─────────────────────────────────────────────────────
//
// The entries above are structurally different transactions. These are the
// same transactions damaged one byte at a time: every truncation length, every
// single-byte flip, a set of hand-picked signature-count prefixes, and trailing
// bytes. Each mutation records what THIS side concludes — whether `messageOf`
// accepts it and what message it yields, and whether `@solana/web3.js` itself
// will deserialize it — and `tests/sak_bridge_corpus.rs` requires Graphite's
// parser to agree with `messageOf` exactly and to be at least as strict as the
// SDK except where the runtime is stricter than the SDK.
//
// Mutations are stored as operations on a named base entry rather than as
// bytes, so ~1,000 of them cost a few tens of kilobytes rather than a megabyte.

type MutationOp =
  | { op: "truncate"; at: number }
  | { op: "flip"; at: number }
  | { op: "prefix"; bytes: number[] }
  | { op: "append"; bytes: number[] }
  /** Zero-pad to exactly `to` bytes: the packet-size bound, from both sides. */
  | { op: "pad"; to: number }
  /**
   * Replace the signature array with `count` zero slots, header untouched
   * (Round 11). The runtime sanitizes a transaction only when the array is
   * exactly as long as the header's signer count.
   */
  | { op: "slots"; count: number };

interface Mutation {
  base: string;
  mutation: MutationOp;
  /** `messageOf` outcome: the message length and digest, or null when it threw. */
  ts_message_len: number | null;
  ts_message_sha256: string | null;
  /** Whether `VersionedTransaction.deserialize` accepts the bytes. */
  sdk_accepts: boolean;
}

function applyMutation(raw: Uint8Array, m: MutationOp): Uint8Array {
  switch (m.op) {
    case "truncate":
      return raw.slice(0, m.at);
    case "flip": {
      const out = Uint8Array.from(raw);
      out[m.at] ^= 0xff;
      return out;
    }
    case "prefix": {
      // Every base entry's signature count is one byte; replace exactly it.
      return Uint8Array.from([...m.bytes, ...raw.slice(1)]);
    }
    case "append":
      return Uint8Array.from([...raw, ...m.bytes]);
    case "pad": {
      if (m.to < raw.length) throw new Error(`pad: ${raw.length} bytes already exceed ${m.to}`);
      const out = new Uint8Array(m.to);
      out.set(raw);
      return out;
    }
    case "slots": {
      // Every base entry's signature count is one byte (asserted below).
      const declared = raw[0];
      return Uint8Array.from([m.count, ...new Uint8Array(64 * m.count), ...raw.slice(1 + 64 * declared)]);
    }
  }
}

function observe(base: string, raw: Uint8Array, m: MutationOp): Mutation {
  const bytes = applyMutation(raw, m);
  let ts_message_len: number | null = null;
  let ts_message_sha256: string | null = null;
  try {
    const msg = messageOf(bytes);
    ts_message_len = msg.length;
    ts_message_sha256 = createHash("sha256").update(msg).digest("hex");
  } catch {
    /* rejected */
  }
  // The SDK that reads the base: web3.js for legacy and v0, kit for v1
  // (web3.js 1.x never decodes v1). Graphite must be at least as strict.
  let sdk_accepts = false;
  if (raw[0] === 0x81) {
    sdk_accepts = kitReadsV1(bytes) !== null;
  } else {
    try {
      VersionedTransaction.deserialize(bytes);
      sdk_accepts = true;
    } catch {
      /* rejected */
    }
  }
  return { base, mutation: m, ts_message_len, ts_message_sha256, sdk_accepts };
}

const PREFIXES: number[][] = [
  [0x00], [0x02], [0x7f],
  [0x80, 0x01], // 128
  [0x80, 0x80, 0x01], // 16384
  [0xff, 0xff, 0x03], // 65535, the largest value a u16 can hold — VALID encoding
  [0x80, 0x80, 0x04], // 65536 — overflows u16
  [0xff, 0xff, 0x7f], // 2,097,151 — three full groups
  [0x81, 0x00], // 1, non-minimal (alias of 0x01)
  [0x80, 0x00], // 0, non-minimal (alias of 0x00)
  [0x80, 0x80, 0x00], // 0, non-minimal, three groups
  [0x80, 0x80, 0x80], // never terminates
  [0xff], // 1 byte with continuation bit and nothing after it
  [0xff, 0xff], // two continuation bytes and nothing after
];

const mutations: Mutation[] = [];
for (const baseName of ["legacy_single_transfer", "legacy_two_signers", "v0_real_lookup_table"]) {
  const base = corpus.find((e) => e.name === baseName)!;
  const raw = Uint8Array.from(base.raw);
  if (raw[0] & 0x80) throw new Error(`${baseName}: prefix mutations assume a one-byte signature count`);
  for (let at = 0; at < raw.length; at++) mutations.push(observe(baseName, raw, { op: "truncate", at }));
  for (let at = 0; at < raw.length; at++) mutations.push(observe(baseName, raw, { op: "flip", at }));
  for (const bytes of PREFIXES) mutations.push(observe(baseName, raw, { op: "prefix", bytes }));
  for (const bytes of [[0x00], [0xff], [0x01, 0x02, 0x03]]) mutations.push(observe(baseName, raw, { op: "append", bytes }));
  // The packet-size bound: 1232 bytes is a legal packet (trailing zeros are
  // still refused as trailing bytes by the message parser, but not by
  // messageOf, which only strips signatures), 1233 is refused by both sides
  // before anything is read.
  for (const to of [MAX_TRANSACTION_BYTES, MAX_TRANSACTION_BYTES + 1]) mutations.push(observe(baseName, raw, { op: "pad", to }));
  // Signature slots against the header's signer count: none, one fewer, one
  // more, and (for the two-signer base) exactly right.
  for (const count of [0, 1, 2, 3]) mutations.push(observe(baseName, raw, { op: "slots", count }));
}
// The v1 bases (R-P8 phase 2): every truncation (the trailing signature array
// has no count, so a short one is a truncated frame), every single-byte flip
// (the config mask, the header the trailing array is sized by, the
// instruction headers that precede all payloads), trailing bytes, and the
// 4,096-byte bound from both sides. Prefix and slot mutations are legacy/v0
// shapes and do not apply.
for (const baseName of ["v1_bridge_transfer_full_config", "v1_bridge_two_signers_limits_only"]) {
  const base = corpus.find((e) => e.name === baseName)!;
  const raw = Uint8Array.from(base.raw);
  if (raw[0] !== 0x81) throw new Error(`${baseName}: a v1 base must start with 0x81`);
  for (let at = 0; at < raw.length; at++) mutations.push(observe(baseName, raw, { op: "truncate", at }));
  for (let at = 0; at < raw.length; at++) mutations.push(observe(baseName, raw, { op: "flip", at }));
  for (const bytes of [[0x00], [0xff], [0x01, 0x02, 0x03]]) mutations.push(observe(baseName, raw, { op: "append", bytes }));
  for (const to of [MAX_V1_TRANSACTION_BYTES, MAX_V1_TRANSACTION_BYTES + 1]) mutations.push(observe(baseName, raw, { op: "pad", to }));
}

// Digests must be pairwise distinct: the corpus exists partly to show that the
// "different" variants really are different transactions.
const seen = new Set<string>();
for (const e of corpus) {
  if (seen.has(e.transaction_sha256)) throw new Error(`duplicate digest in corpus: ${e.name}`);
  seen.add(e.transaction_sha256);
}

const out = "../../graphite-core/fixtures/artifacts/sak_bridge_corpus.json";
writeFileSync(
  new URL(out, import.meta.url),
  JSON.stringify(
    {
      _: "Emitted by integrations/agent-guard/emit-corpus.ts. Each entry is what the TypeScript side believes about its own bytes; tests/sak_bridge_corpus.rs requires the Rust parser to agree from the bytes alone. The v0 entry uses a real mainnet lookup table; the v1 entries are compiled by the bridge through @solana/kit and recorded as kit decodes them. Unsigned throughout.",
      entries: corpus,
      mutations,
    },
    null,
    2,
  ) + "\n",
);
console.log(`wrote ${out}: ${corpus.length} entries, ${mutations.length} mutations`);
const tsAccepts = mutations.filter((m) => m.ts_message_len !== null).length;
const sdkAccepts = mutations.filter((m) => m.sdk_accepts).length;
console.log(`  mutations: messageOf accepts ${tsAccepts}, web3.js deserializes ${sdkAccepts}`);
for (const e of corpus) console.log(`  ${e.name.padEnd(40)} ${e.raw.length} bytes  v${e.version ?? "legacy"}`);
