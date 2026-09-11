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
 * from the bytes captured read-only in `mainnet_v0_alt.json`. Nothing here
 * signs, sends, or contacts a network.
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
import { messageOf } from "./artifact.js";

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
  v0WithRealTable(),
];

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
      _: "Emitted by integrations/solana-agent-kit/emit-corpus.ts. Each entry is what the TypeScript side believes about its own bytes; tests/sak_bridge_corpus.rs requires the Rust parser to agree from the bytes alone. The v0 entry uses a real mainnet lookup table. Unsigned throughout.",
      entries: corpus,
    },
    null,
    2,
  ) + "\n",
);
console.log(`wrote ${out}: ${corpus.length} entries`);
for (const e of corpus) console.log(`  ${e.name.padEnd(40)} ${e.raw.length} bytes  v${e.version ?? "legacy"}`);
