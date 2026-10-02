/**
 * The transaction that is signed must be the transaction that was approved.
 *
 * AuditBind proves the INSTRUCTIONS still match, and that is strong and is a
 * different claim. It cannot see the fee payer, the recent blockhash, the
 * message version, the header, or the lookup structure, because none of those
 * are instruction-level facts. Graphite's own strongest statement — "these
 * exact bytes were verified" — was therefore not the statement the execution
 * path enforced: the bridge serialized one transaction for verification and
 * built another to submit.
 *
 * These tests attack the window between approval and signature. Every case
 * mutates the real transaction object after the digest was taken, which is what
 * an attacker with any foothold in the process would do.
 *
 * Nothing here contacts a network, signs with a real key of consequence, or
 * submits anything. The keypairs are generated per-run.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
import { BoundTransaction, messageOf, readSignatureCount } from "./artifact.js";

/**
 * The transaction inside a BoundTransaction is an ES private field (R-P8,
 * phase 1): no code outside the class can reach it, so it cannot be changed
 * after approval at all. What the tests below pin is the digest check itself:
 * an approval of a transaction that differs in any way does not sign this
 * one. Each builds the transaction Graphite APPROVED and, separately, the one
 * being signed, and requires the signing to be refused.
 */

const payer = Keypair.generate();
const destination = Keypair.generate().publicKey;
const BLOCKHASH = "11111111111111111111111111111111";
const OTHER_BLOCKHASH = "So11111111111111111111111111111111111111112";

function transfer(lamports = 2_000_000): TransactionInstruction {
  return SystemProgram.transfer({
    fromPubkey: payer.publicKey,
    toPubkey: destination,
    lamports,
  });
}

function build(instructions = [transfer()], blockhash = BLOCKHASH) {
  return BoundTransaction.build({
    instructions,
    feePayer: payer.publicKey,
    recentBlockhash: blockhash,
    lastValidBlockHeight: 1,
  });
}

/** What Graphite computes: SHA-256 over the exact artifact bytes it was sent. */
function approvedDigest(b: BoundTransaction): string {
  return createHash("sha256").update(b.artifactBytes).digest("hex");
}

/** A transfer instruction with one account meta changed. */
function withMeta(ix: TransactionInstruction, index: number, change: { isWritable?: boolean; pubkey?: PublicKey }) {
  return new TransactionInstruction({
    programId: ix.programId,
    data: Buffer.from(ix.data),
    keys: ix.keys.map((k, i) => (i === index ? { ...k, ...change } : { ...k })),
  });
}

/** Graphite approved `approved`; signing `signing` with that approval must be refused. */
async function refusedAgainst(approved: BoundTransaction, signing: BoundTransaction, why: string) {
  await assert.rejects(
    () => signing.signApproved(approvedDigest(approved), [payer]),
    /changed between approval and signing/,
    why,
  );
}

test("the honest path: the same transaction verifies, signs and submits", async () => {
  const bound = build();
  const digest = approvedDigest(bound);

  const raw = await bound.signApproved(digest, [payer]); // nothing changed

  assert.deepEqual(
    Array.from(messageOf(raw)),
    Array.from(bound.messageBytes),
    "the message submitted must be the message approved",
  );
  assert.ok(raw.length > bound.messageBytes.length, "signatures were added");
});

test("signing changes only the signatures", async () => {
  const bound = build();
  const before = Uint8Array.from(bound.messageBytes);
  const raw = await bound.signApproved(approvedDigest(bound), [payer]);
  assert.deepEqual(Array.from(messageOf(raw)), Array.from(before));
});

test("a refreshed blockhash after approval is refused", async () => {
  // The specific case the old code did implicitly on every execution: verify
  // with one blockhash, submit with whatever the sender fetched.
  await refusedAgainst(build(), build([transfer()], OTHER_BLOCKHASH), "a new blockhash is a new transaction and must be re-verified");
});

test("a changed fee payer after approval is refused", async () => {
  const other = BoundTransaction.build({
    instructions: [transfer()],
    feePayer: Keypair.generate().publicKey,
    recentBlockhash: BLOCKHASH,
    lastValidBlockHeight: 1,
  });
  await assert.rejects(() => other.signApproved(approvedDigest(build()), [payer]), /changed between approval|signer set/);
});

test("an instruction appended after approval is refused", async () => {
  await refusedAgainst(build(), build([transfer(), transfer(1)]), "an appended instruction");
});

test("a rewritten amount after approval is refused", async () => {
  await refusedAgainst(build(), build([transfer(9_000_000)]), "a rewritten amount");
});

test("a redirected destination after approval is refused", async () => {
  await refusedAgainst(build(), build([withMeta(transfer(), 1, { pubkey: Keypair.generate().publicKey })]), "a redirected destination");
});

test("a flipped writable bit after approval is refused", async () => {
  await refusedAgainst(build(), build([withMeta(transfer(), 1, { isWritable: false })]), "a flipped writable bit");
});

test("the digest names both sides so an operator can tell which moved", async () => {
  const approved = approvedDigest(build());
  const signing = build([transfer()], OTHER_BLOCKHASH);
  try {
    await signing.signApproved(approved, [payer]);
    assert.fail("should have thrown");
  } catch (e) {
    const msg = String(e);
    assert.ok(msg.includes(approved), "the approved digest must be named");
    assert.ok(
      /now serializes to [0-9a-f]{64}/.test(msg),
      `the current digest must be named: ${msg}`,
    );
  }
});

test("two transactions differing only in blockhash have different digests", async () => {
  // The property the whole check rests on: the blockhash is inside the bytes
  // Graphite hashes, so it cannot be swapped invisibly.
  const a = build(undefined, BLOCKHASH);
  const b = build(undefined, OTHER_BLOCKHASH);
  assert.notEqual(approvedDigest(a), approvedDigest(b));
  assert.notEqual(
    Buffer.from(a.messageBytes).toString("hex"),
    Buffer.from(b.messageBytes).toString("hex"),
  );
});

test("messageOf finds the message behind any signature count", async () => {
  // Hand-built frames rather than a real transaction, because the point is the
  // compact-u16 signature count in front of the message, and a real one only
  // ever exercises the single-byte case.
  const body = Uint8Array.from([1, 2, 3, 4]);
  for (const count of [0, 1, 3]) {
    const raw = Uint8Array.from([count, ...new Uint8Array(64 * count), ...body]);
    assert.deepEqual(Array.from(messageOf(raw)), Array.from(body), `count=${count}`);
  }
  // Two-byte compact-u16: 128 signatures. That is 8 KB — no packet holds
  // it, so `messageOf` refuses it on size (Round 9), while the count reader
  // it is built on still decodes the encoding correctly.
  const many = Uint8Array.from([0x80, 0x01, ...new Uint8Array(64 * 128), ...body]);
  assert.throws(() => messageOf(many), /at most 1232/);
  assert.deepEqual(readSignatureCount(many), { count: 128, offset: 2 + 64 * 128 });
});

test("messageOf refuses a signature array that runs past the transaction", async () => {
  assert.throws(
    () => messageOf(Uint8Array.from([4, 0, 0, 0])),
    /runs past the transaction/,
    "a truncated frame must not silently yield an empty message",
  );
});

test("the artifact carries empty signature slots — Graphite verifies before signing", async () => {
  const bound = build();
  const sigArea = bound.artifactBytes.subarray(1, 1 + 64);
  assert.equal(bound.artifactBytes[0], 1, "one signature slot for the payer");
  assert.ok(
    sigArea.every((b) => b === 0),
    "the slot must be empty: a pre-signature gate never sees a signature",
  );
  // And that empty slot is not part of the message, so signing does not disturb
  // what was approved.
  assert.deepEqual(
    Array.from(messageOf(bound.artifactBytes)),
    Array.from(bound.messageBytes),
  );
});

test("a transaction with several instructions binds all of them", async () => {
  const withBudget = build([
    new TransactionInstruction({
      programId: new PublicKey("ComputeBudget111111111111111111111111111111"),
      keys: [],
      data: Buffer.from([2, 0x40, 0x0d, 0x03, 0x00]),
    }),
    transfer(),
  ]);
  const digest = approvedDigest(withBudget);
  await withBudget.signApproved(digest, [payer]);

  // Reordering is a different transaction even with identical instructions.
  const reordered = build([
    transfer(),
    new TransactionInstruction({
      programId: new PublicKey("ComputeBudget111111111111111111111111111111"),
      keys: [],
      data: Buffer.from([2, 0x40, 0x0d, 0x03, 0x00]),
    }),
  ]);
  assert.notEqual(approvedDigest(reordered), digest);
});

// ─── Durable nonces ───────────────────────────────────────────────────────────

const nonceAccount = Keypair.generate().publicKey;
const nonceAdvance = () =>
  SystemProgram.nonceAdvance({ noncePubkey: nonceAccount, authorizedPubkey: payer.publicKey });

test("a durable-nonce transaction is refused at build: lastValidBlockHeight does not bound it", async () => {
  assert.throws(
    () => build([nonceAdvance(), transfer()], "So11111111111111111111111111111111111111112"),
    /durable-nonce transaction.*does not expire/,
  );
});

test("a nonce advance anywhere but position 0 is an ordinary instruction (the runtime's rule)", async () => {
  // Same two instructions, advance second: builds normally. Graphite's L2
  // makes the same distinction from the bytes.
  const b = build([transfer(), nonceAdvance()]);
  assert.equal(b.instructions().length, 2);
});

test("trailing bytes after the nonce-advance discriminator do not hide it", async () => {
  const ix = nonceAdvance();
  const padded = new TransactionInstruction({
    programId: ix.programId,
    keys: ix.keys,
    data: Buffer.concat([ix.data, Buffer.from([0xde, 0xad])]),
  });
  assert.throws(() => build([padded, transfer()]), /durable-nonce/);
});

test("a System instruction that is not an advance is not mistaken for one", async () => {
  // Transfer first (discriminator 2), then something else: no refusal.
  const b = build([transfer(), transfer(1)]);
  assert.equal(b.instructions().length, 2);
});

// ─── Version 0, through lookup tables (Round 22) ────────────────────────────
//
// The bridge built legacy messages only, so a route that needs lookup tables
// to fit in 1,232 bytes could not be bound. `version: 0` compiles a v0
// message through tables the caller has already fetched. Every guarantee
// above is re-asserted on it here: same object verified, signed and
// submitted; the digest checked before signing; the signed bytes carrying
// the verified message.

import { readFileSync } from "node:fs";
import {
  AddressLookupTableAccount,
  VersionedTransaction,
} from "@solana/web3.js";

const seeded = (n: number) =>
  Keypair.fromSeed(Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + n) & 0xff));

/** The real mainnet lookup table the Core's v0 fixture carries. */
function realTable(): AddressLookupTableAccount {
  const alt = JSON.parse(
    readFileSync(
      new URL("../../graphite-core/fixtures/artifacts/mainnet_v0_alt.json", import.meta.url),
      "utf8",
    ),
  );
  const [address, table] = Object.entries(alt.lookup_tables)[0] as [string, { data_base64: string }];
  return new AddressLookupTableAccount({
    key: new PublicKey(address),
    state: AddressLookupTableAccount.deserialize(Buffer.from(table.data_base64, "base64")),
  });
}

const MEMO = new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
const COMPUTE_BUDGET = new PublicKey("ComputeBudget111111111111111111111111111111");

/** The corpus's `v0_real_lookup_table` instructions, rebuilt from its recipe. */
function corpusV0Instructions(signer: PublicKey, table: AddressLookupTableAccount) {
  const limit = Buffer.alloc(5);
  limit.writeUInt8(2, 0);
  limit.writeUInt32LE(200_000, 1);
  return [
    new TransactionInstruction({ programId: COMPUTE_BUDGET, keys: [], data: limit }),
    new TransactionInstruction({
      programId: MEMO,
      keys: [
        { pubkey: signer, isSigner: true, isWritable: true },
        { pubkey: table.state.addresses[5], isSigner: false, isWritable: true },
        { pubkey: table.state.addresses[9], isSigner: false, isWritable: false },
      ],
      data: Buffer.from("graphite corpus v0", "utf8"),
    }),
  ];
}

function buildV0(signer = payer) {
  const table = realTable();
  return BoundTransaction.build({
    instructions: corpusV0Instructions(signer.publicKey, table),
    feePayer: signer.publicKey,
    recentBlockhash: BLOCKHASH,
    lastValidBlockHeight: 1,
    version: 0,
    addressLookupTables: [table],
  });
}

/** A v0 build from the corpus recipe with one input changed. */
function buildV0With(change: { blockhash?: string; lookupIndex?: number }) {
  const table = realTable();
  const instructions = corpusV0Instructions(payer.publicKey, table);
  if (change.lookupIndex !== undefined) {
    instructions[1] = withMeta(instructions[1], 1, { pubkey: table.state.addresses[change.lookupIndex] });
  }
  return BoundTransaction.build({
    instructions,
    feePayer: payer.publicKey,
    recentBlockhash: change.blockhash ?? BLOCKHASH,
    lastValidBlockHeight: 1,
    version: 0,
    addressLookupTables: [table],
  });
}

test("v0: the bridge's bytes are the corpus bytes the Rust parser is pinned to", async () => {
  // tests/sak_bridge_corpus.rs requires the Core to read this entry's version,
  // signers, static keys and lookups from the bytes alone. The bridge must
  // produce exactly those bytes, not a lookalike.
  const corpus = JSON.parse(
    readFileSync(
      new URL("../../graphite-core/fixtures/artifacts/sak_bridge_corpus.json", import.meta.url),
      "utf8",
    ),
  );
  const entry = corpus.entries.find((e: { name: string }) => e.name === "v0_real_lookup_table");
  assert.ok(entry, "corpus entry present");
  const bound = buildV0(seeded(1));
  assert.deepEqual(Array.from(bound.artifactBytes), entry.raw);
  assert.equal(
    createHash("sha256").update(bound.artifactBytes).digest("hex"),
    entry.transaction_sha256,
  );
  assert.equal(bound.version, 0);
  assert.equal(bound.lookupTableCount, 1);
});

test("v0: the honest path verifies, signs and submits the same message", async () => {
  const bound = buildV0();
  const raw = await bound.signApproved(approvedDigest(bound), [payer]);
  assert.deepEqual(Array.from(messageOf(raw)), Array.from(bound.messageBytes));
  assert.equal(messageOf(raw)[0], 0x80, "a v0 message carries the version prefix");
  const back = VersionedTransaction.deserialize(raw);
  assert.equal(back.message.version, 0);
  assert.equal(back.message.addressTableLookups.length, 1);
});

test("v0: the unsigned artifact carries empty signature slots", async () => {
  const bound = buildV0();
  const { count, offset } = readSignatureCount(bound.artifactBytes);
  assert.equal(count, 1);
  assert.ok(bound.artifactBytes.subarray(1, offset).every((b) => b === 0));
});

test("v0: a refreshed blockhash after approval is refused", async () => {
  await refusedAgainst(buildV0(), buildV0With({ blockhash: OTHER_BLOCKHASH }), "v0: a new blockhash");
});

test("v0: a rewritten lookup after approval is refused", async () => {
  // The account read through the table changes from entry 5 to entry 6.
  await refusedAgainst(buildV0(), buildV0With({ lookupIndex: 6 }), "v0: a different lookup entry");
});

test("v0: a second signing is refused, like the first path", async () => {
  const bound = buildV0();
  const digest = approvedDigest(bound);
  await bound.signApproved(digest, [payer]);
  await assert.rejects(() => bound.signApproved(digest, [payer]), /changed between approval/);
});

test("v0: the signer set is read from the v0 message", async () => {
  // A stranger is refused, and the message's own signer is accepted: a
  // signer check that read the wrong list would fail one of the two.
  const refused = buildV0();
  await assert.rejects(
    () => refused.signApproved(approvedDigest(refused), [Keypair.generate()]),
    /signer set does not match/,
  );
  const accepted = buildV0();
  await assert.doesNotReject(() => accepted.signApproved(approvedDigest(accepted), [payer]));
});

test("v0: instructions() returns copies of what was compiled", async () => {
  const bound = buildV0();
  const a = bound.instructions();
  a[1].data.fill(0);
  const b = bound.instructions();
  assert.equal(b.length, 2);
  assert.equal(b[1].data.toString("utf8"), "graphite corpus v0");
});

test("lookup tables for a legacy message are refused, not ignored", async () => {
  assert.throws(
    () =>
      BoundTransaction.build({
        instructions: [transfer()],
        feePayer: payer.publicKey,
        recentBlockhash: BLOCKHASH,
        lastValidBlockHeight: 1,
        addressLookupTables: [realTable()],
      }),
    /legacy message, which cannot read them/,
  );
});

test("v0: a durable-nonce transaction is refused as for legacy", async () => {
  const nonce = SystemProgram.nonceAdvance({
    noncePubkey: Keypair.generate().publicKey,
    authorizedPubkey: payer.publicKey,
  });
  assert.throws(
    () =>
      BoundTransaction.build({
        instructions: [nonce, transfer()],
        feePayer: payer.publicKey,
        recentBlockhash: BLOCKHASH,
        lastValidBlockHeight: 1,
        version: 0,
      }),
    /durable-nonce/,
  );
});

test("R-P8: the transaction inside a BoundTransaction is not reachable from outside it", async () => {
  // The old design kept the transaction in a TypeScript-private field, which
  // any code holding the object could read and mutate at runtime; the digest
  // check was the only thing standing behind that. Now nothing outside the
  // class can reach it: the object's own properties are three numbers and a
  // version, and the bytes it exposes are copies that change nothing signed.
  const bound = build();
  const keys = Reflect.ownKeys(bound).map(String).sort();
  assert.deepEqual(keys, ["lastValidBlockHeight", "lookupTableCount", "version"]);
  const digest = approvedDigest(bound);
  bound.artifactBytes.fill(0xff);
  bound.messageBytes.fill(0xff);
  const raw = await bound.signApproved(digest, [payer]);
  assert.deepEqual(
    Array.from(messageOf(raw)),
    Array.from(messageOf(build().artifactBytes)),
    "the exposed bytes are copies: overwriting them changed nothing that was signed",
  );
});

test("R-P8: two concurrent signings of one bound transaction sign it once", async () => {
  const bound = build();
  const digest = approvedDigest(bound);
  const results = await Promise.allSettled([
    bound.signApproved(digest, [payer]),
    bound.signApproved(digest, [payer]),
  ]);
  assert.equal(results.filter((r) => r.status === "fulfilled").length, 1, "exactly one signs");
  const refused = results.find((r) => r.status === "rejected") as PromiseRejectedResult;
  assert.match(String(refused.reason), /already being signed/);
});
