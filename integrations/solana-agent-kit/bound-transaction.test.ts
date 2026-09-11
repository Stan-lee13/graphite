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
  TransactionInstruction,
} from "@solana/web3.js";
import { BoundTransaction, messageOf } from "./artifact.js";

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

test("the honest path: the same transaction verifies, signs and submits", () => {
  const bound = build();
  const digest = approvedDigest(bound);

  bound.assertApproved(digest); // nothing changed
  const raw = bound.signAndFreeze([payer]);

  assert.deepEqual(
    Array.from(messageOf(raw)),
    Array.from(bound.messageBytes),
    "the message submitted must be the message approved",
  );
  assert.ok(raw.length > bound.messageBytes.length, "signatures were added");
});

test("signing changes only the signatures", () => {
  const bound = build();
  const before = Uint8Array.from(bound.messageBytes);
  const raw = bound.signAndFreeze([payer]);
  assert.deepEqual(Array.from(messageOf(raw)), Array.from(before));
});

test("a refreshed blockhash after approval is refused", () => {
  // The specific case the old code did implicitly on every execution: verify
  // with one blockhash, submit with whatever the sender fetched.
  const bound = build();
  const digest = approvedDigest(bound);
  bound.tx.recentBlockhash = OTHER_BLOCKHASH;
  assert.throws(
    () => bound.assertApproved(digest),
    /changed between approval and signing/,
    "a new blockhash is a new transaction and must be re-verified",
  );
});

test("a changed fee payer after approval is refused", () => {
  const bound = build();
  const digest = approvedDigest(bound);
  bound.tx.feePayer = Keypair.generate().publicKey;
  assert.throws(() => bound.assertApproved(digest), /changed between approval/);
});

test("an instruction appended after approval is refused", () => {
  const bound = build();
  const digest = approvedDigest(bound);
  bound.tx.add(transfer(1));
  assert.throws(() => bound.assertApproved(digest), /changed between approval/);
});

test("a rewritten amount after approval is refused", () => {
  const bound = build();
  const digest = approvedDigest(bound);
  // Mutate the live instruction data in place — the mutation a snapshot-based
  // check cannot see.
  bound.tx.instructions[0].data.writeBigUInt64LE(9_000_000n, 4);
  assert.throws(() => bound.assertApproved(digest), /changed between approval/);
});

test("a redirected destination after approval is refused", () => {
  const bound = build();
  const digest = approvedDigest(bound);
  bound.tx.instructions[0].keys[1].pubkey = Keypair.generate().publicKey;
  assert.throws(() => bound.assertApproved(digest), /changed between approval/);
});

test("a flipped writable bit after approval is refused", () => {
  const bound = build();
  const digest = approvedDigest(bound);
  bound.tx.instructions[0].keys[1].isWritable = false;
  assert.throws(() => bound.assertApproved(digest), /changed between approval/);
});

test("the digest names both sides so an operator can tell which moved", () => {
  const bound = build();
  const digest = approvedDigest(bound);
  bound.tx.recentBlockhash = OTHER_BLOCKHASH;
  try {
    bound.assertApproved(digest);
    assert.fail("should have thrown");
  } catch (e) {
    const msg = String(e);
    assert.ok(msg.includes(digest), "the approved digest must be named");
    assert.ok(
      /now serializes to [0-9a-f]{64}/.test(msg),
      `the current digest must be named: ${msg}`,
    );
  }
});

test("two transactions differing only in blockhash have different digests", () => {
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

test("messageOf finds the message behind any signature count", () => {
  // Hand-built frames rather than a real transaction, because the point is the
  // compact-u16 signature count in front of the message, and a real one only
  // ever exercises the single-byte case.
  const body = Uint8Array.from([1, 2, 3, 4]);
  for (const count of [0, 1, 3]) {
    const raw = Uint8Array.from([count, ...new Uint8Array(64 * count), ...body]);
    assert.deepEqual(Array.from(messageOf(raw)), Array.from(body), `count=${count}`);
  }
  // Two-byte compact-u16: 128 signatures.
  const many = Uint8Array.from([0x80, 0x01, ...new Uint8Array(64 * 128), ...body]);
  assert.deepEqual(Array.from(messageOf(many)), Array.from(body));
});

test("messageOf refuses a signature array that runs past the transaction", () => {
  assert.throws(
    () => messageOf(Uint8Array.from([4, 0, 0, 0])),
    /runs past the transaction/,
    "a truncated frame must not silently yield an empty message",
  );
});

test("the artifact carries empty signature slots — Graphite verifies before signing", () => {
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

test("a transaction with several instructions binds all of them", () => {
  const withBudget = build([
    new TransactionInstruction({
      programId: new PublicKey("ComputeBudget111111111111111111111111111111"),
      keys: [],
      data: Buffer.from([2, 0x40, 0x0d, 0x03, 0x00]),
    }),
    transfer(),
  ]);
  const digest = approvedDigest(withBudget);
  withBudget.assertApproved(digest);

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
