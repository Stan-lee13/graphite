/**
 * Version-1 transactions (SIMD-0385), built, bound and signed by the bridge
 * (roadmap gap R-P8, phase 2).
 *
 * A v1 frame turns the legacy layout around: the message comes first, `0x81`
 * included, and the signatures trail it with no count. Its budget (priority
 * fee, compute limit, loaded-data limit, heap) lives in a config the message
 * carries, not in ComputeBudget instructions, and an unset limit is ZERO, not
 * a default. Every helper on the signing path that slices a frame has to know
 * this, or it compares the wrong bytes.
 *
 * What is pinned here:
 *   - the bridge's bytes for a transfer equal a frame assembled by hand from
 *     the SIMD-0385 layout (an encoder independent of kit);
 *   - signing changes only the trailing slots, the signature verifies over
 *     the message under the fee payer's key, and `firstSignatureOf` reads it
 *     from the right place;
 *   - every v1 rule the runtime enforces is refused at build or by `messageOf`.
 *
 * Nothing here contacts a network or submits anything; keypairs are per-run.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, createPublicKey, verify } from "node:crypto";
import {
  AddressLookupTableAccount,
  Keypair,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
} from "@solana/web3.js";
import bs58 from "bs58";
import {
  BoundTransaction,
  firstSignatureOf,
  MAX_TRANSACTION_BYTES,
  MAX_V1_TRANSACTION_BYTES,
  messageOf,
} from "./artifact.js";

const payer = Keypair.generate();
const cosigner = Keypair.generate();
const destination = Keypair.generate().publicKey;
const BLOCKHASH = "11111111111111111111111111111111";
const LIMITS = { computeUnitLimit: 450, loadedAccountsDataSizeLimit: 32 * 1024 };
const MEMO = new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
const COMPUTE_BUDGET = new PublicKey("ComputeBudget111111111111111111111111111111");

function transfer(from = payer.publicKey, lamports = 2_000_000): TransactionInstruction {
  return SystemProgram.transfer({ fromPubkey: from, toPubkey: destination, lamports });
}

function v1(instructions: TransactionInstruction[] = [transfer()], limits: object = LIMITS) {
  return BoundTransaction.build({
    instructions,
    feePayer: payer.publicKey,
    recentBlockhash: BLOCKHASH,
    lastValidBlockHeight: 1,
    version: 1,
    v1Limits: limits as never,
  });
}

const sha256 = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");
const u32 = (n: number) => {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n);
  return [...b];
};
const u64 = (n: bigint) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(n);
  return [...b];
};

function ed25519Verify(message: Uint8Array, signature: Uint8Array, key: PublicKey): boolean {
  const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), key.toBuffer()]);
  return verify(null, message, createPublicKey({ key: spki, format: "der", type: "spki" }), signature);
}

test("a v1 transfer is the SIMD-0385 frame, byte for byte, assembled without kit", () => {
  const ix = transfer(payer.publicKey, 3_000_000);
  const bound = v1([ix], {
    computeUnitLimit: 450,
    loadedAccountsDataSizeLimit: 32 * 1024,
    priorityFeeLamports: 5_000n,
    heapSize: 64 * 1024,
  });
  // payer (writable signer), destination (writable), System (readonly): one
  // order is possible, so the frame is fully determined by the layout.
  const expected = Uint8Array.from([
    0x81,
    1, 0, 1, // header: 1 signer, 0 readonly signed, 1 readonly unsigned
    ...u32(0b1_1111), // every config field
    ...bs58.decode(BLOCKHASH),
    1, // instructions
    3, // addresses
    ...payer.publicKey.toBytes(),
    ...destination.toBytes(),
    ...SystemProgram.programId.toBytes(),
    ...u64(5_000n), // priority fee (bits 0-1)
    ...u32(450), // compute limit (bit 2)
    ...u32(32 * 1024), // loaded-data limit (bit 3)
    ...u32(64 * 1024), // heap (bit 4)
    2, 2, ...[ix.data.length, 0], // program index, account count, data length (u16 LE)
    0, 1, // accounts
    ...ix.data,
    ...new Uint8Array(64), // the one trailing signature slot, empty
  ]);
  assert.deepEqual(Array.from(bound.artifactBytes), Array.from(expected));
  assert.equal(bound.version, 1);
  assert.equal(bound.lookupTableCount, 0);
  assert.deepEqual(Array.from(messageOf(bound.artifactBytes)), Array.from(bound.messageBytes));
  assert.equal(bound.messageBytes.length, expected.length - 64, "the message is everything before the slot");
});

test("signing a v1 transaction fills only the trailing slots, and the signature verifies over the message", async () => {
  const bound = v1();
  const approved = sha256(bound.artifactBytes);
  const before = bound.messageBytes;
  const raw = await bound.signApproved(approved, [payer]);
  assert.equal(raw[0], 0x81);
  assert.equal(raw.length, bound.artifactBytes.length);
  assert.deepEqual(Array.from(raw.subarray(0, raw.length - 64)), Array.from(before), "message untouched");
  const signature = raw.subarray(raw.length - 64);
  assert.ok(signature.some((b) => b !== 0), "the slot was filled");
  assert.ok(ed25519Verify(before, signature, payer.publicKey), "fee payer's signature over the message");
  assert.equal(firstSignatureOf(raw), bs58.encode(signature), "the transaction id is read from the trailing slot");
  // Zeroing the slot gives back the approved artifact: the digest that joins
  // an on-chain execution to its verification (the Core's unsigned_artifact).
  const zeroed = Uint8Array.from(raw);
  zeroed.fill(0, raw.length - 64);
  assert.equal(sha256(zeroed), approved);
  await assert.rejects(() => bound.signApproved(approved, [payer]), /already being signed|changed between approval/);
});

test("a two-signer v1 message needs both signers, and both slots trail the message in key order", async () => {
  const bound = v1([transfer(payer.publicKey, 1_000), transfer(cosigner.publicKey, 2_000)], {
    computeUnitLimit: 900,
    loadedAccountsDataSizeLimit: 64 * 1024,
  });
  const approved = sha256(bound.artifactBytes);
  await assert.rejects(() => bound.signApproved(approved, [payer]), /signer set does not match/);
  const raw = await bound.signApproved(approved, [cosigner, payer]);
  const message = bound.messageBytes;
  assert.equal(raw.length, message.length + 128);
  const first = raw.subarray(message.length, message.length + 64);
  const second = raw.subarray(message.length + 64);
  assert.ok(ed25519Verify(message, first, payer.publicKey), "slot 0 is the fee payer's");
  assert.ok(ed25519Verify(message, second, cosigner.publicKey), "slot 1 is the co-signer's");
  assert.equal(firstSignatureOf(raw), bs58.encode(first));
});

test("a v1 transaction may exceed 1232 bytes up to 4096; the same instructions cannot be legacy", () => {
  const memo = new TransactionInstruction({
    programId: MEMO,
    keys: [{ pubkey: payer.publicKey, isSigner: true, isWritable: true }],
    data: Buffer.alloc(2_000, 0x61),
  });
  const big = v1([memo]);
  assert.ok(big.artifactBytes.length > MAX_TRANSACTION_BYTES && big.artifactBytes.length <= MAX_V1_TRANSACTION_BYTES);
  assert.throws(
    () =>
      BoundTransaction.build({
        instructions: [memo],
        feePayer: payer.publicKey,
        recentBlockhash: BLOCKHASH,
        lastValidBlockHeight: 1,
      }),
    /at most 1232/,
  );
  const tooBig = new TransactionInstruction({ ...memo, data: Buffer.alloc(4_000, 0x61) });
  assert.throws(() => v1([tooBig]), /at most 4096/);
});

test("v1 limits are required and bounded: an unset limit is zero in v1, not a default", () => {
  assert.throws(
    () =>
      BoundTransaction.build({
        instructions: [transfer()],
        feePayer: payer.publicKey,
        recentBlockhash: BLOCKHASH,
        lastValidBlockHeight: 1,
        version: 1,
      }),
    /needs v1Limits/,
  );
  const bad: [object, RegExp][] = [
    [{ loadedAccountsDataSizeLimit: 32_768 }, /computeUnitLimit/],
    [{ computeUnitLimit: 450 }, /loadedAccountsDataSizeLimit/],
    [{ ...LIMITS, computeUnitLimit: 0 }, /computeUnitLimit/],
    [{ ...LIMITS, computeUnitLimit: 1_400_001 }, /computeUnitLimit/],
    [{ ...LIMITS, computeUnitLimit: 1.5 }, /computeUnitLimit/],
    [{ ...LIMITS, loadedAccountsDataSizeLimit: 0 }, /loadedAccountsDataSizeLimit/],
    [{ ...LIMITS, loadedAccountsDataSizeLimit: 64 * 1024 * 1024 + 1 }, /loadedAccountsDataSizeLimit/],
    [{ ...LIMITS, heapSize: 16 * 1024 }, /heapSize/],
    [{ ...LIMITS, heapSize: 512 * 1024 }, /heapSize/],
    [{ ...LIMITS, heapSize: 33 * 1024 + 1 }, /heapSize/],
    [{ ...LIMITS, priorityFeeLamports: -1n }, /priorityFeeLamports/],
    [{ ...LIMITS, priorityFeeLamports: 5 }, /priorityFeeLamports/],
  ];
  for (const [limits, why] of bad) assert.throws(() => v1([transfer()], limits), why, JSON.stringify(limits, (_, v) => (typeof v === "bigint" ? `${v}n` : v)));
});

test("a ComputeBudget instruction in a v1 message is refused: it would set nothing", () => {
  const setLimit = new TransactionInstruction({ programId: COMPUTE_BUDGET, keys: [], data: Buffer.from([2, 0x40, 0x0d, 0x03, 0x00]) });
  assert.throws(() => v1([setLimit, transfer()]), /ComputeBudget instruction, which does nothing in a v1 message/);
});

test("lookup tables are refused for v1, and v1 limits for legacy and v0", () => {
  const table = new AddressLookupTableAccount({
    key: Keypair.generate().publicKey,
    state: { deactivationSlot: 2n ** 64n - 1n, lastExtendedSlot: 0, lastExtendedSlotStartIndex: 0, addresses: [destination] },
  });
  assert.throws(
    () =>
      BoundTransaction.build({
        instructions: [transfer()],
        feePayer: payer.publicKey,
        recentBlockhash: BLOCKHASH,
        lastValidBlockHeight: 1,
        version: 1,
        v1Limits: LIMITS,
        addressLookupTables: [table],
      }),
    /v1 message, which cannot read them/,
  );
  for (const version of ["legacy", 0] as const) {
    assert.throws(
      () =>
        BoundTransaction.build({
          instructions: [transfer()],
          feePayer: payer.publicKey,
          recentBlockhash: BLOCKHASH,
          lastValidBlockHeight: 1,
          version,
          v1Limits: LIMITS,
        }),
      /v1Limits were given for a legacy or v0 message/,
    );
  }
});

test("messageOf refuses every v1 frame the Core's parse_v1 refuses", () => {
  const good = v1().artifactBytes;
  assert.doesNotThrow(() => messageOf(good));
  const mutate = (f: (b: Uint8Array) => Uint8Array) => f(Uint8Array.from(good));
  const cases: [string, Uint8Array][] = [
    ["truncated signature slot", good.subarray(0, good.length - 1)],
    ["a trailing byte", Uint8Array.from([...good, 0])],
    ["an unknown config bit", mutate((b) => ((b[4] |= 0x20), b))],
    ["half the priority-fee pair", mutate((b) => ((b[4] = (b[4] & ~0b11) | 0b01), b))],
    ["more than 4096 bytes", Uint8Array.from([...good, ...new Uint8Array(MAX_V1_TRANSACTION_BYTES)])],
    ["an impossible header (readonly signers >= signers)", mutate((b) => ((b[2] = 1), b))],
    // The destination's 32 bytes replaced by the payer's: one address twice.
    ["a duplicate address", mutate((b) => (b.set(payer.publicKey.toBytes(), 8 + 32 + 2 + 32), b))],
  ];
  for (const [what, bytes] of cases) assert.throws(() => messageOf(bytes), Error, what);
});

test("firstSignatureOf reads the legacy slot after the count, and refuses a frame with none", () => {
  const legacy = BoundTransaction.build({
    instructions: [transfer()],
    feePayer: payer.publicKey,
    recentBlockhash: BLOCKHASH,
    lastValidBlockHeight: 1,
  }).artifactBytes;
  const raw = Uint8Array.from(legacy);
  raw.fill(7, 1, 65);
  assert.equal(firstSignatureOf(raw), bs58.encode(new Uint8Array(64).fill(7)));
  assert.throws(() => firstSignatureOf(Uint8Array.from([0, ...raw.subarray(65)])), /no signature slot/);
});
